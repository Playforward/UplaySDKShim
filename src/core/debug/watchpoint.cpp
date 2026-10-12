#include "core/debug/watchpoint.h"

#include "core/logging.h"

#include <tlhelp32.h>

#include <cstdio>
#include <cstring>

namespace {

constexpr DWORD kLocalEnable0 = 1u << 0;
constexpr DWORD kExactControl = (1u << 8) | (1u << 9);
constexpr DWORD kConditionShift = 16;
constexpr DWORD kConditionMask = 0xfu << kConditionShift;
constexpr DWORD kReadWrite1Byte = 0x3u << kConditionShift;
constexpr DWORD kWriteOnly1Byte = 0x1u << kConditionShift;

uintptr_t g_address = 0;
bool g_writes_only = false;
char g_label[64] = {};
bool g_handler_installed = false;

struct Reader {
    uintptr_t eip = 0;
    long hits = 0;
};
constexpr int kMaxReaders = 24;
Reader g_readers[kMaxReaders];
int g_reader_count = 0;

bool describe(uintptr_t address, char* name, size_t name_size, uintptr_t* rva) {
    HMODULE module = nullptr;
    if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            reinterpret_cast<LPCSTR>(address), &module) ||
        !module)
        return false;
    char path[MAX_PATH] = {};
    if (!GetModuleFileNameA(module, path, sizeof(path))) return false;
    const char* base_name = path;
    for (const char* cursor = path; *cursor; ++cursor)
        if (*cursor == '\\' || *cursor == '/') base_name = cursor + 1;
    strncpy_s(name, name_size, base_name, _TRUNCATE);
    *rva = address - reinterpret_cast<uintptr_t>(module);
    return true;
}

void apply(CONTEXT* context, uintptr_t address) {
    context->Dr0 = address;
    context->Dr7 = (context->Dr7 & ~kConditionMask) | kLocalEnable0 | kExactControl |
                   (g_writes_only ? kWriteOnly1Byte : kReadWrite1Byte);
    context->Dr6 = 0;
}

LONG WINAPI watch_handler(EXCEPTION_POINTERS* exception) {
    if (exception->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;
    CONTEXT* context = exception->ContextRecord;
    if (g_address == 0 || (context->Dr6 & 0xfu) == 0) return EXCEPTION_CONTINUE_SEARCH;

#if defined(_WIN64)
    const uintptr_t eip = static_cast<uintptr_t>(context->Rip);
#else
    const uintptr_t eip = static_cast<uintptr_t>(context->Eip);
#endif
    Reader* reader = nullptr;
    for (int i = 0; i < g_reader_count; ++i)
        if (g_readers[i].eip == eip) { reader = &g_readers[i]; break; }
    if (!reader && g_reader_count < kMaxReaders) {
        reader = &g_readers[g_reader_count++];
        reader->eip = eip;
    }
    if (reader) {
        reader->hits++;
        char value[48] = {};
        if (!IsBadReadPtr(reinterpret_cast<void*>(g_address), 4)) {
            const unsigned long dword = *reinterpret_cast<const unsigned long*>(g_address);
            sprintf_s(value, "value=0x%08lx (byte 0x%02x)", dword,
                      *reinterpret_cast<const unsigned char*>(g_address));
        } else if (!IsBadReadPtr(reinterpret_cast<void*>(g_address), 1)) {
            sprintf_s(value, "byte=0x%02x", *reinterpret_cast<const unsigned char*>(g_address));
        } else {
            strncpy_s(value, "value unreadable", _TRUNCATE);
        }
        if (reader->hits <= 3 || (reader->hits % 500) == 0) {
            char owner[64] = {};
            uintptr_t rva = 0;
            if (describe(eip, owner, sizeof(owner), &rva))
                shim_log("[watch] %s accessed by %s+0x%llx (next insn after access) "
                         "%s hits=%ld tid=%lu",
                         g_label, owner, static_cast<unsigned long long>(rva), value,
                         reader->hits, static_cast<unsigned long>(GetCurrentThreadId()));
            else
                shim_log("[watch] %s accessed from eip=0x%08lx (module unknown) %s hits=%ld tid=%lu",
                         g_label, static_cast<unsigned long>(eip), value, reader->hits,
                         static_cast<unsigned long>(GetCurrentThreadId()));
        }
    }
    context->Dr6 = 0;
    return EXCEPTION_CONTINUE_EXECUTION;
}

}

void watchpoint_install_handler() {
    if (g_handler_installed) return;
    if (AddVectoredExceptionHandler(0, watch_handler)) {
        g_handler_installed = true;
    } else {
        shim_log("[watch] AddVectoredExceptionHandler failed: %lu", GetLastError());
    }
}

bool watchpoint_arm(uintptr_t address, const char* label, CONTEXT* self, bool writes_only) {
    watchpoint_install_handler();
    if (!g_handler_installed) return false;
    g_address = address;
    g_writes_only = writes_only;
    strncpy_s(g_label, label ? label : "watch", _TRUNCATE);

    int armed = 0, seen = 0, failed = 0;
    bool verified = false;
    if (self) {
        apply(self, address);
        armed++;
        seen++;
    }

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot != INVALID_HANDLE_VALUE) {
        THREADENTRY32 entry = {};
        entry.dwSize = sizeof(entry);
        const DWORD self_pid = GetCurrentProcessId();
        const DWORD self_tid = GetCurrentThreadId();
        if (Thread32First(snapshot, &entry)) {
            do {
                if (entry.th32OwnerProcessID != self_pid) continue;
                if (entry.th32ThreadID == self_tid) continue;
                seen++;
                HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
                                               THREAD_SUSPEND_RESUME,
                                           FALSE, entry.th32ThreadID);
                if (!thread) { failed++; continue; }
                if (SuspendThread(thread) == static_cast<DWORD>(-1)) {
                    CloseHandle(thread);
                    failed++;
                    continue;
                }
                CONTEXT context = {};
                context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                if (GetThreadContext(thread, &context)) {
                    apply(&context, address);
                    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                    if (SetThreadContext(thread, &context)) {
                        armed++;
                        CONTEXT check = {};
                        check.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                        if (GetThreadContext(thread, &check) && check.Dr0 == address &&
                            (check.Dr7 & kLocalEnable0))
                            verified = true;
                    } else {
                        failed++;
                    }
                } else {
                    failed++;
                }
                ResumeThread(thread);
                CloseHandle(thread);
            } while (Thread32Next(snapshot, &entry));
        }
        CloseHandle(snapshot);
    }

    shim_log("[watch] %s armed on 0x%08llx (%s): %d of %d thread(s), %d failed, readback=%s",
             g_label, static_cast<unsigned long long>(address),
             g_writes_only ? "writes only" : "reads and writes", armed, seen, failed,
             verified ? "confirmed" : "NOT CONFIRMED (debug registers may be ignored here)");
    return armed > 0;
}
