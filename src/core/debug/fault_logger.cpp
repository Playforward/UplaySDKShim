#include "core/debug/fault_logger.h"

#include "core/logging.h"

#include <cstdint>
#include <cstring>

namespace {
uintptr_t g_module_base = 0;
uintptr_t g_module_end = 0;
char g_game_id[32] = {};
LONG g_fault_count = 0;

const char* fault_name(DWORD code) {
    switch (code) {
    case EXCEPTION_ACCESS_VIOLATION: return "ACCESS_VIOLATION";
    case EXCEPTION_IN_PAGE_ERROR: return "IN_PAGE_ERROR";
    case EXCEPTION_ILLEGAL_INSTRUCTION: return "ILLEGAL_INSTRUCTION";
    case EXCEPTION_STACK_OVERFLOW: return "STACK_OVERFLOW";
    case EXCEPTION_INT_DIVIDE_BY_ZERO: return "DIVIDE_BY_ZERO";
    case EXCEPTION_PRIV_INSTRUCTION: return "PRIVILEGED_INSTRUCTION";
    default: return "OTHER";
    }
}

bool describe_address(uintptr_t address, char* name, size_t name_size, uintptr_t* rva) {
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

LONG WINAPI fault_handler(EXCEPTION_POINTERS* exception) {
    const DWORD code = exception->ExceptionRecord->ExceptionCode;
    if ((code & 0xf0000000u) != 0xc0000000u) return EXCEPTION_CONTINUE_SEARCH;
    const LONG number = InterlockedIncrement(&g_fault_count);
    if (number > 24) return EXCEPTION_CONTINUE_SEARCH;
    const uintptr_t address = reinterpret_cast<uintptr_t>(exception->ExceptionRecord->ExceptionAddress);
    const bool in_game = address >= g_module_base && address < g_module_end;
    char owner[64] = {};
    uintptr_t owner_rva = 0;
    if (describe_address(address, owner, sizeof(owner), &owner_rva))
        shim_log("[fault] #%ld %s code=0x%08lx at=%p in %s+0x%llx tid=%lu", number,
                 fault_name(code), static_cast<unsigned long>(code),
                 exception->ExceptionRecord->ExceptionAddress, owner,
                 static_cast<unsigned long long>(owner_rva),
                 static_cast<unsigned long>(GetCurrentThreadId()));
    else
        shim_log("[fault] #%ld %s code=0x%08lx at=%p%s0x%llx tid=%lu (module unknown)", number,
                 fault_name(code), static_cast<unsigned long>(code),
                 exception->ExceptionRecord->ExceptionAddress,
                 in_game ? " game_rva=" : " outside_game_rva=",
                 static_cast<unsigned long long>(in_game ? address - g_module_base : 0),
                 static_cast<unsigned long>(GetCurrentThreadId()));
    if ((code == EXCEPTION_ACCESS_VIOLATION || code == EXCEPTION_IN_PAGE_ERROR) &&
        exception->ExceptionRecord->NumberParameters >= 2) {
        const ULONG_PTR operation = exception->ExceptionRecord->ExceptionInformation[0];
        shim_log("[fault] %s of %p", operation == 0 ? "read" : operation == 1 ? "write" : "execute",
                 reinterpret_cast<void*>(exception->ExceptionRecord->ExceptionInformation[1]));

#if !defined(_WIN64)
        const CONTEXT* ctx = exception->ContextRecord;
        const auto* frame = reinterpret_cast<const uint32_t*>(static_cast<uintptr_t>(ctx->Ebp));
        uint32_t ret = 0, arg1 = 0, arg2 = 0, parent_ret = 0;
        if (frame && !IsBadReadPtr(frame, 4 * sizeof(uint32_t))) {
            ret = frame[1];
            arg1 = frame[2];
            arg2 = frame[3];
            const auto* parent = reinterpret_cast<const uint32_t*>(static_cast<uintptr_t>(frame[0]));
            if (parent && !IsBadReadPtr(parent, 2 * sizeof(uint32_t)))
                parent_ret = parent[1];
        }
        shim_log("[fault] regs eip=%08lx eax=%08lx ebx=%08lx ecx=%08lx edx=%08lx esi=%08lx edi=%08lx ebp=%08lx esp=%08lx frame_ret=%08x parent_ret=%08x frame_arg1=%08x frame_arg2=%08x",
                 static_cast<unsigned long>(ctx->Eip), static_cast<unsigned long>(ctx->Eax),
                 static_cast<unsigned long>(ctx->Ebx), static_cast<unsigned long>(ctx->Ecx),
                 static_cast<unsigned long>(ctx->Edx), static_cast<unsigned long>(ctx->Esi),
                 static_cast<unsigned long>(ctx->Edi), static_cast<unsigned long>(ctx->Ebp),
                 static_cast<unsigned long>(ctx->Esp), ret, parent_ret, arg1, arg2);
#endif
    }
    return EXCEPTION_CONTINUE_SEARCH;
}
}

void install_fault_logger(HMODULE game_module, const char* game_id) {
    auto* base = reinterpret_cast<BYTE*>(game_module);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (!base || dos->e_magic != IMAGE_DOS_SIGNATURE) return;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;
    g_module_base = reinterpret_cast<uintptr_t>(base);
    g_module_end = g_module_base + nt->OptionalHeader.SizeOfImage;
    strncpy_s(g_game_id, game_id ? game_id : "game", _TRUNCATE);
    if (AddVectoredExceptionHandler(0, fault_handler))
        shim_log("[fault] first-chance fault logger installed for %s", g_game_id);
    else
        shim_log("[fault] first-chance fault logger registration failed: %lu", GetLastError());
}
