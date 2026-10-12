#include "core/networking/tls.h"

#include "core/config.h"
#include "core/game_adapter.h"
#include "core/logging.h"

#include <tlhelp32.h>
#include <cstdint>

namespace {
uintptr_t g_target = 0;
uintptr_t g_base = 0;
TlsHookDefinition g_definition{};
bool g_handler_installed = false;
bool g_armed = false;
BYTE g_original_byte = 0;
#if defined(_WIN64)
DWORD g_armed_threads[1024] = {};
size_t g_armed_thread_count = 0;
#endif

constexpr ULONGLONG kTrustWindowMilliseconds = 5000;
volatile LONG64 g_trusted_until = 0;

constexpr DWORD kTrapFlag = 0x100;
constexpr DWORD kResumeFlag = 0x10000;

constexpr size_t kMaxSteppingThreads = 64;
DWORD g_stepping_threads[kMaxSteppingThreads] = {};
size_t g_stepping_count = 0;
SRWLOCK g_stepping_lock = SRWLOCK_INIT;

bool write_byte(void* address, BYTE value) {
    DWORD old = 0;
    if (!VirtualProtect(address, 1, PAGE_EXECUTE_READWRITE, &old)) return false;
    *static_cast<BYTE*>(address) = value;
    DWORD ignored = 0; VirtualProtect(address, 1, old, &ignored);
    FlushInstructionCache(GetCurrentProcess(), address, 1);
    return true;
}

bool within_trust_window() {
    return GetTickCount64() < static_cast<ULONGLONG>(InterlockedCompareExchange64(&g_trusted_until, 0, 0));
}

bool take_stepping_thread(DWORD thread) {
    bool found = false;
    AcquireSRWLockExclusive(&g_stepping_lock);
    for (size_t i = 0; i < g_stepping_count; ++i) {
        if (g_stepping_threads[i] != thread) continue;
        g_stepping_threads[i] = g_stepping_threads[--g_stepping_count];
        found = true;
        break;
    }
    ReleaseSRWLockExclusive(&g_stepping_lock);
    return found;
}

void run_real_verifier(CONTEXT* context, bool hardware) {
#if defined(_WIN64)
    if (hardware) { context->EFlags |= kResumeFlag; return; }
    context->Rip = g_target;
#else
    (void)hardware;
    context->Eip = g_target;
#endif
    AcquireSRWLockExclusive(&g_stepping_lock);
    const bool room = g_stepping_count < kMaxSteppingThreads;
    if (room) g_stepping_threads[g_stepping_count++] = GetCurrentThreadId();
    ReleaseSRWLockExclusive(&g_stepping_lock);
    write_byte(reinterpret_cast<void*>(g_target), g_original_byte);
    if (room) context->EFlags |= kTrapFlag;
}

LONG WINAPI tls_handler(EXCEPTION_POINTERS* exception) {
    const DWORD code = exception->ExceptionRecord->ExceptionCode;
    const uintptr_t at = reinterpret_cast<uintptr_t>(exception->ExceptionRecord->ExceptionAddress);
    CONTEXT* context = exception->ContextRecord;

    if (code == EXCEPTION_SINGLE_STEP && at != g_target && take_stepping_thread(GetCurrentThreadId())) {
        write_byte(reinterpret_cast<void*>(g_target), 0xCC);
        context->EFlags &= ~kTrapFlag;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    const bool software = code == EXCEPTION_BREAKPOINT && at == g_target;
#if defined(_WIN64)
    const bool hardware = code == EXCEPTION_SINGLE_STEP && at == g_target &&
                          (context->Dr6 & 1) != 0;
#else
    const bool hardware = false;
#endif
    if (!software && !hardware) return EXCEPTION_CONTINUE_SEARCH;
#if defined(_WIN64)
    if (hardware) context->Dr6 = 0;
#endif

    if (!within_trust_window()) {
        static volatile LONG refused = 0;
        const LONG count = InterlockedIncrement(&refused);
        constexpr LONG kLoggedChecks = 3;
        constexpr LONG kLogEvery = 100;
        if (count <= kLoggedChecks || count % kLogEvery == 0)
            shim_log("[tls] certificate check #%ld with no pinned server key read beforehand: the game's own verifier decides",
                     static_cast<long>(count));
        run_real_verifier(context, hardware);
        return EXCEPTION_CONTINUE_EXECUTION;
    }

#if defined(_WIN64)
    if (g_definition.method == TlsHookMethod::Int3ReturnTrueAndClearError && context->Rcx &&
        !IsBadWritePtr(reinterpret_cast<void*>(context->Rcx + g_definition.error_field_offset), sizeof(int32_t)))
        *reinterpret_cast<int32_t*>(context->Rcx + g_definition.error_field_offset) = 0;
    const uintptr_t stack = context->Rsp;
    if (IsBadReadPtr(reinterpret_cast<void*>(stack), sizeof(uintptr_t))) return EXCEPTION_CONTINUE_SEARCH;
    context->Rax = 1;
    context->Rip = *reinterpret_cast<uintptr_t*>(stack);
    context->Rsp = stack + sizeof(uintptr_t);
#else
    const uintptr_t stack = context->Esp;
    if (IsBadReadPtr(reinterpret_cast<void*>(stack), sizeof(uintptr_t))) return EXCEPTION_CONTINUE_SEARCH;
    const uint32_t argument_bytes = hook_config().tls_verify_stack_bytes
        ? hook_config().tls_verify_stack_bytes : g_definition.x86_stack_bytes;
    context->Eax = 1;
    context->Eip = *reinterpret_cast<uintptr_t*>(stack);
    context->Esp = stack + sizeof(uintptr_t) + argument_bytes;
#endif
    static LONG logged = 0;
    if (InterlockedExchange(&logged, 1) == 0)
        shim_log("[tls] verifier bypass active at RVA 0x%llx via %s, for a pinned server key",
                 static_cast<unsigned long long>(g_target - g_base), hardware ? "hardware breakpoint" : "INT3");
    return EXCEPTION_CONTINUE_EXECUTION;
}

#if defined(_WIN64)
bool thread_is_armed(DWORD id) {
    for (size_t i = 0; i < g_armed_thread_count; ++i) if (g_armed_threads[i] == id) return true;
    return false;
}

bool arm_thread(DWORD id) {
    if (id == GetCurrentThreadId() || thread_is_armed(id)) return false;
    HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, id);
    if (!thread) return false;
    bool armed = false;
    if (SuspendThread(thread) != static_cast<DWORD>(-1)) {
        CONTEXT context{}; context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (GetThreadContext(thread, &context)) {
            context.Dr0 = g_target;
            context.Dr7 &= ~static_cast<DWORD64>(0xF << 16);
            context.Dr7 |= 1;
            context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            armed = SetThreadContext(thread, &context) != FALSE;
        }
        ResumeThread(thread);
    }
    CloseHandle(thread);
    if (armed && g_armed_thread_count < sizeof(g_armed_threads) / sizeof(g_armed_threads[0]))
        g_armed_threads[g_armed_thread_count++] = id;
    return armed;
}

int arm_process_threads() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;
    THREADENTRY32 entry{}; entry.dwSize = sizeof(entry);
    const DWORD process = GetCurrentProcessId();
    int count = 0;
    if (Thread32First(snapshot, &entry)) {
        do {
            if (entry.th32OwnerProcessID == process && arm_thread(entry.th32ThreadID)) ++count;
        } while (Thread32Next(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return count;
}

DWORD WINAPI hardware_keepalive(LPVOID) {
    bool announced = false;
    for (int pass = 0; pass < 3600; ++pass) {
        const int count = arm_process_threads();
        if (count && !announced) {
            shim_log("[tls] hardware verifier breakpoint armed on %d thread%s", count, count == 1 ? "" : "s");
            announced = true;
        }
        Sleep(1000);
    }
    return 0;
}
#endif
}

bool tls_pinning_armed() { return g_armed; }

void tls_trust_pinned_handshake() {
    InterlockedExchange64(&g_trusted_until, static_cast<LONG64>(GetTickCount64() + kTrustWindowMilliseconds));
}

void install_tls_bypass(HMODULE game_module, const TlsHookDefinition& definition) {
    if (!hook_config().bypass_tls_verify) { shim_log("[tls] verifier bypass disabled"); return; }
    const uint64_t rva = hook_config().rva_tls_verify ? hook_config().rva_tls_verify : definition.default_rva;
    if (!rva || definition.method == TlsHookMethod::None) {
        shim_log("[tls] no verified TLS hook definition for this build; bypass not armed");
        return;
    }
    if (!hook_config().tls_pin_count) {
        shim_log("[tls] bypass_tls_verify is on but tls_pin_sha256 is not set, so the bypass is not armed and the "
                 "game's own verifier decides. The game server logs its pin at startup (\"tls_pin_sha256=...\"); "
                 "or: openssl x509 -in <server cert> -pubkey -noout | openssl pkey -pubin -outform der | "
                 "openssl dgst -sha256 -binary | base64");
        return;
    }
    g_base = reinterpret_cast<uintptr_t>(game_module);
    g_target = g_base + static_cast<uintptr_t>(rva);
    g_definition = definition;
    if (IsBadReadPtr(reinterpret_cast<void*>(g_target), 1)) {
        shim_log("[tls] configured verifier RVA 0x%llx is unreadable", static_cast<unsigned long long>(rva));
        return;
    }
    if (!g_handler_installed) {
        g_handler_installed = AddVectoredExceptionHandler(1, tls_handler) != nullptr;
        if (!g_handler_installed) { shim_log("[tls] vectored handler registration failed: %lu", GetLastError()); return; }
    }
    if (definition.method == TlsHookMethod::HardwareBreakpointReturnTrue) {
#if defined(_WIN64)
        HANDLE worker = CreateThread(nullptr, 0, hardware_keepalive, nullptr, 0, nullptr);
        if (worker) { CloseHandle(worker); g_armed = true; }
        else shim_log("[tls] hardware-breakpoint worker creation failed: %lu", GetLastError());
#else
        shim_log("[tls] hardware breakpoint method is unavailable on x86");
#endif
        if (g_armed) shim_log("[tls] bypass armed for %u pinned server key%s",
                              static_cast<unsigned>(hook_config().tls_pin_count), hook_config().tls_pin_count == 1 ? "" : "s");
        return;
    }
    g_original_byte = *reinterpret_cast<BYTE*>(g_target);
    if (write_byte(reinterpret_cast<void*>(g_target), 0xCC)) {
        g_armed = true;
        shim_log("[tls] verifier trap armed at RVA 0x%llx (original=0x%02x) for %u pinned server key%s",
                 static_cast<unsigned long long>(rva), g_original_byte,
                 static_cast<unsigned>(hook_config().tls_pin_count), hook_config().tls_pin_count == 1 ? "" : "s");
    } else {
        shim_log("[tls] verifier page could not be patched at RVA 0x%llx", static_cast<unsigned long long>(rva));
    }
}
