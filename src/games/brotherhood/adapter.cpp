#include "core/config.h"
#include "core/debug/fault_logger.h"
#include "core/game_adapter.h"
#include "core/logging.h"
#include "core/networking/redirect.h"
#include "games/brotherhood/identity.h"
#include "games/brotherhood/versions/current.h"

#include "core/hooking/iat.h"

#include <cstring>

namespace {
using OutputDebugStringAFn = void(WINAPI*)(LPCSTR);
OutputDebugStringAFn g_output_debug_string = nullptr;

void WINAPI hooked_output_debug_string(LPCSTR text) {
    if (text) {
        char line[1024];
        strncpy_s(line, text, _TRUNCATE);
        for (size_t n = strlen(line); n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r'); --n) line[n - 1] = 0;
        if (line[0]) shim_log("[acb-dbg] %s", line);
    }
    if (g_output_debug_string) g_output_debug_string(text);
}

void install_acb_debug_hooks(HMODULE module) {
    install_fault_logger(module, "assassinscreedbrotherhood");
    const HookConfig& c = hook_config();
    shim_log("[acb] adapter selected (tcp=%d rdv=%d)",
             static_cast<int>(c.capture_tcp || c.log_tcp_full), static_cast<int>(c.log_rdv_full));
}

constexpr uintptr_t kInvalidParameterRva = 0x1ab5c9c;
constexpr unsigned char kInvalidParameterPrologue[] = {0x8b, 0xff, 0x55, 0x8b, 0xec};

using InvalidParameterFn = void(__cdecl*)(const wchar_t*, const wchar_t*, const wchar_t*, unsigned, uintptr_t);
InvalidParameterFn g_invalid_parameter = nullptr;
uintptr_t g_main_base = 0;

void __cdecl hooked_invalid_parameter(const wchar_t* expression, const wchar_t* function, const wchar_t* file,
                                      unsigned line, uintptr_t reserved) {
    shim_log("[acb] CRT invalid parameter; call chain (rva in ACBMP.exe):");
    auto* frame = static_cast<uintptr_t*>(__builtin_frame_address(0));
    for (int depth = 0; depth < 16 && frame && !IsBadReadPtr(frame, 2 * sizeof(uintptr_t)); ++depth) {
        const uintptr_t ret = frame[1];
        shim_log("[acb]   #%d %p (rva 0x%llx) args %08lx %08lx %08lx", depth, reinterpret_cast<void*>(ret),
                 static_cast<unsigned long long>(ret - g_main_base),
                 IsBadReadPtr(frame + 2, 12) ? 0ul : static_cast<unsigned long>(frame[2]),
                 IsBadReadPtr(frame + 2, 12) ? 0ul : static_cast<unsigned long>(frame[3]),
                 IsBadReadPtr(frame + 2, 12) ? 0ul : static_cast<unsigned long>(frame[4]));
        auto* next = reinterpret_cast<uintptr_t*>(frame[0]);
        if (next <= frame) break;
        frame = next;
    }
    g_invalid_parameter(expression, function, file, line, reserved);
}

void install_invalid_parameter_trace(HMODULE module) {
    g_main_base = reinterpret_cast<uintptr_t>(module);
    auto* target = reinterpret_cast<unsigned char*>(g_main_base + kInvalidParameterRva);
    if (std::memcmp(target, kInvalidParameterPrologue, sizeof(kInvalidParameterPrologue)) != 0) {
        shim_log("[acb] _invalid_parameter prologue differs at rva 0x%llx; not traced",
                 static_cast<unsigned long long>(kInvalidParameterRva));
        return;
    }
    auto* trampoline = static_cast<unsigned char*>(
        VirtualAlloc(nullptr, 16, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (!trampoline) return;
    std::memcpy(trampoline, kInvalidParameterPrologue, sizeof(kInvalidParameterPrologue));
    trampoline[5] = 0xe9;
    const int32_t back = static_cast<int32_t>(reinterpret_cast<uintptr_t>(target + 5) -
                                              reinterpret_cast<uintptr_t>(trampoline + 10));
    std::memcpy(trampoline + 6, &back, 4);
    g_invalid_parameter = reinterpret_cast<InvalidParameterFn>(trampoline);

    DWORD old = 0;
    if (!VirtualProtect(target, 5, PAGE_EXECUTE_READWRITE, &old)) return;
    target[0] = 0xe9;
    const int32_t jump = static_cast<int32_t>(reinterpret_cast<uintptr_t>(&hooked_invalid_parameter) -
                                              reinterpret_cast<uintptr_t>(target + 5));
    std::memcpy(target + 1, &jump, 4);
    VirtualProtect(target, 5, old, &old);
    FlushInstructionCache(GetCurrentProcess(), target, 5);
    shim_log("[acb] tracing CRT invalid-parameter reports");
}

void install_entry_hooks(HMODULE process_module) {
    install_network_hooks(process_module);
    brotherhood::install_identity(process_module);
    char path[MAX_PATH] = {};
    GetModuleFileNameA(process_module, path, MAX_PATH);
    const char* exe = std::strrchr(path, '\\');
    if (hook_config().trace_debug_strings && _stricmp(exe ? exe + 1 : path, "ACBMP.exe") == 0)
        install_invalid_parameter_trace(process_module);
    if (hook_config().trace_debug_strings) {
        g_output_debug_string = reinterpret_cast<OutputDebugStringAFn>(patch_iat(
            process_module, "KERNEL32.dll", "OutputDebugStringA", reinterpret_cast<void*>(&hooked_output_debug_string)));
    }
}
}

const GameAdapter& game_adapter() {
    static const GameAdapter adapter{
        "assassinscreedbrotherhood", "Assassin's Creed Brotherhood", brotherhood::current::kVersion,
        "binkw32.dll", "binkw32_real.dll",
        brotherhood::current::kModules, brotherhood::current::kHosts,
        ResolverIat,
        brotherhood::current::kNetwork, std::size(brotherhood::current::kNetwork),
        brotherhood::current::kTls,
        nullptr, install_acb_debug_hooks,
        install_entry_hooks,
        brotherhood::current::kPrudpListenerPort,
        brotherhood::current::kPlayforwardTitle,
        brotherhood::current::kLaunchPort
    };
    return adapter;
}
