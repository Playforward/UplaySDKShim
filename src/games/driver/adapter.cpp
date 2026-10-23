#include "core/config.h"
#include "core/debug/fault_logger.h"
#include "core/game_adapter.h"
#include "core/hooking/iat.h"
#include "core/logging.h"
#include "core/networking/redirect.h"
#include "games/driver/identity.h"
#include "games/driver/versions/current.h"

namespace {
using OutputDebugStringAFn = void(WINAPI*)(LPCSTR);
OutputDebugStringAFn g_output_debug_string = nullptr;

void WINAPI hooked_output_debug_string(LPCSTR text) {
    if (text) {
        char line[1024];
        strncpy_s(line, text, _TRUNCATE);
        for (size_t n = strlen(line); n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r'); --n) line[n - 1] = 0;
        if (line[0]) shim_log("[dsf-dbg] %s", line);
    }
    if (g_output_debug_string) g_output_debug_string(text);
}

void install_dsf_debug_hooks(HMODULE module) {
    install_fault_logger(module, "driversanfrancisco");
    const HookConfig& c = hook_config();
    shim_log("[dsf] adapter selected (tcp=%d rdv=%d)",
             static_cast<int>(c.capture_tcp || c.log_tcp_full), static_cast<int>(c.log_rdv_full));
}

void install_entry_hooks(HMODULE process_module) {
    install_network_hooks(process_module);
    driver::install_identity(process_module);
    if (hook_config().trace_debug_strings)
        g_output_debug_string = reinterpret_cast<OutputDebugStringAFn>(patch_iat(
            process_module, "KERNEL32.dll", "OutputDebugStringA", reinterpret_cast<void*>(&hooked_output_debug_string)));
}
}

const GameAdapter& game_adapter() {
    static const GameAdapter adapter{
        "driversanfrancisco", "Driver: San Francisco", driver::current::kVersion,
        "binkw32.dll", "binkw32_real.dll",
        driver::current::kModules, driver::current::kHosts,
        ResolverIat,
        driver::current::kNetwork, std::size(driver::current::kNetwork),
        driver::current::kTls,
        nullptr, install_dsf_debug_hooks,
        install_entry_hooks,
        driver::current::kPrudpListenerPort,
        driver::current::kPlayforwardTitle,
        driver::current::kLaunchPort
    };
    return adapter;
}
