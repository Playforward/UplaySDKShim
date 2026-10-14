#include "core/config.h"
#include "core/debug/fault_logger.h"
#include "core/debug/module_dump.h"
#include "core/game_adapter.h"
#include "core/logging.h"
#include "games/common/uplay_debug.h"
#include "games/farcry3/build_fixes.h"
#include "games/farcry3/input_inject.h"
#include "games/farcry3/launch.h"
#include "games/farcry3/online_autologin.h"
#include "games/farcry3/tracer.h"
#include "games/farcry3/uplay_trace.h"
#include "games/farcry3/versions/current.h"

namespace {
FARPROC wrap_fc3_symbol(HMODULE module, LPCSTR name, FARPROC resolved) {
    if (!name || reinterpret_cast<uintptr_t>(name) <= 0xffff) return resolved;
    return wrap_uplay_symbol("fc3", module, name, resolved);
}

void install_fc3_debug_hooks(HMODULE module) {
    install_fault_logger(module, "farcry3");
    install_trace_points();
    install_uplay_trace();
    const HookConfig& c = hook_config();
    if (c.dump_module) install_module_dump_hotkey(module, "FC3_d3d11_dump.bin");
    shim_log("[fc3] adapter selected (trace_points=%s, uplay=%d tcp=%d rdv=%d)",
             c.trace_points[0] ? c.trace_points : "off",
             static_cast<int>(c.capture_uplay || c.trace_uplay),
             static_cast<int>(c.capture_tcp || c.log_tcp_full),
             static_cast<int>(c.log_rdv_full));
}

void install_entry_hooks(HMODULE process_module) {
    farcry3::install_build_fixes();
    farcry3::install_launch_hooks(process_module);
    farcry3::install_online_autologin();
    farcry3::install_input_hooks();
}
}

const GameAdapter& game_adapter() {
    static const GameAdapter adapter{
        "farcry3", "Far Cry 3", farcry3::current::kVersion, "binkw32.dll", "binkw32_real.dll",
        farcry3::current::kModules, farcry3::current::kHosts,
        ResolverIat | ResolverGetProc,
        farcry3::current::kNetwork, std::size(farcry3::current::kNetwork),
        farcry3::current::kTls,
        wrap_fc3_symbol, install_fc3_debug_hooks,
        install_entry_hooks,
        farcry3::current::kPrudpListenerPort,
        farcry3::current::kPlayforwardTitle,
        farcry3::current::kLaunchPort
    };
    return adapter;
}
