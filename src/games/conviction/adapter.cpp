#include "core/config.h"
#include "core/debug/fault_logger.h"
#include "core/game_adapter.h"
#include "core/logging.h"
#include "core/networking/redirect.h"
#include "games/conviction/agora.h"
#include "games/conviction/orbit.h"
#include "games/conviction/versions/current.h"

namespace {
void install_scc_debug_hooks(HMODULE module) {
    install_fault_logger(module, "splintercellconviction");
    const HookConfig& c = hook_config();
    shim_log("[scc] adapter selected (tcp=%d rdv=%d)",
             static_cast<int>(c.capture_tcp || c.log_tcp_full), static_cast<int>(c.log_rdv_full));
}

void install_entry_hooks(HMODULE process_module) {
    install_network_hooks(process_module);
    conviction::install_orbit(process_module);
    conviction::arm_agora_root_key();
}
}

const GameAdapter& game_adapter() {
    static const GameAdapter adapter{
        "splintercellconviction", "Splinter Cell: Conviction", conviction::current::kVersion,
        "binkw32.dll", "binkw32_real.dll",
        conviction::current::kModules, conviction::current::kHosts,
        ResolverIat,
        conviction::current::kNetwork, std::size(conviction::current::kNetwork),
        conviction::current::kTls,
        nullptr, install_scc_debug_hooks,
        install_entry_hooks,
        conviction::current::kPrudpListenerPort,
        conviction::current::kPlayforwardTitle,
        conviction::current::kLaunchPort
    };
    return adapter;
}
