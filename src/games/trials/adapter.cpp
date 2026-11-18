#include "core/config.h"
#include "core/debug/fault_logger.h"
#include "core/game_adapter.h"
#include "core/logging.h"
#include "core/networking/redirect.h"
#include "games/trials/versions/current.h"
#include "games/trials/game_log.h"
#include "games/trials/identity.h"
#include "games/trials/track_central.h"

namespace {
void install_trials_debug_hooks(HMODULE module) {
    install_fault_logger(module, "trialsevolution");
    trials::install_game_log(module);
    const HookConfig& c = hook_config();
    shim_log("[trials] adapter selected (tcp=%d rdv=%d)",
             static_cast<int>(c.capture_tcp || c.log_tcp_full), static_cast<int>(c.log_rdv_full));
}

void install_entry_hooks(HMODULE process_module) {
    install_network_hooks(process_module);
    trials::install_identity(process_module);
    trials::install_track_central_fix(process_module);
}
}

// Trials ships no Bink, so the shim stands in for steam_api.dll, which
// trialsFMX.exe imports statically.
const GameAdapter& game_adapter() {
    static const GameAdapter adapter{
        "trialsevolution", "Trials Evolution Gold Edition", trials::current::kVersion,
        "steam_api.dll", "steam_api_real.dll",
        trials::current::kModules, trials::current::kHosts,
        ResolverIat,
        trials::current::kNetwork, std::size(trials::current::kNetwork),
        trials::current::kTls,
        nullptr, install_trials_debug_hooks,
        install_entry_hooks,
        trials::current::kPrudpListenerPort,
        trials::current::kPlayforwardTitle,
        trials::current::kLaunchPort
    };
    return adapter;
}
