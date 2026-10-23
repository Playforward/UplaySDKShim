#include "core/config.h"
#include "core/debug/fault_logger.h"
#include "core/game_adapter.h"
#include "core/logging.h"
#include "core/networking/redirect.h"
#include "games/ac3/versions/current.h"
#include "games/revelations/identity.h"

namespace {
void install_ac3_debug_hooks(HMODULE module) {
    install_fault_logger(module, "assassinscreed3");
    const HookConfig& c = hook_config();
    shim_log("[ac3] adapter selected (tcp=%d rdv=%d)",
             static_cast<int>(c.capture_tcp || c.log_tcp_full), static_cast<int>(c.log_rdv_full));
}

void install_entry_hooks(HMODULE process_module) {
    install_network_hooks(process_module);
    revelations::install_identity(process_module);
}
}

const GameAdapter& game_adapter() {
    static const GameAdapter adapter{
        "assassinscreed3", "Assassin's Creed III", ac3::current::kVersion,
        "binkw32.dll", "binkw32_real.dll",
        ac3::current::kModules, ac3::current::kHosts,
        ResolverIat,
        ac3::current::kNetwork, std::size(ac3::current::kNetwork),
        ac3::current::kTls,
        nullptr, install_ac3_debug_hooks,
        install_entry_hooks,
        ac3::current::kPrudpListenerPort,
        ac3::current::kPlayforwardTitle,
        ac3::current::kLaunchPort
    };
    return adapter;
}
