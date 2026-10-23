#include "core/config.h"
#include "core/debug/fault_logger.h"
#include "core/game_adapter.h"
#include "core/logging.h"
#include "core/networking/redirect.h"
#include "games/revelations/identity.h"
#include "games/revelations/versions/current.h"

namespace {
void install_acr_debug_hooks(HMODULE module) {
    install_fault_logger(module, "assassinscreedrevelations");
    const HookConfig& c = hook_config();
    shim_log("[acr] adapter selected (tcp=%d rdv=%d)",
             static_cast<int>(c.capture_tcp || c.log_tcp_full), static_cast<int>(c.log_rdv_full));
}

void install_entry_hooks(HMODULE process_module) {
    install_network_hooks(process_module);
    revelations::install_identity(process_module);
}
}

const GameAdapter& game_adapter() {
    static const GameAdapter adapter{
        "assassinscreedrevelations", "Assassin's Creed Revelations", revelations::current::kVersion,
        "binkw32.dll", "binkw32_real.dll",
        revelations::current::kModules, revelations::current::kHosts,
        ResolverIat,
        revelations::current::kNetwork, std::size(revelations::current::kNetwork),
        revelations::current::kTls,
        nullptr, install_acr_debug_hooks,
        install_entry_hooks,
        revelations::current::kPrudpListenerPort,
        revelations::current::kPlayforwardTitle,
        revelations::current::kLaunchPort
    };
    return adapter;
}
