#include "core/config.h"
#include "core/debug/fault_logger.h"
#include "core/game_adapter.h"
#include "core/logging.h"
#include "core/networking/redirect.h"
#include "games/blackflag/identity.h"
#include "games/blackflag/versions/current.h"

namespace {
void install_ac4_debug_hooks(HMODULE module) {
    install_fault_logger(module, "assassinscreedblackflag");
    const HookConfig& c = hook_config();
    shim_log("[ac4] adapter selected (tcp=%d rdv=%d)",
             static_cast<int>(c.capture_tcp || c.log_tcp_full), static_cast<int>(c.log_rdv_full));
}

void install_entry_hooks(HMODULE process_module) {
    install_network_hooks(process_module);
    blackflag::install_identity(process_module);
}
}

const GameAdapter& game_adapter() {
    static const GameAdapter adapter{
        "assassinscreedblackflag", "Assassin's Creed IV Black Flag", blackflag::current::kVersion,
        "bink2w32.dll", "bink2w32_real.dll",
        blackflag::current::kModules, blackflag::current::kHosts,
        ResolverIat,
        blackflag::current::kNetwork, std::size(blackflag::current::kNetwork),
        blackflag::current::kTls,
        nullptr, install_ac4_debug_hooks,
        install_entry_hooks,
        blackflag::current::kPrudpListenerPort,
        blackflag::current::kPlayforwardTitle,
        blackflag::current::kLaunchPort
    };
    return adapter;
}
