#include "core/config.h"
#include "core/debug/fault_logger.h"
#include "core/debug/module_dump.h"
#include "core/game_adapter.h"
#include "core/logging.h"
#include "core/networking/redirect.h"
#include "games/futuresoldier/versions/current.h"
#include "games/futuresoldier/identity.h"

namespace {
void install_grfs_debug_hooks(HMODULE module) {
    install_fault_logger(module, "ghostreconfuturesoldier");
    const HookConfig& c = hook_config();
    if (c.dump_module) install_module_dump_hotkey(module, "FutureSoldier_dump.bin");
    shim_log("[grfs] adapter selected (tcp=%d rdv=%d)",
             static_cast<int>(c.capture_tcp || c.log_tcp_full), static_cast<int>(c.log_rdv_full));
}

void install_entry_hooks(HMODULE process_module) {
    install_network_hooks(process_module);
    futuresoldier::install_identity(process_module);
}
}

const GameAdapter& game_adapter() {
    static const GameAdapter adapter{
        "ghostreconfuturesoldier", "Ghost Recon Future Soldier", futuresoldier::current::kVersion,
        "binkw32.dll", "binkw32_real.dll",
        futuresoldier::current::kModules, futuresoldier::current::kHosts,
        ResolverIat,
        futuresoldier::current::kNetwork, std::size(futuresoldier::current::kNetwork),
        futuresoldier::current::kTls,
        nullptr, install_grfs_debug_hooks,
        install_entry_hooks,
        futuresoldier::current::kPrudpListenerPort,
        futuresoldier::current::kPlayforwardTitle,
        futuresoldier::current::kLaunchPort
    };
    return adapter;
}
