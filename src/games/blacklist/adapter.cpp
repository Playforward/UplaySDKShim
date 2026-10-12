#include "core/config.h"
#include "core/debug/fault_logger.h"
#include "core/debug/module_dump.h"
#include "core/game_adapter.h"
#include "core/logging.h"
#include "core/networking/redirect.h"
#include "games/blacklist/versions/current.h"
#include "games/blacklist/identity.h"
#include "games/blacklist/net_trace.h"
#include "games/blacklist/nla_stub.h"
#include "games/blacklist/winhttp_trace.h"

namespace {
void install_blacklist_debug_hooks(HMODULE module) {
    install_fault_logger(module, "splintercellblacklist");
    const HookConfig& c = hook_config();
    if (c.dump_module) install_module_dump_hotkey(module, "Blacklist_game_dump.bin");
    shim_log("[scbl] adapter selected (tcp=%d rdv=%d)",
             static_cast<int>(c.capture_tcp || c.log_tcp_full), static_cast<int>(c.log_rdv_full));
    if (c.nla_report_online) blacklist::install_nla_stub(module);
    if (c.trace_net_states) blacklist::install_net_trace(module);
}

void install_entry_hooks(HMODULE process_module) {
    install_network_hooks(process_module);
    blacklist::install_identity(process_module);
    blacklist::install_winhttp_trace(process_module);
}
}

const GameAdapter& game_adapter() {
    static const GameAdapter adapter{
        "splintercellblacklist", "Splinter Cell Blacklist", blacklist::current::kVersion,
        "bink2w32.dll", "bink2w32_real.dll",
        blacklist::current::kModules, blacklist::current::kHosts,
        ResolverIat,
        blacklist::current::kNetwork, std::size(blacklist::current::kNetwork),
        blacklist::current::kTls,
        nullptr, install_blacklist_debug_hooks,
        install_entry_hooks,
        blacklist::current::kPrudpListenerPort,
        blacklist::current::kPlayforwardTitle,
        blacklist::current::kLaunchPort
    };
    return adapter;
}
