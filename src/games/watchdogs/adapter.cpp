#include "core/config.h"
#include "core/debug/fault_logger.h"
#include "core/debug/module_dump.h"
#include "core/game_adapter.h"
#include "core/logging.h"
#include "games/common/uplay_debug.h"
#include "games/watchdogs/versions/current.h"

namespace {
FARPROC wrap_watchdogs_symbol(HMODULE module, LPCSTR name, FARPROC resolved) {
    return wrap_uplay_symbol("watchdogs", module, name, resolved);
}

void install_watchdogs_debug_hooks(HMODULE module) {
    shim_log("[watchdogs] adapter selected; redirect_all_dns=%d", static_cast<int>(hook_config().redirect_all_dns));
    install_fault_logger(module, "watchdogs");
    if (hook_config().dump_module) install_module_dump_hotkey(module, "Disrupt_b64_dump.bin");
}
}

const GameAdapter& game_adapter() {
    static const GameAdapter adapter{
        "watchdogs", "Watch_Dogs", watchdogs::current::kVersion, "bink2w64.dll", "bink2w64_real.dll",
        watchdogs::current::kModules, watchdogs::current::kHosts,
        ResolverIat | ResolverGetProc | ResolverExportDetour,
        watchdogs::current::kNetwork, std::size(watchdogs::current::kNetwork),
        watchdogs::current::kTls,
        wrap_watchdogs_symbol, install_watchdogs_debug_hooks
    };
    return adapter;
}
