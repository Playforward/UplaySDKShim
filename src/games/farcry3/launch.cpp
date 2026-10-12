#include "games/farcry3/launch.h"

#include "core/config.h"
#include "core/hooking/iat.h"
#include "core/logging.h"
#include "games/farcry3/launch_command_line.h"
#include "games/farcry3/versions/current.h"

namespace farcry3 {
namespace {

using RunGameFn = bool (__cdecl*)(HINSTANCE, const char*);
RunGameFn g_real_run_game = nullptr;
constexpr size_t kCommandLineCapacity = 32768;
char g_command_line[kCommandLineCapacity];

bool __cdecl hooked_run_game(HINSTANCE instance, const char* command_line) {
    const char* line = command_line ? command_line : "";
    if (launch::with_login_name(line, hook_config().login_name, g_command_line, sizeof(g_command_line))) {
        shim_log("[launch] RunGame command line: %s", g_command_line);
        line = g_command_line;
    } else {
        shim_log("[launch] could not put login_name on the command line; passing it through unchanged: %s", line);
    }
    return g_real_run_game(instance, line);
}

}

void install_launch_hooks(HMODULE process_module) {
    const HookConfig& c = hook_config();
    if (!c.login_name[0]) {
        shim_log("[launch] no login_name in hook.config; the launcher's own -login (if any) decides who logs in");
        return;
    }
    for (const char* const* module = current::kModules; module && *module; ++module) {
        if (!GetModuleHandleA(*module)) continue;
        void* original = patch_iat(process_module, *module, current::kEntryExport, reinterpret_cast<void*>(&hooked_run_game));
        if (!original) continue;
        g_real_run_game = reinterpret_cast<RunGameFn>(original);
        shim_log("[launch] %s will log in as %s", *module, c.login_name);
        return;
    }
    shim_log("[launch] no engine module imports %s; login_name not applied", current::kEntryExport);
}

}
