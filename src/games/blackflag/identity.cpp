#include "games/blackflag/identity.h"

#include "core/config.h"
#include "core/hooking/iat.h"
#include "core/logging.h"

#include <cstdio>
#include <iterator>

namespace blackflag {
namespace {

constexpr const char* kUplayModule = "uplay_r1_loader.dll";
constexpr const char* kPassword = "playforward";

char g_email[160] = {};

const char* __cdecl hooked_get_username() {
    shim_log("[ac4] UPLAY_USER_GetUsernameUtf8 -> %s (hook.config login_name)", hook_config().login_name);
    return hook_config().login_name;
}

const char* __cdecl hooked_get_password() {
    return kPassword;
}

const char* __cdecl hooked_get_email() {
    return g_email;
}

struct Patch {
    const char* name;
    void* replacement;
};

}

void install_identity(HMODULE process_module) {
    const HookConfig& c = hook_config();
    if (!c.login_name[0]) {
        shim_log("[ac4] no login_name in hook.config; %s decides who logs in", kUplayModule);
        return;
    }
    snprintf(g_email, sizeof(g_email), "%s@playforward.local", c.login_name);
    const Patch patches[] = {
        {"UPLAY_USER_GetUsernameUtf8", reinterpret_cast<void*>(&hooked_get_username)},
        {"UPLAY_USER_GetPasswordUtf8", reinterpret_cast<void*>(&hooked_get_password)},
        {"UPLAY_USER_GetEmailUtf8", reinterpret_cast<void*>(&hooked_get_email)},
    };
    size_t patched = 0;
    for (const Patch& patch : patches)
        if (patch_iat(process_module, kUplayModule, patch.name, patch.replacement)) ++patched;
    shim_log("[ac4] %zu/%zu Uplay identity calls hooked; will log in as %s (hook.config login_name)",
             patched, std::size(patches), c.login_name);
}

}
