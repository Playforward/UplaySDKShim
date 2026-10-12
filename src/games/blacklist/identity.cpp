#include "games/blacklist/identity.h"

#include "core/config.h"
#include "core/hooking/iat.h"
#include "core/logging.h"

#include <cstring>
#include <iterator>

namespace blacklist {
namespace {

constexpr const char* kUplayModule = "uplay_r1_loader.dll";
constexpr size_t kOutCapacity = 0x40;
constexpr const char* kPassword = "playforward";

bool write_out(char* out, const char* value, const char* what) {
    if (!out) {
        shim_log("[scbl] %s asked with a null buffer", what);
        return false;
    }
    const size_t length = strlen(value);
    const size_t copied = length < kOutCapacity ? length : kOutCapacity - 1;
    memcpy(out, value, copied);
    out[copied] = '\0';
    return true;
}

bool __cdecl hooked_get_username(char* out) {
    const bool ok = write_out(out, hook_config().login_name, "UPLAY_USER_GetUsername");
    if (ok) shim_log("[scbl] UPLAY_USER_GetUsername -> %s (hook.config login_name)", out);
    return ok;
}

bool __cdecl hooked_get_password(char* out) {
    return write_out(out, kPassword, "UPLAY_USER_GetPassword");
}

bool __cdecl hooked_get_account_id(char* out) {
    return write_out(out, hook_config().login_name, "UPLAY_USER_GetAccountId");
}

struct Patch {
    const char* name;
    void* replacement;
};

}

void install_identity(HMODULE process_module) {
    const HookConfig& c = hook_config();
    if (!c.login_name[0]) {
        shim_log("[scbl] no login_name in hook.config; %s decides who logs in", kUplayModule);
        return;
    }
    const Patch patches[] = {
        {"UPLAY_USER_GetUsername", reinterpret_cast<void*>(&hooked_get_username)},
        {"UPLAY_USER_GetPassword", reinterpret_cast<void*>(&hooked_get_password)},
        {"UPLAY_USER_GetAccountId", reinterpret_cast<void*>(&hooked_get_account_id)},
    };
    size_t patched = 0;
    for (const Patch& patch : patches)
        if (patch_iat(process_module, kUplayModule, patch.name, patch.replacement)) ++patched;
    if (patched == std::size(patches)) shim_log("[scbl] will log in as %s (hook.config login_name)", c.login_name);
}

}
