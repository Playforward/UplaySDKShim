#include "games/driver/identity.h"

#include "core/config.h"
#include "core/hooking/iat.h"
#include "core/logging.h"

#include <cstdint>

namespace driver {
namespace {

constexpr const char* kOrbitModule = "ubiorbitapi_r2_loader.dll";
constexpr const char* kGetLoginDetails =
    "?GetLoginDetails@OrbitClient@orbitclient@mg@@QAEXIPAVIGetLoginDetailsListener@23@@Z";

constexpr size_t kFieldCapacity = 80;

constexpr const char* kPassword = "playforward";

using LoginDetailsCallback = void(__thiscall*)(void* listener, uint32_t request_id, const char* account_id,
                                               const wchar_t* username, const char* password);

// Driver.exe has no uplay_r1 import and no login arguments: Orbit's
// GetLoginDetails is its only source of the player, as for Future Soldier
// and Revelations.
void __thiscall hooked_get_login_details(void* /*self*/, uint32_t request_id, void* listener) {
    void** vtable = listener ? *static_cast<void***>(listener) : nullptr;
    auto callback = vtable ? reinterpret_cast<LoginDetailsCallback>(vtable[0]) : nullptr;
    if (!callback) {
        shim_log("[dsf] GetLoginDetails req=%u with no listener callback; nothing to answer", request_id);
        return;
    }
    const char* name = hook_config().login_name;
    wchar_t wide_name[kFieldCapacity] = {};
    MultiByteToWideChar(CP_UTF8, 0, name, -1, wide_name, kFieldCapacity - 1);
    shim_log("[dsf] GetLoginDetails req=%u -> %s (hook.config login_name)", request_id, name);
    callback(listener, request_id, name, wide_name, kPassword);
}

}

void install_identity(HMODULE process_module) {
    const HookConfig& c = hook_config();
    if (!c.login_name[0]) {
        shim_log("[dsf] no login_name in hook.config; %s decides who logs in", kOrbitModule);
        return;
    }
    if (patch_iat(process_module, kOrbitModule, kGetLoginDetails, reinterpret_cast<void*>(&hooked_get_login_details)))
        shim_log("[dsf] will log in as %s (hook.config login_name)", c.login_name);
}

}
