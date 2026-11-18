#include "games/trials/identity.h"

#include "core/config.h"
#include "core/hooking/iat.h"
#include "core/logging.h"

#include <cstdint>

namespace trials {
namespace {

constexpr const char* kOrbitModule = "ubiorbitapi_r2_loader.dll";
constexpr const char* kGetLoginDetails =
    "?GetLoginDetails@OrbitClient@orbitclient@mg@@QAEXIPAVIGetLoginDetailsListener@23@@Z";
constexpr const char* kUpdate = "?Update@OrbitClient@orbitclient@mg@@QAEXXZ";

constexpr size_t kFieldCapacity = 80;

constexpr const char* kPassword = "playforward";

// Same listener ABI as Future Soldier's (trialsFMX.exe 0x739fc0 reads the
// account id and the wide name as its 2nd/3rd arguments).
using LoginDetailsCallback = void(__thiscall*)(void* listener, uint32_t request_id, const char* account_id,
                                               const wchar_t* username, const char* password);
using UpdateFn = void(__thiscall*)(void* self);

UpdateFn g_update = nullptr;
void* g_pending_listener = nullptr;
uint32_t g_pending_request = 0;

void deliver(void* listener, uint32_t request_id) {
    void** vtable = *static_cast<void***>(listener);
    auto callback = reinterpret_cast<LoginDetailsCallback>(vtable[0]);
    const char* name = hook_config().login_name;
    wchar_t wide_name[kFieldCapacity] = {};
    MultiByteToWideChar(CP_UTF8, 0, name, -1, wide_name, kFieldCapacity - 1);
    shim_log("[trials] GetLoginDetails req=%u answered -> %s (hook.config login_name)", request_id, name);
    callback(listener, request_id, name, wide_name, kPassword);
}

// trialsFMX.exe asks while it is still building its Uplay wrapper
// (0x73a32c) and faults if the answer arrives inside that call, as the
// real Orbit client never does: it answers from a later Update(). So the
// request is only remembered here and answered on the next Update().
void __thiscall hooked_get_login_details(void* /*self*/, uint32_t request_id, void* listener) {
    if (!listener || !*static_cast<void**>(listener)) {
        shim_log("[trials] GetLoginDetails req=%u with no listener; nothing to answer", request_id);
        return;
    }
    shim_log("[trials] GetLoginDetails req=%u queued for the next Update", request_id);
    g_pending_listener = listener;
    g_pending_request = request_id;
}

void __thiscall hooked_update(void* self) {
    if (g_update) g_update(self);
    if (void* listener = g_pending_listener) {
        g_pending_listener = nullptr;
        deliver(listener, g_pending_request);
    }
}

}

void install_identity(HMODULE process_module) {
    const HookConfig& c = hook_config();
    if (!c.login_name[0]) {
        shim_log("[trials] no login_name in hook.config; %s decides who logs in", kOrbitModule);
        return;
    }
    // Entry hooks run more than once; a second patch would read our own hook
    // back as the original Update and recurse.
    if (g_update) return;
    g_update = reinterpret_cast<UpdateFn>(patch_iat(process_module, kOrbitModule, kUpdate, reinterpret_cast<void*>(&hooked_update)));
    if (!g_update) {
        shim_log("[trials] cannot hook %s!Update; leaving login to the loader", kOrbitModule);
        return;
    }
    if (patch_iat(process_module, kOrbitModule, kGetLoginDetails, reinterpret_cast<void*>(&hooked_get_login_details)))
        shim_log("[trials] will log in as %s (hook.config login_name)", c.login_name);
}

}
