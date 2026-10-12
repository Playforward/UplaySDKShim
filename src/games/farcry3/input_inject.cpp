#include "games/farcry3/input_inject.h"

#include "core/config.h"
#include "core/hooking/iat.h"
#include "core/logging.h"
#include "games/farcry3/online_autologin.h"
#include "games/farcry3/tracer.h"
#include "games/farcry3/versions/current.h"

#include <cstdint>
#include <cstring>

namespace farcry3 {
namespace {

constexpr int kVkRight = 0x27;      // VK_RIGHT
constexpr unsigned kDikRight = 0xCD; // DIK_RIGHT (DirectInput keyboard scancode)
constexpr DWORD kKeyboardStateBytes = 256;
constexpr int kMenuOnlineReady = 0xd;
constexpr long kReadsPressHeld = 12;

bool g_press_done = false;

bool pressing_now() { return false; }

using GetKeyStateFn = SHORT (WINAPI*)(int);
GetKeyStateFn g_real_get_key_state = nullptr;
bool g_logged_getkeystate_right = false;

bool g_gks_seen[256] = {};
long g_gks_logged = 0;
SHORT WINAPI hooked_get_key_state(int vKey) {
    if (vKey >= 0 && vKey < 256 && !g_gks_seen[vKey] && g_gks_logged < 40) {
        g_gks_seen[vKey] = true; ++g_gks_logged;
        shim_log("[input] GetKeyState polled vKey=0x%02x", vKey);
    }
    if (vKey == kVkRight) {
        if (!g_logged_getkeystate_right) {
            g_logged_getkeystate_right = true;
            shim_log("[input] the game polls GetKeyState(VK_RIGHT) -- this API can carry the menu press");
        }
        if (pressing_now()) return (SHORT)0x8000;
    }
    return g_real_get_key_state ? g_real_get_key_state(vKey) : 0;
}

using CreateDeviceFn = HRESULT (WINAPI*)(void* self, const GUID* guid, void** device, void* outer);
using GetDeviceStateFn = HRESULT (WINAPI*)(void* self, DWORD bytes, void* data);
using GetDeviceDataFn = HRESULT (WINAPI*)(void* self, DWORD objSize, void* rgdod, DWORD* inOut, DWORD flags);
using DirectInput8CreateFn = HRESULT (WINAPI*)(HINSTANCE, DWORD, const GUID*, void**, void*);

DirectInput8CreateFn g_real_di8create = nullptr;
CreateDeviceFn g_real_create_device = nullptr;
GetDeviceStateFn g_real_get_device_state = nullptr;
GetDeviceDataFn g_real_get_device_data = nullptr;
bool g_logged_getdevicedata = false;

void* g_keyboard_device = nullptr;
const GUID kGuidSysKeyboard =
    {0x6F1D2B61, 0xD5A0, 0x11CF, {0xBF, 0xC7, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00}};

struct BufferedEvent {
    DWORD ofs;        // for a keyboard, the DIK_ scancode
    DWORD data;       // key state: high bit set = down
    DWORD timestamp;
    DWORD sequence;
    ULONG app_data;
};

constexpr DWORD kPeek = 0x1; // DIGDD_PEEK: a look that must not be disturbed
DWORD g_inject_sequence = 0x0F000000; // above any real sequence, still increasing
long g_kbd_reads = 0;
long g_down_read = 0;
int g_inject_stage = 0; // 0 waiting, 1 down sent, 2 up sent (done)

int buffered_inject_kind() {
    if (g_press_done) return 0;
    ++g_kbd_reads;
    if (g_inject_stage == 0) {
        if (farcry3::first_session_slot_state() != kMenuOnlineReady) return 0;
        g_inject_stage = 1;
        g_down_read = g_kbd_reads;
        return 1;
    }
    if (g_inject_stage == 1 && g_kbd_reads >= g_down_read + kReadsPressHeld) {
        g_inject_stage = 2;
        g_press_done = true;
        return 2;
    }
    return 0;
}

HRESULT WINAPI hooked_get_device_data(void* self, DWORD objSize, void* rgdod, DWORD* inOut, DWORD flags) {
    if (!g_logged_getdevicedata) {
        g_logged_getdevicedata = true;
        shim_log("[input] the game reads input via DirectInput GetDeviceData (buffered) objSize=%lu", (unsigned long)objSize);
    }

    const bool keyboard = (self == g_keyboard_device);
    const bool consuming = (flags & kPeek) == 0;
    if (keyboard && consuming && objSize == sizeof(BufferedEvent) && rgdod && inOut) {
        int kind = buffered_inject_kind();
        if (kind != 0) {
            DWORD capacity = *inOut; // capacity on input, count on output
            HRESULT hr = g_real_get_device_data(self, objSize, rgdod, inOut, flags);
            if (SUCCEEDED(hr) && capacity != INFINITE && *inOut < capacity) {
                BufferedEvent* events = static_cast<BufferedEvent*>(rgdod);
                BufferedEvent& slot = events[*inOut];
                slot.ofs = kDikRight;
                slot.data = (kind == 1) ? 0x80 : 0x00;
                slot.timestamp = GetTickCount();
                slot.sequence = ++g_inject_sequence;
                slot.app_data = 0;
                *inOut += 1;
                shim_log("[input] injected Right key %s into the keyboard buffer (read %ld)",
                         kind == 1 ? "DOWN" : "UP", g_kbd_reads);
            } else if (capacity == INFINITE) {
                shim_log("[input] keyboard buffer read used INFINITE capacity; cannot append safely");
            }
            return hr;
        }
    }
    return g_real_get_device_data(self, objSize, rgdod, inOut, flags);
}
bool g_logged_di_right = false;

void* patch_vtable_slot(void* iface, int index, void* replacement) {
    void** vtable = *reinterpret_cast<void***>(iface);
    DWORD old = 0;
    if (!VirtualProtect(&vtable[index], sizeof(void*), PAGE_READWRITE, &old)) return nullptr;
    void* previous = vtable[index];
    vtable[index] = replacement;
    DWORD ignored = 0;
    VirtualProtect(&vtable[index], sizeof(void*), old, &ignored);
    return previous;
}

long g_gds_sizes_logged = 0;
DWORD g_gds_seen[8] = {};
HRESULT WINAPI hooked_get_device_state(void* self, DWORD bytes, void* data) {
    HRESULT hr = g_real_get_device_state(self, bytes, data);
    bool known = false;
    for (int i = 0; i < g_gds_sizes_logged; ++i) if (g_gds_seen[i] == bytes) known = true;
    if (!known && g_gds_sizes_logged < 8) {
        g_gds_seen[g_gds_sizes_logged++] = bytes;
        shim_log("[input] GetDeviceState polled with bytes=%lu hr=0x%08lx", bytes, (unsigned long)hr);
    }
    if (bytes == kKeyboardStateBytes && data != nullptr) {
        auto* keys = static_cast<uint8_t*>(data);
        if (!g_logged_di_right && (keys[kDikRight] & 0x80)) {
            g_logged_di_right = true;
            shim_log("[input] the game reads DIK_RIGHT via DirectInput GetDeviceState");
        }
        if (pressing_now()) keys[kDikRight] |= 0x80;
    }
    return hr;
}

HRESULT WINAPI hooked_create_device(void* self, const GUID* guid, void** device, void* outer) {
    HRESULT hr = g_real_create_device(self, guid, device, outer);
    if (SUCCEEDED(hr) && device && *device && guid &&
        memcmp(guid, &kGuidSysKeyboard, sizeof(GUID)) == 0) {
        g_keyboard_device = *device;
        shim_log("[input] identified the keyboard device");
    }
    if (SUCCEEDED(hr) && device && *device && !g_real_get_device_state) {
        void* previous = patch_vtable_slot(*device, 9, reinterpret_cast<void*>(&hooked_get_device_state));
        if (previous) {
            g_real_get_device_state = reinterpret_cast<GetDeviceStateFn>(previous);
            shim_log("[input] wrapped a DirectInput device's GetDeviceState (vtable shared across devices)");
        }
        void* prevdata = patch_vtable_slot(*device, 10, reinterpret_cast<void*>(&hooked_get_device_data));
        if (prevdata) {
            g_real_get_device_data = reinterpret_cast<GetDeviceDataFn>(prevdata);
            shim_log("[input] wrapped a DirectInput device's GetDeviceData");
        }
    }
    return hr;
}

HRESULT WINAPI hooked_di8create(HINSTANCE inst, DWORD version, const GUID* riid, void** out, void* outer) {
    HRESULT hr = g_real_di8create(inst, version, riid, out, outer);
    if (SUCCEEDED(hr) && out && *out && !g_real_create_device) {
        void* previous = patch_vtable_slot(*out, 3, reinterpret_cast<void*>(&hooked_create_device));
        if (previous) {
            g_real_create_device = reinterpret_cast<CreateDeviceFn>(previous);
            shim_log("[input] wrapped IDirectInput8::CreateDevice");
        }
    }
    return hr;
}

}

void install_input_hooks() {
    if (!hook_config().menu_autopress) return;
    if (online_autologin_installed()) {
        shim_log("[input] menu autopress not installed: online_autologin already takes the game online");
        return;
    }

    HMODULE engine = nullptr;
    for (const char* const* name = current::kModules; name && *name; ++name) {
        if ((engine = GetModuleHandleA(*name))) break;
    }
    if (!engine) {
        shim_log("[input] no engine module present yet; menu autopress not installed");
        return;
    }

    void* getkeystate = patch_iat(engine, "USER32.dll", "GetKeyState", reinterpret_cast<void*>(&hooked_get_key_state));
    if (getkeystate) g_real_get_key_state = reinterpret_cast<GetKeyStateFn>(getkeystate);

    void* di8 = patch_iat(engine, "DINPUT8.dll", "DirectInput8Create", reinterpret_cast<void*>(&hooked_di8create));
    if (di8) g_real_di8create = reinterpret_cast<DirectInput8CreateFn>(di8);

    shim_log("[input] menu autopress armed (GetKeyState=%s, DirectInput8Create=%s); waits for the state-d latch",
             getkeystate ? "hooked" : "absent", di8 ? "hooked" : "absent");
}

}
