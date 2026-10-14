#include "games/farcry3/online_autologin.h"

#include "core/config.h"
#include "core/logging.h"
#include "games/farcry3/code_scan.h"
#include "games/farcry3/versions/current.h"

#include <cstdint>
#include <cstring>

namespace farcry3 {
namespace {
constexpr const char* kWallHandler =
    "A1 ?? ?? ?? ?? 80 78 6C 00 74 12 8B 40 68 50 E8 ?? ?? ?? ?? 85 C0 74 05 E8 ?? ?? ?? ?? C2 0C 00";
constexpr size_t kWallLookupCall = 15;
constexpr size_t kWallGoOnlineCall = 24;
constexpr const char* kSessionUpdate =
    "55 8B EC A1 ?? ?? ?? ?? 56 50 8B F1 E8 ?? ?? ?? ?? 8D 46 7C E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 35";
constexpr size_t kStolenBytes = 8;
constexpr uintptr_t kSlotArray = 0x84;
constexpr uintptr_t kSlotCount = 0x88;
constexpr uintptr_t kRecordState = 0x4 + 0x10;
constexpr uintptr_t kRecordMode = 0x4 + 0x40;
constexpr int kStateMenuOnlineReady = 0xd;
constexpr long kUpdatesBetweenAttempts = 120;
constexpr int kMaxAttempts = 5;

using WallHandler = void (__stdcall*)(uint32_t, uint32_t, uint32_t);

WallHandler g_wall_handler = nullptr;
bool g_installed = false;
bool g_done = false;
int g_attempts = 0;
long g_updates_until_retry = 0;
int g_last_state = -1;

int first_slot_field(uintptr_t manager, uintptr_t field) {
    const uint8_t* count = reinterpret_cast<const uint8_t*>(manager + kSlotCount);
    const uint32_t* array = reinterpret_cast<const uint32_t*>(manager + kSlotArray);
    if (!manager || IsBadReadPtr(count, 1) || IsBadReadPtr(array, 4) || *count == 0 || *array == 0) return -1;
    const uint32_t* value = reinterpret_cast<const uint32_t*>((uintptr_t)*array + field);
    if (IsBadReadPtr(value, 4)) return -1;
    return (int)*value;
}

__attribute__((force_align_arg_pointer)) void __cdecl on_session_update(uint32_t manager) {
    if (g_done) return;
    const int state = first_slot_field(manager, kRecordState);
    if (state != g_last_state) {
        g_last_state = state;
        shim_log("[autologin] session slot state is now 0x%x", state);
    }
    if (state != kStateMenuOnlineReady) return;
    if (g_updates_until_retry > 0) { --g_updates_until_retry; return; }

    ++g_attempts;
    shim_log("[autologin] main menu is online-ready; running the Wall's go-online (attempt %d)", g_attempts);
    g_wall_handler(0, 0, 0);
    const int after = first_slot_field(manager, kRecordState);
    const int mode = first_slot_field(manager, kRecordMode);
    if (after != kStateMenuOnlineReady || mode != 0) {
        g_done = true;
        shim_log("[autologin] the game took it: slot state 0x%x -> 0x%x, mode %d", state, after, mode);
    } else if (g_attempts >= kMaxAttempts) {
        g_done = true;
        shim_log("[autologin] go-online declined %d times; leaving it to the player (Right / Y)", g_attempts);
    } else {
        g_updates_until_retry = kUpdatesBetweenAttempts;
        shim_log("[autologin] go-online declined (slot still 0xd); will retry");
    }
}

bool install_detour(uint8_t* function) {
    constexpr size_t kTrampolineSize = 1 + 1 + 1 + 5 + 3 + 1 + 1 + kStolenBytes + 5;
    auto* t = static_cast<uint8_t*>(VirtualAlloc(nullptr, kTrampolineSize,
                                                 MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (!t) return false;
    size_t at = 0;
    auto rel32 = [&](const void* target) {
        int32_t rel = (int32_t)((intptr_t)target - (intptr_t)(t + at + 4));
        memcpy(t + at, &rel, 4);
        at += 4;
    };
    t[at++] = 0x60;
    t[at++] = 0x9C;
    t[at++] = 0x51;
    t[at++] = 0xE8; rel32(reinterpret_cast<const void*>(&on_session_update));
    t[at++] = 0x83; t[at++] = 0xC4; t[at++] = 0x04;
    t[at++] = 0x9D;
    t[at++] = 0x61;
    memcpy(t + at, function, kStolenBytes); at += kStolenBytes;
    t[at++] = 0xE9; rel32(function + kStolenBytes);
    FlushInstructionCache(GetCurrentProcess(), t, kTrampolineSize);

    uint8_t jump[5] = {0xE9};
    int32_t rel = (int32_t)((intptr_t)t - (intptr_t)(function + 5));
    memcpy(jump + 1, &rel, 4);
    DWORD old = 0;
    if (!VirtualProtect(function, sizeof(jump), PAGE_EXECUTE_READWRITE, &old)) return false;
    memcpy(function, jump, sizeof(jump));
    DWORD ignored = 0;
    VirtualProtect(function, sizeof(jump), old, &ignored);
    FlushInstructionCache(GetCurrentProcess(), function, sizeof(jump));
    return true;
}

}

bool online_autologin_installed() { return g_installed; }

void install_online_autologin() {
    if (!hook_config().online_autologin) {
        shim_log("[autologin] off in hook.config; going online is left to the player (Right / Y)");
        return;
    }
    HMODULE engine = nullptr;
    const char* engine_name = nullptr;
    for (const char* const* name = current::kModules; name && *name; ++name) {
        if ((engine = GetModuleHandleA(*name))) { engine_name = *name; break; }
    }
    if (!engine) {
        shim_log("[autologin] no engine module loaded; not installed");
        return;
    }

    const uint8_t* walls[4] = {};
    const size_t wall_count = find_all(engine, parse_pattern(kWallHandler), walls, 4);
    const uint8_t* updates[2] = {};
    const size_t update_count = find_all(engine, parse_pattern(kSessionUpdate), updates, 2);
    if (wall_count == 0 || update_count != 1) {
        shim_log("[autologin] %s is not the 2022 build this knows (wall handlers=%u, session updates=%u); not installed",
                 engine_name, (unsigned)wall_count, (unsigned)update_count);
        return;
    }
    if (wall_count > 4) {
        shim_log("[autologin] %u wall-handler matches in %s, expected 2; not installed", (unsigned)wall_count, engine_name);
        return;
    }
    const uint8_t* go_online = call_target(walls[0] + kWallGoOnlineCall);
    const uint8_t* lookup = call_target(walls[0] + kWallLookupCall);
    for (size_t i = 1; i < wall_count; ++i) {
        if (call_target(walls[i] + kWallGoOnlineCall) != go_online ||
            call_target(walls[i] + kWallLookupCall) != lookup) {
            shim_log("[autologin] wall handlers in %s disagree on their callees; not installed", engine_name);
            return;
        }
    }

    const uintptr_t base = reinterpret_cast<uintptr_t>(engine);
    g_wall_handler = reinterpret_cast<WallHandler>(const_cast<uint8_t*>(walls[0]));
    uint8_t* update = const_cast<uint8_t*>(updates[0]);
    if (!install_detour(update)) {
        shim_log("[autologin] could not detour the session update at %s+0x%x; not installed",
                 engine_name, (unsigned)((uintptr_t)update - base));
        return;
    }
    g_installed = true;
    shim_log("[autologin] armed on %s: session update +0x%x, wall handler +0x%x -> go-online +0x%x; "
             "fires when the main menu is online-ready",
             engine_name, (unsigned)((uintptr_t)update - base), (unsigned)((uintptr_t)walls[0] - base),
             (unsigned)((uintptr_t)go_online - base));
}

}
