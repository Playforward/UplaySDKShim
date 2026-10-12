#include "games/farcry3/uplay_trace.h"

#include "core/config.h"
#include "core/hooking/iat.h"
#include "core/logging.h"

#include <cstdio>
#include <cstring>

namespace {

#define UPLAY_TRACE_LIST(X)                                                    \
    X(UPLAY_Init) X(UPLAY_Update) X(UPLAY_Quit) X(UPLAY_Release)                \
    X(UPLAY_GetLastError) X(UPLAY_GetNextEvent)                                 \
    X(UPLAY_HasOverlappedOperationCompleted)                                    \
    X(UPLAY_GetOverlappedOperationResult)                                       \
    X(UPLAY_SetGameSession) X(UPLAY_ClearGameSession)                           \
    X(UPLAY_USER_GetCredentials) X(UPLAY_USER_GetCdKeys)                        \
    X(UPLAY_USER_IsConnected)                                                   \
    X(UPLAY_FRIENDS_Init) X(UPLAY_FRIENDS_GetFriendList)                        \
    X(UPLAY_PARTY_Init) X(UPLAY_PARTY_GetFullMemberList)                        \
    X(UPLAY_PARTY_IsPartyLeader) X(UPLAY_PARTY_SetGuest)                        \
    X(UPLAY_PARTY_SetUserData) X(UPLAY_PARTY_InvitePartyToGame)                 \
    X(UPLAY_ACH_GetAchievements) X(UPLAY_ACH_EarnAchievement)                   \
    X(UPLAY_AVATAR_GetAvatarIdForCurrentUser) X(UPLAY_AVATAR_GetBitmap)         \
    X(UPLAY_OVERLAY_Show)                                                       \
    X(UPLAY_Start)                                                              \
    X(UPLAY_USER_GetNameUtf8) X(UPLAY_USER_GetAccountIdUtf8)                    \
    X(UPLAY_PRODUCT_GetProductList) X(UPLAY_PRODUCT_ReleaseProductList)         \
    X(UPLAY_SAVE_GetSavegames) X(UPLAY_SAVE_Open) X(UPLAY_SAVE_Close)           \
    X(UPLAY_SAVE_Read) X(UPLAY_SAVE_Write) X(UPLAY_SAVE_Remove)                 \
    X(UPLAY_SAVE_SetName) X(UPLAY_SAVE_ReleaseGameList)                         \
    X(UPLAY_WIN_ReleaseRewardList)

using UplayFn = int(__cdecl*)(int, int, int, int, int, int);

#define UPLAY_DECLARE(name) UplayFn real_##name = nullptr; long count_##name = 0;
UPLAY_TRACE_LIST(UPLAY_DECLARE)
#undef UPLAY_DECLARE

uintptr_t g_credential_out = 0;
uintptr_t g_cdkeys_out = 0;
bool g_dumped_credentials = false;

void dump_buffer(const char* tag, uintptr_t base, int length) {
    if (!base || IsBadReadPtr(reinterpret_cast<void*>(base), length)) {
        shim_log("[uplay] %s buffer at 0x%08llx unreadable", tag,
                 static_cast<unsigned long long>(base));
        return;
    }
    const unsigned char* p = reinterpret_cast<const unsigned char*>(base);
    for (int offset = 0; offset < length; offset += 32) {
        char hex[32 * 2 + 1] = {};
        char ascii[33] = {};
        int n = (length - offset) < 32 ? (length - offset) : 32;
        for (int i = 0; i < n; ++i) {
            static const char digits[] = "0123456789abcdef";
            hex[i * 2] = digits[p[offset + i] >> 4];
            hex[i * 2 + 1] = digits[p[offset + i] & 0xf];
            ascii[i] = (p[offset + i] >= 0x20 && p[offset + i] < 0x7f)
                           ? static_cast<char>(p[offset + i]) : '.';
        }
        shim_log("[uplay] %s +%03x %s |%s|", tag, offset, hex, ascii);
    }
}

void dump_friend_list(uintptr_t list_out) {
    if (!list_out || IsBadReadPtr(reinterpret_cast<void*>(list_out), 8))
        return;

    const uint32_t count = *reinterpret_cast<const uint32_t*>(list_out);
    const uintptr_t entries = *reinterpret_cast<const uint32_t*>(list_out + 4);
    shim_log("[uplay] Friends list: count=%u entries=0x%08llx", count,
             static_cast<unsigned long long>(entries));
    dump_buffer("friends header", list_out, 8);

    if (count == 0 || count > 64 || !entries ||
        IsBadReadPtr(reinterpret_cast<void*>(entries), count * sizeof(uint32_t)))
        return;

    const uint32_t sample = count < 4 ? count : 4;
    dump_buffer("friends entries", entries, static_cast<int>(sample * sizeof(uint32_t)));
    for (uint32_t i = 0; i < sample; ++i) {
        const uintptr_t record = *reinterpret_cast<const uint32_t*>(entries + i * sizeof(uint32_t));
        if (!record || IsBadReadPtr(reinterpret_cast<void*>(record), 0x80))
            continue;
        char tag[48] = {};
        snprintf(tag, sizeof(tag), "friends record[%u]", i);
        dump_buffer(tag, record, 0x80);
    }
}

void post_call(const char* name, int a, int b, int result) {
    if (strcmp(name, "UPLAY_GetNextEvent") == 0) {
        if (hook_config().capture_uplay && (result & 0xff) && a &&
            !IsBadReadPtr(reinterpret_cast<void*>(static_cast<uintptr_t>(static_cast<unsigned>(a))), 8)) {
            const auto event_out = static_cast<uintptr_t>(static_cast<unsigned>(a));
            const int32_t type = *reinterpret_cast<const int32_t*>(event_out);
            const uintptr_t event = *reinterpret_cast<const uint32_t*>(event_out + 4);
            shim_log("[uplay] GetNextEvent event header: type=%d event=0x%08llx", type,
                     static_cast<unsigned long long>(event));
            dump_buffer("event header", event_out, 8);
            if (event && !IsBadReadPtr(reinterpret_cast<void*>(event), 0x40))
                dump_buffer("event payload", event, 0x40);
        }
    } else if (strcmp(name, "UPLAY_FRIENDS_GetFriendList") == 0) {
        if (hook_config().capture_uplay && (result & 0xff))
            dump_friend_list(static_cast<uintptr_t>(static_cast<unsigned>(b)));
    } else if (strcmp(name, "UPLAY_USER_GetCredentials") == 0) {
        g_credential_out = static_cast<uintptr_t>(static_cast<unsigned>(a));
        shim_log("[uplay]   credential out-buffer=0x%08x overlapped=0x%08x", a, b);
    } else if (strcmp(name, "UPLAY_USER_GetCdKeys") == 0) {
        g_cdkeys_out = static_cast<uintptr_t>(static_cast<unsigned>(a));
    } else if (strcmp(name, "UPLAY_HasOverlappedOperationCompleted") == 0) {
        if ((result & 0xff) && !g_dumped_credentials && g_credential_out) {
            g_dumped_credentials = true;
            shim_log("[uplay] === credential buffer (0x180 bytes) after completion ===");
            dump_buffer("cred", g_credential_out, 0x180);
            if (g_cdkeys_out) dump_buffer("cdkeys", g_cdkeys_out, 0x40);
        }
    } else if (strcmp(name, "UPLAY_GetOverlappedOperationResult") == 0) {
        if (b && !IsBadReadPtr(reinterpret_cast<void*>(b), 8))
            shim_log("[uplay]   overlapped result slot 0x%08x -> %08x %08x", b,
                     *reinterpret_cast<const unsigned*>(b),
                     *(reinterpret_cast<const unsigned*>(b) + 1));
    }
}

constexpr int kDeferredPolls = 0;
constexpr int kTrackedHandles = 16;
struct OverlappedPoll { int handle = 0; int polls = 0; };
OverlappedPoll g_polls[kTrackedHandles];
int g_poll_count = 0;
bool g_defer_logged = false;

bool defer_this_poll(int handle) {
    if (handle == 0) return false;
    OverlappedPoll* slot = nullptr;
    for (int i = 0; i < g_poll_count; ++i)
        if (g_polls[i].handle == handle) { slot = &g_polls[i]; break; }
    if (!slot) {
        if (g_poll_count >= kTrackedHandles) return false;
        slot = &g_polls[g_poll_count++];
        slot->handle = handle;
        slot->polls = 0;
    }
    if (slot->polls++ < kDeferredPolls) {
        if (!g_defer_logged) {
            g_defer_logged = true;
            shim_log("[uplay] deferring overlapped completion by %d poll(s) per handle "
                     "to match real Uplay latency (diagnostic)", kDeferredPolls);
        }
        return true;
    }
    return false;
}

struct UpcOverlapped {
    unsigned long long completed;   // Internal[0]; 1 == complete
    unsigned long long result;      // Internal[1]; 0 == UPLAY_OverlappedResult.Ok
};

struct UpcBasicList {
    int count;
    void* items;
};

UpcBasicList g_empty_product_list{0, nullptr};
bool g_product_list_completed = false;

bool complete_product_list(int flags, int out_list, int overlapped) {
    if (!hook_config().complete_upc_product_list) return false;
    if (!overlapped) {
        shim_log("[uplay] product-list completion skipped: overlapped arg is null "
                 "(flags=%08x out=%08x)", flags, out_list);
        return false;
    }
    auto* ov = reinterpret_cast<UpcOverlapped*>(overlapped);
    ov->completed = 1;
    ov->result = 0;
    if (out_list) *reinterpret_cast<UpcBasicList**>(out_list) = &g_empty_product_list;
    if (!g_product_list_completed) {
        g_product_list_completed = true;
        shim_log("[uplay] completed the stubbed product-list operation "
                 "(overlapped=%08x out=%08x, empty list) — diagnostic",
                 overlapped, out_list);
    }
    return true;
}

bool should_log(long n) { return n <= 3 || (n % 2000) == 0; }

#define UPLAY_WRAP(name)                                                       \
    int __cdecl wrap_##name(int a, int b, int c, int d, int e, int f) {         \
        int result = real_##name(a, b, c, d, e, f);                            \
        if (strcmp(#name, "UPLAY_HasOverlappedOperationCompleted") == 0 &&      \
            (result & 0xff) && defer_this_poll(a))                             \
            result = 0;                                                        \
        if (strcmp(#name, "UPLAY_PRODUCT_GetProductList") == 0 &&               \
            !(result & 0xff) && complete_product_list(a, b, c))                 \
            result = 1;                                                        \
        long n = ++count_##name;                                              \
        post_call(#name, a, b, result);                                        \
        if (should_log(n))                                                     \
            shim_log("[uplay] %s(%08x %08x %08x %08x) -> %s (al=%02x eax=%08x)"\
                     "  ra=%p  (call %ld)",                                    \
                     #name, a, b, c, d,                                        \
                     (result & 0xff) ? "true " : "FALSE",                      \
                     result & 0xff, result,                                    \
                     __builtin_return_address(0), n);                          \
        return result;                                                         \
    }
UPLAY_TRACE_LIST(UPLAY_WRAP)
#undef UPLAY_WRAP

}

void install_uplay_trace() {
    if (!hook_config().trace_uplay) return;

    HMODULE module = GetModuleHandleA("FC3_d3d11.dll");
    if (!module) module = GetModuleHandleA("FC3.dll");
    if (!module) {
        shim_log("[uplay] neither FC3_d3d11.dll nor FC3.dll is loaded yet — trace not installed");
        return;
    }

    int hooked = 0, missing = 0;
    int from_r1 = 0, from_upc = 0;
#define UPLAY_HOOK(name)                                                       \
    real_##name = reinterpret_cast<UplayFn>(                                   \
        patch_iat(module, "UPLAY_R1_LOADER.DLL", #name,                        \
                  reinterpret_cast<void*>(&wrap_##name)));                     \
    if (real_##name) { hooked++; from_r1++; }                                  \
    else {                                                                     \
        real_##name = reinterpret_cast<UplayFn>(                               \
            patch_iat(module, "UPC_R1_LOADER.DLL", #name,                      \
                      reinterpret_cast<void*>(&wrap_##name)));                 \
        if (real_##name) { hooked++; from_upc++; }                             \
        else { missing++; shim_log("[uplay] %s not imported", #name); }        \
    }
    UPLAY_TRACE_LIST(UPLAY_HOOK)
#undef UPLAY_HOOK

    shim_log("[uplay] call trace installed: %d hooked (%d via UPLAY_R1_LOADER, "
             "%d via UPC_R1_LOADER), %d absent",
             hooked, from_r1, from_upc, missing);
    if (from_upc && !from_r1)
        shim_log("[uplay] this is the 2022 decommission build (UPC SDK only)");
    else if (from_r1 && !from_upc)
        shim_log("[uplay] this is the pre-2022 build (Uplay R1 SDK)");
}
