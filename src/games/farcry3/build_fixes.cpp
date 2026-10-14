#include "games/farcry3/build_fixes.h"

#include "core/config.h"
#include "core/logging.h"
#include "games/farcry3/code_scan.h"
#include "games/farcry3/versions/current.h"

#include <cstring>
#include <iterator>
#include <windows.h>

namespace farcry3 {
namespace {

// Signatures are taken from the 2022 FC3_d3d11.dll (RVAs in the comments) and
// match FC3.dll once each as well. Relocated addresses and call targets are
// wildcarded; every byte a fix steals for its detour is a literal, so a match
// guarantees the instructions being moved.

// FUN_11167d90: the availability predicate that raises the decommission
// notice for reason code 3. Forced to return true.
constexpr const char* kDecommissionCheck =
    "55 8B EC 83 E4 F8 83 EC 0C 53 56 57 8B F0 8B F9 56 89 B7 40 01 00 00 B3 01 E8 ?? ?? ?? ?? 83 FE 18";

// FUN_11219340: CGameFriendProvider_UPlayPC's constructor (this in ESI). It
// never initialises the container at +0x84/+0x88, which the online friend list
// would have filled; the game faults at +0x12194dd reading it once it goes
// online. Its sibling at 0x1210bd0 is identical for the first 0xaa
// bytes but does initialise the pair, hence the tail.
constexpr const char* kFriendProviderCtor =
    "55 8B EC 83 E4 F8 C7 06 ?? ?? ?? ?? C7 46 04 ?? ?? ?? ?? 53 33 DB 89 5E 10 8D 46 08 89 40 04 89 00 89 5E 20";
constexpr size_t kFriendProviderTailOffset = 0xaa;
constexpr const char* kFriendProviderTail = "68 00 00 F0 41 53 89 9E 8C 00 00 00";

// FUN_112181d0 (this in ECX) and FUN_11218290 (destination in arg1) both
// assign the selector vtable 0x11fd8450 without initialising its count at
// +0xc0 and entry array at +0xc4; the menu path faults walking them.
constexpr const char* kSelectorCtorEcx =
    "55 8B EC 83 EC 18 53 56 8B F1 8B 0D ?? ?? ?? ?? 57 8D BE BC 00 00 00 C7 06 ?? ?? ?? ?? "
    "C7 46 10 ?? ?? ?? ?? C7 86 B8 00 00 00 ?? ?? ?? ??";
constexpr const char* kSelectorCtorArg =
    "55 8B EC 53 8B 5D 08 56 57 53 E8 ?? ?? ?? ?? C7 83 B8 00 00 00 ?? ?? ?? ?? C7 83 BC 00 00 00 ?? ?? ?? ??";

// FUN_112ab180: CStatisticService's "player logged in (pid64, code)" listener.
// The -login harness calls it first with pid = crc32(login name), before the
// RendezVous login; its fetch ops never complete and wedge the statistics FIFO,
// so nobody's rank is published (everyone shows level 1) and the host never
// uploads the match. That call is skipped; the real-pid call runs.
constexpr const char* kStatsLoginListener =
    "55 8B EC 83 E4 F8 83 EC 20 83 7D 10 00 56 57 75 3F 8B 75 0C 8B 7D 08 56 57";
constexpr uint16_t kStatsLoginListenerArgBytes = 0x10;

enum class Reg : uint8_t { Ecx = 1, Ebx = 3, Esi = 6 };

struct Code {
    uint8_t bytes[64];
    size_t length = 0;

    void put(uint8_t b) { bytes[length++] = b; }
    void put32(uint32_t v) { memcpy(bytes + length, &v, 4); length += 4; }

    // mov dword ptr [reg+offset], 0
    void zero_field(Reg base, uint32_t offset) {
        put(0xC7); put(0x80 | static_cast<uint8_t>(base)); put32(offset); put32(0);
    }
};

struct Patched {
    uintptr_t start;
    size_t length;
    const char* name;
};

constexpr size_t kMaxPatched = 8;
Patched g_patched[kMaxPatched];
size_t g_patched_count = 0;

uint8_t* g_stub_page = nullptr;
size_t g_stub_used = 0;
constexpr size_t kStubPageSize = 4096;

uint8_t* allocate_stub(size_t length) {
    if (!g_stub_page) {
        g_stub_page = static_cast<uint8_t*>(VirtualAlloc(nullptr, kStubPageSize, MEM_COMMIT | MEM_RESERVE,
                                                         PAGE_EXECUTE_READWRITE));
        if (!g_stub_page) return nullptr;
    }
    if (g_stub_used + length > kStubPageSize) return nullptr;
    uint8_t* stub = g_stub_page + g_stub_used;
    g_stub_used += (length + 15) & ~size_t{15};
    return stub;
}

bool write_code(uint8_t* site, const uint8_t* code, size_t length) {
    DWORD old = 0;
    if (!VirtualProtect(site, length, PAGE_EXECUTE_READWRITE, &old)) return false;
    memcpy(site, code, length);
    DWORD ignored = 0;
    VirtualProtect(site, length, old, &ignored);
    FlushInstructionCache(GetCurrentProcess(), site, length);
    return true;
}

// A JMP rel32 to `target`, written into `out` for execution at `at`.
void put_jump(uint8_t* out, const uint8_t* at, const uint8_t* target) {
    out[0] = 0xE9;
    int32_t rel = (int32_t)((intptr_t)target - (intptr_t)(at + 5));
    memcpy(out + 1, &rel, 4);
}

// Sends `site` through a stub of `before`, the `stolen` bytes moved from the
// site, `after`, and a jump back to the instruction after them. The stolen
// bytes must be whole instructions with nothing position-relative in them.
bool detour(uint8_t* site, size_t stolen, const Code& before, const Code& after) {
    const size_t length = before.length + stolen + after.length + 5;
    uint8_t* stub = allocate_stub(length);
    if (!stub) return false;
    uint8_t* at = stub;
    memcpy(at, before.bytes, before.length); at += before.length;
    memcpy(at, site, stolen); at += stolen;
    memcpy(at, after.bytes, after.length); at += after.length;
    put_jump(at, at, site + stolen);
    FlushInstructionCache(GetCurrentProcess(), stub, length);

    uint8_t entry[16];
    put_jump(entry, site, stub);
    memset(entry + 5, 0x90, stolen - 5);
    return write_code(site, entry, stolen);
}

uint32_t crc32_of(const char* text) {
    uint32_t crc = 0xffffffffu;
    for (const char* p = text; *p; ++p) {
        crc ^= (unsigned char)*p;
        for (int k = 0; k < 8; ++k) crc = (crc >> 1) ^ (0xedb88320u & (0u - (crc & 1u)));
    }
    return ~crc;
}

__attribute__((force_align_arg_pointer)) void __cdecl on_crc_login_skipped() {
    shim_log("[fixes] stats login listener: skipped the pre-login call for crc32(login_name)");
}

bool fix_decommission_check(uint8_t* site) {
    const uint8_t return_true[] = {0xB0, 0x01, 0xC2, 0x04, 0x00};   // mov al,1; ret 4
    return write_code(site, return_true, sizeof(return_true));
}

bool fix_friend_provider(uint8_t* site) {
    Code before;
    before.zero_field(Reg::Esi, 0x84);
    before.zero_field(Reg::Esi, 0x88);
    return detour(site, 6, before, Code{});      // push ebp; mov ebp,esp; and esp,-8
}

bool fix_selector_ecx(uint8_t* site) {
    Code before;
    before.zero_field(Reg::Ecx, 0xc0);
    before.zero_field(Reg::Ecx, 0xc4);
    return detour(site, 6, before, Code{});      // push ebp; mov ebp,esp; sub esp,0x18
}

bool fix_selector_arg(uint8_t* site) {
    Code after;                                  // after mov ebx,[ebp+8]
    after.zero_field(Reg::Ebx, 0xc0);
    after.zero_field(Reg::Ebx, 0xc4);
    return detour(site, 7, Code{}, after);       // push ebp; mov ebp,esp; push ebx; mov ebx,[ebp+8]
}

bool fix_stats_login(uint8_t* site) {
    const char* name = hook_config().login_name;
    if (!name[0]) {
        shim_log("[fixes] stats login listener: no login_name in hook.config, so the pre-login call "
                 "cannot be recognised; other players may show level 1");
        return false;
    }
    Code before;
    before.put(0x81); before.put(0x7C); before.put(0x24); before.put(0x04);
    before.put32(crc32_of(name));                // cmp dword ptr [esp+4], crc32(login_name)
    before.put(0x75); before.put(16);            // jne -> the original function
    before.put(0x60);                            // pushad
    before.put(0x9C);                            // pushfd
    before.put(0xB8);
    before.put32((uint32_t)(uintptr_t)&on_crc_login_skipped);
    before.put(0xFF); before.put(0xD0);          // call eax
    before.put(0x9D);                            // popfd
    before.put(0x61);                            // popad
    before.put(0x31); before.put(0xC0);          // xor eax,eax
    before.put(0xC2);
    before.put(kStatsLoginListenerArgBytes & 0xff);
    before.put(kStatsLoginListenerArgBytes >> 8);  // ret 0x10
    return detour(site, 6, before, Code{});      // push ebp; mov ebp,esp; and esp,-8
}

struct Fix {
    const char* name;
    const char* head;
    size_t tail_offset;
    const char* tail;
    size_t patched_length;
    bool (*apply)(uint8_t* site);
};

constexpr Fix kFixes[] = {
    {"decommission notice check", kDecommissionCheck, 0, nullptr, 5, fix_decommission_check},
    {"friend provider constructor", kFriendProviderCtor, kFriendProviderTailOffset, kFriendProviderTail, 6,
     fix_friend_provider},
    {"selector constructor (ecx)", kSelectorCtorEcx, 0, nullptr, 6, fix_selector_ecx},
    {"selector constructor (arg)", kSelectorCtorArg, 0, nullptr, 7, fix_selector_arg},
    {"stats login listener", kStatsLoginListener, 0, nullptr, 6, fix_stats_login},
};

}

void install_build_fixes() {
    if (!hook_config().build_fixes) {
        shim_log("[fixes] build_fixes=0 in hook.config; the 2022 build's repairs are not applied");
        return;
    }
    HMODULE engine = nullptr;
    const char* engine_name = nullptr;
    for (const char* const* name = current::kModules; name && *name; ++name) {
        if ((engine = GetModuleHandleA(*name))) { engine_name = *name; break; }
    }
    if (!engine) {
        shim_log("[fixes] no engine module loaded; nothing patched");
        return;
    }
    const uintptr_t base = reinterpret_cast<uintptr_t>(engine);

    size_t found = 0, applied = 0;
    for (const Fix& fix : kFixes) {
        const uint8_t* sites[2] = {};
        const size_t count = fix.tail
            ? find_all_with_tail(engine, parse_pattern(fix.head), fix.tail_offset, parse_pattern(fix.tail), sites, 2)
            : find_all(engine, parse_pattern(fix.head), sites, 2);
        if (count == 0) continue;
        ++found;
        if (count > 1) {
            shim_log("[fixes] %s: %u matches in %s, expected one; left alone", fix.name, (unsigned)count, engine_name);
            continue;
        }
        uint8_t* site = const_cast<uint8_t*>(sites[0]);
        if (!fix.apply(site)) {
            shim_log("[fixes] %s at %s+0x%x: not applied", fix.name, engine_name, (unsigned)((uintptr_t)site - base));
            continue;
        }
        if (g_patched_count < kMaxPatched) g_patched[g_patched_count++] = {(uintptr_t)site, fix.patched_length, fix.name};
        ++applied;
        shim_log("[fixes] %s at %s+0x%x: patched", fix.name, engine_name, (unsigned)((uintptr_t)site - base));
    }
    if (found == 0)
        shim_log("[fixes] %s is not the 2022 build; nothing patched", engine_name);
    else
        shim_log("[fixes] %s: %u of %u 2022-build repairs applied", engine_name, (unsigned)applied,
                 (unsigned)std::size(kFixes));
}

const char* build_fix_at(uintptr_t address) {
    for (size_t i = 0; i < g_patched_count; ++i)
        if (address >= g_patched[i].start && address < g_patched[i].start + g_patched[i].length)
            return g_patched[i].name;
    return nullptr;
}

}
