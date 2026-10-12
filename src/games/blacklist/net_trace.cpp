#include "games/blacklist/net_trace.h"

#include "core/logging.h"
#include "games/blacklist/state_names.inc"

#include <cstdint>
#include <cstdio>
#include <cstring>

namespace blacklist {
namespace {
constexpr uintptr_t kExpectedBase = 0x00400000;

const char* hashed_name(unsigned id) {
    int low = 0, high = static_cast<int>(sizeof(kHashedNames) / sizeof(kHashedNames[0])) - 1;
    while (low <= high) {
        int mid = (low + high) / 2;
        if (kHashedNames[mid].id == id) return kHashedNames[mid].name;
        if (kHashedNames[mid].id < id) low = mid + 1; else high = mid - 1;
    }
    return nullptr;
}

bool readable(const void* address, size_t size) {
    return address != nullptr && !IsBadReadPtr(address, size);
}

bool constant_stub(const void* function, uint32_t& value) {
    const uint8_t* code = static_cast<const uint8_t*>(function);
    if (!readable(code, 6) || code[0] != 0xB8 || code[5] != 0xC3) return false;
    std::memcpy(&value, code + 1, sizeof(value));
    return true;
}

const void* vtable_slot(const void* object, int index) {
    if (!readable(object, sizeof(void*))) return nullptr;
    const void* const* vtable = *static_cast<const void* const* const*>(object);
    if (!readable(vtable + index, sizeof(void*))) return nullptr;
    return vtable[index];
}

const char* describe_state(const void* state, char* buffer, size_t size) {
    if (state == nullptr) { std::snprintf(buffer, size, "NULL"); return buffer; }
    uint32_t name_address = 0, id = 0;
    const char* name = nullptr;
    if (constant_stub(vtable_slot(state, 13), name_address) &&
        readable(reinterpret_cast<const char*>(name_address), 1)) {
        name = reinterpret_cast<const char*>(name_address);
    }
    constant_stub(vtable_slot(state, 12), id);
    std::snprintf(buffer, size, "%s(inst=%p, id=%08x)", name ? name : "?", state, id);
    return buffer;
}

const char* gear_string(const void* string, char* buffer, size_t size) {
    buffer[0] = '\0';
    struct GearString { void* allocator; uint32_t unknown; const uint8_t* internal; void* tag; };
    if (!readable(string, sizeof(GearString))) { std::snprintf(buffer, size, "<unreadable>"); return buffer; }
    const GearString* gear = static_cast<const GearString*>(string);
    if (!readable(gear->internal, 12)) { std::snprintf(buffer, size, "<null>"); return buffer; }
    uint32_t length = 0;
    std::memcpy(&length, gear->internal + 4, sizeof(length));
    if (length >= size) length = static_cast<uint32_t>(size) - 1;
    if (!readable(gear->internal + 12, length)) { std::snprintf(buffer, size, "<unreadable>"); return buffer; }
    std::memcpy(buffer, gear->internal + 12, length);
    buffer[length] = '\0';
    return buffer;
}

const char* describe_id(unsigned id, char* buffer, size_t size) {
    const char* name = hashed_name(id);
    if (name) std::snprintf(buffer, size, "%s(id=%08x)", name, id);
    else std::snprintf(buffer, size, "id=%08x", id);
    return buffer;
}

void* call_thiscall(void* function, void* self) {
    void* result;
    __asm__ volatile("call *%1" : "=a"(result) : "r"(function), "c"(self) : "edx", "memory", "cc");
    return result;
}

uint32_t peek32(const void* base, unsigned offset) {
    const uint8_t* at = static_cast<const uint8_t*>(base) + offset;
    return readable(at, 4) ? *reinterpret_cast<const uint32_t*>(at) : 0xDEADBEEFu;
}

void report_bl_conditions(unsigned state_slot) {
    void* notify = readable(reinterpret_cast<void*>(0x0338d5f8), 4)
        ? *reinterpret_cast<void**>(0x0338d5f8) : nullptr;
    shim_log("[scbl-trace]   clear#1 g_338d5f8=%p [+0x9c]=%08x", notify,
             notify ? peek32(notify, 0x9c) : 0u);

    void* core = readable(reinterpret_cast<void*>(0x03383df8), 4)
        ? *reinterpret_cast<void**>(0x03383df8) : nullptr;
    void* session = core ? reinterpret_cast<void*>(peek32(core, 0x48)) : nullptr;
    shim_log("[scbl-trace]   clear#2 core=%p session=%p [+0x404]=%08x mode=%08x expected=%08x",
             core, session, session ? peek32(session, 0x404) : 0u,
             readable(reinterpret_cast<void*>(0x02cf5c50), 4) ? *reinterpret_cast<uint32_t*>(0x02cf5c50) : 0u,
             readable(reinterpret_cast<void*>(0x0338d984), 4) ? *reinterpret_cast<uint32_t*>(0x0338d984) : 0u);

    using GetFn = void* (*)();
    void* owner = reinterpret_cast<GetFn>(0x00451610)();
    shim_log("[scbl-trace]   clear#3 0x451610()=%p [+0x448]=%02x", owner,
             owner ? (peek32(owner, 0x448) & 0xff) : 0u);

    void* state = readable(reinterpret_cast<void*>(state_slot), 4)
        ? *reinterpret_cast<void**>(state_slot) : nullptr;
    void* connection = state ? reinterpret_cast<void*>(peek32(state, 0x30)) : nullptr;
    shim_log("[scbl-trace]   clear#4 state=%p connection=%p id[+0x404]=%08x", state, connection,
             connection ? peek32(connection, 0x404) : 0u);
}

void report_online_check() {
    const uint32_t enabled = readable(reinterpret_cast<void*>(0x03383df8), 4)
        ? *reinterpret_cast<uint32_t*>(0x03383df8) : 0xFFFFFFFFu;

    void* player = nullptr;
    if (readable(reinterpret_cast<void*>(0x0330c198), 4)) {
        if (*reinterpret_cast<uint32_t*>(0x0330c198) != 0) {
            player = *reinterpret_cast<void**>(0x0330c4f8);
        } else {
            player = *reinterpret_cast<void**>(0x0330c4fc);
            if (player == nullptr) player = *reinterpret_cast<void**>(0x0330c4f8);
        }
    }

    void* profile = nullptr;
    if (readable(player, sizeof(void*))) {
        void** vtable = *reinterpret_cast<void***>(player);
        if (readable(vtable, 0x1f4)) {
            void* getter = vtable[0x1f0 / 4];
            if (readable(getter, 1)) profile = call_thiscall(getter, player);
        }
    }

    if (!readable(profile, 0x24)) {
        shim_log("[scbl-trace] online check: enabled=%u player=%p profile=%p (no profile -> logout)",
                 enabled, player, profile);
        return;
    }
    const uint32_t id = *reinterpret_cast<uint32_t*>(static_cast<uint8_t*>(profile) + 0x14);
    const uint8_t flag = *(static_cast<uint8_t*>(profile) + 0x23);
    shim_log("[scbl-trace] online check: enabled=%u player=%p profile=%p id=0x%08x flag=%u"
             " -> %s", enabled, player, profile, id, flag,
             (enabled != 0 && id != 0xFFFFFFFFu && flag == 0) ? "valid" : "INVALID (this is the logout)");
}

enum HookId {
    kNextState = 0, kLeaveState, kChangeState, kResultBase,
    kResultCore, kResultSession, kResultRdvSession, kResultLobby,
    kRaiseGoal, kHookCount
};

struct Target {
    const char* name;
    uintptr_t address;
    const uint8_t* prologue;   // the bytes the offset was measured on
    size_t prologue_length;    // whole instructions, at least 5
};

const uint8_t kPrologueStdFrame[]  = {0x55, 0x8B, 0xEC, 0x6A, 0xFF};              // push ebp; mov ebp,esp; push -1
const uint8_t kPrologueLeave[]     = {0x55, 0x8B, 0xEC, 0x56, 0x57};              // push ebp; mov ebp,esp; push esi; push edi
const uint8_t kPrologueChange[]    = {0x55, 0x8B, 0xEC, 0x56, 0x8B, 0xF1};        // ... push esi; mov esi,ecx

const Target kTargets[kHookCount] = {
    {"NextState",         0x00834FF0, kPrologueStdFrame, sizeof(kPrologueStdFrame)},
    {"LeaveState",        0x007FE000, kPrologueLeave,    sizeof(kPrologueLeave)},
    {"ChangeState",       0x00858ED0, kPrologueChange,   sizeof(kPrologueChange)},
    {"NetResultBase",     0x007FD740, kPrologueStdFrame, sizeof(kPrologueStdFrame)},
    {"NetResultCore",     0x0081E020, kPrologueStdFrame, sizeof(kPrologueStdFrame)},
    {"NetResultSession",  0x0081DE50, kPrologueStdFrame, sizeof(kPrologueStdFrame)},
    {"NetResultRdv",      0x007FFD30, kPrologueStdFrame, sizeof(kPrologueStdFrame)},
    {"NetResultLobby",    0x00801260, kPrologueStdFrame, sizeof(kPrologueStdFrame)},
    {"RaiseGoal",         0x00849F80, kPrologueStdFrame, sizeof(kPrologueStdFrame)},
};

}  // namespace
}  // namespace blacklist

extern "C" {
void* bl_net_trace_trampolines[blacklist::kHookCount];
void __cdecl bl_net_trace_event(int hook, void* self, unsigned a1, unsigned a2, unsigned a3, unsigned caller);
}

#define BL_THUNK(symbol, index)                                                \
    __asm__(".text\n"                                                          \
            ".globl _" #symbol "\n"                                            \
            "_" #symbol ":\n"                                                  \
            "  pushal\n"                 /* +32: edi esi ebp esp ebx edx ecx eax */ \
            "  pushfl\n"                 /* +4 */                              \
            "  movl %esp, %ebp\n"                                              \
            "  pushl 36(%ebp)\n"         /* the caller's return address */     \
            "  pushl 48(%ebp)\n"         /* third stack argument */            \
            "  pushl 44(%ebp)\n"         /* second */                          \
            "  pushl 40(%ebp)\n"         /* first stack argument */             \
            "  pushl 28(%ebp)\n"         /* ecx, the object */                 \
            "  pushl $" #index "\n"                                            \
            "  call _bl_net_trace_event\n"                                     \
            "  addl $24, %esp\n"                                               \
            "  popfl\n"                                                        \
            "  popal\n"                                                        \
            "  jmp *(_bl_net_trace_trampolines + " #index " * 4)\n")

BL_THUNK(bl_thunk_next_state, 0);
BL_THUNK(bl_thunk_leave_state, 1);
BL_THUNK(bl_thunk_change_state, 2);
BL_THUNK(bl_thunk_result_base, 3);
BL_THUNK(bl_thunk_result_core, 4);
BL_THUNK(bl_thunk_result_session, 5);
BL_THUNK(bl_thunk_result_rdv, 6);
BL_THUNK(bl_thunk_result_lobby, 7);
BL_THUNK(bl_thunk_raise_goal, 8);

extern "C" {
void bl_thunk_next_state();
void bl_thunk_leave_state();
void bl_thunk_change_state();
void bl_thunk_result_base();
void bl_thunk_result_core();
void bl_thunk_result_session();
void bl_thunk_result_rdv();
void bl_thunk_result_lobby();
void bl_thunk_raise_goal();
}

namespace blacklist {
namespace {

void* const kThunks[kHookCount] = {
    reinterpret_cast<void*>(&bl_thunk_next_state),
    reinterpret_cast<void*>(&bl_thunk_leave_state),
    reinterpret_cast<void*>(&bl_thunk_change_state),
    reinterpret_cast<void*>(&bl_thunk_result_base),
    reinterpret_cast<void*>(&bl_thunk_result_core),
    reinterpret_cast<void*>(&bl_thunk_result_session),
    reinterpret_cast<void*>(&bl_thunk_result_rdv),
    reinterpret_cast<void*>(&bl_thunk_result_lobby),
    reinterpret_cast<void*>(&bl_thunk_raise_goal),
};

bool install_one(const Target& target, void* thunk, void*& trampoline) {
    uint8_t* code = reinterpret_cast<uint8_t*>(target.address);
    if (!readable(code, target.prologue_length) ||
        std::memcmp(code, target.prologue, target.prologue_length) != 0) {
        shim_log("[scbl-trace] %s at %p does not match the expected prologue; not hooking",
                 target.name, code);
        return false;
    }

    uint8_t* island = static_cast<uint8_t*>(
        VirtualAlloc(nullptr, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (island == nullptr) return false;

    std::memcpy(island, code, target.prologue_length);
    island[target.prologue_length] = 0xE9;
    int32_t back = static_cast<int32_t>(
        (code + target.prologue_length) - (island + target.prologue_length + 5));
    std::memcpy(island + target.prologue_length + 1, &back, sizeof(back));

    DWORD previous = 0;
    if (!VirtualProtect(code, target.prologue_length, PAGE_EXECUTE_READWRITE, &previous)) {
        VirtualFree(island, 0, MEM_RELEASE);
        return false;
    }
    int32_t forward = static_cast<int32_t>(static_cast<uint8_t*>(thunk) - (code + 5));
    code[0] = 0xE9;
    std::memcpy(code + 1, &forward, sizeof(forward));
    for (size_t i = 5; i < target.prologue_length; ++i) code[i] = 0x90;
    VirtualProtect(code, target.prologue_length, previous, &previous);
    FlushInstructionCache(GetCurrentProcess(), code, target.prologue_length);

    trampoline = island;
    return true;
}

}  // namespace

void install_net_trace(HMODULE game_module) {
    if (reinterpret_cast<uintptr_t>(game_module) != kExpectedBase) {
        shim_log("[scbl-trace] game module is at %p, not the %p the offsets were measured at; skipping",
                 game_module, reinterpret_cast<void*>(kExpectedBase));
        return;
    }
    int installed = 0;
    for (int i = 0; i < kHookCount; ++i) {
        if (install_one(kTargets[i], kThunks[i], bl_net_trace_trampolines[i])) ++installed;
    }
    shim_log("[scbl-trace] online state trace installed on %d of %d functions", installed, kHookCount);
}

}  // namespace blacklist

extern "C" void __cdecl bl_net_trace_event(int hook, void* self, unsigned a1, unsigned a2, unsigned a3, unsigned caller) {
    using namespace blacklist;
    char first[192], second[192];
    switch (hook) {
    case kNextState: {
        const void* machine = self;
        const void* current = nullptr;
        const void* last = nullptr;
        if (readable(machine, 24)) {
            const void* const* fields = static_cast<const void* const*>(machine);
            current = fields[4];
            last = fields[5];
        }
        unsigned next_id = 0;
        if (readable(reinterpret_cast<const void*>(a1), sizeof(unsigned))) {
            std::memcpy(&next_id, reinterpret_cast<const void*>(a1), sizeof(next_id));
        }
        char id_text[96];
        shim_log("[scbl-trace] next state %s (machine=%p current=%s)",
                 describe_id(next_id, id_text, sizeof(id_text)), machine,
                 describe_state(current, first, sizeof(first)));
        (void)last; (void)a2; (void)a3;
        break;
    }
    case kLeaveState:
        shim_log("[scbl-trace] leaving %s", describe_state(self, first, sizeof(first)));
        (void)a1; (void)a2; (void)a3;
        break;
    case kChangeState: {
        const char* goal = nullptr;
        if (readable(self, 8)) {
            const char* const* fields = static_cast<const char* const*>(self);
            if (readable(fields[1], 1)) goal = fields[1];
        }
        unsigned next_id = 0;
        if (readable(reinterpret_cast<const void*>(a2), sizeof(unsigned))) {
            std::memcpy(&next_id, reinterpret_cast<const void*>(a2), sizeof(next_id));
        }
        char id_text[96];
        shim_log("[scbl-trace] goal %s: %s -> %s", goal ? goal : "?",
                 describe_state(reinterpret_cast<const void*>(a1), first, sizeof(first)),
                 describe_id(next_id, id_text, sizeof(id_text)));
        (void)a3;
        break;
    }
    case kResultBase:
        shim_log("[scbl-trace] NetResult: %s",
                 gear_string(reinterpret_cast<const void*>(a1), second, sizeof(second)));
        (void)a2; (void)a3;
        break;
    case kResultCore:
    case kResultSession:
    case kResultRdvSession:
    case kResultLobby: {
        static const char* const kKind[] = {"Core", "Session", "Rdv", "Lobby"};
        shim_log("[scbl-trace] NetResult%s: code=0x%08x text=%s", kKind[hook - kResultCore], a1,
                 gear_string(reinterpret_cast<const void*>(a2), second, sizeof(second)));
        (void)self; (void)a3;
        break;
    }
    case kRaiseGoal: {
        const char* goal = nullptr;
        if (readable(reinterpret_cast<const void*>(a2), 8)) {
            const char* const* fields = reinterpret_cast<const char* const*>(a2);
            if (readable(fields[1], 1)) goal = fields[1];
        }
        if (goal != nullptr) {
            shim_log("[scbl-trace] raise %s from %08x (obj=%p)", goal, caller - 5, self);
            if (caller - 5 == 0x00898670 && std::strcmp(goal, "eGoal_LogOut") == 0) {
                report_online_check();
                report_bl_conditions(a1);
            }
        }
        (void)a1; (void)a3;
        break;
    }
    default:
        break;
    }
}
