#include "games/farcry3/tracer.h"
#include "core/config.h"
#include "core/debug/field_sampler.h"
#include "core/debug/watchpoint.h"
#include "core/logging.h"

#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cstdlib>

namespace {

struct TracePoint {
    uintptr_t address = 0;
    BYTE original = 0;
    char label[64] = {};
    bool captured = false;
    uint32_t last[4] = {};
    bool have_last = false;
    long hits = 0;
};

constexpr int kMaxTracePoints = 16;
TracePoint g_points[kMaxTracePoints];
int g_point_count = 0;

uintptr_t g_pending_rearm = 0;

uintptr_t g_latest_ticket_job = 0;
uintptr_t g_latest_ticket_crypto = 0;

void bytes_to_hex(const BYTE* data, size_t length, char* out, size_t cap) {
    static const char digits[] = "0123456789ABCDEF";
    if (cap == 0) return;
    size_t count = length;
    if (count > (cap - 1) / 2) count = (cap - 1) / 2;
    for (size_t i = 0; i < count; ++i) {
        out[i * 2] = digits[data[i] >> 4];
        out[i * 2 + 1] = digits[data[i] & 0x0F];
    }
    out[count * 2] = '\0';
}

bool write_byte(void* address, BYTE value) {
    DWORD old_protection = 0;
    if (!VirtualProtect(address, 1, PAGE_EXECUTE_READWRITE, &old_protection)) return false;
    *(BYTE*)address = value;
    DWORD ignored = 0;
    VirtualProtect(address, 1, old_protection, &ignored);
    FlushInstructionCache(GetCurrentProcess(), address, 1);
    return true;
}

bool write_bytes(void* address, const BYTE* data, size_t length) {
    DWORD old_protection = 0;
    if (!VirtualProtect(address, length, PAGE_EXECUTE_READWRITE, &old_protection)) return false;
    memcpy(address, data, length);
    DWORD ignored = 0;
    VirtualProtect(address, length, old_protection, &ignored);
    FlushInstructionCache(GetCurrentProcess(), address, length);
    return true;
}

uint32_t g_captured[4] = {0, 0, 0, 0};
uintptr_t g_trace_module_base = 0;
bool g_captured_set[4] = {false, false, false, false};
long g_call2_hits = 0;
bool g_latched = false;
long g_latch_ticks = 0;
int g_seq_stage = 0;
void report_guard(const char* label, const char* when);
bool g_call2_done = false;

using SessionCall = void (__stdcall*)(uint32_t object, uint32_t session_id);

constexpr uintptr_t kSlotArray = 0x84;
constexpr uintptr_t kSlotCount = 0x88;
constexpr uintptr_t kSlotStride = 0x50;
constexpr uintptr_t kRecordInSlot = 0x4;
constexpr uintptr_t kRecordState = 0x10;   // the guard: login acts only on 0xf
constexpr uintptr_t kRecordPhase = 0x1c;   // FUN_11169840 writes 3 (login) / 2 here
constexpr uintptr_t kRecordFlags = 0x20;
constexpr uintptr_t kRecordMode = 0x40;    // 0 = first-time path, 1 / 2 = FUN_11169840
constexpr uint32_t kStateReadyToLogin = 0xf;

bool describe_session_slots(const char* label, uintptr_t object, uint32_t* ready_id) {
    const uint8_t* count = (const uint8_t*)(object + kSlotCount);
    const uint32_t* array = (const uint32_t*)(object + kSlotArray);
    if (object == 0 || IsBadReadPtr(count, 1) || IsBadReadPtr(array, 4)) {
        shim_log("[trace] %s: object 0x%08x has no readable slot table", label, (uint32_t)object);
        return false;
    }
    bool found = false;
    shim_log("[trace] %s: object 0x%08x slots=%u array=0x%08x", label, (uint32_t)object, *count, *array);
    for (unsigned i = 0; i < *count; ++i) {
        const uint8_t* slot = (const uint8_t*)(uintptr_t)*array + i * kSlotStride;
        const uint8_t* record = slot + kRecordInSlot;
        if (IsBadReadPtr(slot, kSlotStride)) {
            shim_log("[trace] %s:   slot %u at 0x%08x unreadable", label, i, (uint32_t)(uintptr_t)slot);
            continue;
        }
        const uint32_t state = *(const uint32_t*)(record + kRecordState);
        shim_log("[trace] %s:   slot %u id=0x%02x record=0x%08x state(+0x10)=0x%x phase(+0x1c)=0x%x flags(+0x20)=0x%08x mode(+0x40)=0x%x%s",
                 label, i, slot[0], (uint32_t)(uintptr_t)record, state,
                 *(const uint32_t*)(record + kRecordPhase), *(const uint32_t*)(record + kRecordFlags),
                 *(const uint32_t*)(record + kRecordMode),
                 state == kStateReadyToLogin ? "  <- login would act on this" : "");
        if (!found && state == kStateReadyToLogin) {
            found = true;
            if (ready_id) *ready_id = slot[0];
        }
    }
    return found;
}
bool find_slot_with_state(uintptr_t object, uint32_t wanted, uint32_t* id) {
    const uint8_t* count = (const uint8_t*)(object + kSlotCount);
    const uint32_t* array = (const uint32_t*)(object + kSlotArray);
    if (object == 0 || IsBadReadPtr(count, 1) || IsBadReadPtr(array, 4) || *array == 0) return false;
    for (unsigned i = 0; i < *count; ++i) {
        const uint8_t* slot = (const uint8_t*)(uintptr_t)*array + i * kSlotStride;
        if (IsBadReadPtr(slot, kSlotStride)) continue;
        if (*(const uint32_t*)(slot + kRecordInSlot + kRecordState) == wanted) {
            if (id) *id = slot[0];
            return true;
        }
    }
    return false;
}
constexpr uint32_t kStateMenuOnlineReady = 0xd;
bool g_autologin_done = false;
long g_autopoll_last_state = -1;

void report_guard(const char* label, const char* when) {
    if (!g_captured_set[1]) {
        shim_log("[trace] %s: %s — guard object not captured (need grabeax+1 at the 0xf site)",
                 label, when);
        return;
    }
    const uint32_t* state = (const uint32_t*)((uintptr_t)g_captured[1] + 0x10);
    if (IsBadReadPtr(state, sizeof(uint32_t)))
        shim_log("[trace] %s: %s — guard object 0x%08x unreadable", label, when, g_captured[1]);
    else
        shim_log("[trace] %s: %s — guard obj 0x%08x state=+0x10 -> 0x%x (login needs 0xf)",
                 label, when, g_captured[1], *state);
}

uint32_t login_name_crc32() {
    static uint32_t cached = 0;
    static bool have = false;
    if (have) return cached;
    uint32_t crc = 0xffffffffu;
    for (const char* p = hook_config().login_name; *p; ++p) {
        crc ^= (unsigned char)*p;
        for (int k = 0; k < 8; ++k) crc = (crc >> 1) ^ (0xedb88320u & (0u - (crc & 1u)));
    }
    cached = ~crc;
    have = true;
    return cached;
}

void describe_maybe_pointer(const char* tag, uint32_t value, char* out, size_t cap) {
    void* p = (void*)(uintptr_t)value;
    if (value < 0x10000 || IsBadReadPtr(p, 1)) {
        snprintf(out, cap, "%s=0x%08x", tag, value);
        return;
    }
    char buf[48] = {};
    size_t n = 0;
    for (; n < sizeof(buf) - 1; ++n) {
        if (IsBadReadPtr((const char*)p + n, 1)) break;
        char c = ((const char*)p)[n];
        if (c == '\0') break;
        if ((unsigned char)c < 0x20 || (unsigned char)c > 0x7e) { n = 0; break; }
        buf[n] = c;
    }
    if (n > 1) {
        snprintf(out, cap, "%s=0x%08x \"%s\"", tag, value, buf);
    } else {
        snprintf(out, cap, "%s=0x%08x", tag, value);
    }
}

LONG WINAPI handler(EXCEPTION_POINTERS* exception) {
    DWORD code = exception->ExceptionRecord->ExceptionCode;
    uintptr_t addr = (uintptr_t)exception->ExceptionRecord->ExceptionAddress;
    CONTEXT* ctx = exception->ContextRecord;

    if (code == EXCEPTION_SINGLE_STEP) {
        if (g_pending_rearm == 0) return EXCEPTION_CONTINUE_SEARCH;
        for (int i = 0; i < g_point_count; ++i) {
            if (g_points[i].address == g_pending_rearm) {
                write_byte((void*)g_points[i].address, 0xCC);
                break;
            }
        }
        g_pending_rearm = 0;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    if (code != EXCEPTION_BREAKPOINT) return EXCEPTION_CONTINUE_SEARCH;

    const TracePoint* hit = nullptr;
    for (int i = 0; i < g_point_count; ++i) {
        if (g_points[i].address == addr) { hit = &g_points[i]; break; }
    }
    if (!hit) return EXCEPTION_CONTINUE_SEARCH;

    uint32_t* stack = (uint32_t*)ctx->Esp;
    char a0[80], a1[80], a2[80], a3[80], a4[80];
    bool stack_ok = !IsBadReadPtr(stack, 6 * sizeof(uint32_t));
    const bool quiet = strncmp(hit->label, "dumpiq+", 7) == 0 ||
                       strncmp(hit->label, "call2+", 6) == 0 ||
                       strncmp(hit->label, "callatch+", 9) == 0 ||
                       strncmp(hit->label, "seq2+", 5) == 0 ||
                       strncmp(hit->label, "autologin+", 10) == 0 ||
                       strncmp(hit->label, "autopoll+", 9) == 0 ||
                       strncmp(hit->label, "autologin_seq+", 14) == 0;
    if (stack_ok && !quiet) {
        describe_maybe_pointer("arg1", stack[1], a0, sizeof(a0));
        describe_maybe_pointer("arg2", stack[2], a1, sizeof(a1));
        describe_maybe_pointer("arg3", stack[3], a2, sizeof(a2));
        describe_maybe_pointer("arg4", stack[4], a3, sizeof(a3));
        describe_maybe_pointer("arg5", stack[5], a4, sizeof(a4));
    }
    char eax[80], ecx[80], edx[80];
    describe_maybe_pointer("eax", (uint32_t)ctx->Eax, eax, sizeof(eax));
    describe_maybe_pointer("ecx", (uint32_t)ctx->Ecx, ecx, sizeof(ecx));
    describe_maybe_pointer("edx", (uint32_t)ctx->Edx, edx, sizeof(edx));
    char esi[80], edi[80];
    describe_maybe_pointer("esi", (uint32_t)ctx->Esi, esi, sizeof(esi));
    describe_maybe_pointer("edi", (uint32_t)ctx->Edi, edi, sizeof(edi));

    if (stack_ok && !quiet) {
        shim_log("[trace] %s @ 0x%llx | %s %s %s %s %s | ret=0x%08x %s %s %s %s %s",
                 hit->label, (unsigned long long)addr, eax, ecx, edx, esi, edi,
                 stack[0], a0, a1, a2, a3, a4);
        if (strcmp(hit->label, "connection_data_install_entry") == 0) {
            const uint32_t* descriptor = (const uint32_t*)(uintptr_t)stack[1];
            if (!IsBadReadPtr(descriptor, 5 * sizeof(uint32_t))) {
                shim_log("[trace] connection_data_descriptor @ 0x%08x | d0=0x%08x d1=0x%08x d2=0x%08x position=%u length=%u",
                         stack[1], descriptor[0], descriptor[1], descriptor[2],
                         descriptor[3], descriptor[4]);
            }
        }
        if (strcmp(hit->label, "ticket_finalize") == 0) {
            g_latest_ticket_job = (uintptr_t)ctx->Ecx;
        }
        if (strcmp(hit->label, "install_entry") == 0) {
            g_latest_ticket_crypto = (uintptr_t)ctx->Ecx;
        }
        if (strcmp(hit->label, "hmac_key_set") == 0) {
            const BYTE* key = nullptr;
            uint32_t key_length = 0;
            if (ctx->Ecx != 0 &&
                !IsBadReadPtr((const BYTE*)(uintptr_t)ctx->Ecx + 0x10, 8)) {
                key = *(const BYTE* const*)((const BYTE*)(uintptr_t)ctx->Ecx + 0x10);
                const BYTE* key_end = *(const BYTE* const*)((const BYTE*)(uintptr_t)ctx->Ecx + 0x14);
                if (key && key_end && key_end >= key)
                    key_length = (uint32_t)(key_end - key);
            }
            if (key && key_length > 0 && key_length <= 64 && !IsBadReadPtr(key, key_length)) {
                char key_hex[129] = {};
                bytes_to_hex(key, key_length, key_hex, sizeof(key_hex));
                shim_log("[trace] hmac_key_set caller=0x%08x key_length=%u key=%s",
                         stack_ok ? stack[0] : 0, key_length, key_hex);
            }
        }
        if (strcmp(hit->label, "derive_key_job") == 0 && ctx->Ecx != 0) {
            const BYTE* job = (const BYTE*)(uintptr_t)ctx->Ecx;
            if (!IsBadReadPtr(job + 0xE0, 0x20)) {
                uint32_t field_ec = *(const uint32_t*)(job + 0xEC);
                uint32_t field_f0 = *(const uint32_t*)(job + 0xF0);
                const BYTE* ec_data = (const BYTE*)(uintptr_t)field_ec;
                const BYTE* f0_data = (const BYTE*)(uintptr_t)field_f0;
                char object_hex[65] = {};
                char ec_hex[129] = {};
                char f0_hex[129] = {};
                bytes_to_hex(job + 0xE0, 0x20, object_hex, sizeof(object_hex));
                if (ec_data && !IsBadReadPtr(ec_data, 64))
                    bytes_to_hex(ec_data, 64, ec_hex, sizeof(ec_hex));
                if (f0_data && !IsBadReadPtr(f0_data, 64))
                    bytes_to_hex(f0_data, 64, f0_hex, sizeof(f0_hex));
                shim_log("[trace] derive_key_job job=0x%08x +ec=0x%08x +f0=0x%08x job_bytes=%s ec64=%s f064=%s",
                         (uint32_t)(uintptr_t)job, field_ec, field_f0,
                         object_hex, ec_hex[0] ? ec_hex : "<unreadable>",
                         f0_hex[0] ? f0_hex : "<unreadable>");
            }
        }
        if (strcmp(hit->label, "decoder_valid") == 0) {
            if (g_latest_ticket_crypto != 0) {
                const BYTE* hmac_object =
                    (const BYTE*)(g_latest_ticket_crypto + 0x230);
                if (!IsBadReadPtr(hmac_object, 0x100)) {
                    char object_hex[0x201] = {};
                    bytes_to_hex(hmac_object, 0x100, object_hex, sizeof(object_hex));
                    shim_log("[trace] ticket_hmac_object address=0x%08x data=%s",
                             (uint32_t)(uintptr_t)hmac_object, object_hex);
                }
            }

            if (g_latest_ticket_job != 0) {
                const uint32_t* descriptor =
                    (const uint32_t*)(g_latest_ticket_job + 0x180);
                const uint32_t* frame = (const uint32_t*)ctx->Ebp;
                if (!IsBadReadPtr(descriptor, 5 * sizeof(uint32_t)) &&
                    !IsBadReadPtr(frame - 10, 10 * sizeof(uint32_t))) {
                const BYTE* ticket = (const BYTE*)(uintptr_t)descriptor[2];
                uint32_t ticket_length = descriptor[3];
                const BYTE* expected = *(const BYTE* const*)((const BYTE*)frame - 0x28);
                uint32_t expected_length = *(const uint32_t*)((const BYTE*)frame - 0x24);
                if (ticket_length <= 128 && ticket && !IsBadReadPtr(ticket, ticket_length) &&
                    expected_length <= 32 && expected && !IsBadReadPtr(expected, expected_length)) {
                    char ticket_hex[257] = {};
                    char expected_hex[65] = {};
                    bytes_to_hex(ticket, ticket_length, ticket_hex, sizeof(ticket_hex));
                    bytes_to_hex(expected, expected_length, expected_hex, sizeof(expected_hex));
                    shim_log("[trace] ticket_hmac_material length=%u ticket=%s calculated=%s",
                             ticket_length, ticket_hex, expected_hex);
                }
            }
            }
        }
    } else if (!quiet) {
        shim_log("[trace] %s @ 0x%llx | %s %s %s %s %s | (stack unreadable)",
                 hit->label, (unsigned long long)addr, eax, ecx, edx, esi, edi);
    }

    if (stack_ok && strncmp(hit->label, "retifcrc+", 9) == 0 &&
        stack[1] == login_name_crc32()) {
        unsigned pops = (unsigned)strtoul(hit->label + 9, nullptr, 0);
        shim_log("[trace] %s: arg1 0x%08x is crc32(login_name) — skipped (RET %u)",
                 hit->label, stack[1], pops);
        ctx->Eip = stack[0];
        ctx->Esp += 4 + pops;
        ctx->Eax = 0;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    if (strcmp(hit->label, "friends_empty") == 0) {
        const uint32_t* list = (const uint32_t*)((uintptr_t)ctx->Edi + 0x84);
        if (ctx->Edi != 0 && !IsBadReadPtr(list, 2 * sizeof(uint32_t))) {
            shim_log("[trace] friends_empty: provider(edi)=0x%08x count=%u entries=0x%08x",
                     (uint32_t)ctx->Edi, list[0], list[1]);
        } else {
            shim_log("[trace] friends_empty: edi=0x%08x list unreadable", (uint32_t)ctx->Edi);
        }
    }

    TracePoint* point = const_cast<TracePoint*>(hit);
    bool capture_point = strncmp(hit->label, "watch+", 6) == 0 ||
                         strncmp(hit->label, "sample+", 7) == 0 ||
                         strncmp(hit->label, "samplei+", 8) == 0 ||
                         strncmp(hit->label, "watchw+", 7) == 0 ||
                         strncmp(hit->label, "watchwd+", 8) == 0 ||
                         strcmp(hit->label, "forcelogin") == 0;
    if (!point->captured && strncmp(hit->label, "watch+", 6) == 0) {
        uintptr_t offset = (uintptr_t)strtoull(hit->label + 6, nullptr, 0);
        uintptr_t target = (uintptr_t)ctx->Ecx + offset;
        if (ctx->Ecx != 0 && !IsBadReadPtr((void*)target, 1)) {
            shim_log("[trace] %s: this=0x%08x target=0x%08llx", hit->label,
                     (uint32_t)ctx->Ecx, (unsigned long long)target);
            point->captured = watchpoint_arm(target, hit->label, ctx);
        } else {
            shim_log("[trace] %s: this=0x%08x + 0x%llx unreadable — not arming",
                     hit->label, (uint32_t)ctx->Ecx, (unsigned long long)offset);
        }
    }

    if (strncmp(hit->label, "dumpiq+", 7) == 0) {
        char* sep = nullptr;
        uintptr_t a = (uintptr_t)strtoull(hit->label + 7, &sep, 0);
        uintptr_t b = (sep && *sep == '.') ? (uintptr_t)strtoull(sep + 1, nullptr, 0) : 0;
        point->hits++;
        const uint32_t receiver = (uint32_t)ctx->Ecx;
        const uint32_t* slot = (const uint32_t*)((uintptr_t)ctx->Ecx + a);
        if (ctx->Ecx != 0 && !IsBadReadPtr(slot, 4) && *slot != 0) {
            const uint32_t* target = (const uint32_t*)((uintptr_t)*slot + b);
            if (!IsBadReadPtr(target, 16 * sizeof(uint32_t))) {
                bool changed = !point->have_last || point->last[0] != receiver ||
                               point->last[1] != *slot;
                for (int i = 2; i < 4; ++i)
                    if (point->last[i] != target[i - 2]) changed = true;
                if (changed || (point->hits % 2000) == 0) {
                    shim_log("[trace] %s: this=0x%08x base=0x%08x +0x%llx ->"
                             " %08x %08x %08x %08x %08x %08x %08x %08x"
                             " %08x %08x %08x %08x %08x %08x %08x %08x (hit %ld)",
                             hit->label, receiver, *slot, (unsigned long long)b,
                             target[0], target[1], target[2], target[3],
                             target[4], target[5], target[6], target[7],
                             target[8], target[9], target[10], target[11],
                             target[12], target[13], target[14], target[15],
                             point->hits);
                    point->last[0] = receiver;
                    point->last[1] = *slot;
                    for (int i = 2; i < 4; ++i) point->last[i] = target[i - 2];
                    point->have_last = true;
                }
            }
        } else if (!point->have_last || point->last[0] != receiver || point->last[1] != 0) {
            shim_log("[trace] %s: this=0x%08x slot empty (hit %ld)", hit->label,
                     receiver, point->hits);
            point->last[0] = receiver;
            for (int i = 1; i < 4; ++i) point->last[i] = 0;
            point->have_last = true;
        }
    }

    if (!point->captured && strcmp(hit->label, "forcelogin") == 0) {
        const uint32_t* slot = (const uint32_t*)((uintptr_t)ctx->Ecx + 0x84);
        if (ctx->Ecx != 0 && !IsBadReadPtr(slot, 4) && *slot != 0) {
            uintptr_t base = (uintptr_t)*slot;
            uint32_t* state = (uint32_t*)(base + 0x20);
            uint32_t* flags = (uint32_t*)(base + 0x24);
            if (!IsBadWritePtr(state, 4) && !IsBadWritePtr(flags, 4)) {
                if ((*flags & 0x02) == 0) {
                    shim_log("[force] session 0 at 0x%08llx before: state=%u flags=0x%08x",
                             (unsigned long long)(base + 4), *state, *flags);
                    *flags = (*flags & ~0x40u) | 0x02u;
                    *state = 3;
                    shim_log("[force] session 0 forced to: state=%u flags=0x%08x "
                             "(mirrors FUN_107dc195 success branch) — DIAGNOSTIC ONLY",
                             *state, *flags);
                    point->captured = true;
                } else {
                    shim_log("[force] bit 0x02 already set (flags=0x%08x) — nothing forced",
                             *flags);
                    point->captured = true;
                }
            }
        }
    }

    if (strncmp(hit->label, "seq2+", 5) == 0 && g_latched && g_seq_stage < 2) {
        char* p = (char*)hit->label + 5;
        uintptr_t rva1 = (uintptr_t)strtoull(p, &p, 0);
        uintptr_t rva2 = 0;
        unsigned slot = 0, imm = 0, d1 = 0, d2 = 0;
        if (*p == '.') rva2 = (uintptr_t)strtoull(p + 1, &p, 0);
        if (*p == '.') slot = (unsigned)strtoul(p + 1, &p, 0) & 3;
        if (*p == '.') imm  = (unsigned)strtoul(p + 1, &p, 0);
        if (*p == '.') d1   = (unsigned)strtoul(p + 1, &p, 0);
        if (*p == '.') d2   = (unsigned)strtoul(p + 1, nullptr, 0);
        g_latch_ticks++;
        if (!g_captured_set[slot]) {
            if (g_latch_ticks == 1)
                shim_log("[trace] %s: slot %u never captured — sequence skipped",
                         hit->label, slot);
            g_seq_stage = 2;
        } else if (g_seq_stage == 0 && g_latch_ticks > (long)d1) {
            g_seq_stage = 1;
            uintptr_t t = g_trace_module_base + rva1;
            report_guard(hit->label, "before stage 1");
            shim_log("[trace] %s: stage 1 — calling %p(0x%08x, 0x%08x) [logout]",
                     hit->label, (void*)t, g_captured[slot], imm);
            ((SessionCall)t)(g_captured[slot], imm);
            shim_log("[trace] %s: stage 1 returned", hit->label);
            g_latch_ticks = 0;
        } else if (g_seq_stage == 1 && g_latch_ticks > (long)d2) {
            g_seq_stage = 2;
            uintptr_t t = g_trace_module_base + rva2;
            report_guard(hit->label, "before stage 2");
            shim_log("[trace] %s: stage 2 — calling %p(0x%08x, 0x%08x) [login]",
                     hit->label, (void*)t, g_captured[slot], imm);
            ((SessionCall)t)(g_captured[slot], imm);
            shim_log("[trace] %s: stage 2 returned", hit->label);
            report_guard(hit->label, "after stage 2");
        }
    }

    if (stack_ok && strcmp(hit->label, "slots1") == 0) {
        describe_session_slots(hit->label, (uintptr_t)stack[1], nullptr);
    }

    if (strncmp(hit->label, "autologin+", 10) == 0 && !g_autologin_done && g_latched) {
        char* p = (char*)hit->label + 10;
        uintptr_t target = g_trace_module_base + (uintptr_t)strtoull(p, &p, 0);
        unsigned slot = 0, delay = 0;
        if (*p == '.') slot = (unsigned)strtoul(p + 1, &p, 0) & 3;
        if (*p == '.') delay = (unsigned)strtoul(p + 1, nullptr, 0);
        if (++g_latch_ticks > (long)delay) {
            g_autologin_done = true;
            if (!g_captured_set[slot]) {
                shim_log("[trace] %s: slot %u never captured -- not calling", hit->label, slot);
            } else {
                uint32_t id = 0;
                if (describe_session_slots(hit->label, g_captured[slot], &id)) {
                    shim_log("[trace] %s: calling %p(0x%08x, 0x%02x) %ld tick(s) after the latch",
                             hit->label, (void*)target, g_captured[slot], id, g_latch_ticks);
                    ((SessionCall)target)(g_captured[slot], id);
                    shim_log("[trace] %s: returned", hit->label);
                    describe_session_slots(hit->label, g_captured[slot], nullptr);
                } else {
                    shim_log("[trace] %s: no slot is in state 0xf -- the login would be a no-op, not calling",
                             hit->label);
                }
            }
        }
    }

    if (strncmp(hit->label, "autologin_seq+", 14) == 0 && !g_autologin_done) {
        char* p = (char*)hit->label + 14;
        uintptr_t logout = g_trace_module_base + (uintptr_t)strtoull(p, &p, 0);
        uintptr_t login = (*p == '.') ? g_trace_module_base + (uintptr_t)strtoull(p + 1, nullptr, 0) : 0;
        if (!g_captured_set[0]) {
        } else {
            uintptr_t object = g_captured[0];
            uint32_t id = 0;
            if (find_slot_with_state(object, kStateMenuOnlineReady, &id)) {
                g_autologin_done = true;
                shim_log("[trace] %s: online-ready (object 0x%08x slot id=0x%02x state=0xd); driving logout->login",
                         hit->label, (uint32_t)object, id);
                ((SessionCall)logout)((uint32_t)object, id);
                uint32_t armed_id = 0;
                if (find_slot_with_state(object, kStateReadyToLogin, &armed_id)) {
                    shim_log("[trace] %s: logout armed slot id=0x%02x to 0xf; calling login", hit->label, armed_id);
                    ((SessionCall)login)((uint32_t)object, armed_id);
                    shim_log("[trace] %s: login returned", hit->label);
                } else {
                    shim_log("[trace] %s: logout did not arm a 0xf slot -- login not called", hit->label);
                }
                describe_session_slots(hit->label, object, nullptr);
            }
        }
    }

    if (strncmp(hit->label, "autopoll+", 9) == 0 && !g_autologin_done && g_latched) {
        char* p = (char*)hit->label + 9;
        uintptr_t target = g_trace_module_base + (uintptr_t)strtoull(p, &p, 0);
        unsigned slot = (*p == '.') ? (unsigned)strtoul(p + 1, nullptr, 0) & 3 : 0;
        if (g_captured_set[slot]) {
            uintptr_t object = g_captured[slot];
            const uint8_t* count = (const uint8_t*)(object + kSlotCount);
            const uint32_t* array = (const uint32_t*)(object + kSlotArray);
            if (object && !IsBadReadPtr(count, 1) && !IsBadReadPtr(array, 4) && *array) {
                uint32_t ready_id = 0; bool ready = false; long first_state = -1;
                for (unsigned i = 0; i < *count && !ready; ++i) {
                    const uint8_t* record = (const uint8_t*)(uintptr_t)*array + i * kSlotStride + kRecordInSlot;
                    if (IsBadReadPtr(record, kRecordState + 4)) continue;
                    uint32_t state = *(const uint32_t*)(record + kRecordState);
                    if (i == 0) first_state = (long)state;
                    if (state == kStateReadyToLogin) {
                        ready = true;
                        ready_id = ((const uint8_t*)(uintptr_t)*array + i * kSlotStride)[0];
                    }
                }
                if (first_state != g_autopoll_last_state) {
                    g_autopoll_last_state = first_state;
                    shim_log("[trace] %s: slot 0 state is now 0x%lx", hit->label, first_state);
                }
                if (ready) {
                    g_autologin_done = true;
                    shim_log("[trace] %s: slot at 0xf reached; calling %p(0x%08x, 0x%02x)",
                             hit->label, (void*)target, (uint32_t)object, ready_id);
                    ((SessionCall)target)((uint32_t)object, ready_id);
                    shim_log("[trace] %s: returned", hit->label);
                    describe_session_slots(hit->label, object, nullptr);
                }
            }
        }
    }

    if (strncmp(hit->label, "latcharg2+", 10) == 0 && stack_ok && !g_latched) {
        uint32_t want = (uint32_t)strtoul(hit->label + 10, nullptr, 0);
        if (stack[2] == want) {
            g_latched = true;
            shim_log("[trace] %s: latched on arg2=0x%08x", hit->label, stack[2]);
        }
    }

    if (strncmp(hit->label, "callatch+", 9) == 0 && !g_call2_done && g_latched) {
        char* p = (char*)hit->label + 9;
        uintptr_t target = g_trace_module_base + (uintptr_t)strtoull(p, &p, 0);
        unsigned slot = 0, imm = 0, delay = 0;
        if (*p == '.') slot = (unsigned)strtoul(p + 1, &p, 0) & 3;
        if (*p == '.') imm = (unsigned)strtoul(p + 1, &p, 0);
        if (*p == '.') delay = (unsigned)strtoul(p + 1, nullptr, 0);
        if (++g_latch_ticks > (long)delay) {
            if (!g_captured_set[slot]) {
                shim_log("[trace] %s: slot %u never captured — not calling",
                         hit->label, slot);
            } else {
                g_call2_done = true;
                shim_log("[trace] %s: latch fired; calling %p(0x%08x, 0x%08x) "
                         "%ld tick(s) after the latch", hit->label, (void*)target,
                         g_captured[slot], imm, g_latch_ticks);
                ((SessionCall)target)(g_captured[slot], imm);
                shim_log("[trace] %s: returned", hit->label);
            }
        }
    }

    if (strncmp(hit->label, "grabeax+", 8) == 0) {
        unsigned slot = (unsigned)strtoul(hit->label + 8, nullptr, 0) & 3;
        g_captured[slot] = (uint32_t)ctx->Eax;
        g_captured_set[slot] = true;
        shim_log("[trace] %s: captured eax=0x%08x into slot %u", hit->label,
                 (uint32_t)ctx->Eax, slot);
    }

    if (strncmp(hit->label, "grabesi+", 8) == 0) {
        unsigned slot = (unsigned)strtoul(hit->label + 8, nullptr, 0) & 3;
        g_captured[slot] = (uint32_t)ctx->Esi;
        g_captured_set[slot] = true;
        shim_log("[trace] %s: captured esi=0x%08x into slot %u", hit->label,
                 (uint32_t)ctx->Esi, slot);
    }

    if (strncmp(hit->label, "call2+", 6) == 0 && !g_call2_done) {
        char* p = (char*)hit->label + 6;
        uintptr_t target = g_trace_module_base + (uintptr_t)strtoull(p, &p, 0);
        unsigned slot = 0, imm = 0, skip = 0;
        if (*p == '.') slot = (unsigned)strtoul(p + 1, &p, 0) & 3;
        if (*p == '.') imm = (unsigned)strtoul(p + 1, &p, 0);
        if (*p == '.') skip = (unsigned)strtoul(p + 1, nullptr, 0);
        if (++g_call2_hits > (long)skip) {
            if (!g_captured_set[slot]) {
                shim_log("[trace] %s: slot %u never captured — not calling",
                         hit->label, slot);
            } else {
                g_call2_done = true;
                shim_log("[trace] %s: calling %p(0x%08x, 0x%08x) after %ld hit(s)",
                         hit->label, (void*)target, g_captured[slot], imm,
                         g_call2_hits);
                ((SessionCall)target)(g_captured[slot], imm);
                shim_log("[trace] %s: returned", hit->label);
            }
        }
    }

    const char* init2_fields = nullptr;
    uintptr_t init2_object = 0;
    const char* init2_register = nullptr;
    if (strncmp(hit->label, "init2+", 6) == 0) {
        init2_fields = hit->label + 6;
        init2_object = (uintptr_t)ctx->Ecx;
        init2_register = "ecx";
    } else if (strncmp(hit->label, "init2ebx+", 9) == 0) {
        init2_fields = hit->label + 9;
        init2_object = (uintptr_t)ctx->Ebx;
        init2_register = "ebx";
    } else if (strncmp(hit->label, "init2esi+", 9) == 0) {
        init2_fields = hit->label + 9;
        init2_object = (uintptr_t)ctx->Esi;
        init2_register = "esi";
    }
    if (init2_fields) {
        char* end = nullptr;
        uintptr_t first = (uintptr_t)strtoull(init2_fields, &end, 0);
        uintptr_t second = (*end == '.') ? (uintptr_t)strtoull(end + 1, &end, 0) : first;
        uint32_t* fields[2] = {
            (uint32_t*)(init2_object + first),
            (uint32_t*)(init2_object + second),
        };
        MEMORY_BASIC_INFORMATION region = {};
        const bool executable = VirtualQuery((const void*)init2_object, &region,
                                              sizeof(region)) == sizeof(region) &&
            (region.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                               PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY));
        if (init2_object != 0 &&
            !executable &&
            !IsBadWritePtr(fields[0], sizeof(uint32_t)) &&
            !IsBadWritePtr(fields[1], sizeof(uint32_t))) {
            uint32_t first_was = *fields[0];
            uint32_t second_was = *fields[1];
            *fields[0] = 0;
            *fields[1] = 0;
            shim_log("[trace] %s: constructed container %s=0x%08x "
                     "+0x%llx/%llx was %08x/%08x -> {0, NULL}",
                     hit->label, init2_register, (uint32_t)init2_object,
                     (unsigned long long)first, (unsigned long long)second,
                     first_was, second_was);
        } else {
            shim_log("[trace] %s: %s=0x%08x container fields %s",
                     hit->label, init2_register, (uint32_t)init2_object,
                     executable ? "are executable memory — skipped" : "not writable");
        }
    }

    if (strncmp(hit->label, "zero+", 5) == 0) {
        uintptr_t offset = (uintptr_t)strtoull(hit->label + 5, nullptr, 0);
        uint32_t* target = (uint32_t*)((uintptr_t)ctx->Ecx + offset);
        if (ctx->Ecx != 0 && !IsBadWritePtr(target, sizeof(uint32_t))) {
            uint32_t was = *target;
            *target = 0;
            shim_log("[trace] %s: ecx=0x%08x +0x%llx was %08x -> 0", hit->label,
                     (uint32_t)ctx->Ecx, (unsigned long long)offset, was);
        } else {
            shim_log("[trace] %s: ecx=0x%08x + 0x%llx not writable", hit->label,
                     (uint32_t)ctx->Ecx, (unsigned long long)offset);
        }
    }

    if (strncmp(hit->label, "dumpc+", 6) == 0) {
        uintptr_t offset = (uintptr_t)strtoull(hit->label + 6, nullptr, 0);
        const uint32_t* target = (const uint32_t*)((uintptr_t)ctx->Ecx + offset);
        if (ctx->Ecx != 0 && !IsBadReadPtr(target, 8 * sizeof(uint32_t)))
            shim_log("[trace] %s: ecx=0x%08x +0x%llx -> %08x %08x %08x %08x %08x %08x %08x %08x",
                     hit->label, (uint32_t)ctx->Ecx, (unsigned long long)offset,
                     target[0], target[1], target[2], target[3],
                     target[4], target[5], target[6], target[7]);
        else
            shim_log("[trace] %s: ecx=0x%08x + 0x%llx unreadable", hit->label,
                     (uint32_t)ctx->Ecx, (unsigned long long)offset);
    }

    if (strncmp(hit->label, "dumpi+", 6) == 0) {
        char* sep = nullptr;
        uintptr_t a = (uintptr_t)strtoull(hit->label + 6, &sep, 0);
        uintptr_t b = (sep && *sep == '.') ? (uintptr_t)strtoull(sep + 1, nullptr, 0) : 0;
        const uint32_t* slot = (const uint32_t*)((uintptr_t)ctx->Ecx + a);
        if (ctx->Ecx != 0 && !IsBadReadPtr(slot, 4)) {
            const uint32_t* target = (const uint32_t*)((uintptr_t)*slot + b);
            if (*slot != 0 && !IsBadReadPtr(target, 4 * sizeof(uint32_t)))
                shim_log("[trace] %s: [ecx+0x%llx]=0x%08x +0x%llx -> %08x %08x %08x %08x",
                         hit->label, (unsigned long long)a, *slot, (unsigned long long)b,
                         target[0], target[1], target[2], target[3]);
            else
                shim_log("[trace] %s: [ecx+0x%llx]=0x%08x unreadable at +0x%llx",
                         hit->label, (unsigned long long)a, *slot, (unsigned long long)b);
        } else {
            shim_log("[trace] %s: ecx=0x%08x slot unreadable", hit->label, (uint32_t)ctx->Ecx);
        }
    }

    if (stack_ok && strncmp(hit->label, "dump1+", 6) == 0) {
        uintptr_t offset = (uintptr_t)strtoull(hit->label + 6, nullptr, 0);
        const uint32_t* target = (const uint32_t*)((uintptr_t)stack[1] + offset);
        if (stack[1] != 0 && !IsBadReadPtr(target, 8 * sizeof(uint32_t))) {
            shim_log("[trace] %s: arg1=0x%08x +0x%llx -> %08x %08x %08x %08x %08x %08x %08x %08x",
                     hit->label, stack[1], (unsigned long long)offset,
                     target[0], target[1], target[2], target[3],
                     target[4], target[5], target[6], target[7]);
        } else {
            shim_log("[trace] %s: arg1=0x%08x + 0x%llx unreadable", hit->label,
                     stack[1], (unsigned long long)offset);
        }
    }

    if (!point->captured && strncmp(hit->label, "watchwd+", 8) == 0) {
        uintptr_t offset = (uintptr_t)strtoull(hit->label + 8, nullptr, 0);
        uintptr_t target = (uintptr_t)ctx->Ecx + offset;
        if (ctx->Ecx != 0 && !IsBadReadPtr((void*)target, 1)) {
            shim_log("[trace] %s: this=0x%08x target=0x%08llx", hit->label,
                     (uint32_t)ctx->Ecx, (unsigned long long)target);
            point->captured = watchpoint_arm(target, hit->label, ctx, true);
        } else {
            shim_log("[trace] %s: this=0x%08x + 0x%llx unreadable", hit->label,
                     (uint32_t)ctx->Ecx, (unsigned long long)offset);
        }
    }

    if (!point->captured && strncmp(hit->label, "watchw+", 7) == 0) {
        char* sep = nullptr;
        uintptr_t a = (uintptr_t)strtoull(hit->label + 7, &sep, 0);
        uintptr_t b = (sep && *sep == '.') ? (uintptr_t)strtoull(sep + 1, nullptr, 0) : 0;
        const uint32_t* slot = (const uint32_t*)((uintptr_t)ctx->Ecx + a);
        if (ctx->Ecx != 0 && !IsBadReadPtr(slot, 4) && *slot != 0) {
            uintptr_t target = (uintptr_t)*slot + b;
            if (!IsBadReadPtr((void*)target, 4)) {
                shim_log("[trace] %s: [ecx+0x%llx]=0x%08x target=0x%08llx", hit->label,
                         (unsigned long long)a, *slot, (unsigned long long)target);
                point->captured = watchpoint_arm(target, hit->label, ctx, true);
            }
        }
        if (!point->captured)
            shim_log("[trace] %s: ecx=0x%08x indirection unreadable", hit->label,
                     (uint32_t)ctx->Ecx);
    }

    if (!point->captured && strncmp(hit->label, "samplei+", 8) == 0) {
        char* sep = nullptr;
        uintptr_t a = (uintptr_t)strtoull(hit->label + 8, &sep, 0);
        uintptr_t b = (sep && *sep == '.') ? (uintptr_t)strtoull(sep + 1, nullptr, 0) : 0;
        const uint32_t* slot = (const uint32_t*)((uintptr_t)ctx->Ecx + a);
        if (ctx->Ecx != 0 && !IsBadReadPtr(slot, 4) && *slot != 0) {
            uintptr_t target = (uintptr_t)*slot + b;
            if (!IsBadReadPtr((void*)target, 4)) {
                shim_log("[trace] %s: [ecx+0x%llx]=0x%08x target=0x%08llx", hit->label,
                         (unsigned long long)a, *slot, (unsigned long long)target);
                point->captured = field_sampler_start(target, hit->label);
            }
        }
        if (!point->captured)
            shim_log("[trace] %s: ecx=0x%08x indirection unreadable", hit->label,
                     (uint32_t)ctx->Ecx);
    }

    if (!point->captured && strncmp(hit->label, "sample+", 7) == 0) {
        uintptr_t offset = (uintptr_t)strtoull(hit->label + 7, nullptr, 0);
        uintptr_t target = (uintptr_t)ctx->Ecx + offset;
        if (ctx->Ecx != 0 && !IsBadReadPtr((void*)target, 4)) {
            shim_log("[trace] %s: this=0x%08x target=0x%08llx", hit->label,
                     (uint32_t)ctx->Ecx, (unsigned long long)target);
            point->captured = field_sampler_start(target, hit->label);
        } else {
            shim_log("[trace] %s: this=0x%08x + 0x%llx unreadable — not sampling",
                     hit->label, (uint32_t)ctx->Ecx, (unsigned long long)offset);
        }
    }

    write_byte((void*)hit->address, hit->original);
    if (capture_point && point->captured) {
        shim_log("[trace] %s captured — trace point retired", hit->label);
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    g_pending_rearm = hit->address;
    ctx->EFlags |= 0x100;
    return EXCEPTION_CONTINUE_EXECUTION;
}

bool g_handler_installed = false;

}

namespace farcry3 {
bool menu_latched() { return g_latched; }

int first_session_slot_state() {
    if (!g_captured_set[0]) return -1;
    uintptr_t object = g_captured[0];
    const uint8_t* count = (const uint8_t*)(object + kSlotCount);
    const uint32_t* array = (const uint32_t*)(object + kSlotArray);
    if (object == 0 || IsBadReadPtr(count, 1) || IsBadReadPtr(array, 4) || *count == 0 || *array == 0)
        return -1;
    const uint8_t* record = (const uint8_t*)(uintptr_t)*array + kRecordInSlot;
    if (IsBadReadPtr(record + kRecordState, 4)) return -1;
    return (int)*(const uint32_t*)(record + kRecordState);
}
}

void install_trace_points() {
    if (!hook_config().trace_points[0]) return;
    if (!g_handler_installed) {
        if (!AddVectoredExceptionHandler(1, handler)) {
            shim_log("[trace] AddVectoredExceptionHandler failed: %lu", GetLastError());
            return;
        }
        g_handler_installed = true;
    }

    char buf[512];
    strncpy_s(buf, hook_config().trace_points, sizeof(buf) - 1);

    char* ctx = nullptr;
    char* tok = strtok_s(buf, ",", &ctx);
    while (tok && g_point_count < kMaxTracePoints) {
        char* modctx = nullptr;
        char* module_name = strtok_s(tok, ":", &modctx);
        char* rva_str     = strtok_s(nullptr, ":", &modctx);
        char* label       = strtok_s(nullptr, ":", &modctx);
        tok = strtok_s(nullptr, ",", &ctx);
        if (!module_name || !rva_str) {
            shim_log("[trace] malformed trace point entry, skipping");
            continue;
        }

        HMODULE mod = GetModuleHandleA(module_name);
        g_trace_module_base = (uintptr_t)mod;
        if (!mod) {
            shim_log("[trace] module '%s' not loaded yet — skipping '%s'",
                     module_name, label ? label : rva_str);
            continue;
        }

        uintptr_t rva = (uintptr_t)strtoull(rva_str, nullptr, 0);
        uintptr_t address = (uintptr_t)mod + rva;
        if (IsBadReadPtr((void*)address, 1)) {
            shim_log("[trace] %s+0x%llx is unreadable — skipping", module_name, (unsigned long long)rva);
            continue;
        }

        if (label && strncmp(label, "true+", 5) == 0) {
            unsigned pops = (unsigned)strtoul(label + 5, nullptr, 0);
            BYTE patch[5] = {0xB0, 0x01};   // MOV AL,1
            size_t patch_length;
            if (pops == 0) { patch[2] = 0xC3; patch_length = 3; }
            else { patch[2] = 0xC2; patch[3] = (BYTE)(pops & 0xff);
                   patch[4] = (BYTE)((pops >> 8) & 0xff); patch_length = 5; }
            BYTE was = *(BYTE*)address;
            if (write_bytes((void*)address, patch, patch_length))
                shim_log("[trace] forced %s+0x%llx to MOV AL,1; RET %u (was 0x%02x) — '%s'",
                         module_name, (unsigned long long)rva, pops, was, label);
            else
                shim_log("[trace] failed to force %s+0x%llx", module_name,
                         (unsigned long long)rva);
            continue;
        }

        if (label && strncmp(label, "ret+", 4) == 0) {
            unsigned pops = (unsigned)strtoul(label + 4, nullptr, 0);
            BYTE patch[3];
            size_t patch_length;
            if (pops == 0) { patch[0] = 0xC3; patch_length = 1; }
            else { patch[0] = 0xC2; patch[1] = (BYTE)(pops & 0xff);
                   patch[2] = (BYTE)((pops >> 8) & 0xff); patch_length = 3; }
            if (write_bytes((void*)address, patch, patch_length))
                shim_log("[trace] neutralised %s+0x%llx with RET %u (was 0x%02x) — '%s'",
                         module_name, (unsigned long long)rva, pops,
                         *(BYTE*)address, label);
            else
                shim_log("[trace] failed to neutralise %s+0x%llx", module_name,
                         (unsigned long long)rva);
            continue;
        }

        TracePoint& p = g_points[g_point_count];
        p.address = address;
        p.original = *(BYTE*)address;
        strncpy_s(p.label, label ? label : rva_str, sizeof(p.label) - 1);

        if (write_byte((void*)address, 0xCC)) {
            shim_log("[trace] armed '%s' at %s+0x%llx (0x%llx, original 0x%02x)",
                     p.label, module_name, (unsigned long long)rva,
                     (unsigned long long)address, p.original);
            ++g_point_count;
        } else {
            shim_log("[trace] failed to arm '%s' at 0x%llx", p.label, (unsigned long long)address);
        }
    }
}
