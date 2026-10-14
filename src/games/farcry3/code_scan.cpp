#include "games/farcry3/code_scan.h"

#include <cstdlib>
#include <cstring>

namespace farcry3 {

Pattern parse_pattern(const char* text) {
    Pattern p;
    while (*text && p.length < Pattern::kCapacity) {
        if (*text == ' ') { ++text; continue; }
        if (text[0] == '?') {
            p.wild[p.length] = true;
            p.bytes[p.length++] = 0;
        } else {
            char hex[3] = {text[0], text[1], 0};
            p.wild[p.length] = false;
            p.bytes[p.length++] = (uint8_t)strtoul(hex, nullptr, 16);
        }
        text += 2;
    }
    return p;
}

bool pattern_matches(const uint8_t* at, const Pattern& p) {
    for (size_t i = 0; i < p.length; ++i)
        if (!p.wild[i] && at[i] != p.bytes[i]) return false;
    return true;
}

size_t find_all_with_tail(HMODULE module, const Pattern& head, size_t tail_offset, const Pattern& tail,
                          const uint8_t** out, size_t capacity) {
    auto* base = reinterpret_cast<const uint8_t*>(module);
    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    const IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(nt);
    const size_t span = tail.length ? tail_offset + tail.length : head.length;
    size_t found = 0;
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
        if (!(section->Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
        const uint8_t* start = base + section->VirtualAddress;
        const size_t size = section->Misc.VirtualSize;
        if (size < span || size < head.length) continue;
        for (size_t at = 0; at + span <= size && at + head.length <= size; ++at) {
            if (start[at] != head.bytes[0] || !pattern_matches(start + at, head)) continue;
            if (tail.length && !pattern_matches(start + at + tail_offset, tail)) continue;
            if (found < capacity) out[found] = start + at;
            ++found;
        }
    }
    return found;
}

size_t find_all(HMODULE module, const Pattern& pattern, const uint8_t** out, size_t capacity) {
    return find_all_with_tail(module, pattern, 0, Pattern{}, out, capacity);
}

const uint8_t* call_target(const uint8_t* call) {
    int32_t rel;
    memcpy(&rel, call + 1, sizeof(rel));
    return call + 5 + rel;
}

}
