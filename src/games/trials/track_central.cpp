#include "games/trials/track_central.h"

#include "core/logging.h"
#include "games/trials/versions/current.h"

#include <cstdint>
#include <cstring>

namespace trials {
namespace {

// Track Central's feeds come from tms/ugc.xml, which Ubisoft's title storage
// served; without it the game parses the failsafe copy built into the exe.
// There the "RedLynx Picks" feed is an empty hand-picked list, the game
// fails a by-id request for zero tracks before sending it (0x80010001), and
// that one failure throws away the whole Get Feeds task, so no feed shows a
// track. Switching that feed off ("0" parses as false, 0x74bfa0) keeps the
// other eight. Same length, so the document stays intact.
constexpr char kPicksOn[] = "enabled=\"true\" name=\"FEED_NAME_REDLYNX_PICKS\"";
constexpr char kPicksOff[] = "enabled=\"0\"    name=\"FEED_NAME_REDLYNX_PICKS\"";
static_assert(sizeof(kPicksOn) == sizeof(kPicksOff));

}

void install_track_central_fix(HMODULE process_module) {
    char* xml = reinterpret_cast<char*>(process_module) + current::kFailsafeUgcXmlRva;
    char* end = xml + current::kFailsafeUgcXmlSize;
    if (memcmp(xml, "<UGC>", 5) != 0) {
        shim_log("[trials] track central: no failsafe ugc.xml at +0x%x; feeds left as they are", current::kFailsafeUgcXmlRva);
        return;
    }
    char* picks = nullptr;
    for (char* at = xml; at + sizeof(kPicksOn) - 1 <= end; ++at) {
        if (memcmp(at, kPicksOn, sizeof(kPicksOn) - 1) == 0) { picks = at; break; }
    }
    if (!picks) {
        shim_log("[trials] track central: the failsafe ugc.xml has no enabled RedLynx Picks feed; nothing to do");
        return;
    }
    DWORD old = 0;
    if (!VirtualProtect(picks, sizeof(kPicksOff) - 1, PAGE_READWRITE, &old)) {
        shim_log("[trials] track central: cannot unprotect the failsafe ugc.xml");
        return;
    }
    memcpy(picks, kPicksOff, sizeof(kPicksOff) - 1);
    DWORD ignored = 0;
    VirtualProtect(picks, sizeof(kPicksOff) - 1, old, &ignored);
    shim_log("[trials] track central: RedLynx Picks feed switched off in the failsafe ugc.xml (it has no tracks and fails every feed)");
}

}
