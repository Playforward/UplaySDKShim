#include "core/playforward/play_presence.h"

#include "core/config.h"
#include "core/game_adapter.h"
#include "core/logging.h"
#include "core/playforward/bridge_client.h"

#include <cstdio>
#include <cstring>

namespace playforward {
namespace {

constexpr DWORD kRetryIntervalMs = 5000;

constexpr size_t kReplyCapacity = 128;

constexpr const char* kAccepted = "OK";

DWORD WINAPI hold_playing(LPVOID title_parameter) {
    const char* title = static_cast<const char*>(title_parameter);
    char request[128];
    snprintf(request, sizeof(request), "playing %s\n", title);

    bool failing = false;
    for (;;) {
        bridge::Connection bridge;
        if (bridge.open(failing) && bridge.send_line(request)) {
            char reply[kReplyCapacity];
            bridge.read_line(reply, sizeof(reply));
            if (strcmp(reply, kAccepted) == 0) {
                shim_log("[playforward] told the desktop client at %s that %s is running", bridge.where(), title);
                failing = false;
                bridge.wait_until_closed();
                shim_log("[playforward] the desktop client let go of %s; telling it again", title);
                Sleep(kRetryIntervalMs);
                continue;
            }
            if (!failing) shim_log("[playforward] the desktop client did not take %s as running: %s", title, reply);
        } else if (!failing) {
            shim_log("[playforward] no desktop client to tell %s is running; trying every %lu ms",
                     title, static_cast<unsigned long>(kRetryIntervalMs));
        }
        failing = true;
        Sleep(kRetryIntervalMs);
    }
}

}

void start_play_presence() {
    const char* title = game_adapter().playforward_title;
    if (!title || !hook_config().playforward_presence) return;

    HANDLE thread = CreateThread(nullptr, 0, hold_playing, const_cast<char*>(title), 0, nullptr);
    if (thread) CloseHandle(thread);
    else shim_log("[playforward] could not start reporting %s as running: %lu", title, GetLastError());
}

}
