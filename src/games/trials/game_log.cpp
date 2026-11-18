#include "games/trials/game_log.h"

#include "core/config.h"
#include "core/logging.h"
#include "games/trials/versions/current.h"

#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace trials {
namespace {

// Only the subsystems behind the online menus; the rest of the game logs
// every frame.
constexpr const char* kKeptSources[] = {"online", "sharing", "Content", "UserInterface", "Menu", "Leaderboard"};

bool kept(const char* file, const char* function) {
    for (const char* source : kKeptSources) {
        if ((file && strstr(file, source)) || (function && strstr(function, source))) return true;
    }
    return false;
}

// Replaces the game's logger entry outright (it would drop the line anyway):
// cdecl (logger, channel, ?, level, file, function, line, format, ...).
void __cdecl game_log(void* /*logger*/, int /*channel*/, int /*unknown*/, int level, const char* file,
                      const char* function, int line, const char* format, ...) {
    if (!format || !kept(file, function)) return;
    char text[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(text, sizeof(text), format, args);
    va_end(args);
    size_t length = strlen(text);
    while (length && (text[length - 1] == '\n' || text[length - 1] == '\r')) text[--length] = '\0';
    shim_log("[game] %d %s:%d %s", level, function ? function : "?", line, text);
}

}

void install_game_log(HMODULE process_module) {
    if (!hook_config().game_log) return;
    auto* entry = reinterpret_cast<uint8_t*>(process_module) + current::kGameLogRva;
    if (memcmp(entry, current::kGameLogPrologue, sizeof(current::kGameLogPrologue)) != 0) {
        shim_log("[trials] game_log: the logger entry at +0x%x is not the expected code; not hooked", current::kGameLogRva);
        return;
    }
    uint8_t jump[5] = {0xE9};
    int32_t rel = static_cast<int32_t>(reinterpret_cast<intptr_t>(&game_log) - reinterpret_cast<intptr_t>(entry + 5));
    memcpy(jump + 1, &rel, 4);
    DWORD old = 0;
    if (!VirtualProtect(entry, sizeof(jump), PAGE_EXECUTE_READWRITE, &old)) {
        shim_log("[trials] game_log: cannot unprotect the logger entry");
        return;
    }
    memcpy(entry, jump, sizeof(jump));
    DWORD ignored = 0;
    VirtualProtect(entry, sizeof(jump), old, &ignored);
    FlushInstructionCache(GetCurrentProcess(), entry, sizeof(jump));
    shim_log("[trials] game_log: the game's online/menu log lines go to hook.log ([game])");
}

}
