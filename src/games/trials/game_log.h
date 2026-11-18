#pragma once

#include <windows.h>

namespace trials {
// hook.config game_log=1: the game's own debug log, which ships switched off,
// goes to hook.log instead.
void install_game_log(HMODULE process_module);
}
