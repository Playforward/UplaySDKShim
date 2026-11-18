#pragma once

#include <windows.h>

namespace trials {
// Lets Track Central's front page load without Ubisoft's TMS document.
void install_track_central_fix(HMODULE process_module);
}
