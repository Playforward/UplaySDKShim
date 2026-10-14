#pragma once
#include <cstdint>

namespace farcry3 {

// Code repairs the 2022 decommission build (FC3_d3d11.dll and FC3.dll) needs
// to play online.
void install_build_fixes();

const char* build_fix_at(uintptr_t address);

}
