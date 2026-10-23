#include "games/conviction/agora.h"

#include "core/logging.h"
#include "games/common/agora_root_key.h"

#include <cstdint>

namespace {
constexpr uintptr_t kImageBase = 0x400000;
constexpr uintptr_t kCallSite = 0xbe83b4;
constexpr uintptr_t kRsaImport = 0xc48340;
constexpr const char* kDefaultKeyFile = "conviction_agora_root.pub.der";
}

namespace conviction {
void arm_agora_root_key() {
    agora_root_key::arm("[scc-agora]", kDefaultKeyFile);
}

void install_agora_root_key(HMODULE process_module) {
    if (!agora_root_key::pending()) return;
    const uintptr_t delta = reinterpret_cast<uintptr_t>(process_module) - kImageBase;
    agora_root_key::install_at(reinterpret_cast<uint8_t*>(kCallSite + delta),
                               "AgoraAuthService root key import, 1.04 rva 0x7e83b4", kRsaImport + delta);
}
}
