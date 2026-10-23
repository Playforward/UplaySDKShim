#pragma once

#include <windows.h>
#include <cstdint>

namespace agora_root_key {
bool arm(const char* tag, const char* default_key_file);
bool pending();
bool install_at(uint8_t* call_site, const char* what, uintptr_t expected_rsa_import = 0);
}
