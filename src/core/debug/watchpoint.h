#pragma once

#include <windows.h>

#include <cstdint>

void watchpoint_install_handler();
bool watchpoint_arm(uintptr_t address, const char* label, CONTEXT* self,
                    bool writes_only = false);
