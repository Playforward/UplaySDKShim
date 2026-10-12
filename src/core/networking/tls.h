#pragma once

#include <windows.h>

struct TlsHookDefinition;

void install_tls_bypass(HMODULE game_module, const TlsHookDefinition& definition);

bool tls_pinning_armed();
void tls_trust_pinned_handshake();
