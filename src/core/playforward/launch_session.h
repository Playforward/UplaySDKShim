#pragma once

#include "core/playforward/launch_envelope.h"

#include <winsock2.h>

namespace playforward::session {
bool acquire(envelope::Launch& launch);
void bound(SOCKET socket, const sockaddr_in& server, const envelope::Launch& launch);
void unproved(SOCKET socket, const sockaddr_in& server, const envelope::Launch& launch);
void report(const char* event, const char* detail = nullptr);
}
