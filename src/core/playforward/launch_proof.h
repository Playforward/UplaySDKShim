#pragma once

#include <winsock2.h>
#include <cstdint>

namespace playforward {

void prove_launch(SOCKET socket);
uint16_t launch_port();

}
