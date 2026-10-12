#pragma once

#include <winsock2.h>

// Watches the game's TCP connections for the server's TLS certificate while
// the verifier bypass is armed (see tls.cpp and tls_pin.h). A connection
// whose server presents a pinned key lets the verifier through; one that
// presents any other key, or hides it, is torn down before the game's TLS
// code finishes reading it.
//
// Fails closed. A connection whose bytes the shim cannot see -- read through
// a completion path it does not hook -- never opens the verifier, so the
// game's own verification decides, and that refuses anything not signed by
// a CA the game trusts.
namespace tls_observer {

// The game is connecting a socket. Only stream sockets are watched; this
// also forgets whatever an earlier socket with the same handle left behind.
void on_connect(SOCKET socket);

// Bytes the server sent arrived in the game's buffers. False means the
// connection has been refused: the caller must fail the read, and the
// socket has already been shut down.
bool on_received(SOCKET socket, const WSABUF* buffers, DWORD buffer_count, DWORD bytes);

// Whether a socket is still waiting for its server's certificate, so a read
// posted on it has to be followed to its completion.
bool watching(SOCKET socket);

// An overlapped read was posted on a watched socket. With a completion
// routine, or with an earlier read never seen to complete, the shim will
// miss bytes, so it stops trusting anything it could read from this socket.
void on_read_posted(SOCKET socket, bool has_completion_routine);

// An overlapped read finished with no bytes, or failed.
void on_read_finished(SOCKET socket);

void on_close(SOCKET socket);

}
