#pragma once

#include <winsock2.h>
#include <windows.h>
#include <cstddef>

namespace playforward::bridge {

class Connection {
public:
    Connection() = default;
    Connection(const Connection&) = delete;
    Connection& operator=(const Connection&) = delete;
    ~Connection();

    bool open(bool quiet = false);

    bool send_line(const char* line);

    size_t read_line(char* out, size_t capacity);

    void wait_until_closed();

    void close();

    const char* where() const { return where_; }

private:
    bool open_pipe(bool quiet);
    bool open_socket();

    HANDLE pipe_ = INVALID_HANDLE_VALUE;
    SOCKET socket_ = INVALID_SOCKET;
    char where_[MAX_PATH] = {};
};

// One request and its one-line answer over a fresh connection; false when the
// desktop client could not be reached or said nothing. `line` ends in '\n'.
bool request(const char* line, char* reply, size_t capacity, bool quiet = false);

}
