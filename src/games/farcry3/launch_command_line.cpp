#include "games/farcry3/launch_command_line.h"

#include <cctype>
#include <cstring>

namespace farcry3::launch {
namespace {

bool is_space(char c) { return std::isspace(static_cast<unsigned char>(c)) != 0; }

size_t skip_spaces(const char* text, size_t at) {
    while (text[at] && is_space(text[at])) ++at;
    return at;
}

size_t argument_end(const char* text, size_t at) {
    bool quoted = false;
    for (; text[at]; ++at) {
        if (text[at] == '"') quoted = !quoted;
        else if (!quoted && is_space(text[at])) break;
    }
    return at;
}

bool is_login_option(const char* text, size_t begin, size_t end) {
    const size_t length = strlen(kLoginOption);
    return end - begin == length && strncmp(text + begin, kLoginOption, length) == 0;
}

struct Writer {
    char* out;
    size_t capacity;
    size_t length = 0;

    bool append(const char* text, size_t count) {
        if (length + count >= capacity) return false;
        memcpy(out + length, text, count);
        length += count;
        return true;
    }
    bool append(const char* text) { return append(text, strlen(text)); }
};

}

bool with_login_name(const char* command_line, const char* login_name, char* out, size_t capacity) {
    if (!command_line || !login_name || !login_name[0] || !out || capacity == 0) return false;
    if (strchr(login_name, '"')) return false;

    Writer writer{out, capacity};
    size_t at = 0;
    while (command_line[at]) {
        const size_t begin = skip_spaces(command_line, at);
        if (!writer.append(command_line + at, begin - at)) return false;
        if (!command_line[begin]) { at = begin; break; }

        const size_t end = argument_end(command_line, begin);
        if (is_login_option(command_line, begin, end)) {
            const size_t value = skip_spaces(command_line, end);
            at = command_line[value] ? argument_end(command_line, value) : value;
            continue;
        }
        if (!writer.append(command_line + begin, end - begin)) return false;
        at = end;
    }

    const bool needs_quotes = strpbrk(login_name, " \t") != nullptr;
    const bool needs_separator = writer.length > 0 && !is_space(out[writer.length - 1]);
    if (needs_separator && !writer.append(" ")) return false;
    if (!writer.append(kLoginOption) || !writer.append(" ")) return false;
    if (needs_quotes && !writer.append("\"")) return false;
    if (!writer.append(login_name)) return false;
    if (needs_quotes && !writer.append("\"")) return false;
    out[writer.length] = '\0';
    return true;
}

}
