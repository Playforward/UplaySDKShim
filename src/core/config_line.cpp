#include "core/config_line.h"

namespace config_line {

bool read(FILE* file, char (&out)[kCapacity], bool& too_long) {
    size_t length = 0;
    bool read_anything = false;
    too_long = false;
    int c;
    while ((c = fgetc(file)) != EOF) {
        read_anything = true;
        if (c == '\n') break;
        if (length + 1 < kCapacity) out[length++] = static_cast<char>(c);
        else too_long = true;
    }
    if (too_long) length = 0;
    out[length] = 0;
    return read_anything;
}

}
