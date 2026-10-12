#include "core/logging.h"

#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace {
FILE* g_log = nullptr;
char g_prefix[64] = "UPLAYSDKSHIM";

void write_line(const char* message, bool mirror_to_debugger) {
    SYSTEMTIME now{};
    GetLocalTime(&now);
    char stamp[32] = {};
    snprintf(stamp, sizeof(stamp), "%02u:%02u:%02u.%03u | ",
             now.wHour, now.wMinute, now.wSecond, now.wMilliseconds);
    if (mirror_to_debugger) {
        char debug[2400] = {};
        snprintf(debug, sizeof(debug), "%s: %s%s\n", g_prefix, stamp, message);
        OutputDebugStringA(debug);
    }
    if (g_log) {
        fputs(stamp, g_log);
        fputs(message, g_log);
        fputc('\n', g_log);
        fflush(g_log);
    }
}
}

void initialize_logging(HINSTANCE self, const char* game_id) {
    strncpy_s(g_prefix, game_id, _TRUNCATE);
    char path[MAX_PATH] = {};
    GetModuleFileNameA(self, path, MAX_PATH);
    if (char* slash = strrchr(path, '\\')) *slash = 0;
    char log_path[MAX_PATH] = {};
    snprintf(log_path, sizeof(log_path), "%s\\hook.log", path);
    fopen_s(&g_log, log_path, "a");
    shim_log("========== %s new process ==========", game_id);
    if (const char* command_line = GetCommandLineA())
        shim_log("[cmdline] %s", command_line);
}

void shutdown_logging() { if (g_log) { fclose(g_log); g_log = nullptr; } }

void shim_log(const char* format, ...) {
    char message[2048] = {};
    va_list args; va_start(args, format); vsnprintf(message, sizeof(message), format, args); va_end(args);
    write_line(message, true);
}

void shim_log_bytes(const char* prefix, const void* data, int len) {
    if (!data || len <= 0) return;
    const auto* bytes = static_cast<const unsigned char*>(data);
    static constexpr int kPrefixMax = 128;
    static constexpr int kFallbackMax = 512;
    const size_t needed = kPrefixMax + 32 + static_cast<size_t>(len) * 2 + 1;
    char* line = static_cast<char*>(malloc(needed));
    char fallback[kPrefixMax + 32 + kFallbackMax * 2 + 1] = {};
    char* text = line ? line : fallback;
    const int count = line ? len : (len < kFallbackMax ? len : kFallbackMax);

    int offset = snprintf(text, line ? needed : sizeof(fallback), "%s len=%d ", prefix, len);
    if (offset < 0) { free(line); return; }
    for (int i = 0; i < count; ++i) {
        static const char kHex[] = "0123456789abcdef";
        text[offset + i * 2] = kHex[bytes[i] >> 4];
        text[offset + i * 2 + 1] = kHex[bytes[i] & 0x0f];
    }
    text[offset + count * 2] = 0;
    write_line(text, false);
    if (count < len) shim_log("%s len=%d ...(truncated at %d)", prefix, len, count);
    free(line);
}
