#include "games/common/agora_root_key.h"

#include "core/config.h"
#include "core/logging.h"
#include "core/playforward/sha256.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace {

constexpr size_t kMaxKeyBytes = 4096;

constexpr uint8_t kThunkPrologue[] = {0xff, 0x74, 0x24, 0x04, 0xff, 0x74, 0x24, 0x10, 0xff, 0x74, 0x24, 0x10, 0xe8};
constexpr uint8_t kThunkEpilogue[] = {0x83, 0xc4, 0x0c, 0xc3};

using ImportThunk = int(__cdecl*)(void* key, const unsigned char* data, unsigned long length);

std::vector<uint8_t> g_root_key;
ImportThunk g_import_thunk = nullptr;
bool g_installed = false;
const char* g_tag = "[agora]";

std::string short_hash(const void* data, size_t length) {
    uint8_t digest[playforward::kSha256Length];
    playforward::sha256(static_cast<const uint8_t*>(data), length, digest);
    char text[17];
    for (int i = 0; i < 8; ++i) snprintf(text + 2 * i, 3, "%02x", digest[i]);
    return text;
}

std::string exe_directory() {
    char path[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, path, MAX_PATH);
    if (char* slash = strrchr(path, '\\')) *slash = 0;
    return path;
}

bool is_absolute(const char* path) {
    return path[0] == '\\' || path[0] == '/' || (path[0] && path[1] == ':');
}

const char* check_der_sequence(const std::vector<uint8_t>& key) {
    if (key.size() < 8) return "too short to be a DER public key";
    if (key.size() > kMaxKeyBytes) return "larger than any RSA public key";
    if (key[0] != 0x30) return "does not start with a DER SEQUENCE (0x30); it must be a binary key, not PEM";
    size_t header = 2, length = key[1];
    if (key[1] & 0x80) {
        const size_t count = key[1] & 0x7f;
        if (count == 0 || count > 2) return "unsupported DER length encoding";
        length = 0;
        for (size_t i = 0; i < count; ++i) length = (length << 8) | key[2 + i];
        header = 2 + count;
    }
    if (header + length != key.size()) return "DER length does not match the file size";
    return nullptr;
}

bool load_key_file(const std::string& path) {
    HANDLE file = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        shim_log("%s skipped: no key file at %s (error %lu); the game keeps its own root key", g_tag, path.c_str(), GetLastError());
        return false;
    }
    const DWORD size = GetFileSize(file, nullptr);
    std::vector<uint8_t> bytes;
    DWORD got = 0;
    bool read = size != INVALID_FILE_SIZE && size <= kMaxKeyBytes;
    if (read) {
        bytes.resize(size);
        read = size == 0 || (ReadFile(file, bytes.data(), size, &got, nullptr) && got == size);
    }
    CloseHandle(file);
    if (!read) {
        shim_log("%s skipped: %s is %lu bytes or unreadable; the game keeps its own root key", g_tag, path.c_str(),
                 static_cast<unsigned long>(size));
        return false;
    }
    if (const char* problem = check_der_sequence(bytes)) {
        shim_log("%s skipped: %s (%u bytes) %s; the game keeps its own root key", g_tag, path.c_str(),
                 static_cast<unsigned>(bytes.size()), problem);
        return false;
    }
    const size_t header = bytes[1] & 0x80 ? 2 + (bytes[1] & 0x7f) : 2;
    const bool spki = bytes.size() > header && bytes[header] == 0x30;
    g_root_key = std::move(bytes);
    shim_log("%s root key loaded from %s: %u bytes (%s), sha256 %s...", g_tag, path.c_str(),
             static_cast<unsigned>(g_root_key.size()), spki ? "X.509 SubjectPublicKeyInfo" : "not SubjectPublicKeyInfo; rsa_import falls back to PKCS#1",
             short_hash(g_root_key.data(), g_root_key.size()).c_str());
    return true;
}

int __cdecl import_our_root_key(void* key, const unsigned char* data, unsigned long length) {
    const std::string theirs = data ? short_hash(data, length) : "-";
    shim_log("%s swapping the root key: the game's own key file is %lu bytes (sha256 %s...); "
             "importing ours (%u bytes, sha256 %s...)",
             g_tag, length, theirs.c_str(), static_cast<unsigned>(g_root_key.size()),
             short_hash(g_root_key.data(), g_root_key.size()).c_str());
    const int result = g_import_thunk(key, g_root_key.data(), static_cast<unsigned long>(g_root_key.size()));
    shim_log("%s rsa_import returned %d (%s)", g_tag, result, result == 0 ? "key accepted" : "key REJECTED by the game; certificates will not verify");
    return result;
}

bool relative_call_target(const uint8_t* call, uintptr_t& target) {
    if (call[0] != 0xe8) return false;
    int32_t rel;
    memcpy(&rel, call + 1, sizeof rel);
    target = reinterpret_cast<uintptr_t>(call) + 5 + rel;
    return true;
}

}

namespace agora_root_key {
bool arm(const char* tag, const char* default_key_file) {
    g_tag = tag;
    const char* configured = hook_config().agora_root_key;
    std::string path = configured[0] ? configured : default_key_file;
    if (!is_absolute(path.c_str())) path = exe_directory() + "\\" + path;
    if (!load_key_file(path)) return false;
    shim_log("%s armed: the root key import is patched once the game's code is unpacked", g_tag);
    return true;
}

bool pending() { return !g_root_key.empty() && !g_installed; }

bool install_at(uint8_t* site, const char* what, uintptr_t expected_rsa_import) {
    if (!pending()) return false;
    g_installed = true;   // one attempt per process

    uintptr_t thunk_address = 0, imported = 0;
    const bool shaped = relative_call_target(site, thunk_address);
    auto* thunk = reinterpret_cast<uint8_t*>(thunk_address);
    if (!shaped || IsBadReadPtr(thunk, 21) ||
        memcmp(thunk, kThunkPrologue, sizeof kThunkPrologue) != 0 ||
        !relative_call_target(thunk + 12, imported) ||
        (expected_rsa_import && imported != expected_rsa_import) ||
        memcmp(thunk + 17, kThunkEpilogue, sizeof kThunkEpilogue) != 0) {
        shim_log("%s skipped: the code at %p (%s) is not the root key import "
                 "(bytes %02x %02x %02x %02x %02x); the game keeps its own root key",
                 g_tag, site, what, site[0], site[1], site[2], site[3], site[4]);
        return false;
    }

    g_import_thunk = reinterpret_cast<ImportThunk>(thunk);
    const int32_t rel = static_cast<int32_t>(reinterpret_cast<uintptr_t>(&import_our_root_key) - (reinterpret_cast<uintptr_t>(site) + 5));
    DWORD old = 0;
    if (!VirtualProtect(site + 1, sizeof rel, PAGE_EXECUTE_READWRITE, &old)) {
        shim_log("%s skipped: cannot make %p writable (error %lu); the game keeps its own root key", g_tag, site, GetLastError());
        return false;
    }
    memcpy(site + 1, &rel, sizeof rel);
    DWORD ignored = 0;
    VirtualProtect(site + 1, sizeof rel, old, &ignored);
    FlushInstructionCache(GetCurrentProcess(), site, 5);
    shim_log("%s hook installed at %p (%s; thunk %p, rsa_import %p)", g_tag, site, what, thunk,
             reinterpret_cast<void*>(imported));
    return true;
}
}
