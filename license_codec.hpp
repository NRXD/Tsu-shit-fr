#pragma once
// Blaster license codec: plain C++ (no Windows code), so it can be unit-tested anywhere.
// Formats:
//   HWID code : 10 bytes  -> 16 base32 chars, shown as XXXX-XXXX-XXXX-XXXX
//   License key: 4-byte serial + 1-byte unit + 4-byte count + 64-byte ECDSA P-256 signature (73 bytes)
//                -> 117 base32 chars, shown in groups of 5 separated by '-'
#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace blaster { namespace lic {

static const size_t HWID_BYTES = 10;
static const size_t HWID_CHARS = 16;
static const size_t SERIAL_BYTES = 4;
static const size_t SIG_BYTES = 64;
static const size_t TERM_BYTES = 5;                         // unit(1) + count(4, big-endian)
static const size_t HEAD_BYTES = SERIAL_BYTES + TERM_BYTES; // 9: the part that is signed (with the HWID)
static const size_t KEY_BYTES = HEAD_BYTES + SIG_BYTES;     // 73
static const size_t KEY_CHARS = 117;                        // ceil(73*8/5)

// How long a key lasts, counted from the moment it is activated.
enum Unit : uint8_t { U_LIFETIME = 0, U_SECOND = 1, U_MINUTE = 2, U_HOUR = 3, U_DAY = 4, U_MONTH = 5, U_YEAR = 6 };

// Seconds the key lasts; 0 means lifetime. Month = 30 days, year = 365 days.
inline uint64_t termSeconds(uint8_t unit, uint32_t count) {
    static const uint64_t PER[7] = {0, 1, 60, 3600, 86400, 86400ull * 30, 86400ull * 365};
    if (unit == U_LIFETIME || unit > U_YEAR) return 0;
    return PER[unit] * (uint64_t)count;
}
inline bool termValid(uint8_t unit, uint32_t count) {
    return unit <= U_YEAR && (unit == U_LIFETIME || (count >= 1 && count <= 1000000u));
}
inline const char* unitName(uint8_t unit) {
    static const char* N[7] = {"lifetime", "second", "minute", "hour", "day", "month", "year"};
    return unit <= U_YEAR ? N[unit] : "?";
}

inline std::string b32encode(const uint8_t* d, size_t n) {
    static const char A[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    std::string out;
    uint32_t buf = 0;
    int bits = 0;
    for (size_t i = 0; i < n; ++i) {
        buf = (buf << 8) | d[i];
        bits += 8;
        while (bits >= 5) {
            out.push_back(A[(buf >> (bits - 5)) & 31]);
            bits -= 5;
        }
        buf &= (1u << bits) - 1u;
    }
    if (bits > 0) out.push_back(A[(buf << (5 - bits)) & 31]);
    return out;
}

inline bool b32decode(const std::string& s, std::vector<uint8_t>& out) {
    out.clear();
    uint32_t buf = 0;
    int bits = 0;
    for (char c : s) {
        int v;
        if (c >= 'A' && c <= 'Z') v = c - 'A';
        else if (c >= '2' && c <= '7') v = c - '2' + 26;
        else return false;
        buf = (buf << 5) | (uint32_t)v;
        bits += 5;
        if (bits >= 8) {
            out.push_back((uint8_t)((buf >> (bits - 8)) & 0xFF));
            bits -= 8;
            buf &= (1u << bits) - 1u;
        }
    }
    return true;
}

// Keep only A-Z / 2-7 (upper-cased). Dashes, spaces and line breaks are dropped.
inline std::string normalize(const std::string& in) {
    std::string out;
    for (char c : in) {
        if (c >= 'a' && c <= 'z') c = (char)(c - 'a' + 'A');
        if ((c >= 'A' && c <= 'Z') || (c >= '2' && c <= '7')) out.push_back(c);
    }
    return out;
}

inline std::string groups(const std::string& s, size_t n) {
    std::string out;
    for (size_t i = 0; i < s.size(); ++i) {
        if (i && i % n == 0) out.push_back('-');
        out.push_back(s[i]);
    }
    return out;
}

inline std::string formatHwid(const uint8_t hw[HWID_BYTES]) { return groups(b32encode(hw, HWID_BYTES), 4); }

inline bool parseHwid(const std::string& text, uint8_t hw[HWID_BYTES]) {
    const std::string n = normalize(text);
    if (n.size() != HWID_CHARS) return false;
    std::vector<uint8_t> raw;
    if (!b32decode(n, raw) || raw.size() != HWID_BYTES) return false;
    for (size_t i = 0; i < HWID_BYTES; ++i) hw[i] = raw[i];
    return true;
}

inline std::string formatKey(const uint8_t key[KEY_BYTES]) { return groups(b32encode(key, KEY_BYTES), 5); }

inline bool parseKey(const std::string& text, uint8_t key[KEY_BYTES]) {
    const std::string n = normalize(text);
    if (n.size() != KEY_CHARS) return false;
    std::vector<uint8_t> raw;
    if (!b32decode(n, raw) || raw.size() != KEY_BYTES) return false;
    for (size_t i = 0; i < KEY_BYTES; ++i) key[i] = raw[i];
    return true;
}

}}  // namespace blaster::lic
