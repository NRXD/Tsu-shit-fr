#pragma once
// Blaster license core (Windows). Uses only CNG (bcrypt.dll), which ships with Windows.
// Nothing here talks to the network. Scheme:
//   * The app computes a hardware code (HWID) for this PC.
//   * The owner's key tool signs  SHA-256("BLASTER-LICENSE-V1" | HWID | serial)  with an
//     ECDSA P-256 PRIVATE key that never leaves the owner's PC.
//   * The app only contains the PUBLIC key, so it can check a key but cannot make one.
//   * A key signed for one HWID fails on any other PC.
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#define WIN32_LEAN_AND_MEAN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>
#include <cstring>
#include <string>
#include <vector>
#include "license_codec.hpp"

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "advapi32.lib")

namespace blaster { namespace lic {

inline std::wstring regString(HKEY root, const wchar_t* sub, const wchar_t* val, REGSAM wow) {
    HKEY k = nullptr;
    if (RegOpenKeyExW(root, sub, 0, KEY_QUERY_VALUE | wow, &k) != ERROR_SUCCESS) return L"";
    wchar_t buf[512] = {0};
    DWORD cb = sizeof buf - sizeof(wchar_t), type = 0;
    const LONG r = RegQueryValueExW(k, val, nullptr, &type, (BYTE*)buf, &cb);
    RegCloseKey(k);
    if (r != ERROR_SUCCESS || type != REG_SZ) return L"";
    buf[cb / sizeof(wchar_t)] = 0;
    return buf;
}

inline bool sha256(const uint8_t* d, size_t n, uint8_t out[32]) {
    return BCRYPT_SUCCESS(BCryptHash(BCRYPT_SHA256_ALG_HANDLE, nullptr, 0, (PUCHAR)d, (ULONG)n, out, 32));
}

// Stable per-PC code: Windows machine GUID + CPU name + system volume serial, hashed.
inline bool hwidRaw(uint8_t out[HWID_BYTES]) {
    std::wstring s = L"BLASTER-HWID-V1|";
    const std::wstring guid = regString(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", L"MachineGuid", KEY_WOW64_64KEY);
    if (guid.empty()) return false;
    s += guid;
    s += L"|";
    s += regString(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", L"ProcessorNameString", 0);
    s += L"|";
    wchar_t win[MAX_PATH] = {0};
    if (GetWindowsDirectoryW(win, MAX_PATH) >= 3) {
        wchar_t root[4] = {win[0], L':', L'\\', 0};
        DWORD serial = 0;
        if (GetVolumeInformationW(root, nullptr, 0, &serial, nullptr, nullptr, nullptr, 0)) {
            wchar_t t[16];
            wsprintfW(t, L"%08lX", (unsigned long)serial);
            s += t;
        }
    }
    const int n = WideCharToMultiByte(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0, nullptr, nullptr);
    if (n <= 0) return false;
    std::string u((size_t)n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, s.c_str(), (int)s.size(), &u[0], n, nullptr, nullptr);
    uint8_t h[32];
    if (!sha256((const uint8_t*)u.data(), u.size(), h)) return false;
    memcpy(out, h, HWID_BYTES);
    return true;
}

inline bool licenseDigest(const uint8_t hw[HWID_BYTES], const uint8_t head[HEAD_BYTES], uint8_t out[32]) {
    static const char TAG[] = "BLASTER-LICENSE-V2";
    uint8_t msg[sizeof(TAG) - 1 + HWID_BYTES + HEAD_BYTES];
    memcpy(msg, TAG, sizeof(TAG) - 1);
    memcpy(msg + sizeof(TAG) - 1, hw, HWID_BYTES);
    memcpy(msg + sizeof(TAG) - 1 + HWID_BYTES, head, HEAD_BYTES);
    return sha256(msg, sizeof msg, out);
}

struct Term {
    uint8_t unit = U_LIFETIME;
    uint32_t count = 0;
    uint8_t serial[SERIAL_BYTES] = {0};
    uint64_t seconds() const { return termSeconds(unit, count); }
};

// ---- verify (used by the app: public key only) ----
inline bool verifyKey(const std::string& keyText, const uint8_t hw[HWID_BYTES], const uint8_t pub[64], Term* term = nullptr) {
    uint8_t key[KEY_BYTES];
    if (!parseKey(keyText, key)) return false;
    Term t;
    memcpy(t.serial, key, SERIAL_BYTES);
    t.unit = key[SERIAL_BYTES];
    t.count = ((uint32_t)key[SERIAL_BYTES + 1] << 24) | ((uint32_t)key[SERIAL_BYTES + 2] << 16) |
              ((uint32_t)key[SERIAL_BYTES + 3] << 8) | (uint32_t)key[SERIAL_BYTES + 4];
    if (!termValid(t.unit, t.count)) return false;
    uint8_t digest[32];
    if (!licenseDigest(hw, key, digest)) return false;   // key[0..8] = serial | unit | count

    BCRYPT_ALG_HANDLE alg = nullptr;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_ECDSA_P256_ALGORITHM, nullptr, 0))) return false;
    uint8_t blob[sizeof(BCRYPT_ECCKEY_BLOB) + 64];
    BCRYPT_ECCKEY_BLOB head;
    head.dwMagic = BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
    head.cbKey = 32;
    memcpy(blob, &head, sizeof head);
    memcpy(blob + sizeof head, pub, 64);
    BCRYPT_KEY_HANDLE hk = nullptr;
    bool ok = false;
    if (BCRYPT_SUCCESS(BCryptImportKeyPair(alg, nullptr, BCRYPT_ECCPUBLIC_BLOB, &hk, blob, (ULONG)sizeof blob, 0))) {
        ok = BCRYPT_SUCCESS(BCryptVerifySignature(hk, nullptr, digest, 32, key + HEAD_BYTES, (ULONG)SIG_BYTES, 0));
        BCryptDestroyKey(hk);
    }
    BCryptCloseAlgorithmProvider(alg, 0);
    if (ok && term) *term = t;
    return ok;
}

// ---- signing (used ONLY by the owner's key tool) ----
inline bool generateKeypair(std::vector<uint8_t>& priv, uint8_t pub[64]) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_ECDSA_P256_ALGORITHM, nullptr, 0))) return false;
    BCRYPT_KEY_HANDLE hk = nullptr;
    bool ok = false;
    if (BCRYPT_SUCCESS(BCryptGenerateKeyPair(alg, &hk, 256, 0)) && BCRYPT_SUCCESS(BCryptFinalizeKeyPair(hk, 0))) {
        ULONG cb = 0;
        if (BCRYPT_SUCCESS(BCryptExportKey(hk, nullptr, BCRYPT_ECCPRIVATE_BLOB, nullptr, 0, &cb, 0)) && cb >= sizeof(BCRYPT_ECCKEY_BLOB) + 96) {
            priv.assign(cb, 0);
            if (BCRYPT_SUCCESS(BCryptExportKey(hk, nullptr, BCRYPT_ECCPRIVATE_BLOB, priv.data(), cb, &cb, 0))) {
                memcpy(pub, priv.data() + sizeof(BCRYPT_ECCKEY_BLOB), 64);   // X || Y
                ok = true;
            }
        }
    }
    if (hk) BCryptDestroyKey(hk);
    BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

inline bool publicFromPrivate(const std::vector<uint8_t>& priv, uint8_t pub[64]) {
    if (priv.size() < sizeof(BCRYPT_ECCKEY_BLOB) + 96) return false;
    memcpy(pub, priv.data() + sizeof(BCRYPT_ECCKEY_BLOB), 64);
    return true;
}

inline bool makeKey(const std::vector<uint8_t>& priv, const uint8_t hw[HWID_BYTES], uint8_t unit, uint32_t count,
                    std::string& keyText, std::string* serialHex = nullptr) {
    if (!termValid(unit, count)) return false;
    if (unit == U_LIFETIME) count = 0;
    uint8_t out[KEY_BYTES];
    if (!BCRYPT_SUCCESS(BCryptGenRandom(nullptr, out, (ULONG)SERIAL_BYTES, BCRYPT_USE_SYSTEM_PREFERRED_RNG))) return false;
    out[SERIAL_BYTES] = unit;
    out[SERIAL_BYTES + 1] = (uint8_t)(count >> 24);
    out[SERIAL_BYTES + 2] = (uint8_t)(count >> 16);
    out[SERIAL_BYTES + 3] = (uint8_t)(count >> 8);
    out[SERIAL_BYTES + 4] = (uint8_t)count;
    uint8_t digest[32];
    if (!licenseDigest(hw, out, digest)) return false;

    BCRYPT_ALG_HANDLE alg = nullptr;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_ECDSA_P256_ALGORITHM, nullptr, 0))) return false;
    BCRYPT_KEY_HANDLE hk = nullptr;
    bool ok = false;
    if (BCRYPT_SUCCESS(BCryptImportKeyPair(alg, nullptr, BCRYPT_ECCPRIVATE_BLOB, &hk, (PUCHAR)priv.data(), (ULONG)priv.size(), 0))) {
        ULONG cb = 0;
        if (BCRYPT_SUCCESS(BCryptSignHash(hk, nullptr, digest, 32, out + HEAD_BYTES, (ULONG)SIG_BYTES, &cb, 0)) && cb == SIG_BYTES) {
            keyText = formatKey(out);
            if (serialHex) {
                static const char X[] = "0123456789ABCDEF";
                serialHex->clear();
                for (size_t i = 0; i < SERIAL_BYTES; ++i) { serialHex->push_back(X[out[i] >> 4]); serialHex->push_back(X[out[i] & 15]); }
            }
            ok = true;
        }
        BCryptDestroyKey(hk);
    }
    BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

}}  // namespace blaster::lic
