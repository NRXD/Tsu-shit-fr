#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <string>
#include <cwctype>
#include <cstdio>
#include <functional>
#include <mutex>
#include <vector>

#pragma comment(lib, "bcrypt.lib")

namespace clip {

inline bool isWebPage(const std::wstring& u) {
    std::wstring l = u;
    for (auto& c : l) c = (wchar_t)towlower(c);
    if (l.compare(0, 7, L"http://") != 0 && l.compare(0, 8, L"https://") != 0) return false;
    size_t q = l.find_first_of(L"?#");
    std::wstring path = q == std::wstring::npos ? l : l.substr(0, q);
    static const wchar_t* media[] = {L".mp3", L".m4a", L".aac", L".wav", L".wma", L".flac", L".ogg", L".opus", L".mp4", L".webm", L".m4b", L".aif", L".aiff"};
    for (const wchar_t* e : media) {
        size_t n = wcslen(e);
        if (path.size() > n && path.compare(path.size() - n, n, e) == 0) return false;
    }
    return true;
}
static const wchar_t* const NO_MEDIA = L"Windows is missing its Media Feature Pack, install it to play sounds";

inline bool mediaReady() {
    static const bool ok = [] {
        wchar_t dir[MAX_PATH] = {0};
        const UINT n = GetSystemDirectoryW(dir, MAX_PATH);
        if (!n || n >= MAX_PATH) return false;
        const std::wstring base(dir);
        return LoadLibraryW((base + L"\\mfplat.dll").c_str()) != nullptr && LoadLibraryW((base + L"\\mfreadwrite.dll").c_str()) != nullptr;
    }();
    return ok;
}

inline long long fileSize(const std::wstring& p) {
    WIN32_FILE_ATTRIBUTE_DATA a{};
    if (!GetFileAttributesExW(p.c_str(), GetFileExInfoStandard, &a)) return -1;
    return ((long long)a.nFileSizeHigh << 32) | a.nFileSizeLow;
}
inline std::wstring widen(const std::string& s) {
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    std::wstring w(n > 0 ? n - 1 : 0, L'\0');
    if (n > 0) MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &w[0], n);
    return w;
}
inline std::string narrow(const std::wstring& w) {
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string s(n > 0 ? n - 1 : 0, '\0');
    if (n > 0) WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, &s[0], n, nullptr, nullptr);
    return s;
}

inline void logLine(const std::wstring&) {}

// ---- optional link playing: uses the OFFICIAL yt-dlp.exe that YOU put in the tools folder ----
// Blaster never downloads or updates it. Before every run it hashes yt-dlp.exe and requires the hash to
// be listed for "yt-dlp.exe" in the official SHA2-256SUMS file sitting next to it.
inline std::wstring toolsDir() {
    wchar_t app[MAX_PATH] = {0};
    const DWORD n = GetEnvironmentVariableW(L"APPDATA", app, MAX_PATH);
    std::wstring base = (n && n < MAX_PATH) ? std::wstring(app) : L"C:\\Users\\Public";
    CreateDirectoryW((base + L"\\Blaster").c_str(), nullptr);
    const std::wstring d = base + L"\\Blaster\\tools";
    CreateDirectoryW(d.c_str(), nullptr);
    return d;
}
inline std::wstring workDir() {
    const std::wstring d = toolsDir() + L"\\work";
    CreateDirectoryW(d.c_str(), nullptr);
    return d;
}
inline std::wstring ytdlpPath() { return toolsDir() + L"\\yt-dlp.exe"; }
inline std::wstring sumsPath() { return toolsDir() + L"\\SHA2-256SUMS"; }

static const wchar_t* const HELPER_MISSING =
    L"Link playing needs the official yt-dlp.exe and SHA2-256SUMS. See the Blaster README.";
static const wchar_t* const HELPER_BAD = L"yt-dlp.exe does not match SHA2-256SUMS, so it was not run.";

inline bool sha256Handle(HANDLE h, std::string& hex) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hh = nullptr;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0))) return false;
    bool ok = false;
    if (BCRYPT_SUCCESS(BCryptCreateHash(alg, &hh, nullptr, 0, nullptr, 0, 0))) {
        std::vector<unsigned char> buf(1 << 16);
        LARGE_INTEGER zero{};
        SetFilePointerEx(h, zero, nullptr, FILE_BEGIN);
        DWORD got = 0;
        ok = true;
        while (ReadFile(h, buf.data(), (DWORD)buf.size(), &got, nullptr) && got) {
            if (!BCRYPT_SUCCESS(BCryptHashData(hh, buf.data(), got, 0))) { ok = false; break; }
        }
        unsigned char dig[32];
        if (ok && BCRYPT_SUCCESS(BCryptFinishHash(hh, dig, 32, 0))) {
            static const char X[] = "0123456789abcdef";
            hex.clear();
            for (int i = 0; i < 32; ++i) { hex.push_back(X[dig[i] >> 4]); hex.push_back(X[dig[i] & 15]); }
        } else ok = false;
        BCryptDestroyHash(hh);
    }
    BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

// Is `hex` listed for "yt-dlp.exe" in the sums file?  (GNU style:  <hash>  <name>  or  <hash> *<name>)
inline bool sumsListHash(const std::wstring& sumsFile, const std::string& hex) {
    FILE* f = _wfopen(sumsFile.c_str(), L"rb");
    if (!f) return false;
    std::string all;
    char b[4096];
    size_t n;
    while ((n = fread(b, 1, sizeof b, f)) > 0 && all.size() < (1u << 20)) all.append(b, n);
    fclose(f);
    size_t p = 0;
    while (p < all.size()) {
        size_t e = all.find('\n', p);
        if (e == std::string::npos) e = all.size();
        std::string ln = all.substr(p, e - p);
        p = e + 1;
        while (!ln.empty() && (ln.back() == '\r' || ln.back() == ' ')) ln.pop_back();
        if (ln.size() < 66) continue;
        std::string h = ln.substr(0, 64);
        size_t q = 64;
        while (q < ln.size() && (ln[q] == ' ' || ln[q] == '*' || ln[q] == '\t')) ++q;
        if (ln.substr(q) != "yt-dlp.exe") continue;
        for (auto& c : h) if (c >= 'A' && c <= 'F') c = (char)(c - 'A' + 'a');
        if (h == hex) return true;
    }
    return false;
}

// Verifies yt-dlp.exe. If `held` is given, the verified file stays open with writes/deletes by anyone else
// blocked, so it cannot be swapped between the check and the launch. Caller closes it.
inline bool helperCheck(HANDLE* held, std::wstring& why) {
    const std::wstring exe = ytdlpPath();
    HANDLE h = CreateFileW(exe.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE || GetFileAttributesW(sumsPath().c_str()) == INVALID_FILE_ATTRIBUTES) {
        if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
        why = HELPER_MISSING;
        return false;
    }
    LARGE_INTEGER sz{};
    char mz[2] = {0, 0};
    DWORD got = 0;
    bool ok = GetFileSizeEx(h, &sz) && sz.QuadPart >= 4000000 && ReadFile(h, mz, 2, &got, nullptr) && got == 2 && mz[0] == 'M' && mz[1] == 'Z';
    std::string hex;
    ok = ok && sha256Handle(h, hex) && sumsListHash(sumsPath(), hex);
    if (!ok) { CloseHandle(h); why = HELPER_BAD; return false; }
    if (held) *held = h; else CloseHandle(h);
    return true;
}

static const wchar_t* const FETCH_FORMATS[3] = {
    L"bestaudio[ext=m4a][protocol!*=m3u8]/bestaudio[ext=mp3][protocol!*=m3u8]/bestaudio[acodec^=mp4a][protocol!*=m3u8]/bestaudio[acodec=mp3][protocol!*=m3u8]",
    L"bestaudio[ext=webm][protocol!*=m3u8]/bestaudio[acodec=opus][protocol!*=m3u8]/bestaudio[protocol!*=m3u8]",
    L"bestaudio/best",
};

}
