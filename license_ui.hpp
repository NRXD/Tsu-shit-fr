#pragma once
// Start-up activation window + time-limit watcher for Blaster.
//  * Shows this PC's code. The owner turns that code (plus a time length) into a key with BlasterKeyGen.
//  * A key only works on the PC whose code it was made for.
//  * A key lasts for the time it was made for, counted from the moment it is activated (or forever).
//  * Offline only. Nothing here touches the network.
#include "license_core.hpp"
#include "license_pubkey.inc"
#include <objidl.h>
#include <gdiplus.h>
#include <shlwapi.h>
#include <wincrypt.h>
#include <atomic>
#include <cstdio>
#include <thread>

#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")

namespace blaster {
namespace licui {

enum { ID_COPY = 101, ID_ACT = 102, ID_KEY = 103, ID_HWID = 104, ID_QUIT = 106 };
enum Verdict { V_OK, V_NOKEY, V_EXPIRED, V_USED, V_CLOCK };

// ---------------- time record (kept in %APPDATA%\Blaster\license.dat and HKCU, encrypted per user + per PC) ----------------
#pragma pack(push, 1)
struct Rec {
    uint32_t magic = 0x31534C42;          // "BLS1"
    uint64_t start = 0, last = 0;         // seconds (Windows FILETIME epoch)
    uint8_t active[lic::SERIAL_BYTES] = {0};
    uint8_t nUsed = 0;
    uint8_t used[16][lic::SERIAL_BYTES] = {{0}};
};
#pragma pack(pop)

inline uint64_t nowSec() {
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    return (((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime) / 10000000ull;
}

inline std::wstring appFolder() {
    wchar_t app[MAX_PATH] = {0};
    const DWORD n = GetEnvironmentVariableW(L"APPDATA", app, MAX_PATH);
    if (!n || n >= MAX_PATH) return L"";
    const std::wstring dir = std::wstring(app) + L"\\Blaster";
    CreateDirectoryW(dir.c_str(), nullptr);
    return dir;
}

inline bool readFileAll(const std::wstring& p, std::vector<uint8_t>& out) {
    out.clear();
    if (p.empty()) return false;
    FILE* f = _wfopen(p.c_str(), L"rb");
    if (!f) return false;
    uint8_t b[1024];
    size_t n;
    while ((n = fread(b, 1, sizeof b, f)) > 0 && out.size() < 8192) out.insert(out.end(), b, b + n);
    fclose(f);
    return true;
}
inline bool writeFileAll(const std::wstring& p, const void* d, size_t n) {
    if (p.empty()) return false;
    FILE* f = _wfopen(p.c_str(), L"wb");
    if (!f) return false;
    const bool ok = fwrite(d, 1, n, f) == n;
    fclose(f);
    return ok;
}

inline bool sealRec(const Rec& r, const uint8_t hw[lic::HWID_BYTES], std::vector<uint8_t>& out) {
    DATA_BLOB in{(DWORD)sizeof r, (BYTE*)&r}, ent{(DWORD)lic::HWID_BYTES, (BYTE*)hw}, o{};
    if (!CryptProtectData(&in, L"Blaster", &ent, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &o)) return false;
    out.assign(o.pbData, o.pbData + o.cbData);
    LocalFree(o.pbData);
    return true;
}
inline bool openRec(const std::vector<uint8_t>& in, const uint8_t hw[lic::HWID_BYTES], Rec& r) {
    if (in.empty()) return false;
    DATA_BLOB b{(DWORD)in.size(), (BYTE*)in.data()}, ent{(DWORD)lic::HWID_BYTES, (BYTE*)hw}, o{};
    if (!CryptUnprotectData(&b, nullptr, &ent, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &o)) return false;
    const bool ok = o.cbData == sizeof(Rec);
    if (ok) memcpy(&r, o.pbData, sizeof r);
    LocalFree(o.pbData);
    return ok && r.magic == 0x31534C42 && r.nUsed <= 16;
}

inline bool loadRec(const uint8_t hw[lic::HWID_BYTES], Rec& r) {
    Rec a, b;
    std::vector<uint8_t> f, g;
    bool hasA = readFileAll(appFolder() + L"\\license.dat", f) && openRec(f, hw, a);
    bool hasB = false;
    HKEY k = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Blaster", 0, KEY_QUERY_VALUE, &k) == ERROR_SUCCESS) {
        uint8_t buf[1024];
        DWORD cb = sizeof buf, type = 0;
        if (RegQueryValueExW(k, L"lic", nullptr, &type, buf, &cb) == ERROR_SUCCESS && type == REG_BINARY) {
            g.assign(buf, buf + cb);
            hasB = openRec(g, hw, b);
        }
        RegCloseKey(k);
    }
    if (!hasA && !hasB) return false;
    if (hasA && hasB) {   // if the two copies disagree, believe the one that has seen more time pass
        r = (a.last >= b.last) ? a : b;
        if (a.start && b.start && a.start < r.start && memcmp(a.active, b.active, lic::SERIAL_BYTES) == 0) r.start = a.start;
    } else r = hasA ? a : b;
    return true;
}

inline void saveRec(const uint8_t hw[lic::HWID_BYTES], const Rec& r) {
    std::vector<uint8_t> blob;
    if (!sealRec(r, hw, blob)) return;
    writeFileAll(appFolder() + L"\\license.dat", blob.data(), blob.size());
    HKEY k = nullptr;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Blaster", 0, nullptr, 0, KEY_SET_VALUE, nullptr, &k, nullptr) == ERROR_SUCCESS) {
        RegSetValueExW(k, L"lic", 0, REG_BINARY, blob.data(), (DWORD)blob.size());
        RegCloseKey(k);
    }
}

inline std::wstring licenseFile() {
    const std::wstring d = appFolder();
    return d.empty() ? L"" : d + L"\\license.key";
}
inline std::string readSaved() {
    std::vector<uint8_t> v;
    if (!readFileAll(licenseFile(), v)) return "";
    return std::string(v.begin(), v.end());
}
inline bool writeSaved(const std::string& key) { return writeFileAll(licenseFile(), key.data(), key.size()); }

// Checks a key for THIS PC and (when commit is true) starts / refreshes its time record.
inline Verdict evaluate(const std::string& key, const uint8_t hw[lic::HWID_BYTES], bool commit, lic::Term* termOut, uint64_t* leftOut) {
    lic::Term t;
    if (!lic::verifyKey(key, hw, BLASTER_LICENSE_PUBKEY, &t)) return V_NOKEY;
    if (termOut) *termOut = t;
    if (t.unit == lic::U_LIFETIME) { if (leftOut) *leftOut = 0; return V_OK; }
    const uint64_t now = nowSec(), len = t.seconds();
    Rec r;
    const bool have = loadRec(hw, r);
    const bool sameKey = have && memcmp(r.active, t.serial, lic::SERIAL_BYTES) == 0;
    if (have && !sameKey) {
        for (int i = 0; i < r.nUsed; ++i)
            if (memcmp(r.used[i], t.serial, lic::SERIAL_BYTES) == 0) return V_USED;   // an old key can't be reused
    }
    if (have && now + 300 < r.last) return V_CLOCK;                                  // clock moved back
    if (!sameKey) {                                                                  // new key: its time starts now
        if (have && r.nUsed < 16) { memcpy(r.used[r.nUsed++], r.active, lic::SERIAL_BYTES); }
        r.start = now;
        memcpy(r.active, t.serial, lic::SERIAL_BYTES);
    }
    if (now > r.last) r.last = now;
    if (now >= r.start + len) { if (commit) saveRec(hw, r); return V_EXPIRED; }
    if (leftOut) *leftOut = r.start + len - now;
    if (commit) saveRec(hw, r);
    return V_OK;
}

inline std::wstring human(const lic::Term& t, uint64_t left) {
    if (t.unit == lic::U_LIFETIME) return L"lifetime";
    uint64_t v = left;
    const wchar_t* u = L"seconds";
    if (v >= 86400ull * 365) { v /= 86400ull * 365; u = L"years"; }
    else if (v >= 86400ull * 30) { v /= 86400ull * 30; u = L"months"; }
    else if (v >= 86400) { v /= 86400; u = L"days"; }
    else if (v >= 3600) { v /= 3600; u = L"hours"; }
    else if (v >= 60) { v /= 60; u = L"minutes"; }
    wchar_t b[64];
    swprintf_s(b, 64, L"%llu %ls left", (unsigned long long)v, u);
    return b;
}

// ---------------- window ----------------
struct State {
    HWND win = nullptr, hwidEdit = nullptr, keyEdit = nullptr;
    bool ok = false, done = false;
    int dpi = 96;
    HFONT font = nullptr;
    uint8_t hw[lic::HWID_BYTES] = {0};
    std::wstring hwidText, status;
    Gdiplus::Bitmap* bg = nullptr;   // pre-scaled to the window
};
inline State& S() { static State s; return s; }
inline int px(int v) { return MulDiv(v, S().dpi, 96); }

// layout in 560 x 560 design units
static const int WIN_W = 560, PANEL_X = 236, PANEL_Y = 296, PANEL_W = 312, PANEL_H = 242;

inline void copyToClipboard(HWND owner, const std::wstring& text) {
    if (!OpenClipboard(owner)) return;
    EmptyClipboard();
    const size_t bytes = (text.size() + 1) * sizeof(wchar_t);
    HGLOBAL mem = GlobalAlloc(GMEM_MOVEABLE, bytes);
    if (mem) {
        void* p = GlobalLock(mem);
        if (p) { memcpy(p, text.c_str(), bytes); GlobalUnlock(mem); if (!SetClipboardData(CF_UNICODETEXT, mem)) GlobalFree(mem); }
        else GlobalFree(mem);
    }
    CloseClipboard();
}

inline std::string narrowAscii(const std::wstring& w) {
    std::string s;
    for (wchar_t c : w) if (c < 128) s.push_back((char)c);
    return s;
}

inline HWND child(HWND parent, const wchar_t* cls, const wchar_t* text, DWORD style, int x, int y, int w, int h, int id) {
    HWND c = CreateWindowExW(0, cls, text, WS_CHILD | WS_VISIBLE | style, px(x), px(y), px(w), px(h), parent,
                             (HMENU)(INT_PTR)id, GetModuleHandleW(nullptr), nullptr);
    if (c && S().font) SendMessageW(c, WM_SETFONT, (WPARAM)S().font, TRUE);
    return c;
}

inline void paint(HWND h) {
    State& s = S();
    PAINTSTRUCT ps;
    HDC hdc = BeginPaint(h, &ps);
    RECT rc;
    GetClientRect(h, &rc);
    const int W = rc.right, H = rc.bottom;
    Gdiplus::Bitmap buf(W, H, PixelFormat32bppARGB);
    {
        Gdiplus::Graphics g(&buf);
        g.SetSmoothingMode(Gdiplus::SmoothingModeAntiAlias);
        g.SetTextRenderingHint(Gdiplus::TextRenderingHintAntiAliasGridFit);
        if (s.bg) g.DrawImage(s.bg, 0, 0, W, H);
        else { Gdiplus::SolidBrush dark(Gdiplus::Color(255, 24, 26, 34)); g.FillRectangle(&dark, 0, 0, W, H); }

        Gdiplus::FontFamily fam(L"Segoe UI");
        Gdiplus::Font big(&fam, (Gdiplus::REAL)px(34), Gdiplus::FontStyleBold, Gdiplus::UnitPixel);
        Gdiplus::Font mid(&fam, (Gdiplus::REAL)px(15), Gdiplus::FontStyleRegular, Gdiplus::UnitPixel);
        Gdiplus::Font bold(&fam, (Gdiplus::REAL)px(14), Gdiplus::FontStyleBold, Gdiplus::UnitPixel);
        Gdiplus::Font small(&fam, (Gdiplus::REAL)px(12), Gdiplus::FontStyleRegular, Gdiplus::UnitPixel);
        Gdiplus::SolidBrush white(Gdiplus::Color(255, 255, 255, 255)), soft(Gdiplus::Color(255, 205, 210, 225)),
            shadow(Gdiplus::Color(150, 0, 0, 0)), warn(Gdiplus::Color(255, 255, 196, 120));
        auto text = [&](const wchar_t* t, const Gdiplus::Font& f, const Gdiplus::Brush& b, int x, int y, int w = 0, int hgt = 0) {
            Gdiplus::RectF r((Gdiplus::REAL)px(x), (Gdiplus::REAL)px(y), (Gdiplus::REAL)px(w ? w : 400), (Gdiplus::REAL)px(hgt ? hgt : 40));
            Gdiplus::StringFormat sf;
            g.DrawString(t, -1, &f, r, &sf, &b);
        };
        text(L"BLASTER", big, shadow, 22, 20);
        text(L"BLASTER", big, white, 20, 18);
        text(L"Activation", mid, shadow, 24, 62);
        text(L"Activation", mid, soft, 22, 60);

        Gdiplus::SolidBrush panel(Gdiplus::Color(185, 12, 14, 20));
        Gdiplus::Pen edge(Gdiplus::Color(110, 255, 255, 255), 1.0f);
        const int r = px(10), x = px(PANEL_X), y = px(PANEL_Y), w = px(PANEL_W), hh = px(PANEL_H);
        Gdiplus::GraphicsPath gp;
        gp.AddArc(x, y, r * 2, r * 2, 180, 90);
        gp.AddArc(x + w - r * 2, y, r * 2, r * 2, 270, 90);
        gp.AddArc(x + w - r * 2, y + hh - r * 2, r * 2, r * 2, 0, 90);
        gp.AddArc(x, y + hh - r * 2, r * 2, r * 2, 90, 90);
        gp.CloseFigure();
        g.FillPath(&panel, &gp);
        g.DrawPath(&edge, &gp);

        text(L"1.  Send this code to the seller", bold, white, PANEL_X + 12, PANEL_Y + 8, PANEL_W - 24, 20);
        text(L"2.  Paste the key you get back", bold, white, PANEL_X + 12, PANEL_Y + 66, PANEL_W - 24, 20);
        text(s.status.c_str(), small, warn, PANEL_X + 12, PANEL_Y + 158, PANEL_W - 24, 34);
    }
    Gdiplus::Graphics out(hdc);
    out.DrawImage(&buf, 0, 0, W, H);
    EndPaint(h, &ps);
}

inline LRESULT CALLBACK proc(HWND h, UINT m, WPARAM w, LPARAM l) {
    State& s = S();
    switch (m) {
    case WM_CREATE: {
        s.win = h;
        s.hwidEdit = child(h, L"EDIT", s.hwidText.c_str(), ES_READONLY | ES_CENTER | WS_BORDER | WS_TABSTOP,
                           PANEL_X + 12, PANEL_Y + 30, 190, 26, ID_HWID);
        child(h, L"BUTTON", L"Copy code", BS_PUSHBUTTON | WS_TABSTOP, PANEL_X + 210, PANEL_Y + 29, 90, 28, ID_COPY);
        s.keyEdit = child(h, L"EDIT", L"", ES_MULTILINE | ES_AUTOVSCROLL | WS_VSCROLL | WS_BORDER | WS_TABSTOP,
                          PANEL_X + 12, PANEL_Y + 88, PANEL_W - 24, 64, ID_KEY);
        child(h, L"BUTTON", L"Activate", BS_DEFPUSHBUTTON | WS_TABSTOP, PANEL_X + 12, PANEL_Y + 200, 140, 30, ID_ACT);
        child(h, L"BUTTON", L"Quit", BS_PUSHBUTTON | WS_TABSTOP, PANEL_X + 160, PANEL_Y + 200, 140, 30, ID_QUIT);
        return 0;
    }
    case WM_ERASEBKGND: return 1;
    case WM_PAINT: paint(h); return 0;
    case WM_COMMAND:
        switch (LOWORD(w)) {
        case ID_COPY:
            copyToClipboard(h, s.hwidText);
            s.status = L"Code copied.";
            InvalidateRect(h, nullptr, FALSE);
            return 0;
        case ID_QUIT: DestroyWindow(h); return 0;
        case ID_ACT: {
            wchar_t buf[1024] = {0};
            GetWindowTextW(s.keyEdit, buf, 1023);
            const std::string key = lic::groups(lic::normalize(narrowAscii(buf)), 5);
            lic::Term t;
            uint64_t left = 0;
            const Verdict v = evaluate(key, s.hw, true, &t, &left);
            if (v == V_OK) {
                writeSaved(key);
                s.ok = true;
                const std::wstring msg = L"Blaster is activated: " + human(t, left) + L".";
                MessageBoxW(h, msg.c_str(), L"Blaster", MB_OK | MB_ICONINFORMATION);
                DestroyWindow(h);
                return 0;
            }
            s.status = v == V_EXPIRED ? L"That key's time has run out. Ask for a new one."
                     : v == V_USED    ? L"That key was already used up. Ask for a new one."
                     : v == V_CLOCK   ? L"Your PC clock was moved back. Fix the date and time, then try again."
                                      : L"That key is not valid for this PC. Check it and try again.";
            InvalidateRect(h, nullptr, FALSE);
            return 0;
        }
        }
        break;
    case WM_CLOSE: DestroyWindow(h); return 0;
    case WM_DESTROY: s.done = true; PostQuitMessage(0); return 0;
    }
    return DefWindowProcW(h, m, w, l);
}

inline Gdiplus::Bitmap* loadBackground(HINSTANCE hi, int W, int H) {
    HRSRC r = FindResourceW(hi, MAKEINTRESOURCEW(203), RT_RCDATA);
    if (!r) return nullptr;
    HGLOBAL g = LoadResource(hi, r);
    const void* p = g ? LockResource(g) : nullptr;
    const DWORD n = SizeofResource(hi, r);
    if (!p || !n) return nullptr;
    IStream* st = SHCreateMemStream((const BYTE*)p, n);
    if (!st) return nullptr;
    Gdiplus::Bitmap* src = Gdiplus::Bitmap::FromStream(st);
    Gdiplus::Bitmap* out = nullptr;
    if (src && src->GetLastStatus() == Gdiplus::Ok) {
        out = new Gdiplus::Bitmap(W, H, PixelFormat32bppARGB);
        Gdiplus::Graphics g2(out);
        g2.SetInterpolationMode(Gdiplus::InterpolationModeHighQualityBicubic);
        g2.DrawImage(src, 0, 0, W, H);
    }
    delete src;
    st->Release();
    return out;
}

}  // namespace licui

inline bool& licenseTimed() { static bool t = false; return t; }
inline uint64_t& licenseEnd() { static uint64_t e = 0; return e; }   // 0 = lifetime
inline std::atomic<bool>& licensePaused() { static std::atomic<bool> p{false}; return p; }
inline uint8_t* licenseHw() { static uint8_t hw[lic::HWID_BYTES]; return hw; }
inline std::string& licenseKey() { static std::string k; return k; }

// Returns true when this PC holds a valid key (asks for one if not). Fails closed.
inline bool licenseGate(HINSTANCE hi) {
#if !BLASTER_LICENSE_PUBKEY_SET
    MessageBoxW(nullptr,
                L"This build of Blaster has no license key installed, so it cannot start.\n\n"
                L"Run BlasterKeyGen once, copy the license_pubkey.inc it creates into src\\license, and rebuild.",
                L"Blaster", MB_OK | MB_ICONERROR);
    return false;
#else
    licui::State& s = licui::S();
    s.done = false;
    s.ok = false;
    s.status.clear();
    if (!lic::hwidRaw(s.hw)) {
        MessageBoxW(nullptr, L"Could not read this PC's hardware code.", L"Blaster", MB_OK | MB_ICONERROR);
        return false;
    }
    memcpy(licenseHw(), s.hw, lic::HWID_BYTES);

    const std::string saved = licui::readSaved();
    if (!saved.empty()) {
        lic::Term t;
        uint64_t left = 0;
        const licui::Verdict v = licui::evaluate(saved, s.hw, true, &t, &left);
        if (v == licui::V_OK) {
            licenseKey() = saved;
            licenseTimed() = t.unit != lic::U_LIFETIME;
            licenseEnd() = licenseTimed() ? licui::nowSec() + left : 0;
            return true;
        }
        s.status = v == licui::V_EXPIRED ? L"Your time has run out. Paste a new key below."
                 : v == licui::V_CLOCK   ? L"Your PC clock was moved back. Fix the date and time, then restart."
                                         : L"";
    }

    const std::string hwidAscii = lic::formatHwid(s.hw);
    s.hwidText = std::wstring(hwidAscii.begin(), hwidAscii.end());
    HDC dc = GetDC(nullptr);
    s.dpi = dc ? GetDeviceCaps(dc, LOGPIXELSX) : 96;
    if (dc) ReleaseDC(nullptr, dc);

    ULONG_PTR gdiTok = 0;
    Gdiplus::GdiplusStartupInput gin;
    const bool gdi = Gdiplus::GdiplusStartup(&gdiTok, &gin, nullptr) == Gdiplus::Ok;
    const int WH = licui::px(licui::WIN_W);
    if (gdi) s.bg = licui::loadBackground(hi, WH, WH);

    s.font = CreateFontW(-MulDiv(9, s.dpi, 72), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                         CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");

    WNDCLASSW wc{};
    wc.lpfnWndProc = licui::proc;
    wc.hInstance = hi;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hIcon = LoadIconW(hi, MAKEINTRESOURCEW(1));
    wc.lpszClassName = L"BlasterActivate";
    RegisterClassW(&wc);

    RECT rc = {0, 0, WH, WH};
    const DWORD style = WS_CAPTION | WS_SYSMENU | WS_POPUP;
    AdjustWindowRectEx(&rc, style, FALSE, WS_EX_DLGMODALFRAME);
    const int w = rc.right - rc.left, h = rc.bottom - rc.top;
    const int x = (GetSystemMetrics(SM_CXSCREEN) - w) / 2, y = (GetSystemMetrics(SM_CYSCREEN) - h) / 3;
    HWND win = CreateWindowExW(WS_EX_DLGMODALFRAME | WS_EX_TOPMOST, L"BlasterActivate", L"Blaster - Activation", style,
                               x, y, w, h, nullptr, nullptr, hi, nullptr);
    bool shown = win != nullptr;
    if (shown) {
        ShowWindow(win, SW_SHOW);
        SetForegroundWindow(win);
        MSG msg;
        while (!s.done && GetMessageW(&msg, nullptr, 0, 0) > 0) {
            if (msg.message == WM_KEYDOWN && msg.wParam == 'A' && (GetKeyState(VK_CONTROL) & 0x8000)) {
                const HWND f = GetFocus();
                if (f == s.keyEdit || f == s.hwidEdit) { SendMessageW(f, EM_SETSEL, 0, -1); continue; }
            }
            if (!IsDialogMessageW(win, &msg)) { TranslateMessage(&msg); DispatchMessageW(&msg); }
        }
    }
    if (s.font) { DeleteObject(s.font); s.font = nullptr; }
    delete s.bg;
    s.bg = nullptr;
    if (gdi) Gdiplus::GdiplusShutdown(gdiTok);

    if (s.ok) {
        licenseKey() = licui::readSaved();
        lic::Term t;
        uint64_t left = 0;
        licui::evaluate(licenseKey(), s.hw, false, &t, &left);
        licenseTimed() = t.unit != lic::U_LIFETIME;
        licenseEnd() = licenseTimed() ? licui::nowSec() + left : 0;
    }
    return s.ok;
#endif
}

// Text for the footer: "Lifetime" or the time left ("29d 4h left").
inline std::wstring licenseLabel() {
    if (licenseKey().empty()) return L"";
    if (!licenseTimed()) return L"Lifetime";
    const uint64_t now = licui::nowSec(), e = licenseEnd();
    if (now >= e) return L"Expired";
    const unsigned long long v = e - now, d = v / 86400, h = (v % 86400) / 3600, m = (v % 3600) / 60, sec = v % 60;
    wchar_t b[48];
    if (d) swprintf_s(b, 48, L"%llud %lluh left", d, h);
    else if (h) swprintf_s(b, 48, L"%lluh %llum left", h, m);
    else if (m) swprintf_s(b, 48, L"%llum %llus left", m, sec);
    else swprintf_s(b, 48, L"%llus left", sec);
    return b;
}

// Call once after licenseGate() returned true. For timed keys it closes Blaster when the time is up.
inline void licenseWatch() {
#if BLASTER_LICENSE_PUBKEY_SET
    static bool started = false;
    if (started) return;
    started = true;
    std::thread([] {
        lic::Term t;
        uint64_t left = 0;
        int tick = 0;
        for (;;) {
            Sleep(1000);
            if (licensePaused().load() || !licenseTimed() || licenseKey().empty()) continue;
            const licui::Verdict v = licui::evaluate(licenseKey(), licenseHw(), (++tick % 30) == 0, &t, &left);
            if (v == licui::V_OK) continue;
            MessageBoxW(nullptr,
                        v == licui::V_CLOCK ? L"Your PC clock was moved back, so Blaster is closing. Fix the date and time, then start it again."
                                            : L"Your Blaster time has run out. Start Blaster again and enter a new key.",
                        L"Blaster", MB_OK | MB_ICONINFORMATION | MB_TOPMOST | MB_SETFOREGROUND);
            ExitProcess(0);
        }
    }).detach();
#endif
}

// Sign out: deletes the saved key from this PC (lifetime keys too) and shows the activation window again.
// The time record of a timed key is kept on purpose, so logging out can't be used to restart a key's time.
// Returns true if a valid key was entered again, false if the person closed the activator.
inline bool licenseLogout(HINSTANCE hi) {
    licensePaused() = true;
    DeleteFileW(licui::licenseFile().c_str());
    licenseKey().clear();
    licenseTimed() = false;
    const bool ok = licenseGate(hi);
    licensePaused() = false;
    return ok;
}

}  // namespace blaster
