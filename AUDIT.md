# Audit of OctopusEAX-main.zip (source only)

**Result: no RAT, stealer, keylogger, injector or backdoor found in the source.** Static review of all
82 files: every C++ file, project files, resources, and byte-level checks of the PNG/ICO assets
(no data hidden after the image ends).

## Risky behavior found and REMOVED in Blaster
| # | What it did | Where |
|---|---|---|
| 1 | Downloaded a ZIP from vb-audio.com, unpacked it, then **ran the installer elevated**. Only gate was a weak "signer name contains vb-audio/burel" check. | cable_package.hpp, app.cpp |
| 2 | Downloaded **yt-dlp.exe from GitHub "latest"** into ProgramData and executed it. Only check was that the file starts with `MZ`. Also self-updated it. **Now:** you place the official `yt-dlp.exe` + `SHA2-256SUMS` yourself; Blaster verifies the SHA-256 before every run, locks the file while it runs, and never downloads or updates. | clip_util.hpp, player.hpp |
| 3 | Took **ownership of HKLM audio registry keys** (SeTakeOwnership/SeRestore) to rename a device. | app.cpp |
| 4 | Spawned `schtasks.exe` and `tar.exe` hidden. | app.cpp, cable_package.hpp |
| 5 | Wrote a log (`clip.log`) of every link/path played into ProgramData. | clip_util.hpp |
| 6 | Linked urlmon/wininet (only used by 1-2). | project, app.cpp |

Blaster itself makes **no network requests and downloads nothing**. VB-Cable is installed by you, manually.
The only program it can start is the optional `yt-dlp.exe` that **you** placed in `%APPDATA%\Blaster\tools`, and only if its SHA-256 is listed
in the `SHA2-256SUMS` beside it. Without those two files, web-page links just show a message; local sound files always play.
(yt-dlp itself, once running, talks to the video site; that is its job.)

## Reviewed, normal, kept
- `GetAsyncKeyState` only checks the hotkeys you configure (it does not record keys). `RegisterHotKey` for the same.
- `program_tap.hpp` lists processes/windows only to pick a program whose sound you want on the mic.
- Autostart (HKCU Run key) is only written if you tick "Start with Windows".
- Settings under `HKCU\Software\Blaster` and `%APPDATA%\Blaster`. Scans Desktop/Downloads/Documents
  (3 s, depth-limited) only for its own settings files.
- Manifest runs `asInvoker` (no admin), no post-build steps.

## What this audit can NOT tell you
- The README linked to a prebuilt **build.rar** on GitHub Releases. Your friend's **binary** is not in this zip,
  and a binary can contain things the source does not. Delete it; build from source.
- If you ran that build, treat the PC as possibly compromised: Microsoft Defender Offline scan, check
  Task Scheduler and `HKCU\...\Run`, change important passwords from a different clean device.

## Added after the audit (my code, reviewed)
- `src/license/*` and `tools/keygen/*`: offline license check using Windows CNG (ECDSA P-256) and DPAPI. No network, no outside libraries.
- Images in `res/` are the ones you sent (converted to PNG/ICO/JPG). Nothing else was added to the project.

## Your screenshot of the real build (IMG_3782)
It shows **"Lifetime"** and **"Sign out"** at the bottom right. Neither exists in the source you gave me, so the build in that photo
contains code I never saw (a license system of its own). That is exactly why you should not run it: only a build you make yourself
from this source can be vouched for. Delete `build.rar`, and if you ran it, do the offline scan described above.
