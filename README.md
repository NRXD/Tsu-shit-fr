# Blaster (mixer)

Voice effects for Discord and games on Windows: echo rooms, voice masks, noise isolation, equalizer,
sound clips, soundboard, program-sound tap, recorder, global hotkeys. Windows only.

Default theme is **White**. Theme chips (Look settings): White, Blue, Sky, Teal, Green, Gold, Orange, Red, Pink, Graphite (black).
The figure (logo + About art) changes colour with the theme: black on White, white on Graphite, red on Red, blue on Blue.
A background picture (Look settings) is faded toward white on the White theme and darkened on the dark themes.

Footer (bottom right): `Lifetime` (or time left, e.g. `29d 4h left`)  |  `Sign out`  |  `(c) Blaster`.
**Sign out** deletes the saved key from the PC (lifetime keys too) and goes back to the activation window.
A timed key keeps its remaining time if you sign out and paste the same key again.

## Needs
- Windows 10/11 64-bit, a microphone
- VB-Audio Virtual Cable (free). Blaster does **not** download or install anything. Get it from
  vb-audio.com/Cable yourself, run its installer as administrator, then restart your PC.

## Build it on GitHub (no Visual Studio needed)
1. Make the key generator first (**KeyGenerator-Windows.zip** or **KeyGenerator-Replit.zip**) and create your signing key.
   It gives you a file named `license_pubkey.inc` (public key only, safe to upload).
2. Create a **private** GitHub repository and upload everything inside this folder (the `.github` folder too).
3. Replace `src/license/license_pubkey.inc` with the file from step 1, commit.
4. Open the **Actions** tab > **Build Blaster** > **Run workflow**. When it finishes, open the run and download
   **Artifacts > Blaster**. Inside is `Blaster.exe`. That exe is the only thing you give customers.
   (The build stops with a clear message if the placeholder key file is still there. That is on purpose.)

Build on your own PC instead: Visual Studio 2022 "Desktop development with C++", open `Blaster.sln`, Release x64.
Output: `build\Blaster\Blaster.exe`. If the build shows errors, paste them to me and I'll fix them.

## Selling / activating
1. Customer starts Blaster. The activation window shows a code `XXXX-XXXX-XXXX-XXXX`; they send it to you.
2. In your key generator paste the code, pick the time (seconds, minutes, hours, days, months, years, lifetime) and a number
   (1, 2, 3, 5, 10, 30, 100, 1000 ...), press **Generate key**, send the key back.
3. Customer pastes the key and presses **Activate**. The time starts at that moment and keeps running while Blaster is closed.
   When it ends, Blaster closes and asks for a new key.
- A key made for PC A is rejected on PC B. An old key can't be reused after a newer one was activated.
- Every code + time + number is its own key. You can delete any key (lifetime too) from the generator's list and make a new one.

## Optional: play sound from links (yt-dlp)
Off by default. Blaster **never downloads or updates anything**. To turn it on, get the official files yourself:
1. Open **https://github.com/yt-dlp/yt-dlp/releases/latest** (the official project).
2. Download exactly two files: **`yt-dlp.exe`** and **`SHA2-256SUMS`**.
3. Put both in `%APPDATA%\Blaster\tools`.
4. Best: check the signature as the yt-dlp page describes.
Before every run Blaster hashes `yt-dlp.exe` and refuses to start it unless that hash is listed for `yt-dlp.exe` in `SHA2-256SUMS`.
While it runs the file is locked. It starts with `--ignore-config --no-plugin-dirs --no-update`.

## Pictures
`res\activation_bg.jpg` (activation window background), `res\blaster_art.png` + `blaster_art_ink.png` (the figure for dark / white themes),
`res\blaster.png` + `blaster.ico` (logo, icon). Replace with your own art any time and rebuild.
The figure is Gojo from Jujutsu Kaisen, so it is not yours: if you sell Blaster, use your own art for the version you sell.

## Honest limits
- Fully offline: "one-time redeem" = one key per PC. Counting redemptions across PCs needs a server.
- Time limits are offline too. The start time is stored encrypted in two places and moving the clock back is caught, but someone
  who deletes both records (`%APPDATA%\Blaster\license.dat` and `HKCU\Software\Blaster`) can restart the same key.
- Deleting a key in the generator does not switch it off on a PC that already activated it (nothing is online).
  It stops working when the customer signs out or the time ends.
- Any offline license check can be patched out of an exe by a determined cracker.
- The code changes if the customer reinstalls Windows or swaps hardware; make them a new key.

## License
Original MIT notice kept in `LICENSE` (MIT requires the notice to stay with copies of the original code).
