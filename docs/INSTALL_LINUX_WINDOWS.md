# Install ProxyForge

ProxyForge is a desktop web-security workbench with a packaged headless CLI. Pick your OS below — each Quick Start is 3 steps. Advanced operators and CI users see [Advanced](#advanced).

> **Alpha note.** Binaries in `v0.1.0-alpha.1` are unsigned. Windows SmartScreen and most antivirus tools will warn the publisher is unknown. This is expected for the alpha and goes away once signing certificates are in place. See [Verify your download](#verify-your-download) to confirm authenticity from the SHA-256 sums.

---

## Quick Start — Windows

1. **Download** the installer from the latest release:
   - **Installer (recommended):** `ProxyForge Setup 0.1.0-alpha.1.exe`
   - **Portable (no install):** `ProxyForge 0.1.0-alpha.1.exe`

   https://github.com/the-vibe-dev/proxyforge-public/releases/latest

2. **Run it.** SmartScreen will show *"Windows protected your PC"* — click **More info → Run anyway**. The installer asks where to install; default is fine. Click **Install**.

3. **Export and manually trust the project CA on first launch.**
   - Open ProxyForge → **Settings → Project CA**.
   - Click **Generate root CA**, then **Export PEM**.
   - Open the exported `.pem` with the Certificate Import Wizard and import it to **Trusted Root Certification Authorities → Current User**.

4. **Point your browser at the proxy.** Windows Settings → Network → Proxy → Manual → `127.0.0.1:8080`. Or use the *ProxyForge: Launch Managed Browser* button in the app (does this automatically with an isolated Chromium profile).

You're done. Open any HTTPS site; traffic appears in **Proxy → HTTP history**.

### Windows portable mode

If you grabbed `ProxyForge 0.1.0-alpha.1.exe` (portable), there's no installer step. Double-click to launch. The portable build does **not** put itself in the Start menu and does not register an uninstaller — delete the file to remove it.

---

## Quick Start — Linux (Debian / Ubuntu / Mint)

1. **Download** `proxyforge_0.1.0-alpha.1_amd64.deb` from https://github.com/the-vibe-dev/proxyforge-public/releases/latest

2. **Install:**
   ```bash
   sudo apt install ./proxyforge_0.1.0-alpha.1_amd64.deb
   ```
   `apt` pulls in the GTK / NSS / asound dependencies automatically.

3. **Export and manually trust the project CA on first launch.**
   - Open ProxyForge from your app launcher (or run `proxyforge`).
   - **Settings → Project CA → Generate root CA → Export PEM.**
   - Import the PEM into the browser or OS trust store you use for testing. Chromium-derived browsers on Linux usually use the user NSS store; Firefox and Curl have separate trust stores. See [Linux CA fallback](#linux-ca-fallback).

4. **Browser proxy:** Settings → Network → Manual → `127.0.0.1:8080`. Or click *Launch Managed Browser* in the app.

---

## Quick Start — Linux (AppImage, distro-agnostic)

For Fedora, Arch, openSUSE, and any other distro where `.deb` doesn't apply:

1. **Download** `ProxyForge-0.1.0-alpha.1.AppImage`.

2. **Make it executable and run:**
   ```bash
   chmod +x ProxyForge-0.1.0-alpha.1.AppImage
   ./ProxyForge-0.1.0-alpha.1.AppImage
   ```

3. **Export and manually trust the project CA** using the same `.deb` Quick Start steps.

4. **Browser proxy** → `127.0.0.1:8080`.

The AppImage is self-contained. To uninstall, delete the file.

---

## What the first-run Settings flow does

When you click **Generate root CA**, ProxyForge:

1. Creates a per-project root certificate inside your project folder and exposes it for export.
2. Derives per-host leaf certificates on the fly as you visit HTTPS sites, signed by that root.
3. Keeps the root and host certs isolated per project. No cross-engagement contamination.

ProxyForge does not install or remove OS/browser trust-store entries in this alpha. Trusting the exported PEM and removing that trust are manual operating-system or browser actions. **Revoke** rotates/deletes the local project CA material inside ProxyForge; it cannot remove a certificate you already imported into Windows, NSS, Firefox, Curl, or a system trust store.

---

## Verify your download

Each release publishes `SHA256SUMS.txt` next to the binaries. Verify:

```bash
# Linux / macOS
sha256sum -c SHA256SUMS.txt --ignore-missing
```

```powershell
# Windows PowerShell
Get-FileHash "ProxyForge Setup 0.1.0-alpha.1.exe" -Algorithm SHA256
# Compare against the line for that filename in SHA256SUMS.txt
```

---

## Troubleshooting

### Windows SmartScreen blocks the installer
Expected for the unsigned alpha. Click **More info** → **Run anyway**. If you use Windows Pro with managed app control, ask your admin to allowlist the publisher `dev.proxyforge.desktop` for testing.

### Antivirus quarantines the .exe
Unsigned Electron binaries trip several AV engines. Add an exclusion for the install directory (default `C:\Users\<you>\AppData\Local\Programs\ProxyForge\`) or run from a portable folder you've allowed. Code signing is on the roadmap for the next alpha.

### Browser shows "Your connection is not private" on every site
The project CA isn't trusted by that browser yet.
- **Chrome / Edge / Brave on Windows or Linux:** export the PEM from ProxyForge and import it into that browser's trust source. Restart the browser after trusting.
- **Firefox (any OS):** Firefox uses its own trust store. See [Linux CA fallback](#linux-ca-fallback) → Firefox section, or use Settings → Privacy & Security → Certificates → Import in Firefox to add the exported PEM manually.
- **Safari (macOS):** not supported in this alpha.

### Proxy capture history is empty
- Confirm browser proxy is set to `127.0.0.1:8080` (or whichever port you chose in Settings → Proxy listener).
- Confirm ProxyForge says *Proxy listening on 127.0.0.1:8080* in the status bar.
- Test with `curl -x http://127.0.0.1:8080 -k https://example.com` from a terminal. A reachable upstream produces an HTTP history row.

### The app won't start on Linux
Missing dependency. Run `proxyforge` from a terminal — the error tells you which lib (usually `libnss3`, `libgbm1`, or `libnotify4`). Install with `sudo apt install <package>` and retry.

### I want to uninstall
- **Windows installer:** Settings → Apps → ProxyForge → Uninstall, or run the uninstaller in the install directory.
- **Windows portable:** delete the `.exe`.
- **Linux .deb:** `sudo apt remove proxyforge`.
- **Linux AppImage:** delete the file.
- Removing the app does not remove your project files or trust-store entries. Project files live wherever you saved them. App-managed settings, browser profiles, reports, provider config, and runtime state can also live under Electron's per-user app data directory. Manually remove any imported ProxyForge root CA from each OS/browser trust store you used.

### Linux CA fallback
After exporting the PEM from **Settings → Project CA**, import it into the store your test browser actually uses:

```bash
# Chromium / Chrome / Edge user NSS store (Linux):
sudo apt install libnss3-tools
certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n "ProxyForge Root" -i ~/path/to/proxyforge-ca.pem

# Firefox (Linux/macOS/Windows — same UI per profile):
# Settings → Privacy & Security → Certificates → View Certificates → Authorities → Import
# Tick "Trust this CA to identify websites"

# Curl / system-wide (Debian/Ubuntu):
sudo cp ~/path/to/proxyforge-ca.pem /usr/local/share/ca-certificates/proxyforge.crt
sudo update-ca-certificates
```

### Windows CA fallback
After exporting the PEM from **Settings → Project CA**, use the Certificate Import Wizard:

1. Double-click the exported `.pem` (rename to `.cer` if Windows refuses).
2. Click **Install Certificate** → **Current User** → **Place all certificates in the following store** → **Browse** → **Trusted Root Certification Authorities** → **OK** → **Next** → **Finish**.
3. Confirm the security warning.

---

## Headless CLI

The desktop install includes a packaged headless runner for CI and scripted workflows.

```bash
# Linux: from your installed copy
proxyforge headless --target https://app.example.test \
  --scope app.example.test \
  --report json,bundle \
  --sarif --junit \
  --out-dir ./out

# Windows: from PowerShell
& "C:\Program Files\ProxyForge\proxyforge.exe" headless `
  --target https://app.example.test --scope app.example.test `
  --report json,bundle --out-dir .\out
```

Authenticated CI scans can pass secrets via environment variables instead of config files:

```bash
PROXYFORGE_AUTHORIZATION="Bearer $TOKEN" \
PROXYFORGE_COOKIE="session=$SESSION_ID" \
proxyforge headless --target https://app.example.test --scope app.example.test \
  --report json,bundle --sarif
```

Replay a captured project from CI:

```bash
proxyforge headless --project-file retail-api.proxyforge.json \
  --project-exchange hx-1032 --report json,bundle
```

Exit codes: `0` success, `1` scan blocked (scope/safety), `2` `--fail-on` severity threshold met. Full CLI reference in [OPERATOR_GUIDE.md](OPERATOR_GUIDE.md).

---

## Advanced

The sections below are for release engineers, CI maintainers, and contributors. New users do not need them.

### Build from source

```bash
git clone https://github.com/the-vibe-dev/proxyforge-public.git
cd proxyforge-public
npm install
npm run build          # renderer + electron tsc
npx playwright install --with-deps chromium  # required before local Playwright browser tests
npm run dist:linux     # AppImage + .deb in release/
npm run dist:win       # NSIS installer + portable .exe — requires Wine + Mono on Linux hosts
npm run dist:win:zip   # zip-only fallback when Wine is unavailable
```

The zip fallback emits `ProxyForge-0.1.0-alpha.1-win.zip` for manual unpacked Windows testing.

Wine + Mono setup on Debian/Ubuntu:

```bash
sudo apt install wine wine64 mono-devel
```

### Per-project CA rotation

- **Settings → Project CA → Rotate root** generates a new root and revokes the previous one. Trust must be re-imported.
- Closing a project and opening another changes project context. Any root you manually imported remains trusted until you remove it from the relevant OS/browser trust store. Use **Revoke** to discard ProxyForge's local CA material, then remove the old root from each trust store you used.

### Strict upstream TLS validation

Default is **strict**. ProxyForge refuses upstream certificates that are self-signed, expired, hostname-mismatched, or untrusted unless you explicitly select **relaxed** for a controlled lab/private-CA run. Prefer importing a private CA into the relevant trust store over disabling upstream validation.

### Release smoke commands

Linux unpacked launch smoke (structured exit, no manual clicks):

```bash
npm run release:smoke:linux
```

AppImage launch smoke:

```bash
node scripts/release-smoke.mjs --platform linux \
  --artifact release/ProxyForge-0.1.0-alpha.1.AppImage \
  --out test-results/release-smoke-linux-appimage.json
```

Clean-container deb install/runtime/uninstall smoke (requires Docker):

```bash
PROXYFORGE_DOCKER="sudo -n docker" scripts/release-deb-container-smoke.sh --gui --browser-trust
```

This smoke installs the deb into `debian:bookworm-slim`, verifies the packaged Electron Node runtime, launches the GUI under Xvfb with `PROXYFORGE_RELEASE_SMOKE=1`, installs Chromium plus `libnss3-tools`, imports the project CA into an isolated Chromium NSS trust store, captures trusted HTTPS browser traffic, then uninstalls and confirms cleanup.

Packaged browser-routing smoke on a host with Chromium, Chrome, or Edge:

```bash
node scripts/release-smoke.mjs --platform linux \
  --artifact release/linux-unpacked/proxyforge --browser-routing \
  --out test-results/release-smoke-linux-browser-routing.json
```

Windows installer NSIS install/launch/uninstall smoke (Windows host required):

```powershell
node scripts\release-smoke.mjs --platform windows `
  --artifact "release\ProxyForge Setup 0.1.0-alpha.1.exe" `
  --uninstall --out test-results\release-smoke-windows-installer.json
```

Windows packaged browser-routing and DPAPI sample-cookie smoke:

```powershell
node scripts\release-smoke.mjs --platform windows `
  --artifact release\win-unpacked\ProxyForge.exe `
  --browser-routing --dpapi-cookie `
  --out test-results\release-smoke-windows-browser-dpapi.json
```

Add `--browser-trust-store` only on hosts that permit temporary `Cert:\CurrentUser\Root` mutation and cleanup; if the host rejects it the smoke records a `blocked` lane and continues.

### Smoke output format

```json
{
  "kind": "proxyforge-release-smoke-result",
  "schemaVersion": 1,
  "platform": "linux",
  "status": "passed",
  "artifact": "release/linux-unpacked/proxyforge",
  "checks": [
    { "name": "artifact-exists", "status": "passed" },
    { "name": "electron-node-runtime", "status": "passed" },
    { "name": "packaged-headless-scan-report", "status": "passed" },
    { "name": "packaged-runtime-proxy-cert-oast-report", "status": "passed" },
    { "name": "packaged-browser-routing", "status": "passed" },
    { "name": "packaged-gui-launch", "status": "passed" }
  ]
}
```

Keep JSON output and artifact SHA-256 values with the GitHub release or internal release run, not in the public source tree. A lane is not marked `Production Ready` until its clean-machine install, browser routing/trust-store, packaged headless scan/report, packaged runtime proxy/cert/OAST/report, and platform-specific cookie/decryption smokes have current evidence.

### Known host-dependent lanes

- **Windows `Cert:\CurrentUser\Root` mutation** — blocked with `ERROR_NOT_SUPPORTED` on `windows-trust-runner` and similar locked hosts. This is the trust-store automation lane only; the manual fallback in [Windows CA fallback](#windows-ca-fallback) works on any session.
- **Windows DPAPI sample-cookie extraction** — requires a host where the current user has a Chromium-derived profile key DPAPI can unwrap.
- **Linux Secret Service cookie extraction** — requires a desktop session with an unlocked keyring.

These do not block alpha install. They are noted in the release matrix and revisit cycles.
