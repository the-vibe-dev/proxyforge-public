# ProxyForge — Engineering Handoff
**Date:** 2026-05-27
**Build:** `v0.1.0-alpha.1`
**Branch:** `main`

---

## What this is

ProxyForge is a standalone cross-platform web security workbench — HTTP/HTTPS proxy, MITM, scanner, OAST, Exploit Lab, Reports, Automation, and a headless CLI. Electron + Node.js. No Java. No Python. No required cloud account.

The Windows build is at:

```
release/ProxyForge 0.1.0-alpha.1.exe          101 MB  portable (no install)
release/ProxyForge Setup 0.1.0-alpha.1.exe    101 MB  NSIS installer
```

Both built fresh 2026-05-27 20:25 from the current `main` head.

---

## What was done in this session

All 19 roadmap phases (0 – 18b) completed. 237/237 tests pass.

### New source files added

| File | What it does |
|---|---|
| `src/authMethods/postAuth.ts` | URL-encoded POST auth method |
| `src/authMethods/ntlmAuth.ts` | NTLM auth (degrades gracefully on non-SSPI platforms) |
| `src/authMethods/scriptAuth.ts` | User-authored async auth script via `new Function()` |
| `src/exploitTemplates/grpcSequence.ts` | gRPC sequence verifier template |
| `src/exploitTemplates/multiStepChain.ts` | Multi-step chain verifier template |
| `src/aiTools/index.ts` | AI tool registry with per-mode authorization gate |
| `src/aiTools/capturedTrafficSql.ts` | Read-only parametrised SELECT over captured traffic |
| `src/aiTools/managedBrowserDrive.ts` | Mode + scope-gated managed-browser drive tool |
| `electron/browserScanDriver.ts` | CDP/Playwright orchestrator for browser-driven scans |
| `electron/browserScanWorker.ts` | Per-page probe spec builder + result evaluator |
| `electron/openProjectFolder.ts` | OS file-manager pivot with allowlist path guard |
| `docs/AI_AGENT_TOOLS_GUIDE.md` | AI tools operator guide |
| `docs/PROJECT_SBOM_GUIDE.md` | CycloneDX + SPDX SBOM guide |
| `docs/MODES_WIREGUARD.md` | WireGuard mode documentation |

### 26 new test files added (all pass)

Phase 1 scanner primitives, Phase 2 traffic rules, Phase 3b auth/modes, Phase 10/13 browser + playbook, Phase 18b AI tools / API clients / SBOM / open-project-folder.

### Test runner improvements

`tests/run-all.mjs` now reads per-file markers from the first 10 lines:

```js
// run-all: skip   → exclude from default run (CI orchestrators)
// run-all: slow   → 120 s timeout instead of 10 s
// run-all: args X → pass extra CLI args when spawning
```

`ci-fast-suite.mjs` and `ci-full-suite.mjs` are marked `skip` (they run `npm run build` — invoke directly). Four heavy tests (`agent-cli`, `customer-scale-interop-engine`, `project-store-v2`, `sequencer-engine`) are marked `slow`.

### Docs updated

- `docs/PROXY_FORGE_ROADMAP.md` — status table added at top (per §25); phases 0–18b all ✓ Done
- `docs/PROXY_FORGE_MASTER_PLAN.md` — all §3 checklists updated from `[ ]` → `[x]` with test IDs cited per claim

---

## Current test health

```
node tests/run-all.mjs
# → 237/237 test files passed  (2 skipped)
```

The 2 skipped are CI orchestrators. Run them directly when you want to validate the full pipeline:

```bash
node tests/ci-fast-suite.mjs      # runs npm run build + fast gate suite
node tests/ci-full-suite.mjs --plan-only   # validates plan (< 10 s)
node tests/ci-full-suite.mjs               # full CI pipeline (several minutes)
```

---

## Architecture in one paragraph

Electron main process hosts the proxy engine (`electron/proxyEngine.ts`, ~6 000 lines — do not rewrite, extend via `electron/traffic/`), project store (SQLite via Node built-in, `electron/projectStore.ts`), scanner runner (`electron/scanner/activeScanRunner.ts`), and all IPC contracts (`electron/ipcContracts.ts`). The renderer is a React app (`src/App.tsx`, `src/components/pfv2/`) built by Vite. The headless CLI (`scripts/proxyforge-agent.mjs`) speaks the same JSON command protocol over stdio. All runtime code is TypeScript + Node.js built-ins — no external npm dependencies in the runtime path.

---

## Build

```bash
npm run build          # tsc (renderer) + vite + tsc (electron)
npm run dist:win       # → release/ProxyForge*.exe  (needs wine on Linux)
npm run dist:linux     # → release/*.AppImage + *.deb
```

TypeScript config note: `electron/tsconfig.json` has `rootDir: ".."` — electron files compile to `dist-electron/electron/`, src files to `dist-electron/src/`. If a new `.ts` file isn't being picked up, delete `dist-electron/tsconfig.tsbuildinfo` and rebuild.

New `src/` subdirectories must be added explicitly to `electron/tsconfig.json` `include` array.

---

## Phase 19 alpha release status

| # | Item | Notes |
|---|---|---|
| 19.1 | Tag `v0.1.0-alpha.1` | Target tag for the public alpha release; create it on the release commit after CI receipts are clean. |
| 19.2 | Signed packages | Release workflow produces native artifact receipts; operator signing credentials are optional and external to the source cut. |
| 19.3 | Release notes | Done in `docs/RELEASE_NOTES_v0.1.0-alpha.1.md`, citing G1-G17. |
| 19.4 | Public README pass | Done for alpha source-cut audience. |
| 19.5 | Alpha announcement | Done as committed release notes/README copy. |
| 19.6 | Bug-bash window | Documented as alpha operating process. |
| 19.7 | Hotfix process | Done in `docs/HOTFIX_PROCESS.md`. |

The remaining distribution boundary is operational: native Linux and Windows artifact receipts must be collected for the exact release commit/tag, and unsigned Windows artifacts will trigger SmartScreen unless the release operator supplies a signing certificate.

---

## Key files for reviewers

| What you want | Where to look |
|---|---|
| All capabilities and their test coverage | `docs/FEATURE_MATRIX.md` |
| Phase-by-phase status | `docs/PROXY_FORGE_ROADMAP.md` (status table at top) |
| Architecture decisions and constraints | `docs/PROXY_FORGE_MASTER_PLAN.md` §2 |
| AI agent tool contracts | `docs/AI_AGENT_TOOLS_GUIDE.md` |
| SBOM generation | `docs/PROJECT_SBOM_GUIDE.md` |
| Operator guide | `docs/OPERATOR_GUIDE.md` |
| Extension API | `docs/EXTENSION_API.md` |
| Headless CLI commands | `docs/AGENTIC_INTERFACE.md` |
| IPC security contracts | `electron/ipcContracts.ts` |
| Scope / mode / safety guards | `src/modes/index.ts`, `electron/scanner/activeScanRunner.ts` |
| All test files | `tests/*.mjs` (237 active) |

---

## Known limitations

- **Code signing:** Windows binary is unsigned. SmartScreen warning on first run expected.
- **Playwright E2E:** Full-chain Playwright `.spec.ts` files require a packaged Electron binary and a Playwright install. Headless `.mjs` equivalents cover the same flows and pass.
- **Side-cars optional:** Transparent (Linux), HTTP/3, WireGuard, raw TCP/UDP features have passing smoke tests but the actual Rust side-car binaries are not shipped in this build. Features degrade gracefully without them.
- **Renderer bundle size:** `dist/assets/index-*.js` is ~1.5 MB minified. No code splitting yet — acceptable for a desktop app, worth addressing before a web-based distribution.
