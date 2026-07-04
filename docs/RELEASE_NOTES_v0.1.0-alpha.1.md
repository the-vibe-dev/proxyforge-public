# ProxyForge v0.1.0-alpha.1 Release Notes

**Release type:** alpha source cut
**Release date:** 2026-06-20
**Git tag target:** `v0.1.0-alpha.1`
**Public distribution boundary:** native Linux and Windows release jobs must attach artifact receipts for the exact release commit before publishing installers broadly.

## Summary

ProxyForge `0.1.0-alpha.1` completes the roadmap through Phase 19 as a source and release-process cut. The application includes the local-first Electron workbench, proxy/MITM capture, scanner, OAST, Repeater, Intruder, Exploit Lab, Reports, Extensions, Automations, AI provider control, headless CLI, and release hardening gates described in the master plan.

The alpha package policy is intentionally conservative: npm publication is disabled, non-publishing builds use `--publish never`, Electron fuses are verified on packaged executables, and public installer distribution requires native artifact smoke receipts from Linux and Windows hosts.

## Gate Results

| Gate | Result | Evidence |
|---|---|---|
| G1 | Passed | Scanner core: payload mutation, oracle classification, probe rendering, evidence matrix, insertion points, active scan fixtures. |
| G2 | Passed | Scanner depth: active/passive families, named checks, passive posture rules, retest and evidence packages. |
| G3 | Passed | Browser scan oracle: managed browser scan driver, DOM XSS, prototype pollution, browser workflow smoke. |
| G4 | Passed | OAST and SBOM: signed callback correlation, OAST SSRF, CycloneDX/SPDX project SBOM round trips. |
| G5 | Passed | Traffic Tier 1: flow filters, rule packs, HAR export, cut/export, HTTP history tooling. |
| G6 | Passed | Alternate proxy modes and alpha cut: SOCKS5, reverse, DNS proxy, release notes, release tag target, hotfix process. |
| G7 | Passed | HTTP/2 transport and ALPN capture with frame editor coverage. |
| G8 | Passed | Streaming capture and disk-backed spool coverage for large bodies and SSE. |
| G9 | Passed | Playback client/server and matcher replay coverage. |
| G10 | Passed | Content views for multipart, zip, CSS, MQTT, Socket.IO, WBXML, DNS, GraphQL, SSE, and protobuf. |
| G11 | Passed | Optional native side-car mode stubs: transparent Linux, raw TCP/UDP, HTTP/3, WireGuard. |
| G12 | Passed | Extension SDK: typed API, manifest validation, signed package, runtime policy, compatibility fixtures. |
| G13 | Passed | Project Store: schema migrations, crash recovery, snapshot round trips, workflow persistence. |
| G14 | Passed | Full-chain GUI/headless E2E: Playwright workflow audit, focused browser smoke, headless runner. |
| G15 | Passed | Release hardening: sandboxing, IPC contracts, path traversal, zip-slip, body caps, redaction boundaries. |
| G16 | Passed | API/spec ingest and automation: OpenAPI/Postman/Insomnia/WSDL/OData/GraphQL, AJAX spider, recipes. |
| G17 | Passed | Release trust and packaging process: private npm policy, explicit non-publishing builds, Electron fuse policy, native artifact CI matrix. |

## Verification Commands

The release source cut was validated with:

```bash
npm run build
npm run docs:pages
npm run release:fuses
node tests/electron-fuse-policy.mjs
node tests/release-readiness.mjs
node tests/ci-nightly-policy.mjs
node tests/agent-option-audit.mjs
node tests/release-package-license.mjs
node tests/private-output-permissions.mjs
node tests/install-docs-production-engine.mjs
node tests/release-trust-production-engine.mjs
node tests/roadmap-completion.mjs
npm run test:ci:fast
npm run test:ci:full -- --skip-browser
npx playwright install --with-deps chromium
npx playwright test
npm run release:trust
npm audit --omit=dev
npm audit
```

`npm run test:ci:fast` is the required public-alpha source gate. Publish the source tag only after GitHub CI records a clean run for the exact release commit with Chromium installed. Unsigned binaries can be built for validation, but publish release-certified installers only after native artifact receipts and `npm run release:preflight` pass for the exact release tag.

## Known Alpha Boundaries

- Windows binaries are unsigned unless a release operator supplies a code-signing certificate; SmartScreen warnings are expected for unsigned artifacts.
- Native Linux and Windows artifact receipts must come from the GitHub native artifact matrix or equivalent clean hosts for the exact release commit/tag.
- `npm run release:preflight` is expected to fail in extracted source archives without a git tag, live-validation evidence, native receipts, and `SHA256SUMS.txt`; that is a binary-release blocker, not a source-alpha blocker.
- The renderer remains a large single bundle; Vite emits the existing chunk-size warning.
- Optional native side-car modes remain optional and degrade gracefully when side-car binaries are absent: transparent proxy, raw TCP/UDP, HTTP/3/QUIC, and WireGuard.
- Local Playwright browser tests require `npx playwright install --with-deps chromium` before `npm run test:e2e`.

## Hotfix Window

The alpha hotfix process is documented in `docs/HOTFIX_PROCESS.md`. Hotfixes must branch from the release tag, pass the source gate, pass the curated fast gate, regenerate release trust evidence, and publish replacement native artifact receipts before distribution.
