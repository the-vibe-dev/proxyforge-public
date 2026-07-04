# Release Evidence

This file records concrete desktop release proof. Generated package files stay in ignored `release/`; this document is the committed evidence trail.

## 2026-06-20 Final Source Alpha Blocker Fix Checkpoint

Command and result:

| Command | Result |
| --- | --- |
| `node tests/private-output-permissions.mjs` | Passed. Existing `0775` and `0755` agent export parents retain their modes, newly created parents are `0700`, output files are `0600`, and desktop export helpers use the parent-preserving writer. |
| `node tests/release-package-license.mjs` | Passed in source mode. `LICENSE` is included in the Electron Builder allowlist and the verifier is ready to inspect native `app.asar` payloads with `--verify-artifacts`. |
| `node tests/roadmap-completion.mjs` | Passed. The release tag check remains enforced in Git/tag contexts and becomes source-archive friendly when `.git` metadata is absent. |
| `node tests/ci-nightly-policy.mjs` | Passed. The change-time source gate now runs `npm run test:ci:fast`, and the native artifact matrix verifies packaged license payloads. |
| `node tests/release-readiness.mjs` | Passed. Release readiness now requires packaged license coverage and private-output permission regression coverage. |
| `npm run build` | Passed. Renderer, Vite, Electron TypeScript compile, and entrypoint sync complete with only the existing Vite large-chunk warning. |
| `node tests/release-trust-production-engine.mjs` | Passed. Release Trust remains green after adding `LICENSE` as a required release-trust material. |
| `npm run release:trust` | Passed. Generated manifest, SBOM, checksums, and provenance with 376 lockfile components and 14 artifact digests. |
| `npm audit --omit=dev` / `npm audit` | Passed. Both audits report 0 vulnerabilities. |
| `npm run test:ci:fast` | Passed 100/100 steps in 264751ms, including package license and private-output permission gates plus the focused browser workflow smoke. |
| `npm run test:ci:full -- --skip-browser` | Passed 90/90 steps in 210724ms. |
| `npx playwright test` | Passed 69/69 browser tests in 1.6m. |

## 2026-06-20 Roadmap Completion Checkpoint

Command and result:

| Command | Result |
| --- | --- |
| `node tests/roadmap-completion.mjs` | Passed. Phase 19 is closed in the roadmap, release notes cite G1-G17, the hotfix process is documented, release-tag checks remain enforced in tagged checkouts, and native artifact receipts remain explicitly required before broad installer distribution. |
| `node tests/feature-matrix-lint.mjs` | Passed. Feature Matrix table structure is valid and all gate rows are complete rather than stale `In progress` / `Not started` statuses. |
| `node tests/release-readiness.mjs` | Passed. Release readiness now requires alpha release notes, hotfix process docs, roadmap completion smoke, metadata, fuse policy, and package script coverage. |
| `node tests/install-docs-production-engine.mjs` | Passed. Packaged install/operator/release/agent docs remain synchronized with the current release evidence and full-fidelity secret boundary. |

## 2026-06-20 Prerelease Review Disposition

The June 20 prerelease reviews referenced older archive revisions than the current `main` tree. Against the current source, PF-003, PF-004's core IPC authorization issue, PF-005's audited agent/report paths, PF-007, PF-009, and PF-010's npm-publication ambiguity are addressed in code or policy. The remaining binary-release blocker is artifact-backed installer certification proof: Linux and Windows builds must produce native CI receipts that verify Electron fuses and run `scripts/release-smoke.mjs` against the exact packaged executable.

Current release-hardening evidence now includes:

- `scripts/electron-fuse-policy.mjs`: Electron Builder `afterPack` hook plus `--check-config`, `--policy-json`, `--apply`, and `--verify` modes.
- `tests/electron-fuse-policy.mjs`: source-level fuse policy, CI, release docs, and explicit `RunAsNode` compatibility-exception coverage.
- `.github/workflows/nightly-full-suite.yml`: change-time source gate and native Linux/Windows artifact matrix.
- `SECURITY.md` and `package.json`: concrete private GitHub Security Advisory reporting and non-placeholder project metadata.

Installer publication remains gated on the native artifact matrix producing successful Linux and Windows receipts for the exact release commit/tag.

## 2026-05-26 Proxy Browser Proxy-Chain Diversity Checkpoint

Command and result:

| Command | Result |
| --- | --- |
| `gh run list --workflow nightly-full-suite.yml --limit 20 --json databaseId,event,status,conclusion,createdAt,updatedAt,headBranch,headSha,displayTitle,url` | Current hosted state still shows only manual `workflow_dispatch` runs, including successful warmups `26442381257` and `26442689546`; no scheduled receipts are present yet, so scheduled retained CI history remains pinned. |
| `npm run build` | Passed. TypeScript accepts `ProxyBrowserProxyChainDiversityPackage`; Vite completed with the existing chunk-size warning only. |
| `node tests/proxy-history-engine.mjs` | Passed. The Proxy history fixture now emits `proxyforge-proxy-browser-proxy-chain-diversity-package` with Chromium/Chrome/Edge/Firefox, Linux/Windows, upstream-auth/CONNECT chain/PAC/direct, project/trusted/manual/pinned certificate modes, HTTP/2, CONNECT, WebSocket, isolated profile/cookie stores, upstream credential preservation, full-fidelity operational samples, and report-export-only redaction. |
| `node tests/release-readiness.mjs` | Passed. Release readiness now requires the open-source alpha license, SECURITY policy, README alpha status, Proxy browser/proxy-chain diversity docs, and existing release checklist gates. |
| `node tests/install-docs-production-engine.mjs` | Passed. Packaged install/operator/release/agent docs remain synchronized with the alpha status and full-fidelity secret boundary. |
| `npm run test:ci:fast` | Passed 85/85 steps in 304787ms, including build, release readiness, package/security/doc gates, Project Store persistence/recovery, Proxy/HTTPS/WebSocket, browser launch/cookie matrix, Repeater race/desync, Intruder/OAST, Scanner/Anvil, Exploit Lab, AI actions, Automations, Extensions, Reports/PDF visual QA, headless CLI, agent CLI, and focused browser workflow smoke. |

Ignored evidence artifacts refreshed:

| Path | Purpose |
| --- | --- |
| `.gitignored/test-artifacts/proxy-history-filter-set-*/proxy-edge-profile-package.json` | Proxy edge profile package refreshed as the linked source package for browser/proxy-chain diversity. |
| `.gitignored/test-artifacts/proxy-history-filter-set-*/proxy-browser-proxy-chain-diversity-package.json` | Browser/proxy-chain diversity proof for Chromium/Chrome/Edge/Firefox across Linux/Windows profiles with upstream credential preservation and report-only redaction. |
| `test-results/ci-fast-suite-summary.json` | Source-alpha candidate fast-suite summary showing the 85/85 pass and step timing. |

## 2026-05-26 Project Customer Workspace Restore Interop Checkpoint

Command and result:

| Command | Result |
| --- | --- |
| `npm run build` | Passed. TypeScript accepts the new `ProjectCustomerWorkspaceRestoreInteropPackage`; Vite completed with the existing chunk-size warning only. |
| `node tests/customer-scale-interop-engine.mjs` | Passed. The customer-scale fixture now emits `proxyforge-project-customer-workspace-restore-interop-package` with four imported workspace profiles, 1,390 persisted/restored exchanges, actual Project Store backup/reopen proof, restored-exchange integrity, cross-tool restore counts, full-fidelity raw samples, and report-export-only redaction. |
| `npm run test:customer-scale-interop` | Passed. The package script rebuilt the app and reran the customer-scale interop gate with the new workspace restore package. |
| `node tests/release-readiness.mjs` | Passed. Release checklist, operator guide, and agent schemas now require the customer workspace restore interop package boundary. |
| `node tests/install-docs-production-engine.mjs` | Passed. Packaged install/operator/release/agent docs include the restored-workspace proof and full-fidelity secret handling. |
| `git diff --check` | Passed. |
| `npm run test:ci:fast` | Passed 85/85 steps in 311438ms, including the new customer workspace restore package inside `node tests/customer-scale-interop-engine.mjs`, Project Store persistence/recovery, release/security/doc/package gates, agent control, OAST, exploit, scanner, Repeater/Intruder, Proxy, Reports, and focused browser coverage. |

Ignored evidence artifacts refreshed:

| Path | Purpose |
| --- | --- |
| `.gitignored/test-artifacts/customer-scale-interop/customer-scale-interop-evidence-package.json` | Customer-scale interop package refreshed alongside restored-workspace profiling. |
| `.gitignored/test-artifacts/customer-scale-interop/customer-workspace-restore-interop-package.json` | Four-workspace Project Store backup/reopen proof with restored-exchange integrity and full-fidelity raw samples. |
| `.gitignored/test-artifacts/customer-scale-interop/customer-scale-merge-manifest.json` | Mixed legacy proxy XML/HAR/raw HTTP/JSONL/ProxyForge merge manifest refreshed for the workspace restore checkpoint. |
| `.gitignored/test-artifacts/customer-scale-interop/workspace-restore/` | Ignored Project Store restore profiles and backup directories used to prove actual reopen behavior. |
| `test-results/ci-fast-suite-summary.json` | CI-fast summary showing the 85/85 checkpoint pass and step timing for the customer workspace restore update. |

## 2026-05-26 Reports Template-Library Interop Checkpoint

Command and result:

| Command | Result |
| --- | --- |
| `npm run build` | Passed. TypeScript accepts `ReportTemplateLibraryInteropPackage`; Vite completed with the existing chunk-size warning only. |
| `node tests/report-engine.mjs` | Passed. The report export fixture emits `proxyforge-report-template-library-interop-package` evidence covering template library export/import, duplicate conflict review with renamed imports, built-in/custom template rendering, variable resolution, Markdown/HTML/bundle render hashes, full-fidelity pre-export inputs, and report-export-only redaction. |
| `node tests/report-pdf-visual-qa.mjs` | Passed. Rendered PDF HTML still produces nonblank PNG output, page-break probes, and redacted PDF HTML after the Reports template-library update. |
| `node tests/release-readiness.mjs` | Passed. Operator docs, agent schemas, release checklist, feature matrix, and release docs include the Reports template-library interop package boundary. |
| `node tests/install-docs-production-engine.mjs` | Passed. Packaged install/operator/release/agent docs include the Reports template-library interop proof and full-fidelity secret handling. |
| `npm run test:ci:fast` | Passed 85/85 steps in 272651ms, including the new Reports template-library interop package inside `node tests/report-engine.mjs`, release/security/doc/package gates, agent control, OAST, exploit, scanner, Repeater/Intruder, Proxy, and focused browser workflow smoke. |

Ignored evidence artifacts refreshed:

| Path | Purpose |
| --- | --- |
| `.gitignored/test-artifacts/report-engine/report-parity-evidence-package.json` | Report parity evidence refreshed alongside template-library interop coverage. |
| `.gitignored/test-artifacts/report-engine/report-production-readiness-package.json` | Report production readiness evidence refreshed alongside template-library interop coverage. |
| `.gitignored/test-artifacts/report-engine/report-external-bundle-diversity-package.json` | External shared-bundle diversity evidence refreshed alongside template-library interop coverage. |
| `.gitignored/test-artifacts/report-engine/report-template-library-interop-package.json` | Template library export/import proof with conflict review, built-in/custom render proofs, and redaction checks. |
| `test-results/ci-fast-suite-summary.json` | CI-fast summary showing the 85/85 checkpoint pass and step timing for the Reports template-library interop update. |

## 2026-05-26 Reports External Bundle Diversity Checkpoint

Command and result:

| Command | Result |
| --- | --- |
| `npm run build` | Passed. TypeScript accepts `ReportExternalBundleDiversityPackage`; Vite completed with the existing chunk-size warning only. |
| `node tests/report-engine.mjs` | Passed. The report export fixture emits `proxyforge-report-external-bundle-diversity-package` evidence covering four external recipient/channel/key/template shared-bundle profiles, digest-only no-secret review, canonical JSON round trips, cross-tool attachment diversity, signed verification, tamper rejection, full-fidelity pre-export inputs, and report-export-only redaction. |
| `node tests/report-pdf-visual-qa.mjs` | Passed. Rendered PDF HTML still produces nonblank PNG output, page-break probes, and redacted PDF HTML after the Reports bundle-diversity update. |
| `node tests/release-readiness.mjs` | Passed. Operator docs, agent schemas, release checklist, feature matrix, and release docs include the Reports external-bundle diversity package boundary. |
| `node tests/install-docs-production-engine.mjs` | Passed. Packaged install/operator/release/agent docs include the Reports external-bundle diversity proof and full-fidelity secret handling. |
| `npm run test:ci:fast` | Passed 85/85 steps in 272652ms, including the new Reports external bundle diversity package inside `node tests/report-engine.mjs`, release/security/doc/package gates, agent control, OAST, exploit, scanner, Repeater/Intruder, Proxy, and focused browser workflow smoke. |

Ignored evidence artifacts refreshed:

| Path | Purpose |
| --- | --- |
| `.gitignored/test-artifacts/report-engine/report-parity-evidence-package.json` | Report parity evidence refreshed alongside external bundle diversity coverage. |
| `.gitignored/test-artifacts/report-engine/report-production-readiness-package.json` | Report production readiness evidence refreshed alongside external bundle diversity coverage. |
| `.gitignored/test-artifacts/report-engine/report-external-bundle-diversity-package.json` | Four-profile external shared-bundle diversity proof for bug bounty portal, customer GRC, partner MSSP, and internal remediation handoff lanes. |
| `test-results/ci-fast-suite-summary.json` | CI-fast summary showing the 85/85 checkpoint pass and step timing for the Reports external-bundle diversity update. |

## 2026-05-26 Exploit Lab Package Refresh Checkpoint

Command and result:

| Command | Result |
| --- | --- |
| `node tests/exploit-engine.mjs` | Passed. New `proxyforge-exploit-package-refresh-evidence-package` links Exploit Lab parity, backend execution, saved-chain, report-package, review/import, comparison, and callback-validation proof with stale-package checks, destructive-class exclusion, full-fidelity executor material, and report-export-only redaction. |
| `npm run build` | Passed. TypeScript accepts the Exploit Lab package-refresh API; Vite completed with the existing chunk-size warning only. |
| `node tests/release-readiness.mjs` | Passed. Agent schemas, operator guide, feature matrix, and release docs include the Exploit Lab package-refresh schema and evidence boundary. |
| `node tests/install-docs-production-engine.mjs` | Passed. Packaged install/operator/release/agent docs include the Exploit Lab package-refresh proof and full-fidelity secret handling. |
| `npm run test:ci:fast` | Passed 85/85 steps in 275332ms, including Exploit backend/package-refresh coverage, agent exploit approval, release/security/doc/package gates, and focused browser workflow smoke. |
| `git diff --check` | Passed. No whitespace errors. |

Ignored evidence artifacts refreshed:

| Path | Purpose |
| --- | --- |
| `.gitignored/test-artifacts/exploit-engine/exploit-parity-evidence-package.json` | Exploit Lab parity package refreshed for linked package-refresh proof. |
| `.gitignored/test-artifacts/exploit-engine/exploit-package-refresh-evidence-package.json` | Exploit Lab package-refresh proof linking parity, backend execution, saved-chain, report, review/import, comparison, and callback validation packages. |
| `test-results/ci-fast-suite-summary.json` | CI-fast summary showing the 85/85 checkpoint pass and step timing for the Exploit Lab package-refresh update. |

## 2026-05-26 Full/Nightly Hosted Retained-History Checkpoint

Command and result:

| Command | Result |
| --- | --- |
| `gh run list --workflow nightly-full-suite.yml --limit 10 --json databaseId,event,status,conclusion,createdAt,updatedAt,headBranch,headSha,displayTitle,url` | Current hosted state shows successful manual `workflow_dispatch` warmups `26442381257` and `26442689546`, plus one earlier failed manual dispatch `26441983677`; no true scheduled receipts are present yet, so the full/nightly row remains below Production Ready. |
| `node tests/full-nightly-history-engine.mjs` | Passed. New `proxyforge-full-nightly-hosted-retained-history-evidence-package` models hosted run receipts, scheduled-vs-manual boundaries, branch/workflow continuity, retained-history restore/save, uploaded summary/dashboard artifacts, retained-dashboard run-id linkage, digest integrity, full-fidelity executor material, and report-export-only redaction. |
| `node tests/full-nightly-production-engine.mjs` | Passed. Full/Nightly production evidence remains compatible with the retained-history gate and scheduled workflow continuity proof. |
| `npm run build` | Passed. TypeScript accepts the hosted retained-history evidence API; Vite completed with the existing chunk-size warning only. |
| `node tests/release-readiness.mjs` | Passed. Release checklist, operator guide, and agent schema docs include the hosted retained-history package boundary. |
| `node tests/install-docs-production-engine.mjs` | Passed. Packaged install/operator/release/agent docs include the hosted retained-history package boundary and full-fidelity secret handling. |
| `git diff --check` | Passed. No whitespace errors. |

Ignored evidence artifacts refreshed:

| Path | Purpose |
| --- | --- |
| `.gitignored/test-artifacts/full-nightly-history-engine/full-nightly-retained-history-evidence-package.json` | Retained runtime summaries and dashboard proof refreshed alongside hosted receipt evidence. |
| `.gitignored/test-artifacts/full-nightly-history-engine/full-nightly-hosted-retained-history-evidence-package.json` | Hosted CI receipt proof for scheduled-vs-manual full/nightly retained-history promotion. |

## 2026-05-26 OAST Package Refresh Checkpoint

Command and result:

| Command | Result |
| --- | --- |
| `node tests/callback-live-backend-engine.mjs` | Passed. New `proxyforge-collaborator-package-refresh-evidence-package` links Collaborator parity, signed polling, replay correlation, replay execution, lifecycle/retention, CI handoff, public relay soak, signed external relay, provider diversity, scoped provider-host proof, and report round-trip packages with refresh digests, stale-package checks, full-fidelity callback/provider secrets, and report-export-only redaction. |
| `npm run build` | Passed. TypeScript accepts the new callback package-refresh API; Vite completed with the existing chunk-size warning only. |
| `node tests/callback-listener-service.mjs` | Passed. Captured HTTP, DNS, and SMTP local socket interactions remain covered. |
| `node tests/oast-relay-integration.mjs` | Passed. Signed external relay polling, tenant isolation, full-fidelity relay secrets, and report boundary remain covered. |
| `node tests/oast-provider-diversity.mjs` | Passed. Generic HTTP, DNS webhook, and SMTP provider shapes remain covered. |
| `node tests/release-readiness.mjs` | Passed. Release checklist, schemas, operator docs, release docs, and ignored artifact policy include the OAST package-refresh schema. |
| `node tests/install-docs-production-engine.mjs` | Passed. Packaged install/operator/release/agent docs include the OAST package-refresh evidence and full-fidelity secret boundary updates. |
| `node tests/agent-option-audit.mjs` | Passed. The Codex/Claude/Vantix option audit still verifies all 70 agent commands, callback provider/relay/retention/replay controls, desync/race docs, and secret boundary. |
| `node tests/fast-regression-production-engine.mjs` | Passed. Fast Regression production evidence accepts the current 85-step fast-suite surface. |
| `node tests/full-nightly-production-engine.mjs` | Passed. Full/Nightly production evidence accepts the 82-step skip-browser suite surface plus retained-history linkage. |
| `node tests/full-nightly-history-engine.mjs` | Passed. Retained-history evidence accepts the current 7-run dashboard, latest 82/82 skip-browser pass, digest integrity, and full-fidelity secret boundary. |
| `npm run test:ci:fast` | Passed 85/85 steps in 270278ms, including Callback live backend coverage for 13 helpers, signed tenant-isolated OAST relay integration, external OAST provider diversity, agent callback provider/relay/retention controls, release/security/doc/package gates, and focused browser workflow smoke. |
| `node tests/ci-full-suite.mjs --skip-browser` | Passed 82/82 steps in 179098ms, including Callback listener backend, Callback live backend package-refresh coverage, release production evidence, and retained-history update without the browser E2E tail. |
| `git diff --check` | Passed. No whitespace errors. |

Ignored evidence artifacts refreshed:

| Path | Purpose |
| --- | --- |
| `.gitignored/test-artifacts/callback-live-backend/collaborator-package-refresh-evidence-package.json` | OAST package-refresh proof linking parity, polling, replay, retention, CI, relay, provider, scoped provider-host, and report round-trip packages. |
| `.gitignored/test-artifacts/callback-live-backend/collaborator-parity-evidence-package.json` | Collaborator parity evidence refreshed for linked package-refresh proof. |
| `.gitignored/test-artifacts/callback-live-backend/callback-report-roundtrip-package.json` | Callback report round-trip evidence refreshed for linked package-refresh proof. |
| `.gitignored/test-artifacts/oast-relay-integration/external-relay-integration-package.json` | Signed external relay integration proof refreshed for linked package-refresh proof. |
| `.gitignored/test-artifacts/oast-provider-diversity/external-oast-provider-diversity-package.json` | External OAST provider diversity proof refreshed for linked package-refresh proof. |
| `.gitignored/test-artifacts/full-nightly-history-engine/full-nightly-retained-history-evidence-package.json` | Full/nightly retained-history package refreshed after the 82/82 skip-browser pass. |
| `test-results/ci-fast-suite-summary.json` | CI-fast summary showing the 85/85 checkpoint pass and step timing for the OAST package-refresh update. |
| `test-results/ci-full-suite-summary.json` | Current local full/nightly skip-browser summary showing 82/82 passed steps. |
| `test-results/ci-full-suite-history/dashboard.json` | Retained trend dashboard showing 7 retained runtime passes, 0 failures, and 7 consecutive runtime passes. |

## 2026-05-26 Analysis Tool Package Refresh Checkpoint

Command and result:

| Command | Result |
| --- | --- |
| `node tests/analysis-tool-refresh-engine.mjs` | Passed. New `proxyforge-analysis-tool-refresh-evidence-package` links Search, Logger, Organizer, Viewer, Sequencer, Decoder, and Comparer parity packages with package-refresh digests, stale-package checks, full-fidelity executor material, operational secret samples, and report-export-only redaction. |
| `npm run build` | Passed. TypeScript accepts the new Analysis tool refresh engine and the expanded Fast Regression production requirement; Vite completed with the existing chunk-size warning only. |
| `node tests/search-engine.mjs` | Passed. Search parity still covers full-text, structured predicates, semantic/provider ranking, persistent index restore, large-project soak, live-provider package shape, and full-fidelity corpus handling. |
| `node tests/viewer-engine.mjs` | Passed. Viewer parity still covers raw, pretty, JWT, GraphQL, image, binary, evidence pins, replay comparison exports, report handoff, and full-fidelity secret handling. |
| `node tests/sequencer-engine.mjs` | Passed. Sequencer parity still covers token location extraction, reliability gates, statistical charts, full-fidelity token preservation, and report-export-only redaction. |
| `node tests/decoder-engine.mjs` | Passed. Decoder parity package still covers transform chains, JWT/JWS/JWE workflows, binary inspection, report handoff, and full-fidelity operational samples. |
| `node tests/compare-engine.mjs` | Passed. Comparer parity package still covers text/word/byte, structured HTTP, binary/hex, normalization presets, replay delta review, and operational sample preservation. |
| `node tests/logger-evidence-engine.mjs` | Passed. Logger parity still covers generated traffic, capture filters, custom column linkage, archive conflict/dedupe review, report attachments, and full-fidelity raw material. |
| `node tests/organizer-evidence-engine.mjs` | Passed. Organizer parity still covers collections, reviewer workflow, SLA export, sealed/signed packages, trust review, conflict dedupe, merge modes, and full-fidelity raw material. |
| `node tests/agent-option-audit.mjs` | Passed. The Codex/Claude/Vantix option audit still verifies all 70 agent commands, desync/race docs, secret boundary, and matrix gate after the Analysis package-refresh update. |
| `node tests/release-readiness.mjs` | Passed. Release checklist, packaged files, build outputs, ignored artifacts, schemas, operator docs, and release docs remain synchronized. |
| `node tests/install-docs-production-engine.mjs` | Passed. Packaged install/operator/release/agent docs include the Analysis package-refresh evidence and full-fidelity secret boundary updates. |
| `node tests/fast-regression-production-engine.mjs` | Passed. Fast Regression production evidence now requires the Analysis tool refresh step and accepts the current fast-suite surface. |
| `node tests/release-security-production-engine.mjs` | Passed. Release Security still accepts the full release surface with report-export-only redaction and executor secret preservation. |
| `node tests/full-nightly-production-engine.mjs` | Passed. Full/Nightly production evidence accepts the 83-step plan, retained-history linkage, Analysis tool refresh coverage, and full-fidelity secret boundary. |
| `node tests/full-nightly-history-engine.mjs` | Passed. Retained-history evidence accepts the current 6-run dashboard, latest 82/82 skip-browser pass, digest integrity, and full-fidelity secret boundary. |
| `npm run test:ci:fast` | Passed 85/85 steps in 271972ms, including the new Analysis tool refresh evidence engine, Search/Viewer/Logger/Organizer/Sequencer/Decoder/Comparer parity gates, release/security/doc/package gates, agentic control CLI smoke, and focused browser workflow smoke. |
| `node tests/ci-full-suite.mjs --skip-browser` | Passed 82/82 steps in 178820ms, including the new Analysis tool refresh evidence engine and retained-history update without the browser E2E tail. |
| `git diff --check` | Passed. No whitespace errors. |

Ignored evidence artifacts refreshed:

| Path | Purpose |
| --- | --- |
| `.gitignored/test-artifacts/analysis-tool-refresh-engine/analysis-tool-refresh-evidence-package.json` | Cross-tool package-refresh proof for Search, Logger, Organizer, Viewer, Sequencer, Decoder, and Comparer. |
| `.gitignored/test-artifacts/search-engine/search-parity-evidence-package.json` | Search parity evidence refreshed for linked Analysis proof. |
| `.gitignored/test-artifacts/viewer-engine/viewer-parity-evidence-package.json` | Viewer parity evidence refreshed for linked Analysis proof. |
| `.gitignored/test-artifacts/sequencer-engine/sequencer-parity-evidence-package.json` | Sequencer parity evidence refreshed for linked Analysis proof. |
| `.gitignored/test-artifacts/decoder-engine/decoder-parity-evidence-package.json` | Decoder parity evidence refreshed for linked Analysis proof. |
| `.gitignored/test-artifacts/compare-engine/comparer-parity-evidence-package.json` | Comparer parity evidence refreshed for linked Analysis proof. |
| `.gitignored/test-artifacts/logger-evidence-engine/logger-parity-evidence-package.json` | Logger parity evidence refreshed for linked Analysis proof. |
| `.gitignored/test-artifacts/organizer-evidence-engine/organizer-parity-evidence-package.json` | Organizer parity evidence refreshed for linked Analysis proof. |
| `.gitignored/test-artifacts/fast-regression-production-engine/fast-regression-production-evidence-package.json` | Fast Regression production package refreshed with Analysis tool refresh as a required step. |
| `.gitignored/test-artifacts/full-nightly-production-engine/full-nightly-production-evidence-package.json` | Full/nightly production package refreshed against the updated 83-step plan. |
| `.gitignored/test-artifacts/full-nightly-history-engine/full-nightly-retained-history-evidence-package.json` | Full/nightly retained-history package refreshed after the 82/82 skip-browser pass. |
| `test-results/ci-fast-suite-summary.json` | CI-fast summary showing the 85/85 checkpoint pass and step timing for the Analysis package-refresh update. |
| `test-results/ci-full-suite-summary.json` | Current local full/nightly skip-browser summary showing 82/82 passed steps. |
| `test-results/ci-full-suite-history/dashboard.json` | Retained trend dashboard showing 6 retained runtime passes, 0 failures, and 6 consecutive runtime passes. |

## 2026-05-26 Scanner Package Refresh Checkpoint

Command and result:

| Command | Result |
| --- | --- |
| `node tests/scanner-active-scan-engine.mjs` | Passed. Scanner live-target profile evidence now links passive dedupe, insertion inventory, active scan evidence, OAST promotion, Anvil custom checks, retest deltas, and calibration packages with package-refresh digests and stale-package checks while preserving full-fidelity executor secrets until report export. |
| `node tests/scanner-passive-engine.mjs` | Passed. Passive Scanner parity still proves check-family coverage, dedupe clusters, route variants, confidence/severity policy, suppressions, report attachments, and raw exchange preservation. |
| `node tests/insertion-point-engine.mjs` | Passed. Insertion inventory still extracts scanner-ready query/path/header/cookie/form/JSON/GraphQL/multipart/XML points with full-fidelity raw material. |
| `node tests/scanner-retest-engine.mjs` | Passed. Scanner retest evidence still covers fixed/regressed/still-vulnerable/inconclusive outcomes, request edits, runner controls, report attachments, and operational secret preservation. |
| `node tests/anvil-engine.mjs` | Passed. Anvil parity still covers plain-text `.anvil` definitions, reusable libraries, positive/negative fixtures, headless custom-only runs, signed package review, Scanner handoff, Reports handoff, and full-fidelity raw samples. |
| `npm run build` | Passed. TypeScript accepts the expanded Scanner live-target profile request and package requirement types; Vite completed with the existing chunk-size warning only. |
| `node tests/agent-option-audit.mjs` | Passed. The Codex/Claude/Vantix option audit still verifies all 70 agent commands, desync/race docs, secret boundary, and matrix gate after the Scanner package-refresh update. |
| `node tests/release-readiness.mjs` | Passed. Release checklist, packaged files, build outputs, ignored artifacts, and release docs remain synchronized. |
| `node tests/install-docs-production-engine.mjs` | Passed. Packaged install/operator/release/agent docs include the Scanner package-refresh and full-fidelity secret boundary updates. |
| `node tests/fast-regression-production-engine.mjs` | Passed. Fast Regression production evidence accepts the current fast-suite coverage and artifact policy. |
| `node tests/release-security-production-engine.mjs` | Passed. Release Security still accepts the full release surface with report-export-only redaction and executor secret preservation. |
| `node tests/full-nightly-production-engine.mjs` | Passed. Full/Nightly production evidence accepts the retained-history linkage and updated Scanner matrix evidence. |
| `node tests/full-nightly-history-engine.mjs` | Passed. Retained-history evidence accepts the current runtime summary dashboard and digest integrity. |
| `npm run test:ci:fast` | Passed 84/84 steps in 271863ms, including Scanner passive dedupe, insertion inventory, active evidence package refresh linkage, retest deltas, Anvil parity, live calibration, agentic control CLI smoke with Scanner/Anvil/OAST commands, release/security/doc/package gates, and focused browser workflow smoke. |

Ignored evidence artifacts refreshed:

| Path | Purpose |
| --- | --- |
| `.gitignored/test-artifacts/scanner-active-scan-engine/scanner-live-target-profile-package.json` | Scanner live-target profile package proving package-refresh linkage for passive dedupe, insertion inventory, active scan evidence, OAST promotion, Anvil, retest, and calibration packages. |
| `.gitignored/test-artifacts/scanner-passive-engine/scanner-passive-dedupe-parity-package.json` | Passive Scanner parity package refreshed for linked Scanner profile proof. |
| `.gitignored/test-artifacts/insertion-point-engine/insertion-point-inventory.json` | Insertion inventory package refreshed for linked Scanner profile proof. |
| `.gitignored/test-artifacts/scanner-retest-engine/scanner-retest-evidence-delta-package.json` | Scanner retest evidence package refreshed for linked Scanner profile proof. |
| `.gitignored/test-artifacts/anvil-engine/anvil-custom-check-parity-package.json` | Anvil parity evidence package refreshed for linked Scanner profile proof. |
| `.gitignored/test-artifacts/install-docs-production-engine/install-docs-production-evidence-package.json` | Install docs production package refreshed against the updated Scanner schema/operator docs. |
| `.gitignored/test-artifacts/full-nightly-production-engine/full-nightly-production-evidence-package.json` | Full/nightly production package refreshed after the Scanner matrix update. |
| `.gitignored/test-artifacts/full-nightly-history-engine/full-nightly-retained-history-evidence-package.json` | Full/nightly retained-history package refreshed after the Scanner checkpoint. |
| `test-results/ci-fast-suite-summary.json` | CI-fast summary showing the 84/84 checkpoint pass and step timing for the Scanner package-refresh update. |

## 2026-05-26 Repeater Package Refresh Checkpoint

Command and result:

| Command | Result |
| --- | --- |
| `node tests/repeater-workspace-engine.mjs` | Passed. Repeater parity evidence now proves package-refresh digests and stale-package detection for manual request editing, manual send runtime, workspace tabs, saved request libraries, session profile injection, authorization matrices, transport controls, and bulk replay handoff while preserving full-fidelity executor secrets until report export. |
| `npm run build` | Passed. TypeScript accepts the expanded Repeater parity package-refresh types and renderer/Electron build; Vite completed with the existing chunk-size warning only. |
| `node tests/agent-option-audit.mjs` | Passed. The Codex/Claude/Vantix option audit still verifies all 70 agent commands, desync/race docs, secret boundary, and matrix gate after the Repeater package-refresh update. |
| `node tests/release-readiness.mjs` | Passed. Release checklist, packaged files, build outputs, ignored artifacts, and release docs remain synchronized. |
| `node tests/install-docs-production-engine.mjs` | Passed. Packaged install/operator/release/agent docs include the Repeater package-refresh and full-fidelity secret boundary updates. |
| `node tests/fast-regression-production-engine.mjs` | Passed. Fast Regression production evidence accepts the current fast-suite coverage and artifact policy. |
| `node tests/release-security-production-engine.mjs` | Passed. Release Security still accepts the full release surface with report-export-only redaction and executor secret preservation. |
| `node tests/full-nightly-production-engine.mjs` | Passed. Full/Nightly production evidence accepts the retained-history linkage and updated Repeater matrix evidence. |
| `node tests/full-nightly-history-engine.mjs` | Passed. Retained-history evidence accepts the current runtime summary dashboard and digest integrity. |
| `npm run test:ci:fast` | Passed 84/84 steps in 270122ms, including Repeater workspace package-refresh proof, Repeater transport/OAST/desync/race coverage, agentic control CLI smoke with replay/bulk replay/desync/race/scanner/exploit/report/Vantix commands, release/security/doc/package gates, and focused browser workflow smoke. |

Ignored evidence artifacts refreshed:

| Path | Purpose |
| --- | --- |
| `test-results/ci-fast-suite-summary.json` | CI-fast summary showing the 84/84 checkpoint pass and step timing for the Repeater package-refresh update. |
| `.gitignored/test-artifacts/repeater-workspace-engine/repeater-parity-evidence-package.json` | Repeater parity package proving linked Repeater package refresh digests, stale-package checks, raw executor material, and report-export-only redaction. |
| `.gitignored/test-artifacts/install-docs-production-engine/install-docs-production-evidence-package.json` | Install docs production package refreshed against the updated Repeater schema/operator docs. |
| `.gitignored/test-artifacts/full-nightly-production-engine/full-nightly-production-evidence-package.json` | Full/nightly production package refreshed after the Repeater matrix update. |
| `.gitignored/test-artifacts/full-nightly-history-engine/full-nightly-retained-history-evidence-package.json` | Full/nightly retained-history package refreshed after the Repeater checkpoint. |

## 2026-05-26 Target Package Refresh Checkpoint

Command and result:

| Command | Result |
| --- | --- |
| `node tests/target-map-engine.mjs` | Passed. Target evidence now proves package-refresh digests for content-discovery source routes/candidates, access-control role maps/decisions, analyzer inventory, baseline/candidate/delta site-map comparison, report attachment linkage, and top-level Target parity stale-package detection. |
| `npm run build` | Passed. TypeScript accepts the expanded Target package-refresh types and renderer/Electron build; Vite completed with the existing chunk-size warning only. |
| `node tests/agent-option-audit.mjs` | Passed. The Codex/Claude/Vantix option audit still verifies all 70 agent commands, desync/race docs, secret boundary, and matrix gate after the Target package-refresh update. |
| `node tests/release-readiness.mjs` | Passed. Release checklist, packaged files, build outputs, ignored artifacts, and release docs remain synchronized. |
| `node tests/install-docs-production-engine.mjs` | Passed. Packaged install/operator/release/agent docs include the Target package-refresh and full-fidelity secret boundary updates. |
| `node tests/fast-regression-production-engine.mjs` | Passed. Fast Regression production evidence accepts the current fast-suite coverage and artifact policy. |
| `node tests/release-security-production-engine.mjs` | Passed. Release Security still accepts the full release surface with report-export-only redaction and executor secret preservation. |
| `node tests/full-nightly-production-engine.mjs` | Passed. Full/Nightly production evidence accepts the retained-history linkage and updated Target matrix evidence. |
| `npm run test:ci:fast` | Passed 84/84 steps in 271344ms, including Target access-control/comparison package-refresh proof, agentic control CLI smoke with content discovery and Target access/comparison commands, release/security/doc/package gates, and focused browser workflow smoke. |

Ignored evidence artifacts refreshed:

| Path | Purpose |
| --- | --- |
| `test-results/ci-fast-suite-summary.json` | CI-fast summary showing the 84/84 checkpoint pass and step timing for the Target package-refresh update. |
| `.gitignored/test-artifacts/target-map-engine/target-parity-evidence-package.json` | Target parity package proving linked Target package refresh digests, stale-package checks, raw executor material, and report-export-only redaction. |
| `.gitignored/test-artifacts/install-docs-production-engine/install-docs-production-evidence-package.json` | Install docs production package refreshed against the updated Target schema/operator docs. |
| `.gitignored/test-artifacts/full-nightly-production-engine/full-nightly-production-evidence-package.json` | Full/nightly production package refreshed after the Target matrix update. |

## 2026-05-26 Logger custom column Edge Helper Checkpoint

Command and result:

| Command | Result |
| --- | --- |
| `node tests/logger-column-engine.mjs` | Passed. Logger custom columns now exercise request/response body predicates, request JSON/jsonPath helpers, URL/base64 helper transforms, cookies, path helpers, full-fidelity bearer/API-key/cookie material, compatibility fixture package refresh digests, operational secret signals, and report-export-only redaction. |
| `node tests/logger-evidence-engine.mjs` | Passed. Logger parity evidence now requires custom column package-refresh coverage in addition to tool-generated traffic capture, archive import/review, saved filters, attachments, full-fidelity raw material, and report-phase-only redaction. |
| `npm run build` | Passed. TypeScript accepts the expanded Logger column/evidence package types and the renderer/Electron build; Vite completed with the existing chunk-size warning only. |
| `node tests/release-readiness.mjs` | Passed. Release checklist, packaged files, build outputs, ignored artifacts, and release docs remain synchronized. |
| `node tests/install-docs-production-engine.mjs` | Passed. Packaged install/operator/release/agent docs include the Logger custom column package-refresh and full-fidelity secret boundary updates. |
| `node tests/agent-option-audit.mjs` | Passed. The Codex/Claude/Vantix option audit still verifies all 70 agent commands, desync/race docs, secret boundary, and matrix gate after the Logger update. |
| `node tests/release-security-production-engine.mjs` | Passed. Release Security still accepts the full agent/release surface with report-export-only redaction and executor secret preservation. |
| `node tests/fast-regression-production-engine.mjs` | Passed. Fast Regression production evidence accepts the current fast-suite coverage and artifact policy. |
| `npm run test:ci:fast` | Passed 84/84 steps in 251832ms, including Logger custom column compatibility, Logger parity evidence, agentic control CLI smoke with persistent MITM/Chromium/replay/intruder/desync/race/scanner/Anvil/callback/exploit/report/Vantix handoff, release/security/doc/package gates, and focused browser workflow smoke. |

Ignored evidence artifacts refreshed:

| Path | Purpose |
| --- | --- |
| `test-results/ci-fast-suite-summary.json` | CI-fast summary showing the 84/84 checkpoint pass and step timing for the Logger custom column edge helper update. |
| `.gitignored/test-artifacts/logger-evidence-engine/logger-parity-evidence-package.json` | Logger parity package proving custom column package-refresh coverage, archive review, raw material, and report-export-only redaction. |
| `.gitignored/test-artifacts/agent-control-production-engine/agent-control-production-evidence-package.json` | Agent Control production package refreshed by fast CI after the Logger capability update. |
| `.gitignored/test-artifacts/install-docs-production-engine/install-docs-production-evidence-package.json` | Install docs production package refreshed against the updated Logger schema/operator docs. |

## 2026-05-26 Search Live Provider Invocation Checkpoint

Command and result:

| Command | Result |
| --- | --- |
| `npm run build` | Passed. TypeScript accepts the `search-index --provider-url --execute` live semantic provider path, the Agent Control production proof update, and the renderer/Electron build; Vite completed with the existing chunk-size warning only. |
| `node --check scripts/proxyforge-agent.mjs` | Passed. The agent wrapper syntax accepts the live search provider planner/executor helpers. |
| `node --check tests/agent-cli.mjs` | Passed. The agent CLI fixture coverage syntax accepts the live semantic provider route and package assertions. |
| `node tests/agent-cli.mjs` | Passed. The agent CLI now exercises `search-index --provider-url` dry plans with zero traffic, then scoped `--execute` provider calls that preserve the full semantic corpus, provider Authorization/API-key/cookie credentials, raw provider requests/responses, provider-ranked matches, and report-export-only redaction. |
| `node tests/agent-control-production-engine.mjs` | Passed. Agent Control production evidence now includes search live-provider ranking proof inside the existing 70-command surface. |
| `node tests/agent-option-audit.mjs` | Passed. The Codex/Claude/Vantix option audit still verifies all 70 agent commands, with the new provider invocation documented as a `search-index` execution mode. |
| `node tests/release-security-production-engine.mjs` | Passed. Release Security still accepts the agent-control surface and full-fidelity secret boundary after adding provider-ranking traffic. |
| `node tests/release-readiness.mjs` | Passed. Release checklist, operator guide, agent docs, schemas, packaged files, and packaged-smoke requirements remain synchronized. |
| `node tests/install-docs-production-engine.mjs` | Passed. Packaged install/operator/release/agent docs include the live semantic provider workflow and full-fidelity executor boundary. |
| `node tests/fast-regression-production-engine.mjs` | Passed. Fast Regression production evidence accepts the current fast-suite coverage and artifact policy. |
| `node tests/full-nightly-production-engine.mjs` | Passed. Full/Nightly production evidence accepts the retained-history linkage after the search provider update. |
| `node tests/full-nightly-history-engine.mjs` | Passed. Retained history evidence still validates retained runtime summaries, dashboard linkage, digest integrity, and report-export-only redaction. |
| `npm run test:ci:fast` | Passed 84/84 steps in 256998ms, including Agentic control CLI smoke with `search/index/live-provider/view`, the 70-command Agent Control and option audit gates, release/security/doc/package gates, Release Trust, AI Provider, Automation scheduler/service lifecycle, Proxy, Scanner, Repeater/Intruder, Reports, and focused browser workflow smoke. |
| `git diff --check` | Passed after the checkpoint docs update. No whitespace errors in the changed source, tests, or docs. |

Ignored evidence artifacts refreshed:

| Path | Purpose |
| --- | --- |
| `test-results/ci-fast-suite-summary.json` | CI-fast summary showing the 84/84 checkpoint pass and step timing for the search live provider update. |
| `.gitignored/test-artifacts/agent-control-production-engine/agent-control-production-evidence-package.json` | Agent Control production package proving the current 70-command Codex/Claude/Vantix source and packaged command surface, including search live-provider ranking proof. |
| `.gitignored/test-artifacts/install-docs-production-engine/install-docs-production-evidence-package.json` | Install docs production package refreshed against the updated release evidence and agent docs. |
| `.gitignored/test-artifacts/full-nightly-production-engine/full-nightly-production-evidence-package.json` | Full/nightly production package refreshed against the retained dashboard and current command surface. |
| `.gitignored/test-artifacts/full-nightly-history-engine/full-nightly-retained-history-evidence-package.json` | Retained-history package refreshed after the search provider workflow update. |

## 2026-05-26 Agent Live Target Profiling Checkpoint

Command and result:

| Command | Result |
| --- | --- |
| `npm run build` | Passed. TypeScript accepts the new `live-target-profile` agent command, the 70-command Agent Control surface, Release Security command-count checks, and the renderer/Electron build; Vite completed with the existing chunk-size warning only. |
| `node --check scripts/proxyforge-agent.mjs` | Passed. The agent wrapper syntax accepts the live target profiling planner/executor helpers. |
| `node --check tests/agent-cli.mjs` | Passed. The agent CLI fixture coverage syntax accepts the live target manifest and raw traffic assertions. |
| `node tests/agent-cli.mjs` | Passed. The agent CLI now exercises `live-target-profile` dry plans and scoped execution packages with host/route/status diversity, Scanner candidates, Intruder marked raw requests, replay handoff commands, raw requests/responses, bearer tokens, cookies, and API keys preserved until reporting. |
| `node tests/agent-option-audit.mjs` | Passed. The Codex/Claude/Vantix option audit verifies all 70 agent commands, including `live-target-profile`, desync/race docs, full-fidelity executor handling, and matrix coverage. |
| `node tests/agent-control-production-engine.mjs` | Passed. Agent Control production evidence proves the packaged 70-command source/packaged command surface with live target profiling coverage, long-running soaks, active workflow policy, and report-export-only redaction. |
| `node tests/release-security-production-engine.mjs` | Passed. Release Security accepts the 70-command agent-control surface with live target profiling while preserving exploit controls, local listener review, platform pins, signed trust, and report-export-only redaction. |
| `node tests/release-readiness.mjs` | Passed. Release checklist, operator guide, agent docs, schemas, packaged files, and packaged-smoke requirements reference the 70-command `live-target-profile` surface. |
| `node tests/install-docs-production-engine.mjs` | Passed. Packaged install/operator/release/agent docs remain synchronized with the 70-command surface and live target profiling workflow. |
| `node tests/fast-regression-production-engine.mjs` | Passed. Fast Regression production evidence accepts the live target profiling command and the current agent-control command surface. |
| `node tests/full-nightly-production-engine.mjs` | Passed. Full/Nightly production evidence accepts the current command surface and retained-history linkage after the live target profiling update. |
| `node tests/full-nightly-history-engine.mjs` | Passed. Retained history evidence still validates retained runtime summaries, dashboard linkage, digest integrity, and report-export-only redaction after the command-surface update. |
| `npx playwright test tests/proxyforge.spec.ts -g 'search\|automation\|extension'` | Passed 8/8 after raising the Playwright global timeout to 60s for the large-app Search cold-load path; the focused browser smoke completed in 1.1m on the default dev-server port. |
| `npm run test:ci:fast` | Passed 84/84 steps in 252064ms, including Agentic control CLI smoke with live target profiling, the 70-command Agent Control and option audit gates, release/security/doc/package gates, Release Trust, AI Provider, Automation scheduler/service lifecycle, Proxy, Scanner, Repeater/Intruder, Reports, and focused browser workflow smoke. |

Ignored evidence artifacts refreshed:

| Path | Purpose |
| --- | --- |
| `test-results/ci-fast-suite-summary.json` | CI-fast summary showing the 84/84 checkpoint pass and step timing for the live target profiling update. |
| `.gitignored/test-artifacts/agent-control-production-engine/agent-control-production-evidence-package.json` | Agent Control production package proving the current 70-command Codex/Claude/Vantix source and packaged command surface, including live target profiling. |
| `.gitignored/test-artifacts/release-security-production-engine/release-security-production-evidence-package.json` | Release Security production package refreshed against the 70-command agent-control surface. |
| `.gitignored/test-artifacts/install-docs-production-engine/install-docs-production-evidence-package.json` | Install docs production package refreshed against the updated release evidence and agent docs. |
| `.gitignored/test-artifacts/full-nightly-production-engine/full-nightly-production-evidence-package.json` | Full/nightly production package refreshed against the retained dashboard and current command surface. |
| `.gitignored/test-artifacts/full-nightly-history-engine/full-nightly-retained-history-evidence-package.json` | Retained-history package refreshed after the agent command-surface update. |

## 2026-05-26 OAST Provider Host Agent Proof Checkpoint

Command and result:

| Command | Result |
| --- | --- |
| `npm run build` | Passed. TypeScript accepts the new `callback-provider-probe` agent command, the 69-command Agent Control surface, Release Security command-count checks, and the renderer/Electron build; Vite completed with the existing chunk-size warning only. |
| `node tests/agent-cli.mjs` | Passed. The agent CLI now exercises callback provider host proof with scoped provider manifests, bearer-token-preserving ingest/poll requests, signed raw poll responses, callback payload tokens, and report-export-only redaction. |
| `node tests/agent-option-audit.mjs` | Passed. The Codex/Claude/Vantix option audit verifies all 69 agent commands, including `callback-provider-probe`, desync/race docs, full-fidelity executor handling, and matrix coverage. |
| `node tests/agent-control-production-engine.mjs` | Passed. Agent Control production evidence proves the packaged 69-command source/packaged command surface with callback provider host proof coverage. |
| `node tests/release-security-production-engine.mjs` | Passed. Release Security accepts the 69-command agent-control surface with callback provider host proof while preserving exploit controls, local listener review, platform pins, signed trust, and report-export-only redaction. |
| `node tests/release-readiness.mjs` | Passed. Release checklist, operator guide, agent docs, schemas, packaged files, and packaged-smoke requirements reference the new callback provider host proof command. |
| `node tests/install-docs-production-engine.mjs` | Passed. Packaged install/operator/release/agent docs remain synchronized with the 69-command surface and callback provider host proof workflow. |
| `node tests/fast-regression-production-engine.mjs` | Passed. Fast Regression production evidence accepts the new agent-control command and callback provider host proof coverage. |
| `node tests/full-nightly-production-engine.mjs` | Passed. Full/Nightly production evidence accepts the current command surface and retained-history linkage after the provider-host proof update. |
| `node tests/full-nightly-history-engine.mjs` | Passed. Retained history evidence still validates retained runtime summaries, dashboard linkage, digest integrity, and report-export-only redaction after the command-surface update. |
| `git diff --check` | Passed before this checkpoint update. No whitespace errors in the changed source, tests, or docs. |
| `npm run test:ci:fast` | Passed 84/84 steps in 202006ms, including Agentic control CLI smoke with callback provider host proof, the 69-command Agent Control and option audit gates, release/security/doc/package gates, Release Trust, AI Provider, Automation scheduler/service lifecycle, Proxy, Scanner, Repeater/Intruder, Reports, and focused browser workflow smoke. |

Ignored evidence artifacts refreshed:

| Path | Purpose |
| --- | --- |
| `test-results/ci-fast-suite-summary.json` | CI-fast summary showing the 84/84 checkpoint pass and step timing for the callback provider host proof update. |
| `.gitignored/test-artifacts/agent-control-production-engine/agent-control-production-evidence-package.json` | Agent Control production package proving the current 69-command Codex/Claude/Vantix source and packaged command surface, including callback provider host proof. |
| `.gitignored/test-artifacts/full-nightly-production-engine/full-nightly-production-evidence-package.json` | Full/nightly production package refreshed against the retained dashboard and current command surface. |
| `.gitignored/test-artifacts/full-nightly-history-engine/full-nightly-retained-history-evidence-package.json` | Retained-history package refreshed after the agent command-surface update. |

## 2026-05-26 Full/Nightly Retained History Refresh Checkpoint

Command and result:

| Command | Result |
| --- | --- |
| `gh workflow run nightly-full-suite.yml --repo the-vibe-dev/proxyforge --ref main -f plan_only=false -f skip_browser=true` | GitHub returned HTTP 500 (`Failed to run workflow dispatch`) on the latest pushed `main`; this is recorded as a hosted-dispatch failure, not as hosted retained-history proof. |
| `gh api --method POST repos/the-vibe-dev/proxyforge/actions/workflows/nightly-full-suite.yml/dispatches -f ref=main -F inputs[plan_only]=false -F inputs[skip_browser]=true --silent` | GitHub returned HTTP 500 again through the REST dispatch endpoint. Local production proof continued; scheduled hosted retained history remains the release-wide blocker. |
| `npm run test:ci:full -- --skip-browser` | Passed 81/81 steps in 174830ms on the current `9bc3e5d` code, including Automation installed-host service smoke and the 69-command agent surface. The run wrote `test-results/ci-full-suite-history/local-2026-05-26T11-30-13-639Z-summary.json` and refreshed `test-results/ci-full-suite-history/dashboard.json`. |
| `node tests/full-nightly-production-engine.mjs` | Passed. Full/nightly production evidence accepts the refreshed 81-step plan, latest runtime pass, retained trend dashboard, scheduled restore/save policy, and full-fidelity secret boundary. |
| `node tests/full-nightly-history-engine.mjs` | Passed. Retained-history evidence accepts the refreshed dashboard, current-run linkage, digest integrity, plan-only exclusion, and report-export-only redaction boundary. |
| `node tests/fast-regression-production-engine.mjs` | Passed. Fast Regression production evidence still verifies broad production fast-suite coverage and retained-history linkage after the local full/nightly refresh. |
| `node tests/release-readiness.mjs` | Passed. Release scripts, builder targets, build outputs, ignored artifacts, and checklist policy remain valid after the refreshed runtime history. |

Retained history dashboard after the run:

| Metric | Value |
| --- | ---: |
| Retained runtime runs | 5 |
| Full browser-backed runs | 1 |
| Skip-browser runtime runs | 4 |
| Passed retained runs | 5 |
| Failed retained runs | 0 |
| Consecutive runtime passes | 5 |
| Latest runtime run | `local-2026-05-26T11-30-13-639Z` |
| Latest runtime steps | 81/81 |
| Latest runtime duration | 174830ms |
| Median runtime duration | 171397ms |

Ignored/runtime evidence refreshed:

| Path | Purpose |
| --- | --- |
| `test-results/ci-full-suite-summary.json` | Current local full/nightly skip-browser runtime summary with 81/81 passed steps. |
| `test-results/ci-full-suite-history/local-2026-05-26T11-30-13-639Z-summary.json` | Retained runtime summary for the current 81-step pass. |
| `test-results/ci-full-suite-history/dashboard.json` | Retained trend dashboard showing 5 retained runtime passes, 0 failures, and 5 consecutive runtime passes. |
| `.gitignored/test-artifacts/full-nightly-production-engine/full-nightly-production-evidence-package.json` | Full/nightly production package refreshed against the current retained dashboard. |
| `.gitignored/test-artifacts/full-nightly-history-engine/full-nightly-retained-history-evidence-package.json` | Retained-history package refreshed against the current 5-run retained trend. |

## 2026-05-26 Automation Installed-Host Service Smoke Checkpoint

Command and result:

| Command | Result |
| --- | --- |
| `npm run build` | Passed. TypeScript accepts `scripts/proxyforge-automation-service.mjs`, the 69-command agent surface, and the renderer/Electron build; Vite completed with the existing chunk-size warning only. |
| `node tests/automation-service-smoke.mjs` | Passed. Verified direct service start/status/stop smoke, durable `status.json`, scheduler state, JSONL logs, agent `automation-service-smoke`, full-fidelity operational token/cookie/API-key samples, and report-export-only redaction. |
| `node tests/agent-cli.mjs` | Passed. The agent CLI still exercises Automations list/run/CI/scheduler/parity/service lifecycle plus the broader MITM, search, replay, Intruder, Scanner, Anvil, extension, callback, exploit, report, and Vantix handoff surface. |
| `node tests/agent-option-audit.mjs` | Passed. The audit verifies the 69-command Codex/Claude/Vantix surface, including `automation-service-smoke`, desync/race docs, the full-fidelity executor boundary, and the matrix gate. |
| `node tests/agent-control-production-engine.mjs` | Passed. Agent Control production evidence now proves the packaged 69-command source/packaged command surface with Automation installed-host service smoke coverage. |
| `node tests/release-security-production-engine.mjs` | Passed. Release Security now accepts the 69-command agent-control surface while keeping exploit controls, local listener review, platform pins, signed trust, and report-export-only redaction green. |
| `node tests/release-readiness.mjs` | Passed. Release checklist, operator guide, agent docs, schemas, packaged files, and packaged-smoke requirements reference `automation-service-smoke` and the 69-command surface. |
| `node tests/install-docs-production-engine.mjs` | Passed. Packaged install/operator/release/agent docs remain synchronized with the Automation installed-host service smoke package and agent command. |
| `node tests/fast-regression-production-engine.mjs` | Passed. Fast Regression production evidence now requires the Automation installed-host service smoke step. |
| `node tests/full-nightly-production-engine.mjs` | Passed. Full/Nightly production evidence now links the Automation installed-host service smoke step and fast-suite linkage. |
| `node tests/full-nightly-history-engine.mjs` | Passed. Retained history evidence now keeps Automation installed-host service smoke as a required retained production step. |
| `git diff --check` | Passed. No whitespace errors in the changed files. |
| `npm run test:ci:fast` | Passed 84/84 steps in 209689ms, including the new Automation installed-host service smoke, 69-command Agent Control and option audit gates, release/security/doc/package gates, Release Trust, AI Provider, Automation scheduler/service lifecycle, Proxy, Scanner, Repeater/Intruder, Reports, and focused browser workflow smoke. |

Ignored evidence artifacts refreshed:

| Path | Purpose |
| --- | --- |
| `.gitignored/test-artifacts/automation-service-smoke/agent-service-smoke-package.json` | Agent-facing installed-host Automation service smoke package proving detached Node runner start/status/stop, scheduler tick execution, durable status/state/log files, full-fidelity operational samples, and report-export-only redaction. |
| `.gitignored/test-artifacts/agent-control-production-engine/agent-control-production-evidence-package.json` | Agent Control production package proving the current 69-command Codex/Claude/Vantix source and packaged command surface. |
| `test-results/ci-fast-suite-summary.json` | CI-fast summary showing the 84/84 checkpoint pass and step timing. |

## 2026-05-26 Release Trust Production Evidence Checkpoint

Command and result:

| Command | Result |
| --- | --- |
| `npm run build` | Passed. TypeScript accepts `ReleaseTrustProductionEvidencePackage`, the release-trust generator integration, and the renderer/Electron build; Vite completed with the existing chunk-size warning only. |
| `node tests/release-trust-production-engine.mjs` | Passed. The new gate emits `proxyforge-release-trust-production-evidence-package` coverage for package-lock-derived SBOM, dependency integrity, license/dependency review policy, source/build/docs/workflow SHA-256 checksums, SLSA-lite provenance, signing/notarization state pins, verification commands, 30-day artifact retention, full-fidelity operational samples, and report-export-only redaction. |
| `node scripts/release-trust.mjs --out .gitignored/test-artifacts/release-trust-cli` | Passed. Generated `release-trust-manifest.json`, `release-trust-sbom.json`, `release-trust-checksums.json`, and `release-trust-provenance.json` with 376 lockfile components and 14 artifact digests including `LICENSE`. |
| `node tests/release-readiness.mjs` | Passed. Release checklist, operator guide, agent schema docs, package scripts, and packaged files now include release-trust coverage. |
| `node tests/release-security-production-engine.mjs` | Passed. Release Security remains green with the release-trust gate added beside security/signing/artifact hygiene coverage. |
| `node tests/fast-regression-production-engine.mjs` | Passed. Fast Regression production evidence now requires the Release Trust production evidence step. |
| `node tests/full-nightly-production-engine.mjs` | Passed. Full/Nightly production evidence now links the Release Trust production evidence step and fast-suite linkage. |
| `node tests/full-nightly-history-engine.mjs` | Passed. Retained history evidence now keeps Release Trust as a required retained production step. |
| `git diff --check` | Passed. No whitespace errors in the changed files. |
| `npm run test:ci:fast` | Passed 83/83 steps in 199247ms, including the new Release Trust production evidence engine, release/security/doc/package gates, Agent Control, AI Provider, Automation service lifecycle, Proxy, Scanner, Repeater/Intruder, Reports, and focused browser workflow smoke. |

Ignored evidence artifacts refreshed:

| Path | Purpose |
| --- | --- |
| `.gitignored/test-artifacts/release-trust-production-engine/release-trust-production-evidence-package.json` | Release Trust production package tying SBOM, checksums, provenance, signing/notarization state, retention, full-fidelity executor samples, and report-export redaction. |
| `.gitignored/test-artifacts/release-trust-production-engine/release-trust-sbom.json` | Package-lock-derived SBOM snapshot used by the production evidence gate. |
| `.gitignored/test-artifacts/release-trust-production-engine/release-trust-checksums.json` | SHA-256 checksum manifest for source, lockfile, scripts, build outputs, docs, and workflow files. |
| `.gitignored/test-artifacts/release-trust-production-engine/release-trust-provenance.json` | SLSA-lite provenance statement linking materials and build subjects. |
| `.gitignored/test-artifacts/release-trust-cli/` | Direct CLI output proving `scripts/release-trust.mjs` can generate the same trust manifests outside the test harness. |
| `test-results/ci-fast-suite-summary.json` | CI-fast summary showing the 83/83 checkpoint pass and step timing. |

## 2026-05-26 Automation Service Lifecycle / Agent Surface Checkpoint

Command and result:

| Command | Result |
| --- | --- |
| `npm run build` | Passed. TypeScript accepts `AutomationServiceLifecyclePackage`, the Automation engine package builder, and the 67-command agent surface; Vite completed with the existing chunk-size warning only. |
| `node tests/automation-engine.mjs` | Passed. Automation now emits `proxyforge-automation-service-lifecycle-package` evidence covering Linux systemd user and Windows Task Scheduler install/start/status/stop/uninstall plans, scheduler tick commands, durable state/log paths, restart policy, secret environment names, package refresh proof, raw operational tokens/cookies/API keys, and report-export-only redaction. |
| `node tests/agent-cli.mjs` | Passed. The agent CLI exercised `automation-service-plan` alongside Automations list/run/CI/scheduler/parity, preserving full-fidelity operational material until report export. |
| `node tests/agent-option-audit.mjs` | Passed. The audit verifies the 67-command Codex/Claude/Vantix surface, including `automation-service-plan`, desync/race docs, the full-fidelity executor boundary, and the matrix gate. |
| `node tests/agent-control-production-engine.mjs` | Passed. Agent Control production evidence now proves the packaged 67-command source/packaged command surface with Automation service lifecycle coverage. |
| `node tests/release-readiness.mjs` | Passed. Release checklist, operator guide, agent docs, and packaged-smoke requirements reference the 67-command surface and `automation-service-plan`. |
| `node tests/release-security-production-engine.mjs` | Passed. Release Security now accepts the 67-command agent-control surface while keeping exploit controls, local listener review, platform pins, and report-export-only redaction green. |
| `node tests/install-docs-production-engine.mjs` | Passed. Packaged install/operator/release/agent docs remain synchronized with the Automation service lifecycle package and agent command. |
| `node tests/fast-regression-production-engine.mjs` | Passed. The production fast-suite evidence gate accepts the new agent-control and Automation lifecycle coverage. |
| `git diff --check` | Passed. No whitespace errors in the changed files. |
| `npm run test:ci:fast` | Passed 82/82 steps in 202627ms, including the 67-command Agent Control production gate, Agent option audit, Automation scheduler/service lifecycle engine, agent CLI smoke, release/security/doc/package gates, Proxy, Scanner, Repeater/Intruder, Reports, and focused browser workflow smoke. |

Ignored evidence artifacts refreshed:

| Path | Purpose |
| --- | --- |
| `.gitignored/test-artifacts/automation-engine/automation-service-lifecycle-package.json` | Automation service lifecycle package linking Linux systemd user and Windows Task Scheduler service plans, scheduler tick commands, durable state/log paths, secret environment names, raw operational samples, and report-export redaction. |
| `.gitignored/test-artifacts/agent-control-production-engine/agent-control-production-evidence-package.json` | Agent Control production package proving the current 67-command Codex/Claude/Vantix source and packaged command surface. |
| `test-results/ci-fast-suite-summary.json` | CI-fast summary showing the 82/82 checkpoint pass and step timing. |

## 2026-05-26 Repeater Race/Desync Production Checkpoint

Command and result:

| Command | Result |
| --- | --- |
| `npm run build` | Passed. TypeScript accepts `RepeaterRaceDesyncProductionPackage`, the production package builder, and the renderer/Electron build. |
| `node tests/repeater-desync-race-engine.mjs` | Passed. The Repeater desync/race fixture now emits `proxyforge-repeater-race-desync-production-package` evidence linking parser-differential framing, socket-backed single-connection proof, last-byte race proof, single-packet race soak proof, scope-blocked execution, release-skew/race-window budgets, response ordering, raw transcript preservation, operational Authorization/Cookie/API-key material, package-refresh digests, and report-export-only redaction. |
| `node tests/release-readiness.mjs` | Passed. Release readiness now guards the Repeater race/desync production package in the operator guide and agent schemas. |
| `node tests/install-docs-production-engine.mjs` | Passed. Packaged operator, release checklist, release evidence, and agent schema docs remain synchronized with the new Repeater production package. |
| `npm run test:ci:fast` | Passed 82/82 steps in 192724ms, including the new Repeater race/desync production package inside `node tests/repeater-desync-race-engine.mjs`, Repeater workspace/OAST/transport lanes, Intruder, agent CLI, release/security/doc/package gates, Proxy, Scanner, Reports, and focused browser workflow smoke. |

Ignored evidence artifacts refreshed:

| Path | Purpose |
| --- | --- |
| `.gitignored/test-artifacts/repeater-desync-race-engine/repeater-race-desync-production-package.json` | Repeater race/desync production package linking parser plans, runtime proof, soak proof, blocked scope proof, budget checks, raw transcripts, secret signals, and report-export redaction. |

## 2026-05-26 Report Production Readiness Checkpoint

Command and result:

| Command | Result |
| --- | --- |
| `npm run build` | Passed. TypeScript accepts `ReportProductionReadinessPackage`, semantic report HTML/PDF structure, and JSON-stable signed bundle generation. |
| `node tests/report-engine.mjs` | Passed. The report export fixture emits `proxyforge-report-production-readiness-package` evidence covering renderer comparison, local/external signed bundle interoperability, JSON canonicalization, accessibility/tag readiness, 200 retained exchanges, 220 normalized report attachments, large-PDF warnings, full-fidelity pre-export inputs, and report-export-only redaction. |
| `node tests/report-pdf-visual-qa.mjs` | Passed. Rendered PDF HTML still produces nonblank PNG output, page-break probes, and redacted PDF HTML. |
| `node tests/install-docs-production-engine.mjs` | Passed. Operator, release checklist, release evidence, and agent schema docs remain synchronized with the report production readiness package. |
| `node tests/release-readiness.mjs` | Passed. Release scripts, build outputs, ignored artifacts, and checklist policy remain valid. |
| `node tests/fast-regression-production-engine.mjs` | Passed. The production fast-suite evidence gate accepts the Reports production-readiness lane and full-fidelity secret boundary. |
| `node tests/release-security-production-engine.mjs` | Passed. Release security evidence still covers platform pins, CI gates, agent/AI controls, and report-export-only secret handling. |
| `node tests/full-nightly-production-engine.mjs` | Passed. Full/nightly production evidence still covers the retained history plan and broad suite linkage. |
| `npm run test:ci:fast` | Passed 82/82 steps in 195693ms, including the new report production readiness package inside `node tests/report-engine.mjs`, PDF visual QA, agent CLI, release/security/doc/package gates, Scanner, Repeater/Intruder, Proxy, WebSocket, OAST, Exploit, and focused browser workflow smoke. |

Ignored evidence artifacts refreshed:

| Path | Purpose |
| --- | --- |
| `.gitignored/test-artifacts/report-engine/report-parity-evidence-package.json` | Report parity evidence package covering Markdown, HTML, JSON, PDF HTML, bundle export, signing, and report redaction. |
| `.gitignored/test-artifacts/report-engine/report-production-readiness-package.json` | Production readiness evidence package covering renderer comparison, external signed bundle verification/tamper rejection, accessibility review, long-project scale, large-PDF warning, and report-phase-only redaction. |

## 2026-05-26 Proxy Edge Profile Checkpoint

Command and result:

| Command | Result |
| --- | --- |
| `npm run build` | Passed. TypeScript accepts `ProxyEdgeProfilePackage`, the expanded Proxy history engine export, and the production renderer/Electron build. |
| `node tests/proxy-history-engine.mjs` | Passed. The Proxy history fixture now exercises 11 helpers and emits `proxyforge-proxy-edge-profile-package` evidence linking HTTP listener capture, CONNECT tunnel metadata, HTTPS MITM, intercept controls, match/replace, HTTP/2 fidelity and multiplexing, Proxy-to-Repeater/Scanner/Reports handoff, WebSocket capture/intercept/state packages, browser-routing/proxy-chain proof, package-refresh digests, full-fidelity executor secrets, and report-export-only redaction. |
| `node tests/proxy-listener-engine.mjs` | Passed. HTTP listener capture, streamed/chunked pass-through, proxy-chain forwarding, and full-fidelity Authorization/Cookie/API-key preservation remain covered. |
| `node tests/connect-tunnel.mjs` | Passed. CONNECT success/failure/proxy-chain tunnel byte accounting and close metadata remain covered. |
| `node tests/https-mitm.mjs` | Passed. Project CA generation, decrypted HTTPS capture, strict-upstream failure evidence, and agent MITM status remain covered. |
| `node tests/intercept-engine.mjs` | Passed. Request/response hold, edit, forward, drop, match/replace, and exported intercept evidence remain covered. |
| `node tests/websocket-engine.mjs` | Passed. WebSocket capture, intercept/rewrite/replay, state graph, transcript import/export, and full-fidelity payload handling remain covered. |
| `node tests/install-docs-production-engine.mjs` | Passed. Operator, release checklist, release evidence, and agent schema docs remain synchronized with the Proxy edge package. |
| `node tests/release-readiness.mjs` | Passed. Release scripts, build outputs, ignored artifacts, and checklist policy remain valid. |
| `node tests/fast-regression-production-engine.mjs` | Passed. The production fast-suite evidence gate accepts the Proxy edge profile lane and full-fidelity secret boundary. |
| `node tests/release-security-production-engine.mjs` | Passed. Release security evidence still covers local listener controls, platform pins, CI gates, agent/AI controls, and report-export-only secret handling. |
| `node tests/full-nightly-production-engine.mjs` | Passed. Full/nightly production evidence still covers the retained history plan and broad suite linkage. |
| `npm run test:ci:fast` | Passed 82/82 steps in 207493ms, including the new Proxy edge profile package inside `node tests/proxy-history-engine.mjs`, Proxy listener/CONNECT/MITM/intercept/WebSocket lanes, agent CLI, release/security/doc/package gates, Scanner, Repeater/Intruder, Reports, and focused browser workflow smoke. |

Ignored evidence artifacts refreshed:

| Path | Purpose |
| --- | --- |
| `.gitignored/test-artifacts/proxy-history-filter-set-1779788765747-846822/proxy-edge-profile-package.json` | Proxy edge profile package linking listener, CONNECT, MITM, intercept, match/replace, HTTP/2, WebSocket, browser-proxy-chain, package-refresh, and secret-boundary proof. |
| `.gitignored/test-artifacts/proxyforge-websocket-1779788766626-846859/` | WebSocket capture/intercept/state packages refreshed during the fast-suite Proxy lane. |

## 2026-05-26 Scanner Live-Target Profile Checkpoint

Command and result:

| Command | Result |
| --- | --- |
| `npm run build` | Passed. TypeScript accepts `ScannerLiveTargetProfilePackage` and the expanded Scanner active-scan engine export. |
| `node tests/scanner-active-scan-engine.mjs` | Passed. The Scanner active-scan fixture now exercises 9 helpers and emits `proxyforge-scanner-live-target-profile-package` evidence linking active scan packages, OAST issue promotion, Anvil compatibility, retest deltas, calibration soak metadata, host/route/status diversity, broad check-family depth, package-refresh digests, full-fidelity executor secrets, and report-export-only redaction. |
| `node tests/scanner-live-calibration.mjs` | Passed. The live calibration fixture still verifies vulnerable findings, hardened no-finding behavior, noisy error-page suppression, and Scanner tuning metadata. |
| `node tests/anvil-engine.mjs` | Passed. Anvil compatibility still covers plain-text rules, fixtures, headless custom-only runs, signed package review, Scanner handoff, and full-fidelity secret handling. |
| `node tests/scanner-retest-engine.mjs` | Passed. Retest evidence still covers fixed, regressed, still-vulnerable, and inconclusive outcomes with full-fidelity baseline/retest proof. |
| `node tests/install-docs-production-engine.mjs` | Passed. Operator, checklist, release evidence, and agent docs remain synchronized with the Scanner live-target profile package. |
| `node tests/release-readiness.mjs` | Passed. Release scripts, build outputs, ignored artifacts, and checklist policy remain valid. |
| `node tests/fast-regression-production-engine.mjs` | Passed. The production fast-suite evidence gate still covers Scanner, artifact policy, and full-fidelity secret boundaries. |
| `node tests/release-security-production-engine.mjs` | Passed. Release security evidence still covers platform pins, CI gates, and report-export-only secret handling after the Scanner package expansion. |
| `node tests/full-nightly-production-engine.mjs` | Passed. Full/nightly production evidence still covers the retained history plan and broad suite linkage. |
| `npm run test:ci:fast` | Passed 82/82 steps in 194078ms, including Scanner passive, active check-pack, crawl insertion, active evidence/profile, retest, Anvil, live calibration, agent CLI, release/security/doc/package gates, and focused browser workflow smoke. |

Ignored evidence artifacts refreshed:

| Path | Purpose |
| --- | --- |
| `.gitignored/test-artifacts/scanner-active-scan-engine/scanner-active-scan-evidence-package.json` | Active scan evidence package with plan/review/matrix/replay/report handoff. |
| `.gitignored/test-artifacts/scanner-active-scan-engine/scanner-live-target-profile-package.json` | Scanner production-hardening profile linking active scan, OAST, Anvil, retest, calibration, target diversity, and package-refresh proof. |

## 2026-05-26 Callback Report Round-Trip Checkpoint

Command and result:

| Command | Result |
| --- | --- |
| `npm run build` | Passed. The callback engine now exports `buildCallbackReportRoundTripPackage`, full report package manifests preserve external relay/provider package ids, and TypeScript accepts the expanded callback artifact manifest schema. |
| `node tests/callback-live-backend-engine.mjs` | Passed. The live backend fixture now exercises 12 callback helpers and emits `proxyforge-callback-report-roundtrip-package` evidence proving signed polls, Repeater/Scanner/Exploit replay packages, replay execution batches, lifecycle reviews, CI handoffs, relay soak packages, signed external relay integrations, provider diversity packages, and signed evidence packages survive full report package import while exported report content redacts operational secrets. |
| `node tests/oast-relay-integration.mjs` | Passed. The signed tenant-isolated external relay fixture still preserves HTTP/DNS/SMTP raw requests, responses, signatures, tenant isolation checks, and callback secrets until report export. |
| `node tests/oast-provider-diversity.mjs` | Passed. The generic HTTP, DNS webhook, and SMTP provider diversity fixture still preserves provider tokens, replay metadata, linked relay evidence, and report-export-only redaction boundaries. |
| `node tests/fast-regression-production-engine.mjs` | Passed. The production fast-suite evidence gate accepts the expanded callback report round-trip lane and full-fidelity secret boundary. |
| `node tests/release-security-production-engine.mjs` | Passed. Release security evidence still covers platform pins, CI gates, and report-export-only secret handling after the callback package expansion. |
| `node tests/install-docs-production-engine.mjs` | Passed. Packaged install/operator docs and release evidence remain in sync with the callback/OAST agent-facing docs. |
| `node tests/release-readiness.mjs` | Passed. Release scripts, build outputs, ignored artifacts, and checklist policy remain valid. |
| `npm run test:ci:fast` | Passed 82/82 steps in 193657ms, including callback live backend, OAST relay integration, OAST provider diversity, agent option audit, agentic CLI smoke, report export, release-security, install-docs, platform package evidence, and focused browser workflow smoke. |

Ignored artifacts refreshed:

| Path | Purpose |
| --- | --- |
| `.gitignored/test-artifacts/callback-live-backend/callback-report-roundtrip-package.json` | Round-trip evidence package proving full callback artifact preservation through report package import and redacted submission export. |
| `.gitignored/test-artifacts/callback-live-backend/collaborator-parity-evidence-package.json` | OAST parity package linking the new report round-trip evidence id. |
| `.gitignored/test-artifacts/oast-relay-integration/` | Signed relay integration fixture output. |
| `.gitignored/test-artifacts/oast-provider-diversity/` | Provider diversity fixture output. |

## 2026-05-26 Project Store Manifest Atomic Write Fix

Trigger and failure evidence:

| Source | Result |
| --- | --- |
| GitHub Actions run `26441983677` | Failed during `node tests/ci-full-suite.mjs --skip-browser` on commit `7fe2038`. The new retained-history restore step completed and the save/upload steps still ran. The failure was in `Proxy Project Store workflow engine`: concurrent manifest writes reused the same `manifest.json.<pid>.<Date.now>.tmp` name and one `rename()` hit `ENOENT`. |

Fix and local verification:

| Command | Result |
| --- | --- |
| `npm run build` | Passed after changing Project Store manifest temp paths to include `randomUUID()`. |
| `node tests/project-store-v2.mjs` | Passed. Added a forced same-timestamp concurrent manifest-touch regression with 12 parallel scope updates. |
| `node tests/proxy-project-store-workflow.mjs` | Passed. This is the exact workflow lane that failed on the GitHub runner. |
| `node tests/ci-full-suite.mjs --skip-browser` | Passed 79/79 steps in 168105ms. The local retained dashboard now records 4 consecutive runtime passes, 1 full browser-backed pass, 3 skip-browser passes, and 0 retained failures. |

Remote verification after the fix landed on `main`:

| Source | Result |
| --- | --- |
| GitHub Actions run `26442381257` | Passed on commit `fb2a428bae0ae71aa1fd8152a6bb0869acbf1417`. The GitHub-hosted Ubuntu 24.04 job restored retained full-suite history, ran `node tests/ci-full-suite.mjs --skip-browser`, passed 79/79 steps in 78696ms, saved refreshed history with key `proxyforge-full-suite-history-main-26442381257-1`, and uploaded artifact `proxyforge-full-suite-26442381257` as ID `7212814243` with SHA256 `fc11542a48acb77d1d077d39a7c174f700b1d8741a42b9531934b987c42d27d7`. |
| GitHub Actions run `26442689546` | Passed on commit `a741cc0041115b84cb3216da3c98d16ea97b88c4` after the workflow opted JavaScript actions into Node 24. The job restored retained full-suite history, exposed `FORCE_JAVASCRIPT_ACTIONS_TO_NODE24=true` to checkout/setup/cache/artifact steps, passed 79/79 steps in 76584ms, saved refreshed history with key `proxyforge-full-suite-history-main-26442689546-1`, and uploaded artifact `proxyforge-full-suite-26442689546` as ID `7212939414` with SHA256 `b50b6db66fa3734f3679f303494a63df05478ff97f6868f4b72bdb613fdcfd66`. The remaining annotation now states the Node 20-targeted cache/artifact actions are being forced to run on Node 24. |

## 2026-05-26 Scheduled CI Retained-History Continuity

Command and result:

| Command | Result |
| --- | --- |
| `node tests/ci-nightly-policy.mjs` | Passed. The nightly policy now requires `actions/cache/restore@v4` before the full-suite run, `actions/cache/save@v4` after the run, a branch-local `proxyforge-full-suite-history-${{ github.ref_name }}-*` restore key, the unique run/attempt cache key, and a plan-only save guard. |
| `node tests/full-nightly-production-engine.mjs` | Passed. Full/nightly production evidence now has a `scheduledHistoryContinuityCovered` requirement proving the scheduled workflow restores `test-results/ci-full-suite-history/` before runtime execution and saves refreshed history afterward. |
| `npm run test:ci:fast` | Passed 82/82 steps in 207610ms. The curated fast suite covered the new nightly policy gate, Full/Nightly production evidence with scheduled history continuity, retained-history evidence, package/security/AI/agent production gates, project/customer-scale interop, OAST, scanner, Repeater/Intruder, reports, and the focused browser workflow smoke. |

Changed behavior:

- Scheduled full/nightly CI restores retained runtime history before `npm run test:ci:full`.
- Runtime runs save refreshed retained history back to the branch-local cache before artifact upload.
- Plan-only dispatches keep validating metadata but do not save retained history.
- Artifact upload still publishes `test-results/ci-full-suite-history/` and `test-results/ci-full-suite-history/dashboard.json` for review.

This closes the workflow wiring gap that made retained history local-only. The remaining production proof is to let scheduled CI run and accumulate retained history on GitHub-hosted runners.

## 2026-05-26 Retained Full-Suite Runtime Trend Window

Command and result:

| Command | Result |
| --- | --- |
| `node tests/ci-full-suite.mjs` | Passed 80/80 steps in 396249ms. This was a true full-suite runtime pass, including the full Playwright browser workflow file with 68/68 browser tests passing in 3.7 minutes. The run wrote `test-results/ci-full-suite-history/local-2026-05-26T08-13-48-040Z-summary.json`. |
| `node tests/ci-full-suite.mjs --skip-browser` | Passed 79/79 steps in 171397ms. This retained a second runtime summary while preserving the full browser-backed run as the stronger browser proof. |
| `node tests/ci-full-suite.mjs --skip-browser` | Passed 79/79 steps in 169076ms. This retained a third runtime summary and refreshed `test-results/ci-full-suite-history/dashboard.json`. |

Retained history dashboard state:

| Metric | Value |
| --- | ---: |
| Retained runtime runs | 3 |
| Full browser-backed runs | 1 |
| Skip-browser runtime runs | 2 |
| Consecutive runtime passes | 3 |
| Failed retained runs | 0 |
| Median runtime duration | 171397ms |

Ignored evidence artifacts:

- `test-results/ci-full-suite-history/dashboard.json`
- `test-results/ci-full-suite-history/local-2026-05-26T08-13-48-040Z-summary.json`
- `test-results/ci-full-suite-history/local-2026-05-26T08-20-49-161Z-summary.json`
- `test-results/ci-full-suite-history/local-2026-05-26T08-23-46-741Z-summary.json`
- `test-results/playwright-artifacts/`

The local retained trend window is now real evidence instead of a paper gate. Scheduled CI still needs to retain this same class of history before the full/nightly row is promoted to Production Ready.

## 2026-05-26 Playwright Artifact Isolation For Retained History

Command and result:

| Command | Result |
| --- | --- |
| `node tests/ci-nightly-policy.mjs` | Passed. The nightly policy now asserts `playwright.config.ts` uses `outputDir: 'test-results/playwright-artifacts'` and that the workflow/full-suite upload policy includes `test-results/playwright-artifacts/` alongside retained full-suite history. |
| `node tests/full-nightly-history-engine.mjs` | Passed. Retained-history evidence still proves retained runtime summaries, dashboard history, digest integrity, and the full-fidelity secret boundary after the artifact-policy change. |
| `node tests/full-nightly-production-engine.mjs` | Passed. Full/nightly production evidence now requires `test-results/playwright-artifacts/` in the upload policy so browser artifacts do not share the root retained-history directory. |
| `node tests/release-readiness.mjs` | Passed. Release readiness stayed green after adding the Playwright artifact isolation policy. |
| `node tests/install-docs-production-engine.mjs` | Passed. Packaged release/operator docs now describe the isolated Playwright artifact path and retained-history preservation boundary. |
| `node tests/fast-regression-production-engine.mjs` | Passed. Fast Regression production evidence still validates the 82-step fast-suite surface and retained-history linkage. |
| `node tests/ci-full-suite.mjs --plan-only` | Passed. The full/nightly orchestrator still validates an 80-step plan after adding `test-results/playwright-artifacts/` to the upload policy. |
| `npx playwright test tests/proxyforge.spec.ts -g search` | Passed 3/3 browser tests. A sentinel file in `test-results/ci-full-suite-history/` remained present afterward, proving Playwright cleanup no longer removes retained full/nightly history. |
| `npm run test:ci:fast` | Passed 82/82 steps in 196637ms. The focused browser workflow at the end of the fast suite ran with isolated Playwright artifacts, and `test-results/ci-full-suite-history/playwright-cleanup-sentinel.json` remained present after the run. |

Ignored evidence artifacts:

- `test-results/ci-full-suite-history/playwright-cleanup-sentinel.json`
- `test-results/playwright-artifacts/`
- `test-results/ci-fast-suite-summary.json`
- `.gitignored/test-artifacts/full-nightly-history-engine/`
- `.gitignored/test-artifacts/full-nightly-production-engine/`

## 2026-05-26 Full/Nightly Retained History Checkpoint

Command and result:

| Command | Result |
| --- | --- |
| `node tests/full-nightly-history-engine.mjs` | Passed. Added `proxyforge-full-nightly-retained-history-evidence-package` coverage for retained runtime summaries, `test-results/ci-full-suite-history/dashboard.json`, current runtime summary linkage, plan-only exclusion from runtime history, full/skip-browser run counts, digest integrity, zero-flake policy, safe artifact paths, full-fidelity executor material, and report-export-only redaction. |
| `node tests/full-nightly-production-engine.mjs` | Passed. Full/nightly production evidence now requires the retained-history gate in the full-suite plan and fast-suite linkage proof. |
| `node tests/ci-full-suite.mjs --plan-only` | Passed. The full/nightly orchestrator validates an 80-step plan including retained-history evidence without claiming runtime completion. |
| `node tests/ci-full-suite.mjs --skip-browser` | Passed 79/79 steps in 170873ms. The runtime pass wrote `test-results/ci-full-suite-summary.json`, `.last-run`, `test-results/ci-full-suite-history/local-2026-05-26T07-51-02-927Z-summary.json`, and `test-results/ci-full-suite-history/dashboard.json`; the dashboard recorded one retained runtime run and one consecutive runtime pass. |
| `node tests/ci-nightly-policy.mjs` | Passed. The scheduled nightly policy now requires retained-history artifacts and `tests/full-nightly-history-engine.mjs` in the committed full-suite plan. |
| `node tests/release-readiness.mjs` | Passed. Release readiness now guards the retained-history package script, test file, release checklist entry, operator guide handoff, and agent schema package. |
| `node tests/install-docs-production-engine.mjs` | Passed. Packaged install/operator/agent docs include the retained-history evidence boundary and full-fidelity secret handling. |
| `node tests/fast-regression-production-engine.mjs` | Passed. Fast Regression production evidence now requires `Full/Nightly retained history engine` and checks the new `fullNightlyRetainedHistoryCovered` requirement. |
| `node tests/release-security-production-engine.mjs` | Passed. Release security production evidence now accepts the 82/82 fast-suite gate and 80-step full-suite plan with retained-history coverage. |
| `npm run build` | Passed. TypeScript, renderer build, and Electron compile completed after adding the retained-history evidence builder. |
| `npm run test:ci:fast` | Passed 82/82 steps in 194533ms. The curated fast suite now includes retained-history proof in addition to customer-scale interop profiling, Intruder live-target profiling, Project import compatibility, third-party Extension compatibility, UI Scale, Full/Nightly production, release security, install docs, platform shell, agent control, AI provider, OAST provider diversity, signed relay isolation, callback live backend, agent, scanner, replay, report, release, package, and browser workflow gates. |

Ignored evidence artifacts:

- `.gitignored/test-artifacts/full-nightly-history-engine/`
- `.gitignored/test-artifacts/fast-regression-production-engine/`
- `.gitignored/test-artifacts/full-nightly-production-engine/`
- `.gitignored/test-artifacts/release-security-production-engine/`
- `test-results/ci-full-suite-plan.json`
- `test-results/ci-full-suite-summary.json`
- `test-results/ci-full-suite-history/`
- `test-results/ci-fast-suite-summary.json`

## 2026-05-26 Customer-Scale Interop Profiling Checkpoint

Command and result:

| Command | Result |
| --- | --- |
| `node tests/customer-scale-interop-engine.mjs` | Passed. Added `proxyforge-project-customer-scale-interop-evidence-package` coverage for 3,280 imported mixed-format exchanges, 3,279 merged exchanges, 40 hosts, 3,278 routes, duplicate/conflict diagnostics, Search/Viewer/Logger/Target profiling, Repeater/Scanner/Intruder handoff counts, report attachment scale, Project Store backup/reopen budgets, package refresh proof, full-fidelity raw request/response samples, operational secret samples, and report-export-only redaction. |
| `node tests/release-readiness.mjs` | Passed. Release readiness now guards the customer-scale interop test, release checklist entry, operator guide handoff, and agent schema package. |
| `node tests/fast-regression-production-engine.mjs` | Passed. Fast Regression production evidence now requires `Customer-scale interop profiling engine` and checks the new `customerScaleInteropCovered` requirement. |
| `node tests/full-nightly-production-engine.mjs` | Passed. Full/nightly production evidence now requires customer-scale interop profiling in the full-suite plan and fast-suite linkage proof. |
| `node tests/ci-full-suite.mjs --plan-only` | Passed. The full/nightly orchestrator validates a 79-step plan including customer-scale interop profiling without claiming runtime completion. |
| `node tests/ci-nightly-policy.mjs` | Passed. The scheduled nightly policy now requires the customer-scale interop profiling engine in the committed full-suite plan. |
| `node tests/install-docs-production-engine.mjs` | Passed. Packaged install/operator/agent docs include the customer-scale interop evidence boundary and full-fidelity secret handling. |
| `node tests/release-security-production-engine.mjs` | Passed. Release security production evidence now accepts the 81/81 fast-suite gate and 79-step full-suite plan with customer-scale interop coverage. |
| `npm run build` | Passed. TypeScript, renderer build, and Electron compile all completed after adding the customer-scale interop evidence builder. |
| `npm run test:ci:fast` | Passed 81/81 steps in 197789ms. The curated fast suite now includes customer-scale interop profiling in addition to Intruder live-target profiling, Project import compatibility, third-party Extension compatibility, UI Scale, Full/Nightly, release security, install docs, platform shell, agent control, AI provider, OAST provider diversity, signed relay isolation, callback live backend, agent, scanner, replay, report, release, package, and browser workflow gates. |

Ignored evidence artifacts:

- `.gitignored/test-artifacts/customer-scale-interop/`
- `.gitignored/test-artifacts/fast-regression-production-engine/`
- `.gitignored/test-artifacts/full-nightly-production-engine/`
- `.gitignored/test-artifacts/release-security-production-engine/`
- `test-results/ci-full-suite-plan.json`
- `test-results/ci-full-suite-summary.json`
- `test-results/ci-fast-suite-summary.json`

## 2026-05-26 Intruder Live-Target Profiling Checkpoint

Command and result:

| Command | Result |
| --- | --- |
| `node tests/intruder-engine.mjs` | Passed. Added `proxyforge-intruder-live-target-profile-package` coverage for linked attack-mode, checkpoint/resume, grep/extract comparison, high-volume streaming, resource-pool concurrency, authz differential status classes, payload-transform coverage, package-refresh digests, full-fidelity operational secrets, and report-export-only redaction. |
| `node tests/release-readiness.mjs` | Passed. Release readiness now guards the Intruder live-target profile package in the operator guide and agent schemas. |
| `node tests/install-docs-production-engine.mjs` | Passed. Packaged install/operator/agent docs include the Intruder live-target package boundary and full-fidelity secret handling. |
| `npm run build` | Passed. TypeScript, renderer build, and Electron compile all completed after adding the Intruder live-target profile evidence builder. |
| `npm run test:ci:fast` | Passed 80/80 steps in 185491ms. The curated fast suite re-ran build, release readiness, production evidence gates, Project Store, agent option audit, Search/Viewer/Logger/Organizer/Sequencer/Decoder/Comparer/Automation/Extensions/Callback/OAST/Exploit/AI, Repeater, Intruder, Proxy, Scanner, reports, headless, agent CLI, and focused browser workflow smokes with the new Intruder profile package inside `node tests/intruder-engine.mjs`. |

Ignored evidence artifacts:

- `.gitignored/test-artifacts/proxyforge-intruder-*/`
- `.gitignored/test-artifacts/install-docs-production-engine/`
- `.gitignored/test-artifacts/fast-regression-production-engine/`
- `test-results/ci-fast-suite-summary.json`

## 2026-05-26 Third-Party Extension Compatibility Checkpoint

Command and result:

| Command | Result |
| --- | --- |
| `node tests/extension-third-party-compatibility-engine.mjs` | Passed. Added `proxyforge-extension-third-party-sdk-compatibility-package` coverage for extension package/local/agent profile diversity, `IHttpRequestResponse` mutation and annotations, `IExtensionHelpers` transforms, multi-message context menus, session token refresh, scanner insertion points, editor/state lifecycle cleanup, fail-closed unsupported APIs, manifest/dependency edges, package refresh proof, full-fidelity operational secrets, and report-export-only redaction. |
| `node tests/extension-engine.mjs` | Passed. Extension parity evidence now links third-party SDK edge packages alongside the legacy extension SDK compatibility package and sandbox runtime hooks. |
| `node tests/agent-cli.mjs` | Passed. The agent `extension-fixtures` command now emits third-party SDK edge metadata and package-refresh evidence while preserving selected raw traffic and tokens. |
| `node tests/fast-regression-production-engine.mjs` | Passed. Fast Regression production evidence now requires the `Extension third-party compatibility engine` step. |
| `node tests/full-nightly-production-engine.mjs` | Passed. Full/nightly production evidence now requires third-party Extension compatibility in the plan and fast-suite linkage proof. |
| `node tests/ci-full-suite.mjs --plan-only` | Passed. The full/nightly orchestrator validates a 78-step plan including third-party Extension compatibility without claiming runtime completion. |
| `node tests/ci-nightly-policy.mjs` | Passed. The scheduled nightly policy now requires the third-party Extension compatibility engine in the committed full-suite plan. |
| `node tests/release-readiness.mjs` | Passed. Package scripts, release checklist, operator guide, and agent schemas now expose the third-party Extension compatibility evidence gate. |
| `node tests/install-docs-production-engine.mjs` | Passed. Packaged install/operator/agent docs include the new Extension compatibility boundary and full-fidelity secret handling. |
| `node tests/release-security-production-engine.mjs` | Passed. Release security production evidence now accepts the 80/80 fast-suite gate and 78-step full-suite plan with third-party Extension compatibility coverage. |
| `npm run build` | Passed. TypeScript, renderer build, and Electron compile all completed after extending Extension runtime actions and evidence packages. |
| `npm run test:ci:fast` | Passed 80/80 steps in 187184ms. The curated fast suite now includes third-party Extension compatibility in addition to Project import compatibility, UI Scale, Full/Nightly, release security, install docs, platform shell, agent control, AI provider, OAST provider diversity, signed relay isolation, callback live backend, agent, scanner, replay, report, release, package, and browser workflow gates. |

Ignored evidence artifacts:

- `.gitignored/test-artifacts/extension-third-party-compatibility/`
- `.gitignored/test-artifacts/extension-engine/`
- `.gitignored/test-artifacts/fast-regression-production-engine/`
- `.gitignored/test-artifacts/full-nightly-production-engine/`
- `.gitignored/test-artifacts/release-security-production-engine/`
- `test-results/ci-full-suite-plan.json`
- `test-results/ci-full-suite-summary.json`
- `test-results/ci-fast-suite-summary.json`

## 2026-05-26 Project Import Compatibility Checkpoint

Command and result:

| Command | Result |
| --- | --- |
| `node tests/project-import-compatibility-engine.mjs` | Passed. Added `proxyforge-project-import-compatibility-evidence-package` and `proxyforge-project-import-merge-manifest` coverage for large mixed legacy proxy XML, HAR, raw HTTP, JSONL, and ProxyForge v1 corpora, duplicate detection, conflict preservation, parser diagnostics, package refresh proof, full-fidelity imported tokens/cookies/API keys, and report-export-only redaction. |
| `node tests/project-parity-engine.mjs` | Passed. Existing project parity evidence remains green after the shared import parser gained merge manifests and compatibility evidence helpers. |
| `node tests/fast-regression-production-engine.mjs` | Passed. The fast regression production required-step list now includes `Project import compatibility engine` and checks the new `projectImportCompatibilityCovered` requirement. |
| `node tests/full-nightly-production-engine.mjs` | Passed. Full/nightly production evidence now requires Project import compatibility in the full-suite plan and fast-suite linkage proof. |
| `node tests/ci-full-suite.mjs --plan-only` | Passed. The full/nightly orchestrator validates a 77-step plan including Project import compatibility without claiming runtime completion. |
| `node tests/ci-nightly-policy.mjs` | Passed. The scheduled nightly policy now requires the Project import compatibility engine in the committed full-suite plan. |
| `node tests/release-readiness.mjs` | Passed. Package scripts, release checklist, operator guide, and agent schemas now expose the Project import compatibility evidence gate. |
| `node tests/install-docs-production-engine.mjs` | Passed. Packaged install/operator/agent docs include the new import compatibility evidence boundary and full-fidelity secret handling. |
| `node tests/release-security-production-engine.mjs` | Passed. Release security production evidence now accepts the 79/79 fast-suite gate and 77-step full-suite plan with Project import compatibility, UI Scale, and Full/Nightly production evidence coverage. |
| `npm run build` | Passed. TypeScript, renderer build, and Electron compile all completed after extending the shared project snapshot engine. |
| `npm run test:ci:fast` | Passed 79/79 steps in 189882ms. The curated fast suite now includes Project import compatibility in addition to UI Scale, Full/Nightly, release security, install docs, platform shell, agent control, AI provider, OAST provider diversity, signed relay isolation, callback live backend, agent, scanner, replay, report, release, package, and browser workflow gates. |

Ignored evidence artifacts:

- `.gitignored/test-artifacts/project-import-compatibility/`
- `.gitignored/test-artifacts/project-parity-engine/`
- `.gitignored/test-artifacts/fast-regression-production-engine/`
- `.gitignored/test-artifacts/full-nightly-production-engine/`
- `.gitignored/test-artifacts/release-security-production-engine/`
- `test-results/ci-full-suite-plan.json`
- `test-results/ci-full-suite-summary.json`
- `test-results/ci-fast-suite-summary.json`

## 2026-05-26 UI Scale Production Evidence Checkpoint

Command and result:

| Command | Result |
| --- | --- |
| `node tests/ui-scale-production-engine.mjs` | Passed. Added `proxyforge-ui-scale-production-evidence-package` with requirements for desktop/tablet/mobile coverage, all major surfaces, viewport overlap and overflow checks, long-label text fitting, keyboard and accessible names, stable fixed controls, large-project data density, bounded row windows, latency budgets, report attachment scale, workflow coverage, packaged mode, docs/schema coverage, raw executor material preservation, operational secret preservation, and report-phase-only redaction. |
| `node tests/fast-regression-production-engine.mjs` | Passed. The fast regression production required-step list now includes `UI Scale production evidence engine` and checks the new `uiScaleProductionCovered` requirement. |
| `node tests/full-nightly-production-engine.mjs` | Passed. Full/nightly production evidence now requires both UI Scale production and Full/Nightly production gates in the fast-suite linkage proof. |
| `node tests/ci-full-suite.mjs --plan-only` | Passed. The full/nightly orchestrator validates a 76-step plan including UI Scale production evidence without claiming runtime completion. |
| `node tests/release-readiness.mjs` | Passed. Package scripts, release checklist, operator guide, and agent schemas now expose the UI Scale production evidence gate. |
| `node tests/release-security-production-engine.mjs` | Passed. Release security production evidence now accepts the 78/78 fast-suite gate and 76-step full-suite plan with UI Scale and Full/Nightly production evidence coverage. |
| `npm run build` | Passed. TypeScript, renderer build, and Electron compile all completed after adding the new engine. |
| `npm run test:ci:fast` | Passed 78/78 steps in 183322ms. The curated fast suite now includes UI Scale production evidence in addition to Full/Nightly, release security, install docs, platform shell, agent control, AI provider, OAST provider diversity, signed relay isolation, callback live backend, agent, scanner, replay, report, release, package, and browser workflow gates. |

Ignored evidence artifacts:

- `.gitignored/test-artifacts/ui-scale-production-engine/`
- `.gitignored/test-artifacts/fast-regression-production-engine/`
- `.gitignored/test-artifacts/full-nightly-production-engine/`
- `.gitignored/test-artifacts/release-security-production-engine/`
- `test-results/ci-full-suite-plan.json`
- `test-results/ci-full-suite-summary.json`
- `test-results/ci-fast-suite-summary.json`

## 2026-05-26 Full/Nightly Production Evidence Checkpoint

Command and result:

| Command | Result |
| --- | --- |
| `node tests/full-nightly-production-engine.mjs` | Passed. Added `proxyforge-full-nightly-production-evidence-package` with requirements for the 75-step full/nightly plan, coverage owners, safe artifact paths, upload and retention policy, zero-flake budget, trend dashboard, historical full-run pass, latest runtime pass, fast-suite linkage, plan-only boundary, full-fidelity executor material, and report-export-only redaction. |
| `node tests/ci-full-suite.mjs --plan-only` | Passed. The full/nightly orchestrator now validates a 75-step plan including the new Full/Nightly production evidence engine without claiming runtime completion. |
| `node tests/fast-regression-production-engine.mjs` | Passed. The fast regression production required-step list now includes `Full/Nightly production evidence engine` and checks the new `fullNightlyProductionCovered` requirement. |
| `node tests/release-readiness.mjs` | Passed. Package scripts, release checklist, operator guide, and agent schemas now expose the full/nightly production evidence gate. |
| `node tests/release-security-production-engine.mjs` | Passed. Release security production evidence now accepts the 77/77 fast-suite gate with Full/Nightly production evidence coverage. |
| `npm run build` | Passed. TypeScript, renderer build, and Electron compile all completed after adding the new engine. |
| `npm run test:ci:fast` | Passed 77/77 steps in 185025ms. The curated fast suite now includes Full/Nightly production evidence in addition to OAST provider diversity, signed relay isolation, callback live backend, agent, scanner, replay, report, release, package, and browser workflow gates. |

Ignored evidence artifacts:

- `.gitignored/test-artifacts/full-nightly-production-engine/`
- `.gitignored/test-artifacts/fast-regression-production-engine/`
- `.gitignored/test-artifacts/release-security-production-engine/`
- `test-results/ci-full-suite-plan.json`
- `test-results/ci-full-suite-summary.json`
- `test-results/ci-fast-suite-summary.json`

## 2026-05-26 External OAST Provider Diversity Checkpoint

Command and result:

| Command | Result |
| --- | --- |
| `node tests/callback-live-backend-engine.mjs` | Passed. Collaborator parity evidence now includes `proxyforge-callback-external-oast-provider-diversity-package` and requires provider diversity coverage alongside signed tenant-isolated relay integration. |
| `node tests/oast-provider-diversity.mjs` | Passed. A local multi-provider fixture simulated generic HTTP relay, DNS webhook relay, and SMTP relay providers with signed isolated polls, full raw request/response evidence, provider bearer tokens, callback payload tokens, and a deliberate cross-provider leak failure case. |
| `node tests/fast-regression-production-engine.mjs` | Passed. The fast regression production required-step list now includes `OAST provider diversity engine`. |
| `npm run build` | Passed. TypeScript, renderer build, and Electron compile all completed before fast-suite promotion. |
| `npm run test:ci:fast` | Passed 76/76 steps in 182280ms. The curated fast suite now proves external OAST provider diversity in addition to signed relay isolation, callback live backend, agent, scanner, replay, report, release, package, and browser workflow gates. |

Ignored evidence artifacts:

- `.gitignored/test-artifacts/oast-provider-diversity/`
- `.gitignored/test-artifacts/callback-live-backend/`
- `test-results/ci-fast-suite-summary.json`

## 2026-05-26 legacy extension SDK Compatibility Checkpoint

Command and result:

| Command | Result |
| --- | --- |
| `node tests/extension-engine.mjs` | Passed. Extension parity evidence now includes `proxyforge-extension-legacy-sdk-compatibility-package` coverage for `IHttpListener`, `IProxyListener`, `IScannerCheck`, `IScannerInsertionPointProvider`, `IMessageEditorTab`, `IContextMenuFactory`, `ISessionHandlingAction`, `IExtensionStateListener`, `IExtensionHelpers`, and `ILegacyExtensionCallbacks` policy-denied probes while preserving raw Authorization/Cookie/API-key material until report export. |
| `node tests/release-readiness.mjs` | Passed. Release readiness remains green after the SDK compatibility schema/docs update. |
| `npm run build` | Passed. TypeScript, renderer build, and Electron compile all completed. |
| `npm run test:ci:fast` | Passed 75/75 steps in 190362ms. The curated fast suite now proves the deeper extension SDK compatibility package inside the existing Sandboxed Extension Runtime gate while keeping agent, callback, proxy, scanner, replay, reports, release, package, and browser workflow gates green. |

Ignored evidence artifacts:

- `.gitignored/test-artifacts/extension-engine/`
- `test-results/ci-fast-suite-summary.json`

## 2026-05-26 External OAST Relay Isolation Checkpoint

Command and result:

| Command | Result |
| --- | --- |
| `node tests/callback-live-backend-engine.mjs` | Passed. Collaborator parity evidence now includes `proxyforge-callback-external-relay-integration-package` coverage for signed tenant-isolated relay polls while preserving callback tokens, relay bearer tokens, signing secrets, and raw callback material until report export. |
| `node tests/oast-relay-integration.mjs` | Passed. A local HTTP relay fixture ingested HTTP, DNS, and SMTP callback records for two tenants, returned signed poll responses, proved each tenant only received its own payloads/interactions/tokens, and failed a deliberate cross-tenant leak case. |
| `node tests/fast-regression-production-engine.mjs` | Passed. The fast regression production evidence required-step list now includes `OAST relay integration engine`. |
| `node tests/release-readiness.mjs` | Passed. Release readiness remains green after the relay integration proof and documentation update. |
| `npm run build` | Passed. TypeScript, renderer build, and Electron compile all completed. |
| `npm run test:ci:fast` | Passed 75/75 steps in 185368ms. The curated fast suite now includes signed tenant-isolated OAST relay integration plus the existing callback, proxy, scanner, Repeater, Intruder, AI, agent, release, package, and browser workflow gates. |

Ignored evidence artifacts:

- `.gitignored/test-artifacts/oast-relay-integration/`
- `.gitignored/test-artifacts/callback-live-backend/`
- `test-results/ci-fast-suite-summary.json`

## 2026-05-26 Scanner OAST Issue Promotion Checkpoint

Command and result:

| Command | Result |
| --- | --- |
| `node tests/scanner-active-scan-engine.mjs` | Passed. Scanner active evidence now includes `proxyforge-scanner-oast-issue-promotion-package` creation with linked source/scanner exchanges, callback payload, callback interaction, issue draft, retest commands, full-fidelity executor material, and report-export-only redaction. |
| `node tests/scanner-oast-ssrf.mjs` | Passed. The live OAST SSRF workflow correlated one scanner probe to one stored callback interaction and promoted the observed callback into a report-ready Scanner OAST issue package while preserving scanner/source tokens and raw callback material. |
| `node tests/agent-cli.mjs` | Passed. The agent CLI smoke now exercises `scanner-oast-promote` alongside scanner run/retest/evidence export, callback relay/soak/retention controls, MITM, replay, exploit, report, automation, and Vantix flows. |
| `node tests/agent-option-audit.mjs` | Passed. The post-MVP audit now verifies the 66-command Codex/Claude/Vantix surface, including Scanner OAST issue promotion, Project Store recovery, WebSocket commands, documentation coverage, and the report-phase redaction boundary. |
| `node tests/agent-control-production-engine.mjs` | Passed. Agent Control production evidence now proves the 66-command source/packaged command surface and includes Scanner OAST promotion in the Scanner/Anvil agent-control lane. |
| `node tests/release-security-production-engine.mjs` | Passed. Release Security production evidence now accepts the 66-command agent-control surface while keeping exploit controls, local listener review, platform pins, and report-export-only redaction green. |
| `node tests/release-readiness.mjs` | Passed. Release docs, operator guide, and packaged smoke requirements now reference the current 66-command surface including `scanner-oast-promote`. |
| `npm run test:ci:fast` | Passed 74/74 steps. The curated fast suite now exercises Scanner OAST issue promotion, verifies the 66-command agent surface, and keeps the focused 8-test browser workflow smoke green. |

Ignored evidence artifacts:

- `.gitignored/test-artifacts/scanner-oast-ssrf/`
- `.gitignored/test-artifacts/agent-control-production-engine/`
- `.gitignored/test-artifacts/release-security-production-engine/`
- `test-results/ci-fast-suite-summary.json`

## 2026-05-26 Project Store Crash Recovery Checkpoint

Command and result:

| Command | Result |
| --- | --- |
| `node tests/project-store-crash-recovery.mjs` | Passed. Project Store v2 replays pending HTTP capture recovery journals after a simulated pre-commit crash, preserves raw Authorization/Cookie/API-key/callback material, creates restore-point backups, and reopens the backup with exact recovered evidence intact. |
| `node tests/agent-cli.mjs` | Passed. The agent CLI smoke now exercises `project-store-status`, `project-store-recover`, and `project-store-backup` alongside the existing MITM, WebSocket, replay, scanner, exploit, report, automation, and Vantix flows while preserving full-fidelity Project Store samples until report export. |
| `node tests/agent-option-audit.mjs` | Passed. The post-MVP audit now verifies the 65-command Codex/Claude/Vantix surface, including the three Project Store recovery commands, the four WebSocket commands, documentation coverage, and the report-phase redaction boundary. |
| `npm run test:ci:fast` | Passed 74/74 steps. The curated fast suite now includes the Project Store crash recovery engine, verifies the 65-command agent surface, and keeps the focused 8-test browser workflow smoke green. |

Ignored evidence artifacts:

- `.gitignored/test-artifacts/project-store-crash-recovery/`
- `test-results/ci-fast-suite-summary.json`

## 2026-05-26 WebSocket Agent Operation Checkpoint

Command and result:

| Command | Result |
| --- | --- |
| `node tests/agent-cli.mjs` | Passed. The agent CLI smoke now exercises `websocket-list`, live `websocket-replay`, bounded `websocket-fuzz`, and `websocket-transcript-export` against a local WebSocket echo target while preserving full-fidelity frame payloads, tokens, cookies, keys, handshake proof, received frames, fuzz outcomes, and transcript content until report export. |
| `node tests/agent-option-audit.mjs` | Passed. The post-MVP audit verified the 62-command Codex/Claude/Vantix surface at this checkpoint, including the four WebSocket commands, documentation coverage, and the report-phase redaction boundary. |
| `npm run test:ci:fast` | Passed 73/73 steps. The curated fast suite verified the 62-command agent surface at this checkpoint, the WebSocket agent CLI smoke, the existing Proxy WebSocket capture/intercept/replay/state-transcript engine, and the focused 8-test browser workflow smoke. |

Ignored evidence artifact:

- `test-results/ci-fast-suite-summary.json`

## 2026-05-25 Insertion Point Inventory Agent Checkpoint

Command and result:

| Command | Result |
| --- | --- |
| `node tests/insertion-point-engine.mjs` | Passed. The insertion point engine now extracts scanner-ready query, path, header, cookie, form, JSON, GraphQL, multipart, and XML candidates from full-fidelity raw HTTP exchanges while preserving tokens, cookies, keys, raw requests, and raw responses until report export. |
| `node tests/agent-cli.mjs` | Passed. The agent CLI smoke now exercises `insertion-points` with full-fidelity Authorization, cookie, API key, query, and JSON body candidates alongside the existing MITM, search, Sequencer, Decoder, replay, Intruder, Repeater, Scanner, Anvil, extension, callback, exploit, report, automation, and Vantix flows. |
| `npm run test:ci:fast` | Passed 73/73 steps. The curated fast suite now includes the Scanner insertion point inventory engine, verifies the 58-command agent surface, and keeps the focused 8-test browser workflow smoke green. |

Ignored evidence artifact:

- `.gitignored/test-artifacts/insertion-point-engine/insertion-point-inventory.json`

## 2026-05-25 Decoder Transform Chain Agent Checkpoint

Command and result:

| Command | Result |
| --- | --- |
| `node tests/decoder-golden.mjs` | Passed. The Decoder engine now emits `proxyforge-decoder-golden-corpus-package` with exact golden coverage for URL/Base64/JSON recursive decode, HTML-delimited hex JSON, JWT/JWS decode, decode-and-hash, encode chains, full-fidelity operational secret samples, and report-export-only redaction. |
| `node tests/agent-cli.mjs` | Passed. The agent CLI smoke now exercises `decoder-chain` with full-fidelity decoded token/cookie/API-key material alongside the existing MITM, search, Sequencer, replay, Intruder, Repeater, Scanner, Anvil, extension, callback, exploit, report, automation, and Vantix flows. |
| `npm run test:ci:fast` | Passed 72/72 steps. The curated fast suite added the Decoder transform-chain golden corpus, verified the then-current 57-command agent surface, and kept the focused 8-test browser workflow smoke green. |

Ignored evidence artifact:

- `.gitignored/test-artifacts/decoder-golden/decoder-golden-corpus.json`

## 2026-05-25 Release Security Production Evidence Checkpoint

Command and result:

| Command | Result |
| --- | --- |
| `node tests/release-security-production-engine.mjs` | Passed. The Release Security production engine emits `proxyforge-release-security-production-evidence-package` with all requirement booleans true for the formal zero-warning/zero-fail release security review, local listeners, secret boundary, review/export redaction, exploit controls, agent controls, AI provider controls, platform pins, signed trust, production CI gates, clean Linux/Windows runtime evidence, artifact hygiene, package-refresh proof, docs/schema coverage, full-fidelity raw request/response and token/cookie/API-key/callback-token preservation, and report-export-only redaction. |
| `npm run test:ci:fast` | Passed 58/58 steps, including the Release Security production evidence engine, AI Provider production evidence engine, Agent Control production evidence engine, Platform Shell production evidence, Linux Package production evidence, Windows Package production evidence, Install Docs production evidence, Fast Regression production evidence, Platform/Release parity, and the existing broad runtime/browser checks, plus 8 focused Playwright workflow tests. |

Ignored evidence artifact:

- `.gitignored/test-artifacts/release-security-production-engine/release-security-production-evidence-package.json`

## 2026-05-25 AI Provider Production Evidence Checkpoint

Command and result:

| Command | Result |
| --- | --- |
| `node tests/ai-provider-production-engine.mjs` | Passed. The AI Provider production engine now emits `proxyforge-ai-provider-production-evidence-package` with all requirement booleans true for Codex CLI, Claude CLI, OpenAI-compatible `/v1/chat/completions` HTTP/local providers, provider config persistence, CLI diversity, local-provider interop, streaming telemetry, token/cost accounting, prompt templates, baselines, comparisons, benchmark replay, controlled action packages, scope blocking, no direct provider action traffic, package-refresh proof, long-run profiling, docs/schema coverage, security policy, full-fidelity raw request/response and token/cookie/API-key preservation, and report-export-only redaction. |
| `npm run test:ci:fast` | Passed 57/57 steps, including the AI Provider production evidence engine, Agent Control production evidence engine, Platform Shell production evidence, Linux Package production evidence, Windows Package production evidence, Install Docs production evidence, Fast Regression production evidence, Platform/Release parity, and the existing broad runtime/browser checks, plus 8 focused Playwright workflow tests. |

Ignored evidence artifact:

- `.gitignored/test-artifacts/ai-provider-production-engine/ai-provider-production-evidence-package.json`

## 2026-05-25 Full/Nightly Coverage Refresh Checkpoint

Command and result:

| Command | Result |
| --- | --- |
| `node tests/ci-nightly-policy.mjs` | Passed after refreshing `tests/ci-full-suite.mjs` coverage assertions. The nightly policy gate now requires the full suite to include the newer Platform/Release, Platform Shell production, Agent Control production, AI Provider production, Release Security production, Fast Regression production, Install Docs production, Windows Package production, Linux Package production, Safety/Enterprise, Project, Proxy listener, Scanner passive, Repeater workspace/desync, Logger parity, Organizer parity, Viewer, Exploit, AI action, and agent CLI evidence engines, in addition to scheduled workflow, artifact upload, owner metadata, and zero-flake policy checks. |
| `node tests/ci-full-suite.mjs --plan-only` | Passed. It validated the refreshed full/nightly plan at 61 steps and rewrote `test-results/ci-full-suite-plan.json` / `test-results/ci-full-suite-summary.json` without claiming runtime completion. |
| `npm run test:ci:full` | Previously passed 54/54 steps in local non-skipped mode before the Install Docs, Windows Package, Linux Package, Platform Shell, Agent Control, AI Provider, and Release Security production gates were added, including the refreshed release/platform/safety/project/proxy/scanner/repeater/logger/organizer/viewer/exploit/AI/agent evidence engines and the full browser workflow suite with 68 Playwright tests. The current membership is validated by the 61-step plan-only gate above. |

Ignored evidence artifacts:

- `test-results/ci-full-suite-plan.json`
- `test-results/ci-full-suite-summary.json`

## 2026-05-25 Agent Control Production Evidence Checkpoint

Command and result:

| Command | Result |
| --- | --- |
| `node tests/agent-control-production-engine.mjs` | Passed. The Agent Control production engine emits `proxyforge-agent-control-production-evidence-package` with all requirement booleans true for the source and packaged Codex/Claude/Vantix command surface, packaged app.asar status, external-cwd `~/vantix` invocation, persistent MITM, Chromium/cookie/data collection, search/view/Sequencer/Decoder, replay/Intruder/Repeater race/desync, Scanner/Anvil, extension/callback/exploit/report, automation/Vantix handoff, scope/approval/rate-limit/audit gates, long-running soak evidence, full-fidelity raw request/response and token/cookie/API-key/callback-token preservation, and report-export-only redaction. |
| `npm run test:ci:fast` | Passed 56/56 steps, including the Agent Control production evidence engine, Platform Shell production evidence, Linux Package production evidence, Windows Package production evidence, Install Docs production evidence, Fast Regression production evidence, Platform/Release parity, and the existing broad runtime/browser checks, plus 8 focused Playwright workflow tests. |

Ignored evidence artifact:

- `.gitignored/test-artifacts/agent-control-production-engine/agent-control-production-evidence-package.json`

## 2026-05-25 Platform Shell Production Evidence Checkpoint

Command and result:

| Command | Result |
| --- | --- |
| `node tests/platform-shell-production-engine.mjs` | Passed. The Platform Shell production engine now emits `proxyforge-platform-shell-production-evidence-package` with all requirement booleans true for Linux and Windows packaged Electron shell launch, structured `PROXYFORGE_RELEASE_SMOKE=1` release-smoke payloads, packaged headless and agent CLIs, external-cwd app.asar agent execution, packaged runtime proxy/cert/OAST/report smokes, packaged browser routing, Linux and Windows package production gate inputs, accepted trust-store and known host-limit pins, full-fidelity raw request/response and token/cookie/API-key/callback-token preservation, and report-export-only redaction. |
| `npm run test:ci:fast` | Passed 55/55 steps, including the Platform Shell production evidence engine, Linux Package production evidence, Windows Package production evidence, Install Docs production evidence, Fast Regression production evidence, Platform/Release parity, and the existing broad runtime/browser checks, plus 8 focused Playwright workflow tests. |

Ignored evidence artifact:

- `.gitignored/test-artifacts/platform-shell-production-engine/platform-shell-production-evidence-package.json`

## 2026-05-25 Install Docs Production Evidence Checkpoint

Command and result:

| Command | Result |
| --- | --- |
| `node tests/install-docs-production-engine.mjs` | Passed. The Install Docs production engine now emits `proxyforge-install-docs-production-evidence-package` with all requirement booleans true for packaged Linux/Windows install guide, operator guide, release checklist, release evidence, Codex/Claude/Vantix agent docs, release smoke commands, certificate trust, browser routing, Windows DPAPI and trust-store pin coverage, replay/desync/race/scanner/exploit/OAST workflows, troubleshooting, Production Ready signoff, full-fidelity raw request/response and token/cookie/API-key/callback-token preservation, and report-export-only redaction. |
| `npm run test:ci:fast` | Passed 52/52 steps, including the Install Docs production evidence engine, Fast Regression production evidence, Platform/Release parity, and the existing broad runtime/browser checks, plus 8 focused Playwright workflow tests. |

Ignored evidence artifact:

- `.gitignored/test-artifacts/install-docs-production-engine/install-docs-production-evidence-package.json`

## 2026-05-25 Windows Package Production Evidence Checkpoint

Command and result:

| Command | Result |
| --- | --- |
| `node tests/windows-package-production-engine.mjs` | Passed. The Windows Package production engine now emits `proxyforge-windows-package-production-evidence-package` with all requirement booleans true for native Windows NSIS, portable, and win-unpacked artifacts, Windows zip fallback hygiene, unpacked and installed GUI launch, installed headless CLI plus scan/report, installed runtime proxy/cert/OAST/report, browser routing, DPAPI sample-cookie extraction, quiet uninstall, formal `windows-trust-runner` `ERROR_NOT_SUPPORTED` trust-store pin acceptance, portable-wrapper stdout pinning, full-fidelity raw request/response and token/cookie/API-key/callback-token preservation, and report-export-only redaction. |
| `npm run test:ci:fast` | Passed 53/53 steps, including the Windows Package production evidence engine, Install Docs production evidence, Fast Regression production evidence, Platform/Release parity, and the existing broad runtime/browser checks, plus 8 focused Playwright workflow tests. |

Ignored evidence artifact:

- `.gitignored/test-artifacts/windows-package-production-engine/windows-package-production-evidence-package.json`

## 2026-05-25 Linux Package Production Evidence Checkpoint

Command and result:

| Command | Result |
| --- | --- |
| `node tests/linux-package-production-engine.mjs` | Passed. The Linux Package production engine now emits `proxyforge-linux-package-production-evidence-package` with all requirement booleans true for AppImage, deb, and linux-unpacked artifacts, AppImage and unpacked runtime/GUI smokes, deb metadata/dependency coverage, packaged headless CLI plus scan/report, packaged agent CLI and external-cwd invocation, packaged runtime proxy/cert/OAST/report, packaged browser routing, clean-container deb install/runtime/installed-GUI/trusted-CA HTTPS capture/uninstall proof, known warning pins for Xvfb/Docker-only warnings, full-fidelity raw request/response and token/cookie/API-key/callback-token preservation, and report-export-only redaction. |
| `npm run test:ci:fast` | Passed 54/54 steps, including the Linux Package production evidence engine, Windows Package production evidence, Install Docs production evidence, Fast Regression production evidence, Platform/Release parity, and the existing broad runtime/browser checks, plus 8 focused Playwright workflow tests. |

Ignored evidence artifact:

- `.gitignored/test-artifacts/linux-package-production-engine/linux-package-production-evidence-package.json`

## 2026-05-25 Fast Regression Production Evidence Checkpoint

Command and result:

| Command | Result |
| --- | --- |
| `node tests/fast-regression-production-engine.mjs` | Passed. The Fast Regression production engine now emits `proxyforge-fast-regression-production-evidence-package` with all requirement booleans true for current fast-suite summary shape, completed steps, zero failed steps, required step kinds, required release/platform/security/project/agent/browser/proxy/scanner/repeater/intruder/report step names, CI-uploadable summary artifact retention, full-fidelity raw request/response and token/cookie/API-key/callback-token preservation, and report-export-only redaction. |
| `npm run test:ci:fast` | Passed 52/52 steps after adding the Install Docs production gate. The suite now includes the Fast Regression production evidence engine in addition to Install Docs production, Platform/Release parity, and the existing broad runtime/browser checks. |

Ignored evidence artifact:

- `.gitignored/test-artifacts/fast-regression-production-engine/fast-regression-production-evidence-package.json`

## 2026-05-25 Platform/Release Parity Evidence Checkpoint

Command and result:

| Command | Result |
| --- | --- |
| `node tests/platform-release-engine.mjs` | Passed. The Platform/Release engine now emits `proxyforge-platform-release-parity-evidence-package` with all requirement booleans true for dense React/Vite navigation, desktop/mobile visual QA, Linux and Windows Electron shell launch, Linux AppImage/deb/unpacked artifacts, Windows NSIS/portable/unpacked artifacts, packaged headless CLI, packaged agent CLI, packaged runtime proxy/cert/OAST/report smokes, packaged browser routing, Linux install/trust/uninstall proof, Windows installer/uninstall proof, the explicit `windows-trust-runner` `ERROR_NOT_SUPPORTED` trust-store pin, fast and full/nightly release gates, Linux/Windows install docs, release security review, full-fidelity raw request/response and token/cookie/API-key/callback/signing-secret preservation, and report-export-only redaction. |

Ignored evidence artifact:

- `.gitignored/test-artifacts/platform-release-engine/platform-release-parity-evidence-package.json`

## 2026-05-25 Safety/Enterprise Parity Evidence Checkpoint

Command and result:

| Command | Result |
| --- | --- |
| `node tests/safety-enterprise-engine.mjs` | Passed. The Safety/Enterprise engine now emits `proxyforge-safety-enterprise-parity-evidence-package` with all requirement booleans true for scope gates, throttle floors, request caps, approval-required and approved active lanes, policy override/bypass audit, signed audit exports, governance packages, SSO identity mapping and federation fixtures, remote policy push/pull receipts, enterprise backend soak, remote audit retention, full-fidelity raw request/response and token/cookie/API-key/signing-secret/SSO-secret preservation, and report-export-only redaction. |

Ignored evidence artifact:

- `.gitignored/test-artifacts/safety-enterprise-engine/safety-enterprise-parity-evidence-package.json`

## 2026-05-25 Project Parity Evidence Checkpoint

Command and result:

| Command | Result |
| --- | --- |
| `node tests/project-parity-engine.mjs` | Passed. The Project snapshot engine now migrates legacy project JSON, legacy proxy XML history, HAR, JSONL MITM logs, and raw HTTP archives into v1 through the shared desktop/Project Store import path and emits `proxyforge-project-parity-evidence-package` with all requirement booleans true for local save/restore, `.proxyforge.json` import/export, schema/version migration, selected session profile restore, managed Linux/Windows browser launch profiles, browser cookie extraction/decryption readiness, full-fidelity raw request/response and token/cookie/API-key preservation, and report-export-only redaction. |

Ignored evidence artifact:

- `.gitignored/test-artifacts/project-parity-engine/project-parity-evidence-package.json`
- `.gitignored/test-artifacts/project-parity-engine/project-import-interop.json`

## 2026-05-25 Extensions Parity Evidence Checkpoint

Command and result:

| Command | Result |
| --- | --- |
| `node tests/extension-engine.mjs` | Passed. The Extensions engine now emits `proxyforge-extension-parity-evidence-package` with all requirement booleans true for catalog installs, local manifest imports, enable/disable run logs, sandboxed request/response/editor/scanner/headless hooks, legacy proxy-compatible compatibility fixtures, policy-denied operations, dependency review, headless CI evidence, signed manifests and updates, runtime diagnostics, evidence handoffs, full-fidelity raw request/response and token/cookie/API-key preservation, and report-export-only redaction. |

Ignored evidence artifact:

- `.gitignored/test-artifacts/extension-engine/extension-parity-evidence-package.json`

## 2026-05-25 Organizer Parity Evidence Checkpoint

Command and result:

| Command | Result |
| --- | --- |
| `node tests/organizer-evidence-engine.mjs` | Passed. The Organizer engine now emits `proxyforge-organizer-parity-evidence-package` with all requirement booleans true for multi-tool collections, notes, statuses, highlights, reviewer assignments, due dates, reviewer SLA exports, CSV/share links, plain and passphrase-sealed packages, AES-256-GCM/PBKDF2 metadata, HMAC signatures, trust policy review, import diff review, duplicate/conflict routes, all merge modes, conflict audit trails, full-fidelity raw request/response and token/cookie/API-key preservation, operational passphrase/signing-secret preservation, and report-export-only redaction. |

Ignored evidence artifact:

- `.gitignored/test-artifacts/organizer-evidence-engine/organizer-parity-evidence-package.json`

## 2026-05-25 Scanner Passive/Dedupe Parity Evidence Checkpoint

Command and result:

| Command | Result |
| --- | --- |
| `node tests/scanner-passive-engine.mjs` | Passed. The Scanner passive engine now emits `proxyforge-scanner-passive-dedupe-parity-package` with all requirement booleans true for security headers, cookie flags, CORS, cache controls, mixed content, information disclosure, authz metadata, server errors, exact duplicate folding, route-variant dedupe, confidence summaries, severity policy normalization, false-positive suppressions, report attachments, active Scanner handoff, full-fidelity raw request/response and token/cookie/API-key preservation, and report-export-only redaction. |

Ignored evidence artifact:

- `.gitignored/test-artifacts/scanner-passive-engine/scanner-passive-dedupe-parity-package.json`

## 2026-05-25 Logger Parity Evidence Checkpoint

Command and result:

| Command | Result |
| --- | --- |
| `node tests/logger-evidence-engine.mjs` | Passed. The Logger engine now emits `proxyforge-logger-parity-evidence-package` with all requirement booleans true for tool-generated traffic capture across Proxy/Target/Repeater/Scanner/Intruder/Exploit Lab/Automations/Extensions, capture controls, pinned presets, saved filters and facets, custom column/custom-column evidence linkage, raw HTTP/HAR/legacy proxy XML/project/plain-text archive imports, mapping presets, new-route/route-variant/exact-duplicate conflict review, all merge strategies, replay review receipts, signed provenance, report attachments, redaction policies, full-fidelity raw request/response and token/cookie/API-key preservation, and report-export-only redaction. |

Ignored evidence artifact:

- `.gitignored/test-artifacts/logger-evidence-engine/logger-parity-evidence-package.json`

## 2026-05-25 Sequencer Parity Evidence Checkpoint

Command and result:

| Command | Result |
| --- | --- |
| `node tests/sequencer-engine.mjs` | Passed after build. The Sequencer engine now emits `proxyforge-sequencer-parity-evidence-package` with all requirement booleans true for manual, traffic, and browser-preview token collection; cookie/form/custom location extraction; live capture persistence; entropy, collision, position, character, bit, and FIPS-style statistical analysis; 5,000-sample reliability gates; 20,000-sample FIPS-ready cap behavior; profile comparison; report-ready exports; full-fidelity token sample preservation; and report-export-only redaction. |

Ignored evidence artifact:

- `.gitignored/test-artifacts/sequencer-engine/sequencer-parity-evidence-package.json`

## 2026-05-25 AI Parity Evidence Checkpoint

Command and result:

| Command | Result |
| --- | --- |
| `node tests/ai-engine.mjs` | Passed after build. The AI provider engine now exercises Codex CLI, Claude CLI, and OpenAI-compatible local HTTP execution with full-fidelity operational prompt context, API-key env forwarding for the local endpoint, stream telemetry, usage accounting, prompt readiness checks, and suggested Repeater/Scanner actions. |
| `node tests/ai-action-engine.mjs` | Passed. The AI action engine now emits `proxyforge-ai-parity-evidence-package` with all requirement booleans true for Codex, Claude, OpenAI-compatible local providers, CLI/HTTP execution, streaming telemetry, prompt evaluations, templates, baselines, comparisons, benchmark replay, token/cost accounting, controlled actions, scope blocking, full-fidelity executor token/cookie preservation, and report-export-only redaction. |

Ignored evidence artifact:

- `.gitignored/test-artifacts/ai-action-engine/ai-parity-evidence-package.json`

## 2026-05-25 Search Parity Evidence Checkpoint

Command and result:

| Command | Result |
| --- | --- |
| `node tests/search-engine.mjs` | Passed. The Search engine now emits `proxyforge-search-parity-evidence-package` with all requirement booleans true for full-text metadata/body/raw search, structured predicates, negation, OR queries, semantic ranking, provider score merge, persistent local semantic index restore/reuse, large-project soak proof, `search-index`/`view`/report handoff, full-fidelity executor token/cookie preservation, and report-export-only redaction. |

Ignored evidence artifact:

- `.gitignored/test-artifacts/search-engine/search-parity-evidence-package.json`

## 2026-05-25 Viewer Parity Evidence Checkpoint

Command and result:

| Command | Result |
| --- | --- |
| `node tests/viewer-engine.mjs` | Passed. The Viewer engine now emits `proxyforge-viewer-parity-evidence-package` with all requirement booleans true for raw, Pretty JSON, HTML, JWT, GraphQL, image, and binary/hex views, source-aware snapshots, persistent evidence pins, replay comparison exports, report attachment handoff, full-fidelity executor token/cookie preservation, and report-export-only redaction. |

Ignored evidence artifact:

- `.gitignored/test-artifacts/viewer-engine/viewer-parity-evidence-package.json`

## 2026-05-25 Exploit Lab Parity Evidence Checkpoint

Command and result:

| Command | Result |
| --- | --- |
| `node tests/exploit-engine.mjs` | Passed. The Exploit Lab engine now emits `proxyforge-exploit-parity-evidence-package` with all requirement booleans true for PoC templates, non-destructive previews, approval/scope/stop-on-proof gates, saved exploit chains, callback-assisted validation, report-ready packages, digest review/compare/import, Repeater backend execution, destructive-class exclusion, full-fidelity executor raw material and tokens, and report-export-only redaction. |

Ignored evidence artifact:

- `.gitignored/test-artifacts/exploit-engine/exploit-parity-evidence-package.json`

## 2026-05-25 OAST Parity Evidence Checkpoint

Command and result:

| Command | Result |
| --- | --- |
| `node tests/callback-live-backend-engine.mjs` | Passed. The Callback engine now emits `proxyforge-collaborator-parity-evidence-package` with all requirement booleans true for DNS/HTTP/SMTP payload generation, signed polling, OAST workspace ownership, signed callback evidence packages, local listener backend planning, public relay soak, retention pruning, Repeater/Scanner/Exploit Lab replay staging and execution, CI handoff, report/import persistence, full-fidelity executor callback tokens/keys, and report-export-only redaction. |

Ignored evidence artifact:

- `.gitignored/test-artifacts/callback-live-backend/collaborator-parity-evidence-package.json`

## 2026-05-25 Automations Parity Evidence Checkpoint

Command and result:

| Command | Result |
| --- | --- |
| `node tests/automation-engine.mjs` | Passed. The Automation engine now emits `proxyforge-automation-parity-evidence-package` with all requirement booleans true for macro recording, scheduled/on-tag/CI workflows, scoped execution, approval blocking, durable scheduler queues, lease recovery, scheduler restore, CI/headless CLI commands, GitHub/GitLab/Azure/Jenkins provider presets, report artifacts, scheduler service lifecycle states, full-fidelity executor raw material and tokens, and report-export-only redaction. |
| `node tests/agent-cli.mjs` | Passed. The agent CLI now exposes `automation-list`, `automation-run`, `automation-ci-export`, `automation-scheduler-tick`, and `automation-parity-export` so Codex/Claude/Vantix can inspect, run, schedule, export CI presets, and package Automation parity evidence without scraping the GUI. |

Ignored evidence artifact:

- `.gitignored/test-artifacts/automation-engine/automation-parity-evidence-package.json`

## 2026-05-25 Linux Packaged Agent External-Cwd Release Smoke

Environment:

- Time: `2026-05-25T05:42:20-04:00` / `2026-05-25T09:42:20Z`
- Host: `Linux kalidev 6.16.8+kali-amd64 x86_64`
- Node: `v22.22.2`
- Electron runtime in package: `42.2.0`
- Packaged Node runtime: `v24.15.0`
- Display lane: `/usr/bin/xvfb-run`

Commands and results:

| Command | Result |
| --- | --- |
| `npm run dist:linux` | Passed; rebuilt current `release/linux-unpacked`, AppImage, and deb artifacts from the latest source with the packaged agent CLI smoke wiring. |
| `node scripts/release-smoke.mjs --platform linux --artifact release/linux-unpacked/proxyforge --browser-routing --out test-results/release-smoke-linux-packaged-agent-external-cwd.json --headlessTimeout 45000 --runtimeTimeout 70000 --browser-routing-timeout 90000` | Passed 9/9 with 0 blocked and 0 failed checks. `packaged-agent-cli` started from `resources/app.asar/scripts/proxyforge-agent.mjs`, returned `status: completed`, exposed 40 agent commands, proved required capabilities `mitm-start`, `search-index`, `proxy-import`, `crawl-run`, `content-discovery-plan`, `callback-relay-soak`, `callback-retention-prune`, `repeater-race-run`, and `report-export`, resolved its app root to `resources/app.asar`, and preserved `execution-full-fidelity-secrets-preserved` with `redacted: false`. `packaged-agent-cli-external-cwd` also ran the same packaged agent from `test-results/release-smoke-agent-external-cwd/...`, reported that external cwd in `data.runtime.cwd`, kept `data.runtime.appRoot` on `resources/app.asar`, exposed 40 commands, and proved external agents can invoke the packaged runtime without running from the ProxyForge repo. The same run also passed Electron Node runtime, packaged headless CLI, packaged headless scan/report export, packaged runtime proxy/cert/OAST/report export, Chromium browser routing, and Xvfb GUI launch checks. |

Artifacts:

| Artifact | Size | SHA-256 |
| --- | ---: | --- |
| `release/ProxyForge-0.1.0.AppImage` | 126,286,149 bytes | `2affec56606a14e1e1c7cc886ae99530d495e82cf9d44ff216470d230aae8cc8` |
| `release/proxyforge_0.1.0_amd64.deb` | 98,174,848 bytes | `060de5b8926192035fa57734b5c4c325bad33eead423b32ad346393215c82c96` |
| `release/linux-unpacked/proxyforge` | 210,091,224 bytes | `4cef137da0cf3c33cf3589e1755f8b6c2e3ed3a67643c4e44197dd1bee505656` |

Smoke output files:

- `test-results/release-smoke-linux-packaged-agent-external-cwd.json`
- `test-results/release-smoke-agent-external-cwd/packaged-agent-cli-external-cwd-1779702135429/`
- `test-results/release-smoke-headless/packaged-headless-scan-report-1779702135772/`
- `test-results/release-smoke-runtime/packaged-runtime-proxy-cert-oast-report-1779702136201/`
- `test-results/release-smoke-browser-routing/packaged-browser-routing-1779702137187/`

## 2026-05-25 Linux Packaged Runtime Workflow Smoke

Environment:

- Time: `2026-05-25T01:16:35-04:00` / `2026-05-25T05:16:35Z`
- Host: `Linux kalidev 6.16.8+kali-amd64 x86_64`
- Node: `v22.22.2`
- Electron runtime in package: `42.2.0`
- Packaged Node runtime: `v24.15.0`
- Display lane: `/usr/bin/xvfb-run`

Commands and results:

| Command | Result |
| --- | --- |
| `npm run dist:linux` | Passed; rebuilt `release/linux-unpacked`, AppImage, and deb with `dist-electron/releaseWorkflowSmoke.js` and trusted-CA-capable `dist-electron/releaseBrowserRoutingSmoke.js` inside `resources/app.asar`. |
| `node scripts/release-smoke.mjs --platform linux --artifact release/linux-unpacked/proxyforge --browser-routing --out test-results/release-smoke-linux-browser-routing.json --headlessTimeout 45000 --runtimeTimeout 70000 --browser-routing-timeout 90000` | Passed 7/7; `release/linux-unpacked/proxyforge` exists, `ELECTRON_RUN_AS_NODE=1` reports Electron `42.2.0` and Node `v24.15.0`, packaged headless CLI help starts from `resources/app.asar/dist-electron/headlessRunner.js`, packaged headless scan/report smoke crawled a local loopback target, found 4 synthetic issues, exported JSON/Markdown/SARIF/JUnit artifacts under `test-results/release-smoke-headless/`, packaged runtime workflow smoke captured HTTP proxy traffic, decrypted HTTPS MITM with the project CA, captured HTTP/DNS/SMTP OAST callbacks, exported JSON/Markdown/HTML/PDF/bundle reports, preserved synthetic secrets in the operational capture, redacted them in report artifacts, packaged browser routing launched `/usr/bin/chromium` with an isolated profile and captured its request through ProxyForge under `test-results/release-smoke-browser-routing/`, and `PROXYFORGE_RELEASE_SMOKE=1 xvfb-run -a release/linux-unpacked/proxyforge --no-sandbox` loaded `resources/app.asar/dist/index.html` and exited with a structured `proxyforge-release-smoke` payload. |
| `node scripts/release-smoke.mjs --platform linux --artifact release/ProxyForge-0.1.0.AppImage --out test-results/release-smoke-linux-appimage.json` | Passed; AppImage node-runtime smoke and Xvfb renderer-load smoke both completed. |
| `node scripts/release-smoke.mjs --platform linux --artifact release/proxyforge_0.1.0_amd64.deb --out test-results/release-smoke-linux-deb.json` | Passed; deb metadata reports package `proxyforge`, version `0.1.0`, architecture `amd64`, maintainer `ProxyForge Maintainers <release@proxyforge.local>`, and required desktop dependencies including `libgbm1` and `libasound2`. |
| `PROXYFORGE_DOCKER="sudo -n docker" scripts/release-deb-container-smoke.sh --gui --browser-trust` | Passed in a throwaway `debian:bookworm-slim` container; `apt-get install` pulled declared dependencies, installed `/opt/ProxyForge/proxyforge`, `ELECTRON_RUN_AS_NODE=1` reported Electron `42.2.0`, Node `v24.15.0`, platform `linux`, arch `x64`, installed Xvfb/xauth for the GUI harness, launched `/opt/ProxyForge/proxyforge --no-sandbox` with `PROXYFORGE_RELEASE_SMOKE=1`, loaded `file:///opt/ProxyForge/resources/app.asar/dist/index.html`, emitted a passed `proxyforge-release-smoke` payload in `362ms`, installed Chromium and `libnss3-tools` inside the throwaway container, imported the ProxyForge project CA into a per-run isolated Chromium NSS trust store under `/out/proxyforge-browser-trust/`, launched Chromium to `https://127.0.0.1:<port>/browser?proof=routing` without `--ignore-certificate-errors`, captured trusted HTTPS traffic through ProxyForge with `certificateMode: trusted-ca`, retained ignored host artifacts under `.gitignored/deb-container-smoke/proxyforge-browser-trust/`, `dpkg-query` reported `proxyforge 0.1.0 install ok installed`, `apt-get remove -y proxyforge` removed the package, and `/opt/ProxyForge/proxyforge` no longer existed after uninstall. Earlier clean-container attempts exposed missing `libgbm.so.1` and `libasound.so.2`; both dependencies are now declared in package metadata. |

Artifacts:

| Artifact | Size | SHA-256 |
| --- | ---: | --- |
| `release/ProxyForge-0.1.0.AppImage` | 126,241,231 bytes | `c4192c408c1bb7871ebe8dba300be033cda4086d2bc663aded0fd2e99478b70c` |
| `release/proxyforge_0.1.0_amd64.deb` | 98,093,228 bytes | `d5264bdfb055de3b46f0544c1d384f718a9e77227ff9ea55ba474af0eaab792d` |
| `release/linux-unpacked/proxyforge` | 210,091,224 bytes | `4cef137da0cf3c33cf3589e1755f8b6c2e3ed3a67643c4e44197dd1bee505656` |

Smoke output files:

- `test-results/release-smoke-linux-browser-routing.json`
- `test-results/release-smoke-linux-appimage.json`
- `test-results/release-smoke-linux-deb.json`
- `test-results/release-smoke-headless/packaged-headless-scan-report-*/`
- `test-results/release-smoke-runtime/packaged-runtime-proxy-cert-oast-report-*/`
- `test-results/release-smoke-browser-routing/packaged-browser-routing-*/`

Warnings observed:

- AppImage GUI smoke printed a transient Chromium GPU command-buffer warning under Xvfb, but the renderer loaded and the structured smoke payload reported `status: passed`.
- The deb clean-container install emitted a non-fatal Electron Builder postinstall sandbox warning, `unshare: unshare failed: Operation not permitted`, inside Docker only; package install, runtime, GUI launch, and uninstall still passed.
- The installed GUI launch under Xvfb printed expected container-only DBus and transient GPU command-buffer warnings, but the renderer loaded and the structured smoke payload reported `status: passed`.
- This is a packaged Linux GUI launch proof under Xvfb plus packaged headless report-export, packaged runtime proxy/cert/OAST/report proof, packaged Chromium browser proxy-routing proof, clean-container deb install/runtime/installed-GUI/uninstall proof, and clean-container isolated Chromium trusted-CA HTTPS capture proof. The earlier browser-routing smoke still records the `--ignore-certificate-errors` compatibility lane; the trusted-CA container smoke is the counted browser trust proof.

Remaining release proof:

- Windows OS/browser trust-store HTTPS capture proof, unless explicitly pinned by host constraints.
- Cross-platform browser/trust validation before any release row can be called `Production Ready`, unless the platform lane is explicitly pinned by host constraints.

## 2026-05-24 Linux Artifact Build

Environment:

- Time: `2026-05-24T17:48:02-04:00`
- Host: `Linux kalidev 6.16.8+kali-amd64 #1 SMP PREEMPT_DYNAMIC Kali 6.16.8-1kali1 (2025-09-24) x86_64 GNU/Linux`
- Node: `v22.22.2`
- npm: `9.2.0`

Commands and results:

| Command | Result |
| --- | --- |
| `npm run dist:linux` | Passed after adding package author metadata required by deb maintainer fields. |
| `npm run test:release` | Passed; verifies release scripts, builder targets, compiled Electron outputs, ignored artifact directories, checklist coverage, and maintainer metadata. |
| `dpkg-deb --info release/proxyforge_0.1.0_amd64.deb` | Passed; Debian metadata reports `Package: proxyforge`, `Version: 0.1.0`, `Architecture: amd64`, and `Maintainer: ProxyForge Maintainers <release@proxyforge.local>`. |
| `release/ProxyForge-0.1.0.AppImage --appimage-version` | Passed; returned `Version: effcebc`. |
| `ELECTRON_RUN_AS_NODE=1 release/linux-unpacked/proxyforge -e "console.log(...)"` | Passed; returned `42.2.0 node v24.15.0`. |
| `ELECTRON_RUN_AS_NODE=1 release/ProxyForge-0.1.0.AppImage -e "console.log(...)"` | Passed; returned `42.2.0 node v24.15.0`. |
| `release/linux-unpacked/proxyforge --version` | Failed in this headless shell with `Missing X server or $DISPLAY`; this is not a desktop launch pass. |

Artifacts:

| Artifact | Size | SHA-256 |
| --- | ---: | --- |
| `release/ProxyForge-0.1.0.AppImage` | 151,954,150 bytes | `bc84826ee0c3d61ceb4102fa5f83241c8e2c67727043d552f67a5d9bdbf05899` |
| `release/proxyforge_0.1.0_amd64.deb` | 117,177,512 bytes | `3f71a6c5583300e74f43a39e01a27b713f25fdb270260db909310e9553abbf1e` |
| `release/linux-unpacked/proxyforge` | 210,091,224 bytes | Not recorded; unpacked runtime file is generated as part of the package directory. |

Deb package contents smoke:

- Installs under `/opt/ProxyForge/`.
- Includes `/opt/ProxyForge/proxyforge`.
- Includes `/usr/share/applications/proxyforge.desktop`.
- Includes hicolor application icons from 16x16 through 256x256.

Warnings observed:

- Vite still reports a large renderer chunk after minification.
- The headless CI shell has no graphical display, so GUI launch and installer smoke were not completed here.

Current remaining release proof after later smoke sections:

- Windows OS/browser trust-store HTTPS capture proof or explicit nonblocking pin.
- Cross-platform clean-profile workflow evidence before any release row can be called `Production Ready`.

## 2026-05-24 Windows Artifact Attempt From Linux

Environment:

- Time: `2026-05-24T17:59:00-04:00`
- Host: same Linux host as the Linux artifact build.
- Wine: not installed on PATH.
- NSIS: `/usr/bin/makensis`

Commands and results:

| Command | Result |
| --- | --- |
| `npm run dist:win` | Failed after producing `release/win-unpacked/ProxyForge.exe`; Electron Builder reported `wine is required` while preparing NSIS/portable artifacts. |
| `npx electron-builder --win zip` | Failed on the same Wine requirement. |
| `npm run dist:win:zip` | Passed; produced a Windows x64 zip artifact without Windows executable metadata/icon editing. |
| `file release/win-unpacked/ProxyForge.exe` | Passed; reports `PE32+ executable for MS Windows 10.00 (GUI), x86-64, 14 sections`. |
| `unzip -l release/ProxyForge-0.1.0-win.zip` | Passed; archive includes `ProxyForge.exe`, Electron runtime DLLs, locale packs, `resources.pak`, and `resources/app.asar`. |
| `unzip -l release/ProxyForge-0.1.0-win.zip \| rg "rolldown\|lightningcss\|linux-x64\|vite\|node_modules"` | Passed with no matches after moving `vite` to `devDependencies`. |
| `npm run release:smoke:windows` | Passed artifact-exists and zip-contents checks, wrote `test-results/release-smoke-windows.json`, and correctly marked `windows-gui-launch` as blocked on this Linux host pending Windows-host execution. |

Artifacts:

| Artifact | Size | SHA-256 |
| --- | ---: | --- |
| `release/ProxyForge-0.1.0-win.zip` | 143,849,075 bytes | `8c4e6b4a7f28228be7dadbed59dcd37d1caa09a45c247149f31f755ec584bf37` |
| `release/win-unpacked/ProxyForge.exe` | 226,508,800 bytes | `3a4232ce3f16e16acb54a5ff4743035a6c698d47cfe591fdbb86708c18aff984` |

Packaging hygiene note:

- The first Windows zip inspection showed Linux-native Vite/Rolldown build dependencies inside `resources/app.asar.unpacked`, because `vite` was listed as a production dependency. `vite` has been moved to `devDependencies`; the rebuilt zip has no `resources/app.asar.unpacked` directory and no `rolldown`, `lightningcss`, `linux-x64`, `vite`, or `node_modules` entries.

Remaining Windows release proof after later smoke sections:

- Run Windows OS/browser trust-store HTTPS capture smoke or pin the host lane as nonblocking.
- Keep portable-wrapper stdout behavior pinned; the unpacked and installed app are the counted GUI/runtime proofs.

## 2026-05-24 Windows Host Packaging And GUI Smoke

Environment:

- Time: `2026-05-24T23:58:13-04:00` / `2026-05-25T03:58:13Z`.
- Host: the Windows test runner.
- OS: Windows 11 Pro `10.0.22000`, x64.
- Source snapshot: `a9cd99e` (`Add scanner live calibration tuning`) staged from the pushed repository archive.
- Node/npm: Node `v24.14.1` for scripts; packaged Electron runtime reports Node `24.15.0`.

Commands and results:

| Command | Result |
| --- | --- |
| `npm ci` | Passed; installed 329 packages and reported 0 vulnerabilities. |
| `npm run build` | Passed on Windows; TypeScript, Vite, and Electron TypeScript build completed. |
| `npm run dist:win` | Passed natively on Windows; produced `win-unpacked`, NSIS setup, and portable executable artifacts without the Linux/Wine blocker. |
| `npm run release:smoke:windows` | Passed on Windows; checked `release/win-unpacked/ProxyForge.exe`, `ELECTRON_RUN_AS_NODE=1`, and `PROXYFORGE_RELEASE_SMOKE=1` packaged GUI launch. |

Artifacts:

| Artifact | Size | SHA-256 |
| --- | ---: | --- |
| `release/win-unpacked/ProxyForge.exe` | 226,508,800 bytes | `df0a547343d2e83d778992a5120714ef307060b3d5eca74b8f9739ef39667705` |
| `release/ProxyForge Setup 0.1.0.exe` | 104,100,228 bytes | `da8911e83592dd5e0425b6712cec54f5b3bd64abb05b35785063da45099c2a42` |
| `release/ProxyForge 0.1.0.exe` | 103,933,095 bytes | `89d4013bd655b40f016bc72d83f742c3103ded6ce2559bfbabd58640dedf443e` |

Windows release smoke payload:

- `artifact-exists`: passed for `release/win-unpacked/ProxyForge.exe`.
- `electron-node-runtime`: passed; Electron `42.2.0`, Node `v24.15.0`, platform `win32`, arch `x64`.
- `windows-gui-launch`: passed; `PROXYFORGE_RELEASE_SMOKE` loaded `file:///C:/Users/windows-trust-runner/proxyforge-a9cd99e/release/win-unpacked/resources/app.asar/dist/index.html` and exited with `status: passed`.
- Output file: `test-results/release-smoke-windows.json` on `windows-trust-runner`.

Pinned for Production Ready:

- The portable wrapper artifact exists, but it does not forward the structured smoke payload to stdout when launched over SSH, so the unpacked executable remains the counted GUI proof.
- Windows browser routing through Edge/Chrome and DPAPI sample cookie extraction were later proved in the packaged smoke section below; Windows OS/browser trust-store HTTPS capture remains pinned unless a host lane is explicitly selected for certificate-store mutation.

## 2026-05-25 Windows NSIS Install Runtime Workflow Uninstall Smoke

Environment:

- Time: `2026-05-25T00:52:22-04:00` / `2026-05-25T04:52:22Z`.
- Host: the Windows test runner.
- OS: Windows 11 Pro `10.0.22000`, x64.
- Source snapshot: same Windows package workspace used for the Windows host packaging checkpoint, with the current `electron/releaseWorkflowSmoke.ts` and `scripts/release-smoke.mjs` copied in before `npm run dist:win`.

Command:

```powershell
node scripts\release-smoke.mjs --platform windows --artifact "release\ProxyForge Setup 0.1.0.exe" --uninstall --timeout 30000 --headlessTimeout 45000 --runtimeTimeout 70000 --out test-results\release-smoke-windows-installer.json
```

Result:

- `artifact-exists`: passed for `release/ProxyForge Setup 0.1.0.exe`, 104,106,627 bytes, SHA-256 `da5330380f4d4f5b3a698f3a251f63a4ee5b0a0b22eff48ab6980ad02c6f81d4`.
- `windows-installer-silent-install`: passed with `/S`, exit code `0`.
- `windows-installed-executable`: passed; found `%LOCALAPPDATA%\Programs\proxyforge\ProxyForge.exe`, 226,508,800 bytes, SHA-256 `0e90fad95b0986c2d465d07b8b430a55f7e8cacfa4c4ca2fff7bea6cd6b68c9d`.
- `windows-installed-electron-node-runtime`: passed; Electron `42.2.0`, Node `v24.15.0`, platform `win32`, arch `x64`.
- `windows-installed-headless-cli`: passed; packaged headless help starts from `resources\app.asar\dist-electron\headlessRunner.js`.
- `windows-installed-headless-scan-report`: passed; installed packaged app ran a loopback headless scan, found 4 synthetic issues, exported 2 report artifacts and 2 CI artifacts, and verified `proxyforge-headless-summary.json`, JSON, Markdown, SARIF, and JUnit files under `test-results\release-smoke-headless\windows-installed-headless-scan-report-*`.
- `windows-installed-runtime-proxy-cert-oast-report`: passed; installed packaged app captured HTTP proxy traffic, decrypted HTTPS MITM with a generated project CA, captured HTTP/DNS/SMTP OAST callbacks, exported JSON/Markdown/HTML/PDF/bundle reports, preserved synthetic secrets in operational capture, and redacted them in report artifacts under `test-results\release-smoke-runtime\windows-installed-runtime-proxy-cert-oast-report-*`.
- `windows-installed-gui-launch`: passed; `PROXYFORGE_RELEASE_SMOKE` loaded `file:///C:/Users/windows-trust-runner/AppData/Local/Programs/proxyforge/resources/app.asar/dist/index.html` and exited with `status: passed`.
- `windows-installer-silent-uninstall`: passed with `/currentuser /S`, exit code `0`.
- `windows-installed-executable-removed`: passed; installed `ProxyForge.exe` was removed by quiet uninstall.
- Output file: `test-results/release-smoke-windows-installer.json` on `windows-trust-runner`.

Remaining Windows production proof:

- Windows OS/browser trust-store HTTPS capture remains pinned unless a host lane is explicitly selected for certificate-store mutation.

## 2026-05-25 Windows Browser Routing And DPAPI Sample-Cookie Smoke

Environment:

- Time: `2026-05-25T02:20:36-04:00` / `2026-05-25T06:20:36Z`.
- Host: the Windows test runner.
- OS: Windows 11 Pro `10.0.22000`, x64.
- Source snapshot: pushed `87689ea` source archive plus the packaged DPAPI smoke and release-runner wiring added in this checkpoint before `npm run dist:win`.
- Node/npm: Node `v24.14.1` for scripts; packaged Electron runtime reports Node `24.15.0`.

Commands and results:

| Command | Result |
| --- | --- |
| `npm ci` | Passed in the fresh source directory; installed 329 packages and reported 0 vulnerabilities. |
| `npm run dist:win` | Passed natively on Windows; rebuilt `win-unpacked`, NSIS setup, and portable executable with `releaseCookieDpapiSmoke.js` inside `resources\app.asar`. |
| `node scripts\release-smoke.mjs --platform windows --artifact release\win-unpacked\ProxyForge.exe --browser-routing --dpapi-cookie --out test-results\release-smoke-windows-browser-dpapi.json --headlessTimeout 60000 --runtimeTimeout 90000 --browser-routing-timeout 120000 --dpapi-cookie-timeout 60000` | Passed 8/8 checks with no blocked or failed checks. |

Artifacts:

| Artifact | Size | SHA-256 |
| --- | ---: | --- |
| `release/win-unpacked/ProxyForge.exe` | 226,508,800 bytes | `6b7d423f877a47a428402f595fb619675527353404dbae8f031c51eb374cdba0` |
| `release/ProxyForge Setup 0.1.0.exe` | 104,114,181 bytes | `0a647ebe75b1deaa141aa315303118ac23ced532d9cb5ce70c94b445ec07e3ad` |
| `release/ProxyForge 0.1.0.exe` | 103,947,050 bytes | `5ea96546bffb6615e7ad3d2ef136dbfe2d5e7749aead74fbaba830926e1fad5d` |

Windows browser and DPAPI smoke payload:

- `artifact-exists`: passed for `release\win-unpacked\ProxyForge.exe`.
- `electron-node-runtime`: passed; Electron `42.2.0`, Node `v24.15.0`, platform `win32`, arch `x64`.
- `windows-packaged-headless-cli`: passed; packaged headless help starts from `resources\app.asar\dist-electron\headlessRunner.js`.
- `windows-packaged-headless-scan-report`: passed; packaged app ran a loopback headless scan, found 4 synthetic issues, exported 2 report artifacts and 2 CI artifacts, and verified JSON, Markdown, SARIF, JUnit, and `proxyforge-headless-summary.json` under `test-results\release-smoke-headless\windows-packaged-headless-scan-report-*`.
- `windows-packaged-runtime-proxy-cert-oast-report`: passed; packaged app captured HTTP proxy traffic, decrypted HTTPS MITM with a generated project CA, captured HTTP/DNS/SMTP OAST callbacks, exported JSON/Markdown/HTML/PDF/bundle reports, preserved synthetic secrets in operational capture, and redacted them in report artifacts.
- `windows-packaged-browser-routing`: passed; launched Google Chrome from `C:\Program Files\Google\Chrome\Application\chrome.exe` with an isolated profile, configured the packaged ProxyForge proxy, captured browser-routed traffic, and wrote `proxyforge-browser-routing-operational-capture.json` plus `proxyforge-browser-routing-summary.json` under `test-results\release-smoke-browser-routing\windows-packaged-browser-routing-*`.
- `windows-packaged-dpapi-cookie`: passed; created a synthetic Chromium profile, wrapped the profile key with the current Windows user's DPAPI, extracted and decrypted one Chromium sample cookie through the packaged runtime, preserved the full cookie header in `proxyforge-dpapi-cookie-operational-capture.json`, redacted cookie values from `proxyforge-dpapi-cookie-summary.json`, and reported `readinessStatus: ready`, `cookieCount: 1`, `decryptedCount: 1`, `encryptedCount: 0`.
- `windows-gui-launch`: passed; `PROXYFORGE_RELEASE_SMOKE` loaded `file:///C:/Users/windows-trust-runner/proxyforge-current-87689ea-src/release/win-unpacked/resources/app.asar/dist/index.html` and exited with `status: passed`.
- Output file retained locally under ignored `.gitignored/windows-runner/release-smoke-windows-browser-dpapi.json` and on `windows-trust-runner` under `test-results\release-smoke-windows-browser-dpapi.json`.

Pinned for Production Ready:

- Windows OS/browser trust-store HTTPS capture remains pinned as nonblocking unless a host lane is explicitly selected for temporary certificate-store mutation and cleanup. The follow-up `windows-trust-runner` proof below records the current runner limitation as a blocked lane with no failed checks.
- The portable wrapper artifact exists, but the unpacked executable remains the counted GUI/runtime proof.

## 2026-05-25 Target Parity Evidence Checkpoint

Commands and results:

| Command | Result |
| --- | --- |
| `node tests/crawl-engine.mjs` | Passed; scoped crawler runtime handles route discovery and insertion-point extraction. |
| `node tests/session-profile-refresh.mjs` | Passed; authenticated session refresh and cookie merge behavior remain covered. |
| `node tests/target-map-engine.mjs` | Passed; wrote `.gitignored/test-artifacts/target-map-engine/target-parity-evidence-package.json` and proved URL tree, crawl-path, scoped crawler, session reuse, technology inventory, parameter/insertion inventory, access-control review, site-map comparison, Reports handoff, full-fidelity operational samples, and report-export-only redaction. |
| `node tests/report-engine.mjs` | Passed; report export still redacts submission artifacts while accepting Target evidence attachments. |
| `npx playwright test tests/proxyforge.spec.ts -g "advanced Target\|session profiles"` | Passed 3/3; Target report evidence handoff and session reuse across crawler, Repeater, and scanner remain covered, with operational previews preserving executor secrets before reporting. |
| `npm run test:ci:fast` | Passed 42/42 after adding the crawler runtime engine to the curated suite. |

Target parity payload:

- `proxyforge-target-parity-evidence-package` is operational evidence, not submission material.
- It preserves cookies, bearer tokens, refreshed session names, route evidence, comparison bodies, and Target/Reports linkage until report export.
- `docs/FEATURE_MATRIX.md` now records all remaining Target rows as `Parity Candidate`; remaining Target work is imported legacy proxy sitemap/crawl interop, long-running live crawl diversity, GUI scale hardening, and package-refresh proof.

## 2026-05-25 Repeater Parity Evidence Checkpoint

Commands and results:

| Command | Result |
| --- | --- |
| `node tests/repeater-workspace-engine.mjs` | Passed; wrote `.gitignored/test-artifacts/repeater-workspace-engine/repeater-parity-evidence-package.json` and proved manual request editing/send, tabs, grouped workspaces, saved request libraries, snapshots/diffs, session profile injection, authorization matrix linkage, transport controls, bulk replay handoff, full-fidelity operational samples, and report-export-only redaction. |
| `node tests/repeater-transport.mjs` | Passed; socket-backed Repeater transport controls still cover redirect, timeout, and connection behavior. |
| `npx playwright test tests/proxyforge.spec.ts -g "Replay session profiles|saves Repeater requests"` | Passed; Repeater UI session injection, saved requests, bulk replay, authorization matrix, and transport settings remain covered. |

Repeater parity payload:

- `proxyforge-repeater-parity-evidence-package` is operational evidence, not submission material.
- It preserves edited raw requests, response bodies, session headers/cookies, saved request bodies, authorization matrix bodies, and operational tokens until report export.
- `docs/FEATURE_MATRIX.md` now records core Repeater manual send, workspaces/saved requests, and session profile injection as `Parity Candidate`.

## 2026-05-25 Windows Trusted-CA Browser Lane Pin

Environment:

- Time: `2026-05-25T03:00:46-04:00` / `2026-05-25T07:00:46Z`.
- Host: `windows-trust-runner` / Windows 11 Pro `10.0.22000`, x64.
- Source snapshot: pushed `87689ea` source archive plus the current browser trust-store diagnostics and release-smoke blocked-lane classification before `npm run dist:win`.
- Node/npm: Node `v24.14.1` for scripts; packaged Electron runtime reports Electron `42.2.0`, Node `v24.15.0`.

Commands and results:

| Command | Result |
| --- | --- |
| `npm run dist:win` | Passed natively on Windows; rebuilt `win-unpacked`, NSIS setup, and portable executable with the current `releaseBrowserRoutingSmoke.js` inside `resources\app.asar`. |
| `node scripts\release-smoke.mjs --platform windows --artifact release\win-unpacked\ProxyForge.exe --browser-routing --browser-trust-store --dpapi-cookie --out test-results\release-smoke-windows-browser-trust-dpapi.json --headlessTimeout 60000 --runtimeTimeout 90000 --browser-routing-timeout 120000 --dpapi-cookie-timeout 60000` | Completed with `status: blocked`, `passedChecks: 7`, `blockedChecks: 1`, and `failedChecks: 0`. |

Windows trusted-CA lane payload:

- `artifact-exists`: passed for `release\win-unpacked\ProxyForge.exe`, size `226,508,800` bytes, SHA-256 `3669086a4265858ab5dbd8e3afe41df157df39cfaf6b5a55cf4fea088168833e`.
- `electron-node-runtime`: passed; Electron `42.2.0`, Node `v24.15.0`, platform `win32`, arch `x64`.
- `windows-packaged-headless-cli`: passed from `resources\app.asar\dist-electron\headlessRunner.js`.
- `windows-packaged-headless-scan-report`: passed; loopback scan found 4 synthetic issues and exported JSON, Markdown, SARIF, JUnit, and summary artifacts.
- `windows-packaged-runtime-proxy-cert-oast-report`: passed; packaged runtime captured HTTP proxy traffic, HTTPS MITM with generated project CA, HTTP/DNS/SMTP OAST callbacks, full report exports, operational-secret preservation, and report redaction.
- `windows-packaged-browser-routing`: blocked for the trusted-CA mode only. Google Chrome was discovered, but the runner rejected temporary import into `Cert:\CurrentUser\Root` through `C:\Windows\System32\certutil.exe` with `0x80070032 (WIN32: 50 ERROR_NOT_SUPPORTED)`. A .NET `X509Store` probe returned the same host/session limitation. No ProxyForge certificate remained in the current-user Root store after the attempts.
- `windows-packaged-dpapi-cookie`: passed; the synthetic Chromium DPAPI profile decrypted one sample cookie and preserved full operational cookie output while redacting summary values.
- `windows-gui-launch`: passed with `PROXYFORGE_RELEASE_SMOKE`.
- Output file retained locally under ignored `.gitignored/windows-runner/release-smoke-windows-browser-trust-dpapi-blocked.json` and on `windows-trust-runner` under `test-results\release-smoke-windows-browser-trust-dpapi.json`.
