# Agent JSON Schemas

All agent commands emit a shared envelope:

```json
{
  "kind": "proxyforge-agent-result",
  "schemaVersion": 1,
  "command": "status",
  "generatedAt": "2026-05-24T00:00:00.000Z",
  "status": "completed",
  "mode": "read-only",
  "project": {
    "name": "Assessment",
    "scopeCount": 1,
    "exchangeCount": 1,
    "findingCount": 0
  },
  "safety": {
    "redacted": false,
    "secretHandling": "execution-full-fidelity-secrets-preserved",
    "scopeAllowlist": ["example.test"],
    "trafficSent": false,
    "requestCount": 0,
    "approvals": [],
    "gates": ["full-fidelity-operational-output"]
  },
  "artifacts": [],
  "data": {},
  "audit": []
}
```

## Status Values

- `completed`: command finished and the output is usable.
- `planned`: command prepared a workflow but sent no traffic.
- `queued`: command created an approved execution package for another backend.
- `blocked`: safety or input validation stopped the command.

## Phase Boundary

Operational/executor commands preserve Authorization, Cookie, X-API-Key, token, session, secret, password, API key fields, raw request bodies, raw response bodies, and callback tokens so agents can replay, exploit, scan, and gather intel correctly. Redaction happens only when generating submission/reporting artifacts such as report exports and signed bundles.

## Platform And Release Evidence

`proxyforge-platform-release-parity-evidence-package` is the proof bundle for UI, desktop shell, packaging, release gates, install docs, and security-review parity:

```json
{
  "kind": "proxyforge-platform-release-parity-evidence-package",
  "artifactCount": 6,
  "smokeCount": 16,
  "gateCount": 4,
  "documentationCount": 3,
  "requirements": {
    "denseNavigationCovered": true,
    "visualQaCovered": true,
    "linuxElectronShellCovered": true,
    "windowsElectronShellCovered": true,
    "linuxArtifactsCovered": true,
    "windowsArtifactsCovered": true,
    "packagedHeadlessCliCovered": true,
    "packagedAgentCliCovered": true,
    "packagedRuntimeProxyCertOastReportCovered": true,
    "packagedBrowserRoutingCovered": true,
    "linuxInstallTrustUninstallCovered": true,
    "windowsInstallerUninstallCovered": true,
    "windowsTrustStorePinCovered": true,
    "fastSuiteCovered": true,
    "fullNightlySuiteCovered": true,
    "installDocsCovered": true,
    "securityReviewCovered": true,
    "platformPinsCovered": true,
    "rawExecutorMaterialPreserved": true,
    "operationalSecretsPreserved": true,
    "reportPhaseOnlyRedaction": true
  },
  "secretHandling": "execution-full-fidelity-secrets-preserved",
  "reportRedactionBoundary": "redact-only-during-report-export"
}
```

Agents should use this package to decide whether Platform and Release rows are still at parity after package refreshes. It includes Linux AppImage/deb/unpacked evidence, Windows NSIS/portable/unpacked evidence, `PROXYFORGE_RELEASE_SMOKE=1` shell proof, packaged headless and agent CLI proof, browser routing, Linux trusted-CA install proof, the `windows-trust-runner` `ERROR_NOT_SUPPORTED` trust-store pin, `test:ci:fast`, `test:ci:full`, release docs, and release security review material. It preserves raw executor tokens, cookies, callback tokens, and request/response bodies until a report command emits submission artifacts.

## UI Scale Production Evidence

`proxyforge-ui-scale-production-evidence-package` is the proof bundle for dense analyst UI scale and responsive overflow hardening:

```json
{
  "kind": "proxyforge-ui-scale-production-evidence-package",
  "viewportCount": 3,
  "largeProjectProfileCount": 2,
  "workflowProofCount": 9,
  "requirements": {
    "desktopTabletMobileCovered": true,
    "allMajorSurfacesReachable": true,
    "noViewportOverlapOrOverflow": true,
    "textFitAndLongLabelsCovered": true,
    "keyboardAndAccessibleNamesCovered": true,
    "stableFixedControlsCovered": true,
    "largeProjectDataDensityCovered": true,
    "boundedRowWindowsCovered": true,
    "latencyBudgetsCovered": true,
    "reportAttachmentScaleCovered": true,
    "workflowSurfaceCoverage": true,
    "packagedModeCovered": true,
    "docsAndSchemasCovered": true,
    "rawExecutorMaterialPreserved": true,
    "operationalSecretsPreserved": true,
    "reportPhaseOnlyRedaction": true
  },
  "secretHandling": "execution-full-fidelity-secrets-preserved",
  "reportRedactionBoundary": "redact-only-during-report-export",
  "productionReady": true
}
```

Agents should use this package before trusting ProxyForge for large workspaces or compact displays. It records desktop, tablet, and mobile proofs; all major surfaces; zero overlap and horizontal overflow; long-label fitting; keyboard and accessible-name coverage; stable fixed-format controls; bounded retained row windows for large Proxy/Target/Intruder/WebSocket/Report datasets; latency budgets; packaged `resources/app.asar` proof; and report-export-only redaction. Operational UI evidence keeps raw requests, raw responses, tokens, cookies, keys, and callbacks intact until report export.

## Release Security Production Evidence

`proxyforge-release-security-production-evidence-package` is the proof bundle for the release-wide security review row:

```json
{
  "kind": "proxyforge-release-security-production-evidence-package",
  "proofCount": 12,
  "reviewFindingCount": 20,
  "requirements": {
    "formalSecurityReviewPassed": true,
    "allSecurityCategoriesCovered": true,
    "noCriticalHighFindings": true,
    "localListenersCovered": true,
    "secretBoundaryCovered": true,
    "reviewRedactionCovered": true,
    "exploitControlsCovered": true,
    "agentControlsCovered": true,
    "aiProviderControlsCovered": true,
    "platformPinsCovered": true,
    "signedTrustCovered": true,
    "productionCiCovered": true,
    "cleanMachineRuntimeEvidenceCovered": true,
    "artifactHygieneCovered": true,
    "packageRefreshCovered": true,
    "docsAndSchemasCovered": true,
    "rawExecutorMaterialPreserved": true,
    "operationalSecretsPreserved": true,
    "reportPhaseOnlyRedaction": true
  },
  "secretHandling": "execution-full-fidelity-secrets-preserved",
  "reportRedactionBoundary": "redact-only-during-report-export",
  "productionReady": true
}
```

Agents should treat this package as the Production Ready evidence for release security only. It proves the formal zero-warning security review, local listener bindings, exploit controls, agent controls, AI provider controls, platform pins, signed trust, production CI gates, clean Linux/Windows runtime evidence, artifact hygiene, package refresh, docs/schemas, and full-fidelity executor material. It also proves the boundary that operational artifacts keep tokens, cookies, keys, raw requests, raw responses, and callback tokens until report/export commands produce redacted submission artifacts.

## Platform Shell Production Evidence

`proxyforge-platform-shell-production-evidence-package` is the proof bundle for the Linux/Windows packaged Electron shell row:

```json
{
  "kind": "proxyforge-platform-shell-production-evidence-package",
  "smokeCount": 15,
  "requirements": {
    "linuxShellLaunchCovered": true,
    "windowsShellLaunchCovered": true,
    "structuredReleaseSmokeCovered": true,
    "packagedHeadlessCovered": true,
    "packagedAgentCovered": true,
    "externalCwdAgentCovered": true,
    "appRootAsarCovered": true,
    "packagedRuntimeCovered": true,
    "packagedBrowserRoutingCovered": true,
    "linuxPackageProductionGateCovered": true,
    "windowsPackageProductionGateCovered": true,
    "trustStorePinAccepted": true,
    "knownHostLimitsPinned": true,
    "releaseDocsCovered": true,
    "rawExecutorMaterialPreserved": true,
    "operationalSecretsPreserved": true,
    "reportPhaseOnlyRedaction": true
  },
  "secretHandling": "execution-full-fidelity-secrets-preserved",
  "reportRedactionBoundary": "redact-only-during-report-export",
  "productionReady": true
}
```

Agents should treat this package as the Production Ready evidence for the desktop shell itself. It ties Linux and Windows `PROXYFORGE_RELEASE_SMOKE=1` packaged Electron launch, packaged headless and agent CLIs, external-cwd `~/vantix` app.asar agent execution, packaged runtime proxy/cert/OAST/report proof, packaged browser routing, Linux/Windows package production gates, the accepted `windows-trust-runner` trust-store pin, known host-limit pins, and full-fidelity executor material into one compact handoff. It does not make unrelated release/security/full-nightly rows complete.

## Agent Control Production Evidence

`proxyforge-agent-control-production-evidence-package` is the proof bundle for Codex CLI, Claude CLI, and `~/vantix` driving ProxyForge through the packaged agent surface:

```json
{
  "kind": "proxyforge-agent-control-production-evidence-package",
  "requiredCapabilityCount": 68,
  "requirements": {
    "sourceCommandSurfaceCovered": true,
    "packagedLinuxCommandSurfaceCovered": true,
    "packagedWindowsCommandSurfaceCovered": true,
    "packagedExternalCwdCovered": true,
    "persistentMitmCovered": true,
    "chromiumDataCollectionCovered": true,
    "projectStoreRecoveryCovered": true,
    "searchViewingCovered": true,
    "replayIntruderRepeaterCovered": true,
    "scannerBcheckCovered": true,
    "extensionCallbackExploitReportCovered": true,
    "automationVantixCovered": true,
    "policyAuditCovered": true,
    "scopeApprovalRateLimitCovered": true,
    "longRunningSoakCovered": true,
    "linuxWindowsPackageInputsCovered": true,
    "docsAndSchemasCovered": true,
    "rawExecutorMaterialPreserved": true,
    "operationalSecretsPreserved": true,
    "reportPhaseOnlyRedaction": true
  },
  "secretHandling": "execution-full-fidelity-secrets-preserved",
  "reportRedactionBoundary": "redact-only-during-report-export",
  "productionReady": true
}
```

Agents should use this package to decide whether the control plane can be trusted for autonomous intel gathering and execution without scraping the GUI. It covers packaged app.asar status for the current 70 commands, external-cwd `~/vantix` invocation, persistent MITM, Chromium and cookie capture, proxy import, Project Store `project-store-status`, `project-store-recover`, and `project-store-backup`, search/view/Sequencer/Decoder, replay/bulk replay/live-target profiling/WebSocket/Intruder, Repeater desync/race, insertion-point extraction, Scanner/Anvil/OAST issue promotion, extension fixtures, callback provider host proof/relay/retention/replay and signed relay isolation evidence, exploit preview/run, reports/bundles, automation scheduler/CI/parity/service lifecycle/installed-host smoke, Vantix handoff, scope/approval/rate-limit/audit gates, and long-running soak packages. Operational outputs keep tokens, cookies, keys, callbacks, raw requests, raw responses, Project Store recovery journals, backup manifests, and WebSocket payloads; report/bundle commands redact only for submission.

## Proxy Edge Profile Evidence

`proxyforge-proxy-edge-profile-package` is the compact evidence package agents should use before treating the Proxy/HTTPS lane as parity-ready for replay, scanning, exploitation prep, Chromium capture, and report handoff:

```json
{
  "kind": "proxyforge-proxy-edge-profile-package",
  "hostCount": 3,
  "routeCount": 4,
  "protocolCoverage": ["HTTP/2", "HTTP/1.1", "WebSocket"],
  "packageRefreshProof": {
    "linkedPackageKinds": [
      "proxyforge-proxy-http-listener-capture-package",
      "proxyforge-proxy-connect-tunnel-metadata-package",
      "proxyforge-https-mitm-evidence-package",
      "proxyforge-proxy-intercept-evidence-package",
      "proxyforge-proxy-match-replace-rule-library",
      "proxyforge-browser-routing-proxy-chain-package",
      "proxyforge-websocket-capture-evidence-package"
    ],
    "stalePackageIds": []
  },
  "requirements": {
    "httpListenerCaptureCovered": true,
    "connectTunnelCovered": true,
    "httpsMitmCovered": true,
    "interceptControlsCovered": true,
    "matchReplaceCovered": true,
    "http2FidelityCovered": true,
    "crossToolHandoffCovered": true,
    "websocketEdgeCovered": true,
    "browserProxyChainCovered": true,
    "packageRefreshCovered": true,
    "rawExecutorMaterialPreserved": true,
    "operationalSecretsPreserved": true,
    "reportPhaseOnlyRedaction": true
  },
  "secretHandling": "execution-full-fidelity-secrets-preserved",
  "reportRedactionBoundary": "redact-only-during-report-export"
}
```

Agents should keep this package with Proxy artifacts when they drive `mitm-start`, Chromium routing, proxy import, Repeater/WebSocket replay, Scanner promotion, Repeater desync/race, or exploit preparation. It proves listener capture, CONNECT, HTTPS MITM, intercept controls, match/replace, HTTP/2 fidelity and multiplexing, cross-tool handoff, WebSocket capture/intercept/state, browser-routing/proxy-chain evidence, package refresh digests, and the rule that executor tokens, cookies, keys, and payloads remain unredacted until report export.

`proxyforge-proxy-browser-proxy-chain-diversity-package` is the browser/proxy-chain diversity proof agents should preserve before treating Chromium capture, managed browser routing, upstream proxies, CONNECT chains, PAC/direct routing, or mixed certificate trust modes as broadly covered:

```json
{
  "kind": "proxyforge-proxy-browser-proxy-chain-diversity-package",
  "profileCount": 4,
  "browserFamilies": ["chromium", "chrome", "edge", "firefox"],
  "platforms": ["linux", "windows"],
  "proxyModes": ["upstream-auth", "connect-chain", "pac", "direct"],
  "certificateModes": ["project-ca", "trusted-ca", "pinned-nonblocking", "manual-import"],
  "protocolCoverage": ["HTTP/1.1", "HTTP/2", "CONNECT", "WebSocket"],
  "linkedPackageKind": "proxyforge-proxy-edge-profile-package",
  "requirements": {
    "multiBrowserFamilyCovered": true,
    "linuxWindowsProfileCoverage": true,
    "proxyChainModeDiversityCovered": true,
    "httpsMitmTrustModesCovered": true,
    "connectHttp2WebSocketCovered": true,
    "isolatedProfileAndCookieStoresCovered": true,
    "upstreamCredentialPreservationCovered": true,
    "edgeProfileLinked": true,
    "packageRefreshCovered": true,
    "rawExecutorMaterialPreserved": true,
    "operationalSecretsPreserved": true,
    "reportPhaseOnlyRedaction": true
  },
  "secretHandling": "execution-full-fidelity-secrets-preserved",
  "reportRedactionBoundary": "redact-only-during-report-export"
}
```

Agents should keep raw upstream proxy credentials, browser cookies, bearer tokens, WebSocket keys, route notes, profile paths, and certificate trust notes in this executor package. Redaction belongs only in report/export artifacts, not in the package used by Codex, Claude, or `~/vantix` automation.

## Fast Regression Production Evidence

`proxyforge-fast-regression-production-evidence-package` is the proof bundle for the curated fast regression gate itself:

```json
{
  "kind": "proxyforge-fast-regression-production-evidence-package",
  "stepCount": 82,
  "requirements": {
    "currentSummaryPassed": true,
    "completedEveryStep": true,
    "noFailedSteps": true,
    "broadSurfaceCoverage": true,
    "releaseReadinessCovered": true,
    "platformReleaseCovered": true,
    "uiScaleProductionCovered": true,
    "platformShellProductionCovered": true,
    "agentControlProductionCovered": true,
    "fullNightlyProductionCovered": true,
    "fullNightlyRetainedHistoryCovered": true,
    "safetyEnterpriseCovered": true,
    "projectPersistenceCovered": true,
    "projectImportCompatibilityCovered": true,
    "agenticControlCovered": true,
    "analysisToolRefreshCovered": true,
    "browserWorkflowCovered": true,
    "proxyScannerRepeaterIntruderCovered": true,
    "reportAndSecurityCovered": true,
    "artifactUploadReady": true,
    "retentionPolicyCovered": true,
    "rawExecutorMaterialPreserved": true,
    "operationalSecretsPreserved": true,
    "reportPhaseOnlyRedaction": true
  },
  "secretHandling": "execution-full-fidelity-secrets-preserved",
  "reportRedactionBoundary": "redact-only-during-report-export",
  "productionReady": true
}
```

Agents should treat this package as the production proof for whether `npm run test:ci:fast` remains broad enough to trust before package refreshes. It references `test-results/ci-fast-suite-summary.json`, required step names and kinds, release/security/project/agent/browser/proxy/scanner/repeater/intruder/report lanes, and the operational secret boundary. It is not a submission artifact; report commands redact later.

## Full/Nightly Production Evidence

`proxyforge-full-nightly-production-evidence-package` is the proof bundle for the scheduled full/nightly regression gate:

```json
{
  "kind": "proxyforge-full-nightly-production-evidence-package",
  "stepCount": 80,
  "trendRunCount": 3,
  "requirements": {
    "fullSuitePlanValid": true,
    "coverageOwnershipComplete": true,
    "uniqueStepNamesCovered": true,
    "requiredProductionGatesCovered": true,
    "proxyScannerRepeaterIntruderCovered": true,
    "callbackExploitReportBrowserCovered": true,
    "uploadPolicyCovered": true,
    "retentionPolicyCovered": true,
    "zeroFlakeBudgetCovered": true,
    "currentSummaryLinked": true,
    "planOnlyBoundaryCovered": true,
    "trendDashboardCovered": true,
    "scheduledHistoryContinuityCovered": true,
    "historicalRuntimePassCovered": true,
    "latestRuntimeRunPassed": true,
    "noRecentFailedRuns": true,
    "fastSuiteLinked": true,
    "docsAndSchemasCovered": true,
    "artifactPathsSafe": true,
    "rawExecutorMaterialPreserved": true,
    "operationalSecretsPreserved": true,
    "reportPhaseOnlyRedaction": true
  },
  "trendDashboard": {
    "kind": "proxyforge-full-nightly-trend-dashboard",
    "runCount": 3,
    "passRate": 1,
    "zeroFlakeViolations": 0
  },
  "secretHandling": "execution-full-fidelity-secrets-preserved",
  "reportRedactionBoundary": "redact-only-during-report-export",
  "productionReady": true
}
```

Agents should use this package to decide whether the scheduled full/nightly gate has real retained evidence rather than just a workflow file. It covers the full-suite plan, coverage owners, upload and failure retention policy, scheduled `actions/cache/restore` plus `actions/cache/save` continuity for `test-results/ci-full-suite-history/`, zero-flake budget, safe artifact paths, `test-results/ci-full-suite-summary.json`, retained trend dashboard history, a historical full runtime pass, latest runtime pass, fast-suite linkage, and the explicit boundary that a plan-only summary validates metadata but does not claim runtime completion. Operational summaries preserve tokens, cookies, keys, callbacks, raw requests, and raw responses until report export.

`proxyforge-full-nightly-retained-history-evidence-package` is the companion proof bundle for retained runtime summaries:

```json
{
  "kind": "proxyforge-full-nightly-retained-history-evidence-package",
  "retainedRunCount": 3,
  "runtimeRunCount": 3,
  "requirements": {
    "planValid": true,
    "uploadPolicyIncludesHistory": true,
    "retentionPolicyCovered": true,
    "currentRuntimeSummaryRetained": true,
    "planOnlyRunsExcludedFromRuntimeHistory": true,
    "minimumRuntimeHistoryCovered": true,
    "fullRunHistoryCovered": true,
    "latestRuntimeRunPassed": true,
    "noRecentFailedRuns": true,
    "coverageOwnershipStable": true,
    "requiredProductionStepsRetained": true,
    "artifactPathsSafe": true,
    "digestIntegrityCovered": true,
    "zeroFlakeBudgetCovered": true,
    "dashboardArtifactCovered": true,
    "rawExecutorMaterialPreserved": true,
    "operationalSecretsPreserved": true,
    "reportPhaseOnlyRedaction": true
  },
  "dashboard": {
    "kind": "proxyforge-full-nightly-retained-history-dashboard",
    "historyArtifactPath": "test-results/ci-full-suite-history/dashboard.json",
    "consecutiveRuntimePasses": 3
  },
  "secretHandling": "execution-full-fidelity-secrets-preserved",
  "reportRedactionBoundary": "redact-only-during-report-export",
  "productionReady": true
}
```

Agents should use the retained-history package before promoting the full/nightly row. It proves per-run runtime summaries under `test-results/ci-full-suite-history/`, the retained dashboard, current runtime summary linkage, digest integrity, full-run and skip-browser history, zero-flake policy, and that plan-only summaries do not count as runtime proof. Playwright browser artifacts live under `test-results/playwright-artifacts/` so browser cleanup cannot remove retained runtime summaries. Operational summaries preserve raw executor material until report export.

`proxyforge-full-nightly-hosted-retained-history-evidence-package` is the hosted CI receipt layer for the same gate:

```json
{
  "kind": "proxyforge-full-nightly-hosted-retained-history-evidence-package",
  "hostedRunCount": 3,
  "scheduledRunCount": 2,
  "requirements": {
    "hostedRunReceiptsCovered": true,
    "scheduledRunReceiptsCovered": true,
    "workflowIdentityCovered": true,
    "branchContinuityCovered": true,
    "hostedRunsCompletedSuccessfully": true,
    "retainedHistoryRestoreSaveCovered": true,
    "hostedArtifactUploadCovered": true,
    "retainedDashboardLinksHostedRuns": true,
    "minimumRuntimeHistoryCovered": true,
    "requiredProductionStepsRetained": true,
    "digestIntegrityCovered": true,
    "noFailedHostedRuns": true,
    "rawExecutorMaterialPreserved": true,
    "operationalSecretsPreserved": true,
    "reportPhaseOnlyRedaction": true
  },
  "dashboard": {
    "kind": "proxyforge-full-nightly-retained-history-dashboard",
    "historyArtifactPath": "test-results/ci-full-suite-history/dashboard.json"
  },
  "secretHandling": "execution-full-fidelity-secrets-preserved",
  "reportRedactionBoundary": "redact-only-during-report-export",
  "productionReady": true
}
```

Agents should use this package to separate manual hosted warmups from actual scheduled CI accumulation. Manual `workflow_dispatch` runs can prove the hosted lane and cache mechanics, but the row should not move to Production Ready until scheduled run receipts are linked by run id to retained summaries, prove `actions/cache/restore` plus `actions/cache/save`, include uploaded summary and dashboard artifacts, preserve full-fidelity operational material, and keep redaction at report export only.

## Install Docs Production Evidence

`proxyforge-install-docs-production-evidence-package` is the proof bundle for packaged install, operator, release, and agent documentation:

```json
{
  "kind": "proxyforge-install-docs-production-evidence-package",
  "documentCount": 8,
  "packagedDocumentCount": 8,
  "requirements": {
    "installGuidePackaged": true,
    "operatorGuidePackaged": true,
    "releaseChecklistPackaged": true,
    "releaseEvidencePackaged": true,
    "agentDocsPackaged": true,
    "packageScriptCovered": true,
    "linuxInstallCovered": true,
    "windowsInstallCovered": true,
    "smokeCommandsCovered": true,
    "certTrustCovered": true,
    "browserRoutingCovered": true,
    "dpapiAndTrustPinCovered": true,
    "agenticOperationCovered": true,
    "highRiskWorkflowsCovered": true,
    "troubleshootingCovered": true,
    "productionSignoffCovered": true,
    "releaseEvidenceSynchronized": true,
    "rawExecutorMaterialPreserved": true,
    "operationalSecretsPreserved": true,
    "reportPhaseOnlyRedaction": true
  },
  "secretHandling": "execution-full-fidelity-secrets-preserved",
  "reportRedactionBoundary": "redact-only-during-report-export",
  "productionReady": true
}
```

Agents should use this package to decide whether the packaged docs remain safe to follow from Codex CLI, Claude CLI, or `~/vantix` before driving ProxyForge. The package covers Linux AppImage/deb/clean-container install proof, Windows NSIS/portable/zip lanes, `release:smoke:linux`, `release:smoke:windows`, `PROXYFORGE_RELEASE_SMOKE`, browser routing, certificate trust, DPAPI cookie proof, the `windows-trust-runner` trust-store pin, persistent MITM, replay/desync/race/scanner/exploit/OAST workflows, troubleshooting, Production Ready signoff, and the rule that operational tokens, cookies, keys, callbacks, raw requests, and raw responses are preserved until report export.

## Windows Package Production Evidence

`proxyforge-windows-package-production-evidence-package` is the proof bundle for the Windows package lane:

```json
{
  "kind": "proxyforge-windows-package-production-evidence-package",
  "artifactCount": 4,
  "smokeCount": 12,
  "requirements": {
    "nativeArtifactsCovered": true,
    "zipFallbackHygieneCovered": true,
    "nativeBuildCovered": true,
    "unpackedGuiCovered": true,
    "nsisInstallUninstallCovered": true,
    "installedHeadlessCovered": true,
    "installedRuntimeCovered": true,
    "browserRoutingCovered": true,
    "dpapiCookieCovered": true,
    "trustStorePinAccepted": true,
    "portableWrapperPinned": true,
    "releaseDocsCovered": true,
    "rawExecutorMaterialPreserved": true,
    "operationalSecretsPreserved": true,
    "reportPhaseOnlyRedaction": true
  },
  "secretHandling": "execution-full-fidelity-secrets-preserved",
  "reportRedactionBoundary": "redact-only-during-report-export",
  "productionReady": true
}
```

Agents should treat this package as the formal acceptance record for Windows package production readiness when using the current `windows-trust-runner` lane. It proves native NSIS, portable, and win-unpacked artifacts, zip fallback hygiene, unpacked and installed GUI launch, installed headless CLI plus scan/report, installed runtime proxy/cert/OAST/report, browser routing, DPAPI sample-cookie extraction, quiet uninstall, the `ERROR_NOT_SUPPORTED` trust-store pin, and the portable-wrapper stdout pin. It does not redact operational Windows captures; report commands redact later.

## Linux Package Production Evidence

`proxyforge-linux-package-production-evidence-package` is the proof bundle for the Linux package lane:

```json
{
  "kind": "proxyforge-linux-package-production-evidence-package",
  "artifactCount": 3,
  "smokeCount": 18,
  "requirements": {
    "appImageDebUnpackedArtifactsCovered": true,
    "nativeBuildCovered": true,
    "appImageRuntimeAndGuiCovered": true,
    "debMetadataDependencyCovered": true,
    "unpackedRuntimeAndGuiCovered": true,
    "packagedHeadlessCovered": true,
    "packagedAgentCovered": true,
    "packagedRuntimeCovered": true,
    "browserRoutingCovered": true,
    "cleanContainerInstallRuntimeGuiCovered": true,
    "cleanContainerTrustedCaCovered": true,
    "cleanContainerUninstallCovered": true,
    "knownWarningsPinned": true,
    "releaseDocsCovered": true,
    "rawExecutorMaterialPreserved": true,
    "operationalSecretsPreserved": true,
    "reportPhaseOnlyRedaction": true
  },
  "secretHandling": "execution-full-fidelity-secrets-preserved",
  "reportRedactionBoundary": "redact-only-during-report-export",
  "productionReady": true
}
```

Agents should treat this package as the formal acceptance record for Linux package production readiness. It proves AppImage, deb, and linux-unpacked artifacts, AppImage and unpacked GUI/runtime smokes, deb metadata and dependency coverage for `libgbm1` and `libasound2`, packaged headless scan/report, packaged agent and external-cwd invocation, packaged runtime proxy/cert/OAST/report, packaged browser routing, clean-container deb install/runtime/GUI/trusted-CA/uninstall proof, and known warning pins. The counted browser trust proof is isolated Chromium trusted-CA capture without `--ignore-certificate-errors`; operational captures stay full fidelity until report export.

## AI Provider Evidence

`proxyforge-ai-provider-production-evidence-package` is the production proof bundle for Codex CLI, Claude CLI, and OpenAI-compatible HTTP/local providers:

```json
{
  "kind": "proxyforge-ai-provider-production-evidence-package",
  "proofCount": 14,
  "requirements": {
    "codexCliProviderCovered": true,
    "claudeCliProviderCovered": true,
    "openAiCompatibleProviderCovered": true,
    "providerConfigPersistenceCovered": true,
    "cliProviderDiversityCovered": true,
    "httpProviderInteropCovered": true,
    "streamingTelemetryCovered": true,
    "tokenCostAccountingCovered": true,
    "promptLibraryCovered": true,
    "baselinesComparisonsBenchmarksCovered": true,
    "controlledActionsCovered": true,
    "scopeBlockingCovered": true,
    "noDirectActionTrafficCovered": true,
    "packageRefreshCovered": true,
    "longRunProfilingCovered": true,
    "docsAndSchemasCovered": true,
    "securityPolicyCovered": true,
    "rawExecutorMaterialPreserved": true,
    "operationalSecretsPreserved": true,
    "reportPhaseOnlyRedaction": true
  },
  "secretHandling": "execution-full-fidelity-secrets-preserved",
  "reportRedactionBoundary": "redact-only-during-report-export",
  "productionReady": true
}
```

Agents should treat this package as the formal acceptance record for AI provider production readiness. It proves provider execution and action staging only; Repeater, Scanner, Exploit Lab, Automation, and Reports execution still happens behind their own scope, approval, throttle, and audit gates. Provider prompts and action packages preserve full raw executor context, tokens, keys, cookies, and callbacks until a report/export command explicitly redacts them.

`proxyforge-ai-parity-evidence-package` is the proof bundle for Codex, Claude, and OpenAI-compatible local provider parity:

```json
{
  "kind": "proxyforge-ai-parity-evidence-package",
  "providerCount": 3,
  "providerRunCount": 3,
  "promptTemplateCount": 4,
  "baselineCount": 2,
  "comparisonCount": 2,
  "benchmarkRunCount": 1,
  "requirements": {
    "codexProviderCovered": true,
    "claudeProviderCovered": true,
    "openAiCompatibleProviderCovered": true,
    "cliProviderExecutionCovered": true,
    "httpProviderExecutionCovered": true,
    "streamingTelemetryCovered": true,
    "promptEvaluationCovered": true,
    "promptTemplatesCovered": true,
    "baselinesCovered": true,
    "comparisonsCovered": true,
    "benchmarkReplayCovered": true,
    "tokenCostAccountingCovered": true,
    "controlledActionsCovered": true,
    "scopeBlockingCovered": true,
    "fullFidelityContextPreserved": true,
    "operationalSecretsPreserved": true,
    "reportPhaseOnlyRedaction": true
  },
  "secretHandling": "execution-full-fidelity-secrets-preserved",
  "reportRedactionBoundary": "redact-only-during-report-export"
}
```

Provider runs include full prompt context, stream events, token/cost accounting, prompt evaluations, suggested actions, context digests, and raw executor evidence. `proxyforge-ai-action-execution` packages are UI-controlled receipts for Repeater staging, replay matrices, Scanner queueing, Exploit Lab dry-run review, automation recording, and report drafting; traffic is sent only by the gated tool backend.

## Automation Evidence

`automation-parity-export` emits `proxyforge-agent-automation-parity-evidence-package`:

```json
{
  "kind": "proxyforge-agent-automation-parity-evidence-package",
  "workflowCount": 4,
  "executionCount": 4,
  "ciProviderPresetCount": 4,
  "requirements": {
    "macroRecordingCovered": true,
    "scheduledWorkflowCovered": true,
    "onTagWorkflowCovered": true,
    "ciWorkflowCovered": true,
    "scopedExecutionCovered": true,
    "approvalBlockingCovered": true,
    "durableSchedulerQueueCovered": true,
    "leaseRecoveryCovered": true,
    "schedulerRestoreCovered": true,
    "ciHeadlessCliCovered": true,
    "ciProviderPresetsCovered": true,
    "reportArtifactExportCovered": true,
    "serviceLifecycleCovered": true,
    "rawExecutorMaterialPreserved": true,
    "operationalSecretsPreserved": true,
    "reportPhaseOnlyRedaction": true
  },
  "secretHandling": "execution-full-fidelity-secrets-preserved",
  "reportRedactionBoundary": "redact-only-during-report-export"
}
```

`automation-service-plan` emits `proxyforge-automation-service-lifecycle-package`:

```json
{
  "kind": "proxyforge-automation-service-lifecycle-package",
  "platformCount": 2,
  "plans": [
    {
      "platform": "linux-systemd-user",
      "installCommand": "install -Dm0644 ... && systemctl --user enable ...",
      "startCommand": "systemctl --user start ...",
      "statusCommand": "systemctl --user status ...",
      "stopCommand": "systemctl --user stop ...",
      "uninstallCommand": "systemctl --user disable --now ...",
      "agentCommand": "proxyforge-agent automation-scheduler-tick --execute --service-run --json"
    },
    {
      "platform": "windows-task-scheduler",
      "installCommand": "schtasks /Create ...",
      "startCommand": "schtasks /Run ...",
      "statusCommand": "schtasks /Query ...",
      "stopCommand": "schtasks /End ...",
      "uninstallCommand": "schtasks /Delete ..."
    }
  ],
  "requirements": {
    "linuxSystemdInstallStartCovered": true,
    "windowsTaskSchedulerInstallStartCovered": true,
    "startStatusStopUninstallCovered": true,
    "schedulerTickCommandCovered": true,
    "durableStatePathsCovered": true,
    "secretEnvironmentCovered": true,
    "operationalSecretsPreserved": true,
    "reportPhaseOnlyRedaction": true
  },
  "secretHandling": "execution-full-fidelity-secrets-preserved",
  "reportRedactionBoundary": "redact-only-during-report-export"
}
```

`automation-service-smoke` emits `proxyforge-automation-service-installed-host-smoke-package`:

```json
{
  "kind": "proxyforge-automation-service-installed-host-smoke-package",
  "productionReady": true,
  "requirements": {
    "serviceStarted": true,
    "statusProbeCovered": true,
    "stopCovered": true,
    "durableStatusFileCovered": true,
    "durableStateFileCovered": true,
    "jsonlLogCovered": true,
    "schedulerTickCovered": true,
    "pidLifecycleCovered": true,
    "crossPlatformNodeRunnerCovered": true,
    "rawExecutorMaterialPreserved": true,
    "operationalSecretsPreserved": true,
    "reportPhaseOnlyRedaction": true
  },
  "secretHandling": "execution-full-fidelity-secrets-preserved",
  "reportRedactionBoundary": "redact-only-during-report-export"
}
```

Use `automation-list`, `automation-run`, `automation-ci-export`, `automation-scheduler-tick`, `automation-service-plan`, and `automation-service-smoke` for day-to-day agent control. Automation execution results include workflow steps, request caps, approval-block receipts, scheduler leases, CI/headless configs, OS service manifests, installed-host status/state/log files, and `operationalRawMaterial` with source raw requests/responses. These are executor artifacts; reporting commands redact later.

## Exploit Lab Evidence

`proxyforge-exploit-parity-evidence-package` is the proof bundle for agent-driven exploit validation:

```json
{
  "kind": "proxyforge-exploit-parity-evidence-package",
  "requirements": {
    "pocTemplatesCovered": true,
    "nonDestructivePreviewsCovered": true,
    "approvalGatesCovered": true,
    "scopeGatesCovered": true,
    "stopOnProofCovered": true,
    "savedExploitChainsCovered": true,
    "callbackAssistedValidationCovered": true,
    "reportReadyPackagesCovered": true,
    "packageReviewCovered": true,
    "packageComparisonCovered": true,
    "backendRunnerCovered": true,
    "repeaterBackendCovered": true,
    "destructiveClassExcluded": true,
    "rawExecutorMaterialPreserved": true,
    "operationalSecretsPreserved": true,
    "reportPhaseOnlyRedaction": true
  },
  "secretHandling": "execution-full-fidelity-secrets-preserved",
  "reportRedactionBoundary": "redact-only-during-report-export"
}
```

Use this package with `exploit-preview` and approval-gated `exploit-run` results when Codex, Claude, or Vantix agents need to prove that PoC previews, scope/approval gates, callback validation, Repeater backend transport, saved chain packages, digest review/compare/import, and raw executor secrets stayed available until report export.

`proxyforge-exploit-package-refresh-evidence-package` links the Exploit Lab parity package to its backend execution, saved-chain, report-package, review/import, comparison, and callback-validation proof:

```json
{
  "kind": "proxyforge-exploit-package-refresh-evidence-package",
  "packageRefreshProof": {
    "requiredPackageKinds": [
      "proxyforge-exploit-parity-evidence-package",
      "proxyforge-exploit-backend-execution",
      "proxyforge-exploit-chain-plan",
      "proxyforge-exploit-report-package",
      "proxyforge-exploit-package-review",
      "proxyforge-exploit-chain-comparison",
      "proxyforge-exploit-callback-validation-package"
    ],
    "stalePackageIds": [],
    "freshDigest": "fnv-digest"
  },
  "requirements": {
    "parityRefreshCovered": true,
    "backendExecutionRefreshCovered": true,
    "repeaterBackendRefreshCovered": true,
    "savedChainRefreshCovered": true,
    "callbackValidationRefreshCovered": true,
    "reportPackageRefreshCovered": true,
    "packageReviewRefreshCovered": true,
    "packageComparisonRefreshCovered": true,
    "packageRefreshCovered": true,
    "destructiveClassStillExcluded": true,
    "rawExecutorMaterialPreserved": true,
    "operationalSecretsPreserved": true,
    "reportPhaseOnlyRedaction": true
  },
  "secretHandling": "execution-full-fidelity-secrets-preserved",
  "reportRedactionBoundary": "redact-only-during-report-export"
}
```

Use this package before treating Exploit Lab evidence as fresh enough for report or production signoff. It proves stale-package checks, Repeater backend refresh, callback-validation linkage, destructive-class exclusion, full-fidelity operational tokens/callbacks/raw traffic, and report-export-only redaction.

## Persistent MITM Session

`mitm-start` emits the same envelope once, then keeps the process alive. Use `--ensure-ca` to generate the project CA before capture and `--upstream-tls strict|relaxed` to choose upstream certificate validation. The `data` object contains:

```json
{
  "sessionId": "agent-mitm-...",
  "pid": 12345,
  "status": "running",
  "proxyUrl": "http://127.0.0.1:8080",
  "statusPath": "./agent-session/session.json",
  "logPath": "./agent-session/exchanges.jsonl",
  "httpsInspection": {
    "enabled": true,
    "upstreamTlsMode": "strict",
    "upstreamProxy": {
      "enabled": true,
      "url": "http://127.0.0.1:8081/",
      "noProxy": ["metadata.local"],
      "message": "Upstream proxy chaining through 127.0.0.1:8081"
    },
    "certificate": {
      "ready": true,
      "rootCertificatePath": "./agent-session/certs/projects/default-project/proxyforge-root-ca.pem",
      "fingerprintSha256": "AA:..."
    }
  },
  "exchangeCount": 0,
  "capabilities": ["http-proxy", "connect-tunnel", "https-mitm", "project-ca-status", "upstream-tls-mode", "upstream-proxy-chain", "streamed-response-capture", "websocket-capture"]
}
```

Agents should poll `mitm-status` for counters and `mitm-export` for full-fidelity operational exchanges. `mitm-start --upstream-proxy http://127.0.0.1:8081 --upstream-proxy-authorization "Bearer ..."` preserves proxy-chain credentials and target credentials in operational JSONL until report export. Streamed HTTP responses are forwarded before upstream end when response editing is inactive and appear with `streamed-response`, `chunked-response`, and optional `capture-truncated` tags. Treat session directories as sensitive operator-controlled workspaces.

## Search Index

`search-index` builds a persistent full-fidelity semantic index for agents that need repeatable large-project lookup:

```json
{
  "query": "authz",
  "indexPath": "./artifacts/search-index.json",
  "index": {
    "kind": "proxyforge-search-semantic-index",
    "schemaVersion": 1,
    "exchangeCount": 42,
    "tokenCount": 12000,
    "indexedTokenCount": 4096,
    "secretHandling": "execution-full-fidelity-secrets-preserved"
  },
  "matchCount": 3,
  "matches": [
    {
      "exchangeId": "hx-1",
      "score": 0.84,
      "providerId": "proxyforge-local-index",
      "labels": ["authz", "authorization", "role"]
    }
  ]
}
```

If `--out` is omitted, `data.index.content` contains the full JSON index. If `--out` is provided, the path contains raw requests, cookies, tokens, and response bodies for operational agent execution; treat it as sensitive until a reporting command redacts submission artifacts.

Add `--soak` when an agent needs repeatable large-project/vector-index evidence before relying on semantic lookup across a big workspace:

```json
{
  "soakReport": {
    "kind": "proxyforge-search-large-project-soak-report",
    "status": "pass",
    "exchangeCount": 384,
    "queryCount": 3,
    "totalMatches": 36,
    "secretHandling": "execution-full-fidelity-secrets-preserved",
    "indexRestored": true
  }
}
```

Use `--soak-out ./artifacts/search-soak.json` for large outputs. The soak artifact embeds the full operational index corpus unless written to disk and must be treated like captured traffic, not like a redacted report.

For authorized external/local semantic providers, `search-index` can call a scoped rerank endpoint only when `--execute` is present. Without `--execute`, it emits `proxyforge-agent-search-live-provider-invocation-plan` and sends no provider traffic:

```bash
node scripts/proxyforge-agent.mjs search-index --project ./workspace.proxyforge.json --query "authz bypass" --provider-url http://127.0.0.1:9000/rank --provider-token "$SEARCH_PROVIDER_TOKEN" --scope 127.0.0.1 --execute --provider-out ./artifacts/search-provider.json --json
```

Executed provider calls emit `proxyforge-agent-search-live-provider-invocation-package`:

```json
{
  "kind": "proxyforge-agent-search-live-provider-invocation-package",
  "provider": {
    "id": "agent-live-semantic",
    "label": "Agent live semantic provider",
    "model": "rerank-v1",
    "url": "http://127.0.0.1:9000/rank"
  },
  "providerRequest": {
    "rawRequest": "POST /rank HTTP/1.1\r\nAuthorization: Bearer ...",
    "body": "{\"documents\":[{\"corpus\":\"...Authorization: Bearer real token...\"}]}"
  },
  "providerResponse": {
    "rawResponse": "HTTP/1.1 200 OK\r\n...",
    "body": "{\"matches\":[{\"exchangeId\":\"hx-1\",\"score\":0.98}]}"
  },
  "providerMatches": [
    {
      "exchangeId": "hx-1",
      "score": 0.98,
      "rationale": "Provider-ranked authz evidence.",
      "labels": ["authz", "role"]
    }
  ],
  "requirements": {
    "providerHostScopeCovered": true,
    "explicitExecuteCovered": true,
    "liveProviderRequestCovered": true,
    "providerScoreMergeCovered": true,
    "rawExecutorMaterialPreserved": true,
    "operationalSecretsPreserved": true,
    "reportPhaseOnlyRedaction": true
  },
  "secretHandling": "execution-full-fidelity-secrets-preserved",
  "reportRedactionBoundary": "redact-only-during-report-export"
}
```

The provider request embeds the operational semantic corpus with raw headers, cookies, tokens, request bodies, and response bodies. Treat `--provider-out` artifacts as executor evidence; final report commands are the first place redaction should occur.

`proxyforge-search-parity-evidence-package` is the agent-readable proof bundle for Search parity. It records the full-text run, structured predicate run, semantic run, optional provider-ranked run, persistent semantic index, restored index, provider-style index matches, large-project soak report, and tool handoffs:

```json
{
  "kind": "proxyforge-search-parity-evidence-package",
  "requirements": {
    "fullTextSearchCovered": true,
    "metadataBodyRawCovered": true,
    "structuredPredicatesCovered": true,
    "negationCovered": true,
    "orQueriesCovered": true,
    "semanticRankingCovered": true,
    "providerScoreMergeCovered": true,
    "persistentIndexCovered": true,
    "largeProjectSoakCovered": true,
    "toolHandoffCovered": true,
    "rawExecutorMaterialPreserved": true,
    "operationalSecretsPreserved": true,
    "reportPhaseOnlyRedaction": true
  },
  "secretHandling": "execution-full-fidelity-secrets-preserved",
  "reportRedactionBoundary": "redact-only-during-report-export"
}
```

Use this package when Codex, Claude, or Vantix agents need to prove that search results can be replayed into `view`, report staging, or later tool execution without losing raw headers, cookies, request bodies, provider labels, or index provenance.

## Viewer Evidence

`proxyforge-viewer-parity-evidence-package` is the proof bundle for agents that depend on exact viewing and report handoff:

```json
{
  "kind": "proxyforge-viewer-parity-evidence-package",
  "requirements": {
    "rawViewCovered": true,
    "prettyJsonViewCovered": true,
    "htmlViewCovered": true,
    "jwtViewCovered": true,
    "graphqlViewCovered": true,
    "imageViewCovered": true,
    "binaryViewCovered": true,
    "sourceAwareSnapshotsCovered": true,
    "evidencePinsCovered": true,
    "replayComparisonExportsCovered": true,
    "reportAttachmentCovered": true,
    "rawExecutorMaterialPreserved": true,
    "operationalSecretsPreserved": true,
    "reportPhaseOnlyRedaction": true
  },
  "secretHandling": "execution-full-fidelity-secrets-preserved",
  "reportRedactionBoundary": "redact-only-during-report-export"
}
```

Use this package after `view` or report staging when an agent needs to prove that raw request/response bytes, decoded previews, source-aware snapshots, pinned snippets, and replay comparison rows stayed linked to stable exchange ids until the reporting command performs submission redaction.

## Logger Evidence

`proxyforge-logger-parity-evidence-package` is the proof bundle for agents that depend on tool-generated traffic logs and archive review workflows:

```json
{
  "kind": "proxyforge-logger-parity-evidence-package",
  "entryCount": 8,
  "archiveImportReviewCount": 5,
  "savedFilterSetCount": 2,
  "requirements": {
    "toolGeneratedTrafficCovered": true,
    "captureControlsCovered": true,
    "savedFiltersCovered": true,
    "customColumnsLinked": true,
    "archiveImportExportCovered": true,
    "archiveMappingCovered": true,
    "archiveConflictDedupeCovered": true,
    "mergeStrategiesCovered": true,
    "replayReviewCovered": true,
    "reportAttachmentCovered": true,
    "provenanceSigningCovered": true,
    "redactionPolicyCovered": true,
    "customColumnPackageRefreshCovered": true,
    "fullFidelityRawMaterialPreserved": true,
    "operationalSecretsPreserved": true,
    "reportPhaseOnlyRedaction": true
  },
  "secretHandling": "execution-full-fidelity-secrets-preserved",
  "reportRedactionBoundary": "redact-only-during-report-export"
}
```

Use this package when Codex, Claude, or Vantix agents need to prove Logger entries from Proxy, Target, Repeater, Scanner, Intruder, Exploit Lab, Automations, and Extensions stayed filterable and report-attachable, and that archive imports preserved raw requests, raw responses, tokens, cookies, API keys, conflict review, signed provenance, and merge decisions until report export.

`proxyforge-logger-custom-column-compatibility-fixtures` is the column-level proof bundle agents should keep beside Logger parity evidence when custom Logger columns drive triage:

```json
{
  "kind": "proxyforge-logger-custom-column-compatibility-fixtures",
  "fixtureCount": 8,
  "passedFixtures": 8,
  "packageRefresh": {
    "sourceColumnCount": 4,
    "sourceEntryCount": 2,
    "sourceDigestPreview": "fnv-digest",
    "fixtureDigestPreview": "fnv-digest",
    "rawMaterialDigestPreview": "fnv-digest",
    "operationalSecretSignals": ["authorization-header", "cookie-header", "x-api-key-header"]
  },
  "requirements": {
    "apiSurfaceCovered": true,
    "fixtureRefreshCovered": true,
    "encodedMaterialCovered": true,
    "operationalSecretsPreserved": true,
    "reportPhaseOnlyRedaction": true
  },
  "secretHandling": "execution-full-fidelity-secrets-preserved",
  "reportRedactionBoundary": "redact-only-during-report-export"
}
```

Supported Logger column helpers include request/response header lookup, body predicates, params, cookies, request/response JSON field and jsonPath lookup, path segments/extensions, `helpers.default`, `helpers.urlDecode`, `helpers.urlEncode`, `helpers.base64Decode`, and `helpers.base64Encode`. Agents should treat these fixtures as execution evidence and redact only when a report/export command builds submission material.

## Organizer Evidence

`proxyforge-organizer-parity-evidence-package` is the proof bundle for curated analyst evidence workflows:

```json
{
  "kind": "proxyforge-organizer-parity-evidence-package",
  "collectionCount": 2,
  "packageArtifactCount": 2,
  "requirements": {
    "collectionsCovered": true,
    "multiToolCurationCovered": true,
    "notesStatusHighlightCovered": true,
    "reviewerAssignmentCovered": true,
    "reviewerSlaCovered": true,
    "csvExportCovered": true,
    "shareLinksCovered": true,
    "packageExportCovered": true,
    "passphraseSealedPackageCovered": true,
    "signedPackageCovered": true,
    "trustPolicyCovered": true,
    "importReviewDiffCovered": true,
    "conflictDedupeCovered": true,
    "mergeModesCovered": true,
    "conflictAuditCovered": true,
    "fullFidelityRawMaterialPreserved": true,
    "operationalSecretsPreserved": true,
    "reportPhaseOnlyRedaction": true
  },
  "secretHandling": "execution-full-fidelity-secrets-preserved",
  "reportRedactionBoundary": "redact-only-during-report-export"
}
```

Use this package when agents need to prove that Proxy, Logger, Repeater, Scanner, and Search evidence stayed curated with reviewer ownership, SLA metadata, sealed/signed package import review, conflict audit, merge decisions, raw HTTP material, passphrases, and signing secrets intact until a reporting-phase command exports submission material.

## Sequencer Analysis

`sequencer-analyze` analyzes explicit samples from `--samples`, `--sample-file`, or extracted project traffic. Add `--soak`, `--min-samples`, and `--min-reliability` when agents need large-sample reliability evidence:

```json
{
  "sampleCount": 5000,
  "samples": ["agent-secret-token-0000-...", "agent-secret-token-0001-..."],
  "result": {
    "sampleCount": 5000,
    "uniqueCount": 5000,
    "reliability": {
      "level": "reliable",
      "sampleTarget": 5000,
      "maxSupportedSamples": 20000
    },
    "estimatedEntropyBits": 192,
    "statisticalTests": []
  },
  "soakPackage": {
    "kind": "proxyforge-agent-sequencer-large-sample-soak-package",
    "status": "pass",
    "budgets": {
      "minSamples": 5000,
      "minReliability": "reliable",
      "minEntropyBits": 96
    },
    "secretHandling": "execution-full-fidelity-secrets-preserved"
  }
}
```

The `samples` array preserves token material exactly as supplied or extracted for executor analysis. Use reporting commands before sharing Sequencer evidence outside the operational workspace.

`proxyforge-sequencer-parity-evidence-package` is the proof bundle for agents that depend on token collection, location extraction, statistical analysis, chart data, and report handoff:

```json
{
  "kind": "proxyforge-sequencer-parity-evidence-package",
  "resultCount": 5,
  "liveCaptureCount": 3,
  "profileComparisonCount": 1,
  "exportArtifactCount": 1,
  "requirements": {
    "manualTokenCollectionCovered": true,
    "trafficTokenCollectionCovered": true,
    "browserPreviewCollectionCovered": true,
    "tokenLocationExtractionCovered": true,
    "liveCapturePersistenceCovered": true,
    "entropyAnalysisCovered": true,
    "collisionAnalysisCovered": true,
    "positionAnalysisCovered": true,
    "characterAndBitChartsCovered": true,
    "statisticalTestsCovered": true,
    "largeSampleReliabilityCovered": true,
    "fipsCapCovered": true,
    "profileComparisonCovered": true,
    "exportArtifactsCovered": true,
    "fullFidelityTokenSamplesPreserved": true,
    "operationalSecretsPreserved": true,
    "reportPhaseOnlyRedaction": true
  },
  "secretHandling": "execution-full-fidelity-secrets-preserved",
  "reportRedactionBoundary": "redact-only-during-report-export"
}
```

Use this package with `sequencer-analyze --soak` and Sequencer export artifacts to prove cookie, form-field, and custom token extraction; 5,000-sample reliability; 20,000-sample FIPS-ready cap behavior; profile comparison; and full-fidelity operational token samples before any report command redacts them.

## Project Parity Evidence

Use this package when Codex, Claude, or Vantix agents need to prove a project workspace can be saved, restored, migrated, and reused by browser/cookie workflows without losing executor material:

```json
{
  "kind": "proxyforge-project-parity-evidence-package",
  "requirements": {
    "localPersistenceRestoreCovered": true,
    "proxyforgeJsonRoundTripCovered": true,
    "schemaVersionMigrationCovered": true,
    "schemaIntegrityCovered": true,
    "sessionProfileRestoreCovered": true,
    "managedBrowserLaunchProfilesCovered": true,
    "linuxWindowsBrowserMatrixCovered": true,
    "cookieExtractionCovered": true,
    "cookieDecryptionReadinessCovered": true,
    "rawExecutorMaterialPreserved": true,
    "operationalSecretsPreserved": true,
    "reportPhaseOnlyRedaction": true
  },
  "secretHandling": "execution-full-fidelity-secrets-preserved",
  "reportRedactionBoundary": "redact-only-during-report-export"
}
```

The package covers local v1 save/restore, `.proxyforge.json` roundtrips, legacy schema migration into v1, legacy proxy XML history, HAR, JSONL MITM log, raw HTTP archive imports, migrated scope/traffic/session data, selected session profile restore, Linux/Windows Chrome/Chromium/Edge/Firefox launch matrices, browser cookie extraction and decryption readiness, DPAPI/Secret Service host-lane notes, raw request/response preservation, cookie headers, bearer tokens, API keys, and report-export-only redaction.

## Project Import Compatibility Evidence

Use this package when an agent needs to prove imported history from legacy proxy, HAR, raw HTTP text, JSONL MITM logs, and ProxyForge project exports can be merged at scale without losing executor material:

```json
{
  "kind": "proxyforge-project-import-compatibility-evidence-package",
  "sourceCount": 5,
  "importedExchangeCount": 166,
  "mergedExchangeCount": 165,
  "duplicateCount": 1,
  "conflictCount": 1,
  "requirements": {
    "legacyProxyXmlCorpusCovered": true,
    "harCorpusCovered": true,
    "rawHttpCorpusCovered": true,
    "agentJsonlCorpusCovered": true,
    "proxyforgeRoundTripCovered": true,
    "largeCorpusScaleCovered": true,
    "duplicateDetectionCovered": true,
    "conflictPreservationCovered": true,
    "parserDiagnosticsCovered": true,
    "packageRefreshCovered": true,
    "importedScopeCovered": true,
    "rawExecutorMaterialPreserved": true,
    "operationalSecretsPreserved": true,
    "reportPhaseOnlyRedaction": true
  },
  "secretHandling": "execution-full-fidelity-secrets-preserved",
  "reportRedactionBoundary": "redact-only-during-report-export"
}
```

The package includes a `proxyforge-project-import-merge-manifest` with source summaries, format counts, host/scope coverage, duplicate diagnostics, conflict diagnostics, id-collision diagnostics, package refresh digests, and the merged v1 snapshot. It is executor material: legacy proxy Authorization headers, HAR cookies, raw HTTP API keys, JSONL callback material, and ProxyForge session cookies remain full fidelity until a report/export command creates submission artifacts.

`proxyforge-project-customer-scale-interop-evidence-package` is the higher-volume companion for customer-scale workspaces and cross-tool profiling:

```json
{
  "kind": "proxyforge-project-customer-scale-interop-evidence-package",
  "importedExchangeCount": 3280,
  "mergedExchangeCount": 3279,
  "hostCount": 40,
  "routeCount": 3278,
  "profile": {
    "searchIndexedRows": 3279,
    "searchQueryCount": 18,
    "viewerDecodedSamples": 420,
    "loggerRows": 3279,
    "targetRoutes": 3278,
    "repeaterCandidates": 540,
    "scannerCandidates": 860,
    "intruderCandidates": 610,
    "reportAttachments": 920,
    "projectStoreBackupBytes": 1200000
  },
  "requirements": {
    "mixedCorpusCovered": true,
    "customerScaleCorpusCovered": true,
    "hostAndRouteDiversityCovered": true,
    "duplicateConflictDiagnosticsCovered": true,
    "searchViewerScaleCovered": true,
    "loggerTargetScaleCovered": true,
    "repeaterScannerIntruderHandoffCovered": true,
    "reportAttachmentScaleCovered": true,
    "projectStoreRoundTripProfileCovered": true,
    "performanceBudgetsCovered": true,
    "packageRefreshCovered": true,
    "rawExecutorMaterialPreserved": true,
    "operationalSecretsPreserved": true,
    "reportPhaseOnlyRedaction": true
  },
  "secretHandling": "execution-full-fidelity-secrets-preserved",
  "reportRedactionBoundary": "redact-only-during-report-export"
}
```

Agents should preserve this package when a customer-scale imported workspace is used as the basis for Search, Viewer, Logger, Target, Repeater, Scanner, Intruder, Project Store backup/reopen, or report attachment decisions. The package keeps representative raw executor samples and operational secret samples full fidelity; reporting commands redact later.

`proxyforge-project-customer-workspace-restore-interop-package` is the restored-workspace companion. It is produced by the same customer-scale gate after importing multiple customer-like workspaces into Project Store, backing them up, reopening the backups, and recording cross-tool restore counts:

```json
{
  "kind": "proxyforge-project-customer-workspace-restore-interop-package",
  "totals": {
    "workspaceCount": 4,
    "importedExchangeCount": 1390,
    "persistedExchangeCount": 1390,
    "restoredExchangeCount": 1390,
    "sourceFormats": [
      "agent-jsonl",
      "legacy-proxy-xml",
      "har",
      "proxyforge-v1",
      "raw-http"
    ]
  },
  "requirements": {
    "multipleCustomerWorkspacesCovered": true,
    "mixedThirdPartyCorpusCovered": true,
    "projectStoreBackupRestoreCovered": true,
    "restoreIntegrityCovered": true,
    "crossToolRestoreProfileCovered": true,
    "performanceBudgetsCovered": true,
    "packageRefreshCovered": true,
    "rawExecutorMaterialPreserved": true,
    "operationalSecretsPreserved": true,
    "reportPhaseOnlyRedaction": true
  },
  "secretHandling": "execution-full-fidelity-secrets-preserved",
  "reportRedactionBoundary": "redact-only-during-report-export"
}
```

Agents should preserve this package when a restored customer workspace becomes the operating base for Search, Viewer, Logger, Target, Repeater, Scanner, Intruder, or report workflows. Raw request/response samples and restore-session tokens remain full fidelity in executor evidence; only report/bundle exports redact for submission.

## Safety And Enterprise Parity Evidence

Use this package before treating active testing, enterprise policy, or SSO controls as parity-ready:

```json
{
  "kind": "proxyforge-safety-enterprise-parity-evidence-package",
  "requirements": {
    "scopeGateCovered": true,
    "throttleGateCovered": true,
    "requestCapCovered": true,
    "approvalGateCovered": true,
    "bypassOverrideAuditCovered": true,
    "auditLoggingCovered": true,
    "signedAuditExportCovered": true,
    "governancePackageCovered": true,
    "ssoIdentityMappingCovered": true,
    "ssoFederationFixtureCovered": true,
    "remotePolicyTransportCovered": true,
    "enterpriseBackendSoakCovered": true,
    "remoteAuditRetentionCovered": true,
    "rawExecutorMaterialPreserved": true,
    "operationalSecretsPreserved": true,
    "reportPhaseOnlyRedaction": true
  },
  "secretHandling": "execution-full-fidelity-secrets-preserved",
  "reportRedactionBoundary": "redact-only-during-report-export"
}
```

The package covers allowed and blocked scope decisions, throttle floors, request caps, exploit/Intruder/callback approval gates, policy override and bypass audit, signed audit exports, signed governance packages, SSO identity mapping, SSO federation/JIT fixtures, remote policy push/pull receipts, enterprise backend soak, remote audit retention, raw requests/responses, bearer tokens, cookies, API keys, signing secrets, SSO assertion secrets, and report-export-only redaction.

## Data Collection

`proxy-import` ingests ProxyForge projects, MITM JSONL logs, HAR files, legacy proxy XML history, raw HTTP text archives, and agent result exports into a full-fidelity operational package:

```json
{
  "kind": "proxyforge-agent-proxy-import",
  "sourceFormat": "agent-jsonl",
  "exchangeCount": 12,
  "secretHandling": "execution-full-fidelity-secrets-preserved",
  "exchanges": [
    {
      "id": "hx-1",
      "method": "POST",
      "url": "https://app.example.test/api/refunds",
      "requestRaw": "POST /api/refunds HTTP/1.1\r\nAuthorization: Bearer ...",
      "responseRaw": "HTTP/1.1 202 Accepted\r\n..."
    }
  ]
}
```

`content-discovery-plan` is dry and returns scoped candidates generated from observed traffic. `content-discovery-run` is planned until `--execute` is passed, then returns a `proxyforge-agent-content-discovery-run-summary`, retained full-fidelity request/response results, throttle/concurrency telemetry, and an optional `proxyforge-agent-content-discovery-runner-soak-package` when `--soak` is set. `crawl-run` is also planned until `--execute` is passed, then returns `data.summary.exchanges`, routes, insertion points, and a follow-on `data.contentDiscovery` plan. These outputs are executor material and keep cookies, tokens, raw request bodies, and raw response bodies intact until reporting.

`live-target-profile` is dry until `--execute` is passed. It accepts `--manifest ./live-targets.json` or project history, scope-checks every URL, sends bounded live probes, and returns `data.package.kind = "proxyforge-agent-live-target-profile-package"` with host/route/status/content-type diversity, raw requests, raw responses, Scanner candidate commands, Intruder marked raw requests, replay handoff commands, and report-export-only redaction:

```json
{
  "kind": "proxyforge-agent-live-target-profile-package",
  "liveRequestCount": 4,
  "hostCount": 1,
  "routeCount": 4,
  "statusClassCount": 3,
  "scannerCandidateCount": 4,
  "intruderCandidateCount": 3,
  "requirements": {
    "scopedLiveTargetsCovered": true,
    "liveTrafficExecuted": true,
    "externalHostDiversityCovered": true,
    "routeDiversityCovered": true,
    "statusClassDiversityCovered": true,
    "scannerCandidateHandoffCovered": true,
    "intruderCandidateHandoffCovered": true,
    "rawExecutorMaterialPreserved": true,
    "operationalSecretsPreserved": true,
    "reportPhaseOnlyRedaction": true
  }
}
```

This package is operational executor evidence. It intentionally keeps bearer tokens, cookies, API keys, marked Intruder raw requests, response bodies, and Scanner candidate context intact until a reporting-phase export redacts them.

The Target GUI import path accepts HAR, legacy proxy XML history, ProxyForge project exchanges, raw HTTP archive JSON, and request/response text into imported Target routes and insertion points. Imported query, path, header, cookie, and body material remains executor-full-fidelity until report export.

`target-access-review` is read-only and returns `data.review.kind = "proxyforge-agent-target-access-control-review"` with role lanes, route decisions, observed status codes, drift classifications (`none`, `overexposed`, `underexposed`, `missing-observation`), linked exchange ids, raw exchanges, and next commands for `replay-matrix`, `scanner-run --checks authz-diff`, and report export. It is executor material and keeps raw headers, cookies, tokens, and response bodies intact until reporting.

`target-map-compare` is read-only and returns `data.comparison.kind = "proxyforge-agent-target-site-map-comparison"` with baseline/candidate route counts, normalization rules, `stats.added`, `stats.removed`, `stats.changed`, `stats.statusChanged`, `stats.mimeChanged`, `stats.parameterChanged`, `stats.authzSensitiveChanged`, per-delta `changeTypes`, affected parameters, route snapshots, linked exchange ids, raw exchanges, digest preview, and next commands for access review, content discovery, and report export. It is executor material and keeps raw headers, cookies, tokens, and response bodies intact until reporting.

Target parity evidence uses `proxyforge-target-parity-evidence-package`. It is executor material and must preserve cookies, bearer tokens, refreshed session material, route bodies, crawl responses, comparison bodies, and Scanner/Reports linkage until a reporting-phase export redacts them:

```json
{
  "kind": "proxyforge-target-parity-evidence-package",
  "routeCount": 4,
  "hostCount": 2,
  "crawlPathCount": 4,
  "insertionPointCount": 8,
  "technologyCount": 4,
  "parameterCount": 8,
  "requirements": {
    "siteMapUrlTreeCovered": true,
    "crawlPathViewCovered": true,
    "scopedCrawlerCovered": true,
    "authenticatedSessionReuseCovered": true,
    "technologyInventoryCovered": true,
    "parameterInsertionInventoryCovered": true,
    "contentDiscoveryHandoffCovered": true,
    "accessControlReviewCovered": true,
    "siteMapComparisonCovered": true,
    "reportsHandoffCovered": true,
    "packageRefreshCovered": true,
    "rawExecutorMaterialPreserved": true,
    "operationalSecretsPreserved": true,
    "reportPhaseOnlyRedaction": true
  },
  "packageRefreshProof": {
    "linkedPackageKinds": [
      "proxyforge-target-site-map-analysis",
      "proxyforge-target-content-discovery-handoff",
      "proxyforge-target-access-control-review",
      "proxyforge-target-site-map-comparison",
      "proxyforge-target-site-map-evidence"
    ],
    "stalePackageIds": [],
    "freshDigest": "fnv-digest"
  },
  "secretHandling": "execution-full-fidelity-secrets-preserved",
  "reportRedactionBoundary": "redact-only-during-report-export"
}
```

## Replay Transport

Core Repeater parity evidence uses `proxyforge-repeater-parity-evidence-package`. It is executor material and preserves edited raw requests, replay responses, saved request bodies, tab snapshots/diffs, session profile headers/cookies, authorization matrix bodies, and operational tokens until report export. The Repeater request library importer accepts ProxyForge library JSON, project exchange arrays, HAR, legacy proxy XML history, raw HTTP archive JSON, and request-only raw HTTP while keeping imported Authorization, Cookie, API-key, and body material full fidelity:

```json
{
  "kind": "proxyforge-repeater-parity-evidence-package",
  "tabCount": 2,
  "savedRequestCount": 1,
  "sessionProfileCount": 1,
  "sessionInjectionCount": 1,
  "requirements": {
    "manualRequestEditorCovered": true,
    "manualSendRuntimeCovered": true,
    "tabsAndGroupedWorkspacesCovered": true,
    "savedRequestsCovered": true,
    "snapshotsAndDiffsCovered": true,
    "sessionProfileInjectionCovered": true,
    "authorizationMatrixCovered": true,
    "transportControlsCovered": true,
    "bulkReplayHandoffCovered": true,
    "packageRefreshCovered": true,
    "rawExecutorMaterialPreserved": true,
    "operationalSecretsPreserved": true,
    "reportPhaseOnlyRedaction": true
  },
  "packageRefreshProof": {
    "requiredPackageKinds": [
      "proxyforge-repeater-manual-request-editor",
      "proxyforge-repeater-manual-send-runtime",
      "proxyforge-repeater-workspace-tabs",
      "proxyforge-repeater-saved-request-library",
      "proxyforge-repeater-session-profile-injection",
      "proxyforge-repeater-authorization-matrix",
      "proxyforge-repeater-transport-controls",
      "proxyforge-repeater-bulk-replay-handoff"
    ],
    "linkedPackageKinds": [
      "proxyforge-repeater-manual-request-editor",
      "proxyforge-repeater-manual-send-runtime",
      "proxyforge-repeater-workspace-tabs",
      "proxyforge-repeater-saved-request-library",
      "proxyforge-repeater-session-profile-injection",
      "proxyforge-repeater-authorization-matrix",
      "proxyforge-repeater-transport-controls",
      "proxyforge-repeater-bulk-replay-handoff"
    ],
    "stalePackageIds": [],
    "freshDigest": "fnv-digest",
    "rawMaterialDigestPreview": "fnv-digest"
  },
  "secretHandling": "execution-full-fidelity-secrets-preserved",
  "reportRedactionBoundary": "redact-only-during-report-export"
}
```

`replay-run` supports transport controls for redirect, timeout, and connection-sensitive analysis:

```json
{
  "transportSettings": {
    "redirectMode": "follow",
    "maxRedirects": 5,
    "connectionMode": "keep-alive",
    "timeoutMs": 10000
  },
  "response": {
    "status": 200,
    "finalUrl": "https://app.example.test/final",
    "redirectHistory": [
      {
        "from": "https://app.example.test/redirect",
        "to": "https://app.example.test/final",
        "status": 302,
        "location": "/final"
      }
    ],
    "rawResponse": "HTTP/1.1 200 OK\r\n..."
  }
}
```

Timeouts return `status: blocked` with `data.response.error`, while the envelope still preserves the original request headers and body for executor debugging. Redirect following remains scope gated; an out-of-scope redirect target is not fetched.

## Bulk Replay Soak

`bulk-replay` is dry by default. With `--execute`, it replays scoped project exchanges. Add `--soak`, `--concurrency`, `--limit`, and `--result-window-size` when agents need high-volume Repeater evidence:

```json
{
  "summary": {
    "kind": "proxyforge-agent-bulk-replay-summary",
    "candidateCount": 50,
    "totalRequests": 50,
    "completedRequests": 50,
    "failedRequests": 0,
    "maxConcurrency": 5,
    "maxInFlight": 5,
    "retainedResultCount": 10,
    "droppedResultCount": 40,
    "durationMs": 1800,
    "requestRatePerSecond": 27.78,
    "secretHandling": "execution-full-fidelity-secrets-preserved"
  },
  "soakPackage": {
    "kind": "proxyforge-agent-bulk-replay-high-volume-soak-package",
    "status": "pass",
    "reportReady": true
  }
}
```

Retained `data.results` include the replayed request headers/bodies and response bodies. Treat them as executor material because Authorization, Cookie, X-API-Key, tokens, raw request bodies, and raw response bodies remain intact until report export.

## Intruder Runs

`intruder-run` is dry by default. It auto-builds a payload-position plan from the selected request or `--raw-request`; live traffic requires explicit `--execute` and scope. Dry plans include `plan.attackModeMatrix`, which enumerates Sniper, Battering Ram, Pitchfork, and Cluster Bomb expansion counts, payload-position semantics, representative payload tuples, representative raw requests, and warnings such as reused payload sets or capped Cartesian products. The same matrix includes `payloadTransformations` with applied processors, recursive rules, input counts, expanded counts, and sample expanded payloads. Agent processors include `url-encode`, `double-url-encode`, `base64`, `html-encode`, `json-escape`, `hex-encode`, `uppercase`, and `lowercase`; recursive rules include `case-variants`, `url-recursive`, `path-depth`, `delimiter-variants`, `extension-bypass`, and `null-byte`. The GUI Intruder attack library exports/imports `proxyforge-intruder-attack-library` JSON with saved attacks and payload generators, preserving raw requests, payloads, processors, recursive rules, grep/extract settings, Authorization headers, cookies, and API keys until report export. Add `--soak` when an agent needs an `intruder-high-volume-soak` package proving streamed chunks, retained result windows, request-rate telemetry, and resource-pool concurrency. For paused or sliced runs, keep `proxyforge-intruder-checkpoint-resume-package` evidence with queue status, checkpoint offsets, resume links, resource-pool state, payload-rule state, retained/dropped result-window metadata, and raw executor material. For result triage, keep `proxyforge-intruder-grep-extract-comparison-package` evidence with retained result samples, grep/extract signals, baseline/candidate deltas, clustered response signatures, statistical outlier rankings, and Scanner promotion context. For broader Intruder parity proof, keep `proxyforge-intruder-live-target-profile-package` evidence because it links the attack-mode matrix, checkpoint/resume package, grep/extract package, high-volume streaming telemetry, resource-pool concurrency, 2xx/4xx target diversity, authz differential behavior, payload transformations, package-refresh digests, full-fidelity raw executor material, and report-export-only redaction.

```json
{
  "plan": {
    "kind": "proxyforge-agent-intruder-run-plan",
    "targetUrl": "https://app.example.test/api/refunds?orderId=100",
    "attackMode": "sniper",
    "payloadPositions": 1,
    "estimatedRequestCount": 128,
    "attackModeMatrix": {
      "kind": "proxyforge-agent-intruder-attack-mode-matrix",
      "payloadTransformations": {
        "processors": ["uppercase", "html-encode"],
        "rules": ["case-variants", "url-recursive", "path-depth", "delimiter-variants", "extension-bypass", "null-byte"],
        "expandedPayloadCounts": [8, 6]
      },
      "modes": [
        { "mode": "sniper", "requestCount": 4 },
        { "mode": "battering-ram", "requestCount": 2 },
        { "mode": "pitchfork", "requestCount": 2 },
        { "mode": "cluster-bomb", "requestCount": 6 }
      ]
    },
    "resourcePoolMaxConcurrent": 4,
    "streamChunkSize": 32,
    "resultWindowSize": 25,
    "rawRequest": "POST /api/refunds?orderId=§orderId§ HTTP/1.1\r\nCookie: session=...\r\n\r\n..."
  },
  "summary": {
    "totalRequests": 128,
    "streaming": {
      "maxConcurrency": 4,
      "maxInFlight": 4,
      "completedChunks": 4,
      "retainedResultCount": 25,
      "droppedResultCount": 103,
      "durationMs": 2200,
      "requestRatePerSecond": 58.18
    },
    "results": [
      {
        "payload": "admin",
        "requestRaw": "POST /api/refunds?orderId=admin HTTP/1.1\r\nAuthorization: Bearer ...",
        "responseRaw": "HTTP/1.1 403 Forbidden\r\n..."
      }
    ]
  },
  "soakPackage": {
    "kind": "proxyforge-agent-intruder-high-volume-soak-package",
    "status": "pass",
    "secretHandling": "execution-full-fidelity-secrets-preserved"
  }
}
```

The plan, summary, retained results, and soak package are operational executor outputs. They preserve payloads, raw requests, Authorization headers, cookies, keys, response bodies, grep/extract matches, and timing data until a reporting-phase command redacts submission artifacts.

Checkpoint and triage packages use the same redaction boundary:

```json
{
  "checkpointPackage": {
    "kind": "proxyforge-intruder-checkpoint-resume-package",
    "checkpointCount": 2,
    "resumeLinks": [{ "expectedOffset": 32, "actualStartOffset": 32, "linked": true }],
    "requirements": {
      "checkpointPauseCovered": true,
      "resumeCovered": true,
      "queueStateCovered": true,
      "rawExecutorMaterialPreserved": true,
      "operationalSecretsPreserved": true,
      "reportPhaseOnlyRedaction": true
    }
  },
  "analysisPackage": {
    "kind": "proxyforge-intruder-grep-extract-comparison-package",
    "grepMatchCount": 4,
    "extractMatchCount": 4,
    "comparisonCount": 3,
    "clusterCount": 2,
    "rankingCount": 4,
    "requirements": {
      "grepMatchCovered": true,
      "extractRegexCovered": true,
      "baselineComparisonCovered": true,
      "clusteringCovered": true,
      "statisticalRankingCovered": true,
      "scannerPromotionCovered": true
    }
  }
}
```

Live-target profile packages stitch the Intruder proof set together for agents that need to decide whether a run family is broad enough for parity promotion:

```json
{
  "kind": "proxyforge-intruder-live-target-profile-package",
  "targetUrlCount": 3,
  "attackModeCount": 4,
  "totalRequestsSent": 384,
  "retainedResultCount": 88,
  "droppedResultCount": 296,
  "maxInFlight": 5,
  "statusClasses": ["2xx", "4xx"],
  "packageRefreshProof": {
    "linkedPackageKinds": [
      "proxyforge-intruder-attack-mode-matrix",
      "proxyforge-intruder-checkpoint-resume-package",
      "proxyforge-intruder-grep-extract-comparison-package"
    ],
    "staleSummaryIds": []
  },
  "requirements": {
    "liveTargetDiversityCovered": true,
    "attackModeDiversityCovered": true,
    "highVolumeStreamingCovered": true,
    "resourcePoolConcurrencyCovered": true,
    "checkpointResumeCovered": true,
    "grepExtractTriageCovered": true,
    "authzDifferentialCovered": true,
    "payloadTransformCoverageCovered": true,
    "packageRefreshCovered": true,
    "rawExecutorMaterialPreserved": true,
    "operationalSecretsPreserved": true,
    "reportPhaseOnlyRedaction": true
  },
  "secretHandling": "execution-full-fidelity-secrets-preserved",
  "reportRedactionBoundary": "redact-only-during-report-export"
}
```

The live-target profile is still operational executor evidence. Agents can use the requirement booleans to decide whether Intruder diversity, soak, checkpoint, and grep/extract proof is present, but they must keep raw requests, response bodies, bearer tokens, cookies, and keys intact until report export.

## Repeater Desync And Race

`repeater-desync-plan` is dry by default and returns `data.plan.requests` with baseline, poison, and victim raw requests plus `data.plan.parserDifferential`, a parser-framing package that compares `strict-rfc`, `frontend-content-length`, `backend-transfer-encoding`, and `cl0-backend` outcomes for each raw request. Preserve `ambiguityFlags`, per-profile `signal`, `leftoverPreview`, `interpretedRequestCount`, and `queued-followup` evidence before deciding whether `repeater-desync-probe --execute` is authorized. The execute command sends the plan through the socket-backed single-connection runtime. `repeater-race-run --execute` sends a synchronized race group with `--sync last-byte` or `--sync single-packet`. Add `--soak`, `--min-requests`, `--max-release-skew-ms`, and `--max-race-window-ms` when agents need high-concurrency proof.

The execution result appears at `data.result`:

```json
{
  "id": "repeater-desync-runtime-...",
  "transport": "parallel-last-byte",
  "syncTechnique": "last-byte",
  "status": "proof",
  "requestCount": 3,
  "responseOrder": ["1/3 baseline:Parallel race request 1 200"],
  "jitterMs": 8,
  "raceWindowMs": 2,
  "releaseSkewMs": 2,
  "responses": [
    {
      "requestId": "agent-race-plan-request-1",
      "status": 200,
      "rawRequest": "GET /transfer HTTP/1.1\r\nHost: app.example.test\r\nCookie: session=...\r\n\r\n",
      "rawResponse": "HTTP/1.1 200 OK\r\n..."
    }
  ],
  "rawTranscript": ">>> request\n...\n<<< response\n..."
}
```

With `--soak`, the envelope also includes `data.soakPackage`:

```json
{
  "kind": "proxyforge-agent-repeater-race-high-concurrency-soak-package",
  "status": "pass",
  "budgets": {
    "minRequests": 12,
    "maxFailures": 0,
    "maxReleaseSkewMs": 100,
    "maxRaceWindowMs": 100
  },
  "observed": {
    "transport": "parallel-single-packet",
    "syncTechnique": "single-packet",
    "requestCount": 12,
    "observedResponses": 12,
    "missingResponses": 0,
    "releaseSkewMs": 4,
    "raceWindowMs": 4,
    "responseStatusCounts": {
      "200": 12
    }
  },
  "secretHandling": "execution-full-fidelity-secrets-preserved",
  "reportReady": true
}
```

The runtime production handoff is `proxyforge-repeater-race-desync-production-package`. Preserve it when agents need one artifact that ties the parser plan, single-connection probe, race proof, soak proof, scope block, timing budgets, response order, and raw transcript material together:

```json
{
  "kind": "proxyforge-repeater-race-desync-production-package",
  "runtimeProfileCount": 3,
  "requestCount": 22,
  "observedResponseCount": 22,
  "highRiskParserCandidateCount": 1,
  "maxReleaseSkewMs": 8,
  "maxRaceWindowMs": 8,
  "transportModes": [
    "parallel-last-byte",
    "parallel-single-packet",
    "single-connection"
  ],
  "packageRefreshProof": {
    "parserDigest": "fnv...",
    "runtimeDigests": ["fnv..."],
    "blockedDigests": ["fnv..."],
    "productionDigest": "fnv...",
    "staleRuntimeIds": []
  },
  "requirements": {
    "parserDifferentialCovered": true,
    "singleConnectionProofCovered": true,
    "lastByteRaceCovered": true,
    "singlePacketRaceSoakCovered": true,
    "scopeBlockingCovered": true,
    "timingBudgetCovered": true,
    "responseOrderCovered": true,
    "rawTranscriptPreserved": true,
    "operationalSecretsPreserved": true,
    "packageRefreshCovered": true,
    "reportPhaseOnlyRedaction": true
  },
  "secretHandling": "execution-full-fidelity-secrets-preserved",
  "reportRedactionBoundary": "redact-only-during-report-export"
}
```

These are operational executor outputs: raw requests, cookies, keys, tokens, response bodies, timing, and transcripts remain intact until `report-preview`, `report-export`, `bundle-sign`, or another reporting-phase command is used.

## Scanner Calibration

`scanner-run` is dry through `scanner-plan` unless `--execute` is present. Read `status.data.scannerCatalog` to discover active checks and use `--check-pack baseline`, `input-attacks`, `api-graphql`, `auth-state`, or `full-active` when agents need a stable pack selector. `input-attacks` covers reflected XSS, SQL injection, path traversal, open redirect, and command injection; `full-active --max-requests 13` covers every built-in active check. Add `--soak`, `--min-requests`, and `--min-findings` when agents need live calibration and false-positive tuning evidence:

Passive Scanner parity evidence uses `proxyforge-scanner-passive-dedupe-parity-package`. Preserve `checkCoverage`, `confidenceSummary`, `severitySummary`, `dedupeClusters`, `severityReviews`, `falsePositiveControls`, `reportAttachments`, `raw request/response` samples, `operationalSecretSignals`, and `requirements`; it is executor material and redacts only during report export.

```json
{
  "parityPackage": {
    "kind": "proxyforge-scanner-passive-dedupe-parity-package",
    "requirements": {
      "passiveChecksCovered": true,
      "dedupeCovered": true,
      "routeVariantDedupeCovered": true,
      "confidenceSummaryCovered": true,
      "severityNormalizationCovered": true,
      "falsePositiveTuningCovered": true,
      "issueRulePolicyCovered": true,
      "reportAttachmentCovered": true,
      "activeScannerHandoffCovered": true,
      "rawRequestResponsePreserved": true,
      "operationalSecretsPreserved": true,
      "reportPhaseOnlyRedaction": true
    },
    "secretHandling": "execution-full-fidelity-secrets-preserved",
    "reportRedactionBoundary": "redact-only-during-report-export"
  }
}
```

Active check-pack parity evidence uses `proxyforge-active-scan-check-pack-evidence-package`. When present, preserve `checkPackMatrix`, `checkCoverage`, `scopeGate`, `rawProbeSamples`, `operationalSecretSignals`, and `requirements`; it is executor material and redacts only during report export.

Crawl-derived insertion audit parity evidence uses `proxyforge-crawl-audit-insertion-evidence-package`. Preserve query/form/path coverage, duplicate merges, out-of-scope skips, active Scanner handoff, raw probe samples, operational secret signals, and report-export-only redaction.

Scanner live-target profile evidence uses `proxyforge-scanner-live-target-profile-package`. Agents should preserve it when deciding whether Scanner proof is broad enough for production hardening because it links passive dedupe, insertion inventory, active-scan evidence, OAST issue promotion, Anvil compatibility, retest deltas, calibration soak packages, target host/route/status diversity, check-family coverage, false-positive tuning controls, package-refresh digests, stale-package checks, and full-fidelity executor secrets:

```json
{
  "kind": "proxyforge-scanner-live-target-profile-package",
  "targetHostCount": 2,
  "routeCount": 3,
  "statusClasses": ["2xx", "4xx"],
  "totalRequests": 12,
  "checkCoverage": ["security-headers", "authz-diff", "graphql-introspection"],
  "packageRefreshProof": {
    "linkedPackageKinds": [
      "proxyforge-scanner-passive-dedupe-parity-package",
      "proxyforge-insertion-point-inventory-package",
      "proxyforge-scanner-active-scan-evidence-package",
      "proxyforge-scanner-oast-issue-promotion-package",
      "proxyforge-anvil-custom-check-parity-package",
      "proxyforge-scanner-retest-evidence-delta-package"
    ],
    "stalePackageIds": []
  },
  "requirements": {
    "liveTargetDiversityCovered": true,
    "checkPackDepthCovered": true,
    "longRunningTuningCovered": true,
    "passiveDedupeCovered": true,
    "insertionInventoryCovered": true,
    "anvilCompatibilityCovered": true,
    "oastPromotionCovered": true,
    "retestEvidenceCovered": true,
    "packageRefreshCovered": true,
    "rawExecutorMaterialPreserved": true,
    "operationalSecretsPreserved": true,
    "reportPhaseOnlyRedaction": true
  },
  "secretHandling": "execution-full-fidelity-secrets-preserved",
  "reportRedactionBoundary": "redact-only-during-report-export"
}
```

Agent history-derived insertion point packages use `proxyforge-agent-insertion-point-inventory-package` from `insertion-points`. Preserve `coverage`, `points`, `rawExchanges`, `requirements`, and `content`; the command extracts query, path, header, cookie, form, JSON, XML, multipart, and GraphQL candidates for Scanner/Intruder/Target handoff while keeping raw executor material full-fidelity:

```json
{
  "kind": "proxyforge-agent-insertion-point-inventory-package",
  "targetUrl": "https://app.example.test/api/refunds?orderId=100",
  "coverage": [
    { "type": "query", "count": 1 },
    { "type": "header", "count": 2 },
    { "type": "cookie", "count": 1 },
    { "type": "json", "count": 3 },
    { "type": "graphql", "count": 0 }
  ],
  "points": [
    {
      "exchangeId": "hx-1",
      "location": "json",
      "name": "amount",
      "route": "POST /api/refunds?orderId=100",
      "evidence": "JSON body field \"amount\"",
      "valuePreview": "7900"
    }
  ],
  "rawExchanges": [
    {
      "id": "hx-1",
      "requestRaw": "POST /api/refunds?orderId=100 HTTP/1.1\nAuthorization: Bearer live-token\nCookie: session=live-session\n\n{\"amount\":7900}",
      "responseRaw": "HTTP/1.1 403 Forbidden\n\n{\"error\":\"denied\"}"
    }
  ],
  "requirements": {
    "scannerReadyCorpus": true,
    "rawExecutorMaterialPreserved": true,
    "operationalSecretsPreserved": true,
    "reportPhaseOnlyRedaction": true
  },
  "secretHandling": "execution-full-fidelity-secrets-preserved",
  "reportRedactionBoundary": "redact-only-during-report-export"
}
```

Scanner OAST issue promotion uses `scanner-oast-promote` after an OAST SSRF check and callback poll have correlated. Preserve `proxyforge-scanner-oast-issue-promotion-package` fields, including source/scanner exchanges, callback payloads, callback interactions, issue draft, retest commands, raw material, and report-export-only redaction:

```json
{
  "kind": "proxyforge-scanner-oast-issue-promotion-package",
  "issue": {
    "id": "issue-scanner-oast-...",
    "title": "Out-of-band callback was triggered",
    "severity": "high",
    "confidence": "certain"
  },
  "evidence": {
    "scannerExchange": {
      "id": "hx-scanner-oast",
      "requestRaw": "GET /ssrf?url=https://callbacks.example.test/probe/cb-token HTTP/1.1\nAuthorization: Bearer live-token\nCookie: session=live-session\n\n",
      "responseRaw": "HTTP/1.1 200 OK\n\n{\"callbackStatus\":204}"
    },
    "callbackPayload": {
      "id": "cb-1",
      "token": "cb-token",
      "endpoint": "https://callbacks.example.test/probe/cb-token"
    },
    "callbackInteraction": {
      "id": "int-1",
      "raw": "GET /probe/cb-token HTTP/1.1\nAuthorization: Bearer callback-token\n\n"
    }
  },
  "requirements": {
    "sourceExchangeLinked": true,
    "scannerExchangeLinked": true,
    "callbackPayloadLinked": true,
    "callbackInteractionLinked": true,
    "oastTokenObserved": true,
    "reportPhaseOnlyRedaction": true
  },
  "secretHandling": "execution-full-fidelity-secrets-preserved",
  "reportRedactionBoundary": "redact-only-during-report-export"
}
```

## Agent WebSocket Packages

Agent WebSocket commands return full-fidelity operational payloads. Use `websocket-list` for inventory, `websocket-replay --execute` for live frame replay, `websocket-fuzz --execute` for bounded probe runs, and `websocket-transcript-export` for JSON/Markdown transcript handoff:

```json
{
  "kind": "proxyforge-agent-websocket-replay-result",
  "plan": {
    "kind": "proxyforge-agent-websocket-replay-plan",
    "sourceFrame": {
      "id": "ws-1",
      "connectionId": "ws-conn-1",
      "url": "ws://app.example.test/socket",
      "payload": "{\"token\":\"live-token\",\"session\":\"live-session\"}"
    },
    "request": {
      "url": "ws://app.example.test/socket",
      "opcode": 1,
      "payloadEncoding": "text",
      "payload": "{\"token\":\"live-token\",\"session\":\"live-session\"}"
    }
  },
  "result": {
    "handshakeAccepted": true,
    "acceptVerified": true,
    "sentFrame": {
      "payload": "{\"token\":\"live-token\",\"session\":\"live-session\"}",
      "payloadEncoding": "text"
    },
    "receivedFrames": [
      {
        "type": "text",
        "payload": "{\"ok\":true,\"token\":\"live-token\"}"
      }
    ]
  },
  "secretHandling": "execution-full-fidelity-secrets-preserved"
}
```

Transcript exports use `proxyforge-agent-websocket-transcript` and include `frames`, `connectionIds`, `hosts`, `paths`, `content`, `secretHandling`, and `reportRedactionBoundary`. Fuzz exports use `proxyforge-agent-websocket-fuzz-result` and include `summary`, per-probe `outcome`, full probe payloads, and received frames. These artifacts remain executor material until report export.

Scanner retest parity evidence uses `proxyforge-scanner-retest-evidence-delta-package` from `scanner-retest` or `scanner-evidence-export`. Preserve `issue`, `workflow`, `comparison`, `outcomeCoverage`, `controls.requestEdits`, `reportAttachments`, `rawExchangeSamples`, `operationalSecretSignals`, and `requirements`; this package keeps baseline and retest proof full-fidelity until a reporting command performs submission redaction.

```json
{
  "plan": {
    "targetUrl": "https://app.example.test/api/refunds",
    "checks": ["security-headers", "cors-origin", "authz-diff"],
    "throttleMs": 0,
    "maxRequests": 7,
    "falsePositiveControls": ["dedupe-key", "confidence-reason", "retest-before-report"]
  },
  "calibrationPackage": {
    "kind": "proxyforge-agent-scanner-live-calibration-soak-package",
    "status": "pass",
    "budgets": {
      "minRequests": 7,
      "minFindings": 1,
      "minTuningProfiles": 1
    },
    "observed": {
      "totalRequests": 8,
      "findingCount": 2,
      "suppressedFindingCount": 0,
      "falsePositiveControls": [
        "suppress-error-page-security-header-noise",
        "preserve-confidence-reason-per-finding"
      ],
      "findingDedupeKeys": ["authz-diff:app.example.test:/api/refunds:authenticated-state-comparison-preserved-privileged-response"]
    },
    "secretHandling": "execution-full-fidelity-secrets-preserved"
  }
}
```

`data.seedExchange` preserves the selected raw request/response, including Authorization, Cookie, keys, and bodies, so agents can retest and explain confidence without losing executor context. Report commands perform submission redaction later.

## Anvil Custom Scan Checks

`anvil-plan` is read-only. `anvil-run` stays planned unless `--execute` is present, but execution is offline/project-history custom-check evaluation and does not send live traffic. `anvil-package-export` writes a reusable full-fidelity artifact when `--out` is supplied.

The run envelope includes `data.parityPackage.kind = "proxyforge-anvil-custom-check-parity-package"`:

```json
{
  "parityPackage": {
    "kind": "proxyforge-anvil-custom-check-parity-package",
    "definition": {
      "name": "Privileged workflow metadata exposure",
      "language": "v2-beta",
      "source": "metadata:\n  name: \"Privileged workflow metadata exposure\"\n\ngiven response then\n  report issue:"
    },
    "fixtureCoverage": {
      "fixtureCount": 2,
      "positiveFixtureCount": 1,
      "negativeFixtureCount": 1,
      "passedCount": 2
    },
    "headless": {
      "builtInChecksDisabled": true,
      "extensionChecksDisabled": true,
      "reportReady": true
    },
    "requirements": {
      "plainTextDefinitionPreserved": true,
      "reusableLibraryCovered": true,
      "positiveNegativeFixturesCovered": true,
      "fixtureValidationPassed": true,
      "headlessCustomOnlyCovered": true,
      "signedPackageReviewCovered": true,
      "scannerIssueHandoffCovered": true,
      "reportsHandoffCovered": true,
      "rawExecutorMaterialPreserved": true,
      "operationalSecretsPreserved": true,
      "reportPhaseOnlyRedaction": true
    },
    "secretHandling": "execution-full-fidelity-secrets-preserved",
    "reportRedactionBoundary": "redact-only-during-report-export"
  }
}
```

Preserve `.anvil` source, reusable library content, positive/negative fixture raw requests and responses, validation/headless run content, signed package review, Scanner issue handoff, Reports attachments, `rawExchangeSamples`, and `operationalSecretSignals` until a reporting-phase command exports submission material.

## Decoder And Comparer Parity

Decoder and Comparer parity artifacts are operational evidence, not submission material. Preserve tokens, cookies, keys, compact JWT/JWE values, request/response bodies, binary bytes, and comparison bodies until a reporting-phase export redacts them. Agents can run `decoder-chain` against inline input, selected requests, selected responses, or files. The operational package shape is:

```json
{
  "kind": "proxyforge-agent-decoder-transform-chain-package",
  "transformIds": ["base64-decode", "json-pretty"],
  "run": {
    "kind": "proxyforge-agent-decoder-transform-chain-run",
    "steps": [{ "transformId": "base64-decode", "ok": true }],
    "finalOutput": "{\"token\":\"agent-secret-token\"}",
    "secretHandling": "execution-full-fidelity-secrets-preserved",
    "reportRedactionBoundary": "redact-only-during-report-export"
  },
  "requirements": {
    "transformChainExecuted": true,
    "rawInputPreserved": true,
    "rawOutputPreserved": true,
    "operationalSecretsPreserved": true,
    "reportPhaseOnlyRedaction": true
  }
}
```

Decoder parity evidence uses `proxyforge-decoder-parity-evidence-package`:

```json
{
  "kind": "proxyforge-decoder-parity-evidence-package",
  "transformCategories": [
    { "category": "encode", "count": 6 },
    { "category": "decode", "count": 9 },
    { "category": "hash", "count": 2 },
    { "category": "format", "count": 2 }
  ],
  "requirements": {
    "encodeDecodeHashFormatCovered": true,
    "recursiveSmartRecipeCovered": true,
    "jwtJwsSigningPreviewCovered": true,
    "jweDecryptEditReencryptCovered": true,
    "binaryHexInspectionCovered": true,
    "transformLibraryCovered": true,
    "reportHandoffCovered": true,
    "rawExecutorMaterialPreserved": true,
    "operationalSecretsPreserved": true,
    "reportPhaseOnlyRedaction": true
  },
  "secretHandling": "execution-full-fidelity-secrets-preserved",
  "reportRedactionBoundary": "redact-only-during-report-export"
}
```

Comparer parity evidence uses `proxyforge-comparer-parity-evidence-package`:

```json
{
  "kind": "proxyforge-comparer-parity-evidence-package",
  "coverage": {
    "advancedModes": ["words", "bytes", "structured-http", "binary-hex"],
    "normalizationPresetIds": ["raw", "ignore-whitespace", "http-noise", "authz-review", "text-only"]
  },
  "requirements": {
    "textLineUnifiedDiffCovered": true,
    "wordDiffCovered": true,
    "byteDiffCovered": true,
    "structuredHttpDiffCovered": true,
    "binaryHexComparisonCovered": true,
    "normalizationPresetsCovered": true,
    "replayDeltaReviewCovered": true,
    "savedComparisonLibraryCovered": true,
    "evidenceHandoffCovered": true,
    "rawExecutorMaterialPreserved": true,
    "operationalSecretsPreserved": true,
    "reportPhaseOnlyRedaction": true
  },
  "secretHandling": "execution-full-fidelity-secrets-preserved",
  "reportRedactionBoundary": "redact-only-during-report-export"
}
```

## Analysis Tool Refresh Evidence

When an agent depends on Search, Logger, Organizer, Viewer, Sequencer, Decoder, and Comparer in the same workflow, preserve `proxyforge-analysis-tool-refresh-evidence-package` beside the source packages. It links all seven parity artifacts, records package-refresh digests, marks stale package ids, and keeps raw executor material full-fidelity until a report/export command redacts submission material:

```json
{
  "kind": "proxyforge-analysis-tool-refresh-evidence-package",
  "packageRefreshProof": {
    "requiredPackageKinds": [
      "proxyforge-search-parity-evidence-package",
      "proxyforge-logger-parity-evidence-package",
      "proxyforge-organizer-parity-evidence-package",
      "proxyforge-viewer-parity-evidence-package",
      "proxyforge-sequencer-parity-evidence-package",
      "proxyforge-decoder-parity-evidence-package",
      "proxyforge-comparer-parity-evidence-package"
    ],
    "linkedPackageKinds": [
      "proxyforge-search-parity-evidence-package",
      "proxyforge-logger-parity-evidence-package",
      "proxyforge-organizer-parity-evidence-package",
      "proxyforge-viewer-parity-evidence-package",
      "proxyforge-sequencer-parity-evidence-package",
      "proxyforge-decoder-parity-evidence-package",
      "proxyforge-comparer-parity-evidence-package"
    ],
    "stalePackageIds": [],
    "freshDigest": "fnv-digest",
    "rawMaterialDigestPreview": "fnv-digest"
  },
  "requirements": {
    "searchRefreshCovered": true,
    "loggerRefreshCovered": true,
    "organizerRefreshCovered": true,
    "viewerRefreshCovered": true,
    "sequencerRefreshCovered": true,
    "decoderRefreshCovered": true,
    "comparerRefreshCovered": true,
    "packageRefreshCovered": true,
    "rawExecutorMaterialPreserved": true,
    "operationalSecretsPreserved": true,
    "reportPhaseOnlyRedaction": true
  },
  "secretHandling": "execution-full-fidelity-secrets-preserved",
  "reportRedactionBoundary": "redact-only-during-report-export"
}
```

## Report Export Parity

`report-preview`, `report-export`, `bundle-sign`, and `bundle-verify` are reporting-phase commands. Their outputs are submission material and should redact executor tokens, cookies, keys, raw secrets, and signing secrets while keeping evidence ids, host/path, finding text, remediation text, and attachment provenance useful. Report parity evidence uses `proxyforge-report-parity-evidence-package`:

```json
{
  "kind": "proxyforge-report-parity-evidence-package",
  "formats": [
    { "format": "markdown", "rendered": true, "redacted": true },
    { "format": "html", "rendered": true, "redacted": true },
    { "format": "json", "rendered": true, "redacted": true },
    { "format": "pdf", "rendered": true, "redacted": true },
    { "format": "bundle", "rendered": true, "redacted": true }
  ],
  "bundleVerification": {
    "validStatus": "valid",
    "tamperStatus": "invalid",
    "signatureCovers": ["manifest", "evidence", "crossToolEvidenceAttachments", "reportMarkdown"]
  },
  "requirements": {
    "allSubmissionFormatsCovered": true,
    "signedBundleVerificationCovered": true,
    "tamperRejectionCovered": true,
    "customTemplateCovered": true,
    "crossToolEvidenceAttachmentsCovered": true,
    "pdfRenderQaCovered": true,
    "reportExportsRedacted": true,
    "reportPhaseOnlyRedaction": true
  }
}
```

Preserve the package with release evidence when promoting report workflows. It proves Markdown/HTML/JSON/PDF/bundle rendering, executive/technical/remediation/evidence/appendix sections, custom operator template rendering, signed bundle verification, tamper rejection, cross-tool attachments, and PDF render QA metadata.

Report production readiness evidence uses `proxyforge-report-production-readiness-package` when agents need stronger proof before a release or customer handoff:

```json
{
  "kind": "proxyforge-report-production-readiness-package",
  "rendererComparison": [
    { "renderer": "markdown", "redacted": true },
    { "renderer": "html", "redacted": true },
    { "renderer": "json", "redacted": true },
    { "renderer": "bundle", "redacted": true },
    { "renderer": "pdf-html", "redacted": true },
    { "renderer": "fallback-pdf", "redacted": true },
    { "renderer": "pdf-render-qa-metadata", "redacted": true }
  ],
  "signedBundleInterop": {
    "localValidStatus": "valid",
    "externalValidStatus": "valid",
    "externalNoSecretStatus": "unverified",
    "externalTamperStatus": "invalid",
    "signatureCovers": ["manifest", "evidence", "crossToolEvidenceAttachments", "reportMarkdown"]
  },
  "accessibilityReview": {
    "htmlLanguageDeclared": true,
    "mainLandmarkPresent": true,
    "taggedPdfReadiness": true,
    "passed": true
  },
  "scaleProfile": {
    "normalizedExchangeCount": 200,
    "totalAttachmentCount": 220,
    "estimatedPdfPageCount": 40
  },
  "requirements": {
    "rendererComparisonCovered": true,
    "externalSignedBundleInteropCovered": true,
    "accessibilityReviewCovered": true,
    "longProjectAttachmentScaleCovered": true,
    "pdfLargeReportWarningCovered": true,
    "reportExportsRedacted": true,
    "signedBundleTamperRejectionCovered": true,
    "rawOperationalInputsPreservedPreExport": true,
    "reportPhaseOnlyRedaction": true
  }
}
```

Agents should preserve this package with the release evidence trail. It is submission-phase evidence, so exported content is redacted; the package still proves that executor artifacts were full-fidelity before report export and that bundle signatures verify after JSON serialization.

External shared-bundle diversity evidence uses `proxyforge-report-external-bundle-diversity-package` when agents need to hand the same report evidence across bug bounty portals, customer GRC imports, partner MSSP vaults, and internal remediation boards:

```json
{
  "kind": "proxyforge-report-external-bundle-diversity-package",
  "bundleProfiles": [
    {
      "profileId": "bug-bounty-portal-handoff",
      "shareChannel": "bug-bounty-portal",
      "recipient": "Bug bounty program portal",
      "templateId": "evidence-bundle",
      "verificationStatus": "valid",
      "noSecretStatus": "unverified",
      "noSecretDigestMatches": true,
      "tamperStatus": "invalid",
      "canonicalRoundTripStatus": "valid",
      "redacted": true
    }
  ],
  "diversity": {
    "profileCount": 4,
    "shareChannelCount": 4,
    "recipientCount": 4,
    "keyIdCount": 4,
    "templateCount": 4,
    "attachmentKindCount": 10,
    "crossToolKindCount": 6,
    "canonicalDigestCount": 4
  },
  "requirements": {
    "externalSharedBundleDiversityCovered": true,
    "signedBundleVerificationCovered": true,
    "digestOnlyNoSecretReviewCovered": true,
    "tamperRejectionCovered": true,
    "canonicalRoundTripCovered": true,
    "crossToolAttachmentDiversityCovered": true,
    "templateLibraryInteropCovered": true,
    "reportExportsRedacted": true,
    "rawOperationalInputsPreservedPreExport": true,
    "reportPhaseOnlyRedaction": true
  }
}
```

Agents should keep this package next to report production readiness evidence when external bundle sharing is in scope. It is still a reporting-phase artifact: signing secrets, bearer tokens, cookies, API keys, callback tokens, raw exploit material, and raw requests/responses stay intact in executor artifacts, then report and bundle outputs redact for submission.

Template library import/export interop evidence uses `proxyforge-report-template-library-interop-package` when agents need to move operator report templates between workspaces without scraping the GUI:

```json
{
  "kind": "proxyforge-report-template-library-interop-package",
  "exportedLibrary": {
    "kind": "proxyforge-report-template-library",
    "templateCount": 4,
    "templateIds": [
      "executive-board-summary",
      "technical-remediation-runbook",
      "signed-evidence-bundle",
      "bug-bounty-narrative"
    ]
  },
  "importReview": {
    "existingTemplateCount": 1,
    "incomingTemplateCount": 4,
    "acceptedTemplateCount": 4,
    "conflictCount": 1,
    "conflicts": [
      {
        "existingId": "executive-board-summary",
        "incomingId": "executive-board-summary",
        "importedId": "executive-board-summary-imported",
        "resolution": "renamed-import"
      }
    ]
  },
  "renderProofs": [
    {
      "templateId": "bug-bounty-narrative",
      "reportTemplateId": "custom",
      "redacted": true,
      "unresolvedTokenCount": 0
    }
  ],
  "requirements": {
    "templateLibraryExportCovered": true,
    "templateLibraryImportCovered": true,
    "duplicateConflictReviewCovered": true,
    "builtinTemplateInteropCovered": true,
    "customTemplateInteropCovered": true,
    "templateVariablesResolved": true,
    "bundleRenderCovered": true,
    "reportExportsRedacted": true,
    "rawOperationalInputsPreservedPreExport": true,
    "reportPhaseOnlyRedaction": true
  }
}
```

Agents should preserve this package when report templates are exchanged between Codex, Claude, Vantix, or analyst workspaces. It proves export hashes, import acceptance, duplicate conflict review, built-in/custom template rendering, variable resolution, and Markdown/HTML/bundle output redaction; raw executor material remains full fidelity before reporting-phase export.

## Extension Parity Evidence

Use this package when Codex, Claude, or Vantix agents need to prove extension-like workflows are ready for parity hardening beyond the basic compatibility fixture output:

```json
{
  "kind": "proxyforge-extension-parity-evidence-package",
  "requirements": {
    "catalogInstallCovered": true,
    "localManifestCovered": true,
    "enableDisableRunLogsCovered": true,
    "hookCoverageCovered": true,
    "sandboxApiCovered": true,
    "legacyCompatibilityCovered": true,
    "legacySdkDepthCovered": true,
    "thirdPartySdkEdgeCovered": true,
    "policyDenialCovered": true,
    "dependencyReviewCovered": true,
    "headlessCiCovered": true,
    "signedManifestCovered": true,
    "signedUpdatePolicyCovered": true,
    "runtimeDiagnosticsCovered": true,
    "evidenceHandoffCovered": true,
    "rawExecutorMaterialPreserved": true,
    "operationalSecretsPreserved": true,
    "reportPhaseOnlyRedaction": true
  },
  "secretHandling": "execution-full-fidelity-secrets-preserved",
  "reportRedactionBoundary": "redact-only-during-report-export"
}
```

The package covers catalog installs, local manifest imports, enable/disable run logs, sandbox API hooks, legacy proxy-compatible request/response listeners, proxy listeners, scanner checks, insertion-point providers, message editor tabs, context menu factories, session-handling actions, extension state listeners, helper request/build operations, third-party SDK edge packages, policy-denied operations, dependency review, headless CI execution, signed manifests and updates, runtime diagnostics, evidence handoff, and raw token/cookie/API-key preservation until a reporting-phase export performs redaction.

Deeper extension SDK coverage is retained as `proxyforge-extension-legacy-sdk-compatibility-package`:

```json
{
  "kind": "proxyforge-extension-legacy-sdk-compatibility-package",
  "coveredApis": [
    "IHttpListener",
    "IProxyListener",
    "IScannerCheck",
    "IScannerInsertionPointProvider",
    "IMessageEditorTab",
    "IContextMenuFactory",
    "ISessionHandlingAction",
    "IExtensionStateListener",
    "IExtensionHelpers",
    "ILegacyExtensionCallbacks"
  ],
  "missingApis": [],
  "secretHandling": "execution-full-fidelity-secrets-preserved",
  "reportRedactionBoundary": "redact-only-during-report-export",
  "reportReady": true
}
```

Agents should keep the package together with compatibility fixtures and migration guidance. It preserves raw request/response material for SDK probes and records whether a legacy extension API is directly supported, adapter-required, denied by policy before side effects, or unsupported.

Third-party extension edge coverage is retained as `proxyforge-extension-third-party-sdk-compatibility-package`:

```json
{
  "kind": "proxyforge-extension-third-party-sdk-compatibility-package",
  "coveredCategories": [
    "http-message-mutation",
    "helpers-transform",
    "context-menu-multi-selection",
    "session-handling-token-refresh",
    "scanner-insertion-point",
    "editor-state-lifecycle",
    "unsupported-api-fail-closed",
    "manifest-dependency-edge",
    "package-refresh"
  ],
  "missingCategories": [],
  "requirements": {
    "profileDiversityCovered": true,
    "httpRequestResponseMutationCovered": true,
    "helpersTransformCovered": true,
    "contextMenuMultiSelectionCovered": true,
    "sessionHandlingTokenRefreshCovered": true,
    "insertionPointProviderCovered": true,
    "editorStateLifecycleCovered": true,
    "unsupportedApisFailClosedCovered": true,
    "dependencyAndManifestEdgesCovered": true,
    "packageRefreshCovered": true,
    "sdkPackageLinked": true,
    "rawExecutorMaterialPreserved": true,
    "operationalSecretsPreserved": true,
    "reportPhaseOnlyRedaction": true
  },
  "secretHandling": "execution-full-fidelity-secrets-preserved",
  "reportRedactionBoundary": "redact-only-during-report-export",
  "reportReady": true
}
```

Agents should preserve this package when evaluating migrated extension package/local/agent manifests. It proves `IHttpRequestResponse` mutations and annotations, `IExtensionHelpers` transforms, multi-message context menus, session token refresh, custom scanner insertion points, editor/state lifecycle cleanup, fail-closed unsupported APIs, dependency/manifest migration edges, and package-refresh digests while keeping executor tokens and raw traffic intact.

## Extension Fixtures

`extension-fixtures` is read-only and produces operational compatibility evidence for migrated legacy proxy-compatible extension behavior:

```json
{
  "kind": "proxyforge-agent-extension-compatibility-fixture-package",
  "status": "pass",
  "fixtureCount": 5,
  "fixtures": [
    {
      "hook": "request-editor",
      "legacyExtensionApi": "IHttpListener",
      "operation": "processHttpMessage(request)",
      "policyOutcome": "allowed",
      "status": "pass"
    },
    {
      "hook": "request-editor",
      "legacyExtensionApi": "IProxyListener",
      "operation": "processProxyMessage(request)",
      "policyOutcome": "allowed",
      "status": "pass"
    },
    {
      "hook": "scanner-check",
      "legacyExtensionApi": "IScannerInsertionPointProvider",
      "operation": "getInsertionPoints",
      "policyOutcome": "allowed",
      "status": "pass"
    },
    {
      "hook": "headless-runner",
      "legacyExtensionApi": "ILegacyExtensionCallbacks",
      "operation": "makeHttpRequest policy-denied probe",
      "policyOutcome": "denied",
      "status": "pass"
    }
  ],
  "policyDeniedOperations": ["ILegacyExtensionCallbacks.makeHttpRequest"],
  "secretHandling": "execution-full-fidelity-secrets-preserved"
}
```

The package embeds the selected raw exchange, manifest runtime actions, request listener, response listener, proxy listener, scanner check, insertion-point provider, editor tab, context menu factory, session-handling action, extension-state listener, helper analysis/build operation, third-party SDK edge metadata, package-refresh digest, and policy-denied operation metadata. It is executor evidence and keeps raw traffic/tokens intact until a reporting-phase command redacts output.

## Callback Relay And Retention

`callback-relay-plan` is dry and returns relay deployment metadata for public OAST service setup:

```json
{
  "kind": "proxyforge-agent-callback-relay-plan",
  "publicBaseUrl": "callbacks.app.example.test",
  "protocols": ["dns", "http", "smtp"],
  "dnsRecords": ["*.callbacks.app.example.test 300 IN CNAME relay.proxyforge.local."],
  "routes": ["https://*.callbacks.app.example.test/probe/:token"],
  "healthChecks": ["GET https://callbacks.app.example.test/healthz"],
  "retentionHours": 72,
  "secretStorage": {
    "mode": "os-keychain",
    "signingKeyId": "callback-local",
    "secretRef": "proxyforge/oast/callback-local",
    "signingSecret": "operator-supplied-secret",
    "relayApiToken": "operator-supplied-token",
    "operationalSecretPolicy": "full-fidelity-until-reporting"
  }
}
```

`callback-retention-prune` returns expired and retained ids plus `prunedInteractions` with the original raw callback content. Passing `--apply --workspace ./callbacks.json` rewrites the workspace with expired payloads archived and expired interactions removed from the active list. The command remains an operational executor command, so callback tokens, relay keys, raw interaction records, and listener evidence are preserved until report export.

`callback-relay-soak` returns a public relay soak package for larger OAST projects:

```json
{
  "kind": "proxyforge-agent-callback-public-relay-soak-package",
  "publicBaseUrl": "callbacks.app.example.test",
  "payloadCount": 128,
  "interactionCount": 256,
  "observedProtocolCount": 3,
  "rawInteractionBytes": 98304,
  "reportImportProbe": {
    "kind": "proxyforge-agent-callback-report-import-probe",
    "expectedManifestArtifactCount": 4
  },
  "secretHandling": "execution-full-fidelity-secrets-preserved"
}
```

The package includes raw `payloads`, raw `interactions`, signed poll/replay/lifecycle/CI ids when present, relay DNS/routes/health checks, and the listener secret-storage reference. It is not a submission artifact; report commands perform redaction later.

Signed relay isolation evidence is represented by `proxyforge-callback-external-relay-integration-package`. Agents should preserve each tenant poll's `rawRequest`, `rawResponse`, `signature`, `payloadIds`, `interactionIds`, and `isolationStatus`; passing packages have at least two isolated tenant polls, signed HMAC response metadata, no leaked interaction ids, and `reportRedactionBoundary: "redact-only-during-report-export"`. The focused relay integration test proves HTTP/DNS/SMTP callbacks through a local relay fixture and deliberately fails a cross-tenant leak case.

Provider diversity evidence is represented by `proxyforge-callback-external-oast-provider-diversity-package`. Agents should preserve every provider probe's `rawRequest`, `rawResponse`, provider id/kind, protocol, tenant id, payload ids, interaction ids, signature, isolation status, and replay-support metadata. Passing packages cover generic HTTP relay, DNS webhook relay, and SMTP relay provider shapes, link a signed tenant-isolated relay integration package, and keep provider bearer tokens/callback payload tokens full fidelity until report export.

`callback-provider-probe` emits `proxyforge-agent-callback-provider-host-proof-package` when agents need live provider-host proof from a scoped manifest:

```json
{
  "kind": "proxyforge-agent-callback-provider-host-proof-package",
  "providerCount": 2,
  "protocolCount": 2,
  "interactionCount": 2,
  "requirements": {
    "providerHostScopeCovered": true,
    "externalHostRequestsCovered": true,
    "signedPollsCovered": true,
    "tenantIsolationCovered": true,
    "rawExecutorMaterialPreserved": true,
    "reportPhaseOnlyRedaction": true
  },
  "secretHandling": "execution-full-fidelity-secrets-preserved",
  "reportRedactionBoundary": "redact-only-during-report-export"
}
```

The package is operational evidence. Keep provider bearer tokens, callback payload tokens, raw ingest requests, raw poll requests, raw poll responses, signatures, and callback interactions intact until a report/export command creates submission-safe artifacts.

Callback report round-trip evidence is represented by `proxyforge-callback-report-roundtrip-package`. Agents should preserve its imported artifact manifest, external relay/provider package ids, signed full-report-package metadata, `operationalSecretSamples`, and `reportRedactionBoundary`. Passing packages prove signed polls, Repeater/Scanner/Exploit replay packages, replay execution batches, lifecycle reviews, CI handoffs, public relay soaks, signed external relay integrations, provider diversity packages, and evidence packages all survive full report package import while exported submission content redacts only at report time.

Collaborator/OAST package freshness is represented by `proxyforge-collaborator-package-refresh-evidence-package`. Agents should keep it with the source OAST artifacts when deciding whether callback proof is stale enough to rerun:

```json
{
  "kind": "proxyforge-collaborator-package-refresh-evidence-package",
  "packageRefreshProof": {
    "requiredPackageKinds": [
      "proxyforge-collaborator-parity-evidence-package",
      "proxyforge-callback-signed-poll-batch",
      "proxyforge-callback-correlation-replay",
      "proxyforge-callback-replay-execution-batch",
      "proxyforge-callback-payload-lifecycle-review",
      "proxyforge-callback-ci-handoff-package",
      "proxyforge-callback-public-relay-soak-package",
      "proxyforge-callback-external-relay-integration-package",
      "proxyforge-callback-external-oast-provider-diversity-package",
      "proxyforge-agent-callback-provider-host-proof-package",
      "proxyforge-callback-report-roundtrip-package"
    ],
    "stalePackageIds": [],
    "freshDigest": "fnv-digest",
    "rawMaterialDigestPreview": "fnv-digest"
  },
  "requirements": {
    "collaboratorParityRefreshCovered": true,
    "signedPollingRefreshCovered": true,
    "replayCorrelationRefreshCovered": true,
    "replayExecutionRefreshCovered": true,
    "lifecycleRetentionRefreshCovered": true,
    "ciHandoffRefreshCovered": true,
    "relaySoakRefreshCovered": true,
    "externalRelayRefreshCovered": true,
    "externalProviderDiversityRefreshCovered": true,
    "providerHostProofRefreshCovered": true,
    "reportRoundTripRefreshCovered": true,
    "packageRefreshCovered": true,
    "rawExecutorMaterialPreserved": true,
    "callbackSecretsPreserved": true,
    "reportPhaseOnlyRedaction": true
  },
  "secretHandling": "execution-full-fidelity-secrets-preserved",
  "reportRedactionBoundary": "redact-only-during-report-export"
}
```

Collaborator/OAST parity evidence is exported as `proxyforge-collaborator-parity-evidence-package`:

```json
{
  "kind": "proxyforge-collaborator-parity-evidence-package",
  "payloadCount": 3,
  "interactionCount": 3,
  "listenerProfileCount": 1,
  "requirements": {
    "payloadGenerationCovered": true,
    "dnsHttpSmtpProtocolsCovered": true,
    "interactionPollingCovered": true,
    "oastWorkspaceOwnershipCovered": true,
    "signedEvidencePackagesCovered": true,
    "localListenerBackendCovered": true,
    "publicRelaySoakCovered": true,
    "externalRelayTenantIsolationCovered": true,
    "externalProviderDiversityCovered": true,
    "retentionPruneCovered": true,
    "correlationReplayCovered": true,
    "scannerExploitRepeaterStagingCovered": true,
    "automatedReplayExecutionCovered": true,
    "ciHandoffCovered": true,
    "reportPackagePersistenceCovered": true,
    "reportPackageRoundTripCovered": true,
    "rawExecutorMaterialPreserved": true,
    "callbackSecretsPreserved": true,
    "reportPhaseOnlyRedaction": true
  },
  "artifactIds": {
    "payloadIds": ["cb-live-http"],
    "interactionIds": ["cb-int-http"],
    "listenerProfileIds": ["callback-listener-..."],
    "signedPollBatchIds": ["callback-poll-..."],
    "evidencePackageIds": ["callback-evidence-live"],
    "externalRelayIntegrationPackageIds": ["callback-external-relay-integration-..."],
    "externalProviderDiversityPackageIds": ["external-oast-provider-diversity-..."],
    "replayPackageIds": ["callback-replay-repeater", "callback-replay-scanner", "callback-replay-exploit-lab"],
    "replayExecutionBatchIds": ["callback-replay-execution-..."],
    "lifecycleReviewIds": ["callback-lifecycle-..."],
    "ciHandoffPackageIds": ["callback-ci-handoff-..."],
    "relaySoakPackageIds": ["callback-public-relay-soak-..."],
    "reportRoundTripPackageIds": ["callback-report-roundtrip-..."]
  },
  "secretHandling": "execution-full-fidelity-secrets-preserved",
  "reportRedactionBoundary": "redact-only-during-report-export"
}
```

Agents should treat this as operational evidence. It preserves raw callback requests, callback tokens, listener keys, replay manifests, report/import probes, signed external relay/provider packages, and callback report round-trip packages for executor use; submission-safe redaction happens only when `report-export` or another reporting command emits final artifacts.

## Release Trust Production Evidence

Agents should preserve `proxyforge-release-trust-production-evidence-package` before a build is promoted:

```json
{
  "kind": "proxyforge-release-trust-production-evidence-package",
  "requirements": {
    "sbomGeneratedFromLockfile": true,
    "dependencyIntegrityCovered": true,
    "licenseReviewCovered": true,
    "packageLockFrozenCovered": true,
    "sourceChecksumsCovered": true,
    "buildChecksumsCovered": true,
    "docsAndAgentChecksumsCovered": true,
    "workflowChecksumsCovered": true,
    "provenanceStatementCovered": true,
    "provenanceLinksMaterialsAndSubjects": true,
    "signingStatePinned": true,
    "notarizationStatePinned": true,
    "verificationCommandsCovered": true,
    "releaseArtifactRetentionCovered": true,
    "reportPhaseOnlyRedaction": true
  },
  "secretHandling": "execution-full-fidelity-secrets-preserved",
  "reportRedactionBoundary": "redact-only-during-report-export",
  "productionReady": true
}
```

The package links the `package-lock.json` SBOM, SHA-256 checksum manifest, SLSA-lite provenance statement, verification commands, signing/notarization state pins, and retained release artifacts. It is operational release evidence; any executor tokens, cookies, callback secrets, and raw request/response samples remain full fidelity until report export.
