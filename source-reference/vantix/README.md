# Vantix Source Reference (Vendored, Dev-Only)

## Purpose

A **curated snapshot** of selected source from the sibling repo `vantix`, which mirrors and extends the open-source [`the-vibe-dev/sechive`](https://github.com/the-vibe-dev/sechive) corpus. Vendored into ProxyForge as committed reference material for the porting backlog described in [`docs/PROXY_FORGE_MASTER_PLAN.md`](../../docs/PROXY_FORGE_MASTER_PLAN.md) and [`docs/PROXY_FORGE_ROADMAP.md`](../../docs/PROXY_FORGE_ROADMAP.md).

These files are **not imported at runtime** and **not shipped in packaged installers** — the `package.json#build.files` allowlist explicitly excludes this directory from Electron Builder output. They are tracked in git so contributors can do the TypeScript port work without external repo dependencies.

The corpus is curated to **only the items the master plan and roadmap need**:

- ~64 web/API/agent-orchestration playbooks (skips kernel, firmware, AD, mobile, cloud-IAM)
- 26 product-detection workflows for high-value targets (Apache, Tomcat, JBoss, WebLogic, GitLab, Jenkins, Jira, Confluence, Artifactory, Harbor, Drupal, WordPress, Joomla, Kibana, Grafana, Prometheus, Cisco ASA/Meraki, Fortinet, VMware, Cacti, Adminer, Webmin, ColdFusion, AEM, ActiveMQ)
- 95 web/API/agentic theory templates
- 63 web-relevant skill packs (`SKILL.md` + `metadata.yaml`)
- 14 shared operator rules
- `secops/skills/` — 22 Python files (payload mutation, oracle classifier, skilllets, scoring, gates, etc.)
- `secops/verify/` — 14 Python files (14 verifier classes + base + helpers)
- `secops/exploits/` — 7 template seeds + registry

Operator-method docs (`methods/`) and the protocol SDK (`sdk/`) are intentionally **not** vendored — they don't feed the playbook/skill/template porting backlog.

## Provenance

```
sechive (open-source skill / playbook / theory corpus)
    https://github.com/the-vibe-dev/sechive
        ↓
vantix (sibling Python research workspace — mirrors and extends sechive)
        ↓
ProxyForge source-reference/ (this directory — frozen snapshot for porting)
    rewritten as native TS under src/scanner/, src/exploitTemplates/, etc.
```

- **Immediate source repo (this snapshot):** vantix (sibling project, same owner)
- **Source git commit:** `f6ccef00cc4c11ba37b315289def05f7ea52c61b`
- **Source git timestamp:** 2026-05-26 02:12:16 -0400
- **Vendored on:** 2026-05-26
- **Upstream content origin:** [`the-vibe-dev/sechive`](https://github.com/the-vibe-dev/sechive) — open-source skill/playbook/theory corpus.
- **License:** All projects in the chain (sechive, vantix, ProxyForge) are under the same ownership. No third-party license entanglement.

## Inventory (383 files, ~3.0 MB)

```
secops/                                — scanner engine + verifier source (47 files)
  skills/                              22 .py files (~488 KB)
    payload_mutation.py                PayloadMutationPlanner + OracleGuidedPlanner
    skilllets.py                       formal skilllet metadata
    skill_mappers / scoring / router / scanner / persistence /
    payload mutation / hypothesis_seed / gates / features /
    capabilities / manifest / migration / safe_probe_planner / etc.
  verify/                              14 .py files (~232 KB)
    base.py                            ReplaySpec / ReplayVerifier / VerifyContext / VerifyOutcome
    extended_verifiers.py              14 multi-step verifier classes (OAuth, MFA, race, cache, upload, OOB, etc.)
    http.py                            HTTP replay verifier
    browser.py / browser_actions.py    browser verifier base
    api_sequence.py                    API sequence verifier
    authz_matrix.py                    tenant/role matrix verifier
    multi_step_chain.py                multi-step chain validation
    side_effect_guard.py / state_diff.py / artifact.py / script.py
  exploits/                            template seeds + registry
    {auth_weakness,authz_bypass,idor,privesc_chain,sql_injection,ssrf,xss_reflected}/template.json
    registry.py

playbooks/                             — playbook corpus (94 files)
  registry.yaml                        playbook IDs and metadata
  schema.json                          playbook schema
  README.md                            playbook authoring notes
  references.yaml                      cross-references
  templates/                           ~90 .yaml playbook recipes (web / API / agentic)

theories/                              — vuln theory corpus (98 files)
  registry.yaml                        theory registry
  schema.json                          theory schema
  learning_sources.yaml                theory learning source map
  templates/                           95 web/API/agentic/CTF .yaml theory templates
                                       (excludes AD/kernel/firmware/mobile/cloud-IAM/hardware)

agent_skills/                          — agent skill packs (143 files)
  capability_ontology.yaml             role/capability taxonomy
  registry.yaml                        skill pack registry
  schema.json                          skill pack schema
  shared/                              14 .md shared operator rules
    adaptive_attack_theory / authorization_anchor / compute_nodes /
    diff_security_review / evidence_rules / execution_policy /
    external_context_research / false_positive_exclusions /
    memory_protocol / mutation_ladder / ...
  packs/                               63 SKILL.md + metadata.yaml pairs
                                       (web/API/auth/crypto/scanner/exploit/
                                        recon/oast/fuzz/ctf-relevant)
```

## Mapping table — source → ProxyForge target

Use this table as the porting backlog. Each row is one PR-worth of work.

### Scanner core (Track A)

| Source | Target |
|---|---|
| `secops/skills/payload_mutation.py` → `PayloadMutationPlanner` | `src/scanner/payloadMutationEngine.ts` |
| `secops/skills/payload_mutation.py` → `OracleGuidedPlanner` | `src/scanner/oracleResponseClassifier.ts` |
| `secops/skills/skilllets.py` | `src/data/scannerSkilllets.json` + `src/scanner/skillletMapper.ts` |
| `secops/skills/scoring.py` | `src/scanner/findingScoring.ts` |
| `secops/skills/scanner.py` | `src/scanner/scannerCoordinator.ts` |
| `secops/skills/safe_probe_planner.py` | `src/scanner/safetyBudget.ts` |
| `secops/skills/hypothesis_seed.py` | `src/scanner/hypothesisSeed.ts` |
| `secops/skills/blind_inference.py` | `src/scanner/blindInference.ts` |
| `secops/skills/features.py` | `src/scanner/responseSignals.ts` (feature extractor seed) |
| `secops/skills/gates.py` | `src/scanner/evidenceGates.ts` |
| `secops/skills/stagnation.py` | `src/scanner/stagnationDetector.ts` |
| `secops/skills/supply_chain.py` | `src/scanner/supplyChainSignals.ts` |
| `secops/skills/payload_mutation.py` family tables | per-family files under `src/scanner/families/` |

### Exploit Lab verifiers (Track C)

| Source | Target |
|---|---|
| `secops/verify/base.py` | `src/exploitTemplates/verifierBase.ts` |
| `secops/verify/http.py` | `src/exploitTemplates/httpReplayVerifier.ts` |
| `secops/verify/api_sequence.py` | `src/exploitTemplates/apiSequence.ts` |
| `secops/verify/authz_matrix.py` | `src/exploitTemplates/authzMatrix.ts` |
| `secops/verify/multi_step_chain.py` | `src/exploitTemplates/multiStepChain.ts` |
| `secops/verify/state_diff.py` | `src/exploitTemplates/stateDiff.ts` |
| `secops/verify/side_effect_guard.py` | `src/exploitTemplates/sideEffectGuard.ts` |
| `secops/verify/browser.py` + `browser_actions.py` | `src/exploitTemplates/browserVerifier.ts` |
| `secops/verify/extended_verifiers.py::OobCallbackVerifier` | `src/exploitTemplates/oastCallback.ts` |
| `secops/verify/extended_verifiers.py::WebhookReplayVerifier` | `src/exploitTemplates/webhookReplay.ts` |
| `secops/verify/extended_verifiers.py::RaceWindowVerifier` | `src/exploitTemplates/raceWindow.ts` |
| `secops/verify/extended_verifiers.py::TenantMatrixVerifier` | `src/exploitTemplates/tenantMatrix.ts` |
| `secops/verify/extended_verifiers.py::CacheKeyDiffVerifier` | `src/exploitTemplates/cacheKeyDiff.ts` |
| `secops/verify/extended_verifiers.py::FileUploadRoundtripVerifier` | `src/exploitTemplates/fileUploadRoundtrip.ts` |
| `secops/verify/extended_verifiers.py::WebsocketSequenceVerifier` | `src/exploitTemplates/websocketSequence.ts` |
| `secops/verify/extended_verifiers.py::OAuthFlowVerifier` | `src/exploitTemplates/oauthFlow.ts` |
| `secops/verify/extended_verifiers.py::MfaFlowVerifier` | `src/exploitTemplates/mfaFlow.ts` |
| `secops/verify/extended_verifiers.py::GrpcSequenceVerifier` | `src/exploitTemplates/grpcSequence.ts` |
| `secops/verify/extended_verifiers.py::ModelOutputSinkVerifier` | `src/exploitTemplates/modelOutputSink.ts` |
| `secops/verify/extended_verifiers.py::RedactionInvariantVerifier` | `src/exploitTemplates/redactionInvariant.ts` |
| `secops/verify/extended_verifiers.py::ArtifactBoundaryVerifier` | `src/exploitTemplates/artifactBoundary.ts` |
| `secops/exploits/{auth_weakness,authz_bypass,idor,privesc_chain,sql_injection,ssrf,xss_reflected}/template.json` | `src/exploitTemplates/seeds/*.json` |

### Automation recipes (Track C)

| Source playbook | Target |
|---|---|
| `playbooks/templates/playbook.web_payload_family_validation.playbook.yaml` | `src/automation/recipes/webPayloadFamilyValidation.ts` |
| `...ssrf_and_oob_callback_validation...` | `src/automation/recipes/ssrfCallbackValidation.ts` |
| `...api_authz_idor_matrix...` | `src/automation/recipes/apiAuthzMatrix.ts` |
| `...web_blind_sql_oracle_escalation...` | `src/automation/recipes/blindSqlOracleMatrix.ts` |
| `...file_upload_processing_abuse...` | `src/automation/recipes/fileUploadRoundtrip.ts` |
| `...websocket_realtime_api_review...` | `src/automation/recipes/websocketSequenceReview.ts` |
| `...graphql_attack_surface...` | `src/automation/recipes/graphqlSurfaceValidation.ts` |
| `...content_discovery_parameter_mining...` | `src/automation/recipes/contentDiscoveryParamMining.ts` |
| `...identity_session_management_review...` | `src/automation/recipes/identitySessionReview.ts` |
| `...proof_pack_completion...` | `src/automation/recipes/proofPackCompletion.ts` |
| `...active_scan_orchestration_rate_limited...` | `src/automation/recipes/activeScanOrchestration.ts` |
| `...ato_through_xss...` | `src/automation/recipes/atoThroughXss.ts` |
| `...business_logic_abuse_case_modeling...` | `src/automation/recipes/businessLogicAbuse.ts` |
| `...client_side_js_secret_and_sink_review...` | `src/automation/recipes/clientSideJsSinkReview.ts` |
| `...cross_surface_idor...` | `src/automation/recipes/crossSurfaceIdor.ts` |
| `...crypto_token_review...` | `src/automation/recipes/cryptoTokenReview.ts` |
| `...subdomain_takeover_and_dns_exposure...` | `src/automation/recipes/subdomainTakeover.ts` |
| `...token_signature_validation_attacks...` | `src/automation/recipes/tokenSignatureAttacks.ts` |
| `...transport_security_review...` | `src/automation/recipes/transportSecurityReview.ts` |
| `...web_advanced_techniques...` | `src/automation/recipes/webAdvancedTechniques.ts` |
| `...web_api_coverage...` | `src/automation/recipes/webApiCoverage.ts` |
| `...web_application_review...` | `src/automation/recipes/webApplicationReview.ts` |
| `...web_route_family_coverage...` | `src/automation/recipes/webRouteFamilyCoverage.ts` |
| `...web_weakness_coverage...` | `src/automation/recipes/webWeaknessCoverage.ts` |
| `...sechive.{api_security,authentication,authorization,business_logic,client_side,config_deployment,cryptography,info_gathering,input_validation,session_management}...` | `src/automation/recipes/sechive/*.ts` |
| `...llm_application_review.../ai_application_review.../agentic_system_security_review...` | `src/automation/recipes/llm/*.ts` |
| `...secrets_exposure_responsible_validation.../credential_material_strategy...` | `src/automation/recipes/secretsExposure.ts` etc. |
| `...threat_model_to_theory.../objective_proof_gap_closure...` | `src/automation/recipes/proofGapClosure.ts` etc. |
| `...safe_exploit_poc_development.../safe_scanner_module_triage...` | `src/automation/recipes/safePocDevelopment.ts` etc. |
| `...schema_driven_api_validation.../variant_analysis_and_patch_bypass_review...` | `src/automation/recipes/schemaDrivenApi.ts` etc. |
| `...report_triage_and_disclosure_workflow.../scope_roe_intake_and_policy_matrix...` | `src/automation/recipes/reportTriage.ts` etc. |
| `...bugbounty_recon_asset_graph.../same_host_side_service_mapping...` | `src/automation/recipes/reconAssetGraph.ts` etc. |
| `...cve_public_exploit_triage.../dependency_supply_chain_variant_hunt...` | `src/automation/recipes/cvePublicExploitTriage.ts` etc. |
| `...regression_bisect.../target_disclosed_objective_solver...` | `src/automation/recipes/regressionBisect.ts` etc. |
| `...ctf_web_solve_loop...` | `src/automation/recipes/ctfWebSolveLoop.ts` |
| `...electron_desktop_app_review.../browser_extension_review...` | `src/automation/recipes/electronDesktopReview.ts` etc. |

### Detection workflows → Anvil scan checks (Track A2)

The `playbook.detection.<product>-workflow.playbook.yaml` files are agent-driven detectors for specific products (Apache, GitLab, Drupal, Confluence, etc.). They feed a product-fingerprint scanner check library that runs after general checks. Port pattern:

| Source | Target |
|---|---|
| `playbooks/templates/playbook.detection.<product>-workflow.playbook.yaml` | `src/scanner/families/productDetections/<product>.ts` (Anvil-style rules emitting findings tied to fingerprinted product/version) |

Priority: detections for the top ~30 high-value products first (Apache, Nginx, IIS, Tomcat, JBoss, WebLogic, GitLab, Jenkins, Jira, Confluence, Artifactory, Harbor, Nexus, Drupal, WordPress, Joomla, Elasticsearch, Kibana, Grafana, Prometheus, Cisco ASA, Fortinet, Citrix, VMware vCenter, Cacti, Adminer, Webmin, ColdFusion, AEM, ActiveMQ). Long tail lands later.

### Theory templates → check metadata + research seeds (Track A)

The 95 vendored theory templates document specific weakness patterns with prerequisites, payloads, and proof requirements. They feed the scanner skilllet metadata and seed individual check implementations.

| Source pattern | Target |
|---|---|
| `theories/templates/api.*.theory.yaml` | scanner skilllet metadata for API checks; seeds for `src/scanner/families/graphql*` etc. |
| `theories/templates/authn.*.theory.yaml` | seeds for `src/scanner/families/sessionFixation.ts`, `mfaPasskey*`, etc. |
| `theories/templates/authz.*.theory.yaml` | seeds for `src/scanner/families/idor*`, `corsMisconfigCredentialed.ts`, etc. |
| `theories/templates/bizlogic.*.theory.yaml` | recipe input for business-logic recipes |
| `theories/templates/cache.*.theory.yaml` | seeds for `src/scanner/families/cache*.ts`, smuggling families |
| `theories/templates/client.*.theory.yaml` | seeds for `src/scanner/families/dom*`, `prototypePollution*`, `postmessage*` |
| `theories/templates/crypto.*.theory.yaml` | seeds for `src/scanner/families/jwt*`, token signature checks |
| `theories/templates/file_upload.*.theory.yaml` | seeds for `src/scanner/families/fileUpload*` |
| `theories/templates/injection.*.theory.yaml` | seeds for `src/scanner/families/{sqlInjection,commandInjection,ssti,xss*}` |
| `theories/templates/path.*.theory.yaml` | seeds for `src/scanner/families/pathTraversal.ts` |
| `theories/templates/recon.*.theory.yaml` | seeds for `src/contentDiscoveryEngine.ts`, `paramMinerEngine.ts` |
| `theories/templates/secret.*.theory.yaml` | seeds for `src/extensions/sampleExtensions/passive-secret-detector/` |
| `theories/templates/session.*.theory.yaml` | seeds for `src/scanner/families/sessionFixation.ts` |
| `theories/templates/smuggling.*.theory.yaml` | seeds for `src/scanner/families/requestSmuggling*.ts` |
| `theories/templates/ssrf.*.theory.yaml` | seeds for `src/scanner/families/ssrf*.ts` |
| `theories/templates/xxe.*.theory.yaml` | seeds for `src/scanner/families/xxe*.ts` |
| `theories/templates/llm.*.theory.yaml` | seeds for AI provider guardrail content |
| `theories/templates/agentic.*.theory.yaml` | seeds for AI provider guardrail content |
| `theories/templates/transport.*.theory.yaml` | seeds for transport-security checks |
| `theories/templates/webhook.*.theory.yaml` | seeds for webhook replay templates |
| `theories/templates/websocket.*.theory.yaml` | seeds for WebSocket sequence templates |

### Skill packs → scanner UI metadata + recipe inputs (Track C)

The 63 vendored skill packs (`SKILL.md` + `metadata.yaml`) document operator skill domains with operating rules, role focus, coverage matrices, and proof requirements. Use as:

- **scanner UI tooltips** — per-check operator guidance pulled from the relevant pack.
- **recipe selection context** — when an operator picks a recipe, surface the relevant skill pack guidance in the workspace.
- **agent prompt seed** — the AI provider integration can include relevant pack content as system prompt for a given check or recipe.

Port pattern:

| Source pattern | Target |
|---|---|
| `agent_skills/packs/web_hunter/SKILL.md` | `src/data/skillPacks/web_hunter.md` (bundled with renderer; rendered in scanner help panel) |
| `agent_skills/packs/{api_security,auth_tester,xss_control_matrix,sqli_*,ssrf_*,graphql_hunter,jwt_*,oauth_sso_attacker,session_*,webhook_callback_hunter,websocket_*,cors_tester,cache_smuggling,clientside_template_injection,deserialization*,file_upload_mutator,parameter_mutator,payload_crafter,poc_validator,recon_advisor,report_generator,evidence_ledger,exploit_*}/...` | `src/data/skillPacks/<pack>.md` |
| `agent_skills/shared/*.md` | `src/data/skillPacks/_shared/*.md` |
| `agent_skills/capability_ontology.yaml` | `src/data/capabilityOntology.json` |

## Hard rules

1. **Never imported at runtime.** A CI guard test enforces:

   ```bash
   grep -R "source-reference/vantix" src electron scripts package.json package-lock.json
   ```

   Expected result: zero matches (only provenance comments in ported TS files are allowed, and those reference the source path as documentation — not as an import).

2. **Never modified.** Frozen snapshot. To refresh, replace the directory wholesale, update the commit hash above, and re-port any affected modules.

3. **Removed after porting.** Per-file: once a source has been fully ported and its TS target has passing fixture tests, the source file may be removed. The provenance comment in the ported TS file is the historical record.

4. **Tracked in git, not shipped in installers.** The `package.json#build.files` allowlist excludes this directory from Electron Builder output — packaged binaries do not contain it. The files are committed to the repository as reference material for the porting backlog.

## Provenance comment template

Every ported TS file should carry a header like:

```ts
// Adapted from source-reference/vantix/secops/skills/payload_mutation.py
// (snapshot 2026-05-26, vantix commit f6ccef0).
// Rewritten in TypeScript with ProxyForge naming, types, and storage model.
// No runtime dependency on the vendored source.
```

## When to delete this directory

When every source file in the mapping table above has a corresponding ported TS module with passing fixture tests. At that point, this directory has served its purpose and ProxyForge is fully independent.
