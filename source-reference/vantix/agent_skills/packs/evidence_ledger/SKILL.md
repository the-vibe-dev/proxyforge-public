---
name: evidence_ledger
description: STUB - methodology pending. This pack exists to satisfy playbook references; full content is not yet implemented. Today falls back to shared/evidence_rules.md.
---
# Evidence Ledger (DRAFT / STUB)

> **Status: DRAFT.** This pack exists so the playbook registry resolves cleanly. The methodology is not yet implemented in depth.

## Why this pack exists

Older playbook designs reference `evidence_ledger` as a primary or supporting skill. To keep `scripts/validate_links.py` clean and the playbook registry coherent, this stub registers the pack id. Operators should treat it as a placeholder.

## Today, fall back to

`shared/evidence_rules.md` — which already provides the closest mature methodology for this role.

## Referenced by

- `playbook.active_scan_orchestration_rate_limited`
- `playbook.ad_attack_path_orchestration`
- `playbook.agent_orchestrated_bug_bounty_run`
- `playbook.agent_parallel_hypothesis_router`
- `playbook.agent_tool_governance_and_evidence_ledger`
- `playbook.agentic_system_security_review`
- `playbook.api_authz_idor_matrix`
- `playbook.aws_iam_attack_paths`
- `playbook.binary_dynamic_analysis_lab`
- `playbook.binary_re_intake_to_review`
- `playbook.browser_extension_review`
- `playbook.bugbounty_recon_asset_graph`
- `playbook.business_logic_abuse_case_modeling`
- `playbook.chromium_vrp_research_loop`
- `playbook.cicd_pipeline_attack_paths`
- `playbook.client_side_js_secret_and_sink_review`
- `playbook.cloud_azure_resource_attack_paths`
- `playbook.cloud_gcp_iam_attack_paths`
- `playbook.container_escape_paths`
- `playbook.container_image_supply_chain_review`
- `playbook.content_discovery_parameter_mining`
- `playbook.crash_to_root_cause`
- `playbook.credential_material_strategy`
- `playbook.crypto_token_review`
- `playbook.ctf_crypto_forensics_misc_loop`
- `playbook.ctf_pwn_exploit_development_loop`
- `playbook.ctf_reverse_engineering_loop`
- `playbook.ctf_web_solve_loop`
- `playbook.cve_public_exploit_triage`
- `playbook.dependency_supply_chain_variant_hunt`
- `playbook.electron_desktop_app_review`
- `playbook.enterprise_protocol_recon`
- `playbook.entra_oauth_app_consent`
- `playbook.file_upload_processing_abuse`
- `playbook.firmware_iot_reversing`
- `playbook.fuzzing_campaign`
- `playbook.graphql_attack_surface`
- `playbook.iac_terraform_cloudformation_review`
- `playbook.identity_session_management_review`
- `playbook.k8s_cluster_compromise`
- `playbook.llm_application_review`
- `playbook.memory_corruption_exploitability_review`
- `playbook.mobile_dynamic_instrumentation`
- `playbook.mobile_review`
- `playbook.mobile_static_dynamic_review`
- `playbook.network_protocol_review`
- `playbook.objective_proof_gap_closure`
- `playbook.patch_diff_security_delta`
- `playbook.persistence_and_exfiltration_review`
- `playbook.proof_pack_completion`
- `playbook.regression_bisect`
- `playbook.report_triage_and_disclosure_workflow`
- `playbook.safe_exploit_poc_development`
- `playbook.safe_scanner_module_triage`
- `playbook.same_host_side_service_mapping`
- `playbook.schema_driven_api_validation`
- `playbook.scope_roe_intake_and_policy_matrix`
- `playbook.secrets_exposure_responsible_validation`
- `playbook.skill_supply_chain_audit`
- `playbook.smart_contract_web3_review`
- `playbook.source_audit_loop`
- `playbook.ssrf_and_oob_callback_validation`
- `playbook.subdomain_takeover_and_dns_exposure`
- `playbook.supply_chain_package_takeover_review`
- `playbook.threat_model_to_theory`
- `playbook.token_signature_validation_attacks`
- `playbook.transport_security_review`
- `playbook.unix_gtfobins_privilege_risk_review`
- `playbook.variant_analysis_and_patch_bypass_review`
- `playbook.web_advanced_techniques`
- `playbook.web_api_coverage`
- `playbook.web_blind_sql_oracle_escalation`
- `playbook.web_payload_family_validation`
- `playbook.web_route_family_coverage`
- `playbook.web_weakness_coverage`
- `playbook.websocket_realtime_api_review`
- `playbook.windows_lolbas_risk_review`
- `playbook.wireless_protocol_assessment`

## When implemented

The full content will follow the pattern in `agent_skills/packs/web_hunter/SKILL.md` and similar mature packs. Sections planned:

- When to use
- Operating rules
- Methodology
- Submission gates (compose with `triage_validation`)
- Evidence (per `shared/evidence_rules.md`)
- Exclusions
- See also

## Composes with

- `agent_skills/shared/scope_guard.md` — authorization anchor
- `agent_skills/shared/evidence_rules.md` — evidence + session-id hashing
- `agent_skills/shared/execution_policy.md` — Tier 1 / Tier 2 + risk-tier
- `agent_skills/packs/../shared/evidence_rules/SKILL.md` — current fallback

## Exclusions

- No destructive actions. No DoS. No persistence. No out-of-scope assets.
