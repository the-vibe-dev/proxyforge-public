# Execution Policy

- Execution-capable skills only propose actions through SecHive approvals and execution controls.
- Commands require timeout/rate-limit defaults and evidence output paths.
- Raw network probes must use bounded per-request timeouts (`curl --connect-timeout` plus `--max-time`, or explicit Python client timeouts). A hang is evidence about that payload/parser state, not a reason to block the run; record it and continue the matrix.
- No blind piping into shells, `eval`, target-controlled substitutions, or unbounded destructive changes.
- In-scope high-impact validation is permitted when bounded by run policy; record the attempted proof, risk tags, blast-radius limit, state-change status, cleanup status, and artifact path.
- `moderate` and `loud` actions require approval unless run config explicitly permits them.
- If the run selects target-scoped proof mode with explicit acknowledgement, execute the authorized proof plan directly inside that target scope. Do not rewrite meaningful in-scope validation into metadata-only checks; record risk metadata and evidence instead.
- When proof mode discovers new product/version/route/source/auth evidence, loop back through CVE/intel and skill triage before finalizing failure.

## Tier 1 (Advisory) vs Tier 2 (Execution)

Every SecHive pack operates in one of two tiers. The tier is set by the pack's `execution_level` field in `metadata.yaml`. Both Claude and Codex respect this contract.

### Tier 1 — Advisory (`execution_level: advisory`)

- The pack reads, analyzes, and proposes. It does not send network traffic against the target, does not modify on-target state, does not invoke active tools.
- Operator pastes input (response body, source code, decompiled output, scanner output); the pack returns analysis.
- Safe for any session, any scope, any authorization state. No scope-verification block required *before* invoking an advisory pack, though every active step downstream still requires scope.
- Examples in our catalog: `bb_methodology`, `engagement_planner`, `threat_modeler`, `triage_validation`, `pre_submission_self_audit`, `skeptic_validator`, `referee_arbiter`, `report_generator`, all `*_advisor` packs.

### Tier 2 — Execution (`execution_level: gated` or `active`)

- The pack invokes tools that touch the target — HTTP requests, port scans, exploit attempts, payload sends, on-chain transactions, file uploads, etc.
- **Mandatory pre-execution gates** (before the first network request hits the target):
  1. Authorization confirmed via `agent_skills/shared/scope_guard.md` authorization-anchor.
  2. Target asset is in the program's in-scope list (or in operator-declared lab scope).
  3. The pack's `safety_level` is honored: `passive` allows probes; `gated` requires explicit operator approval; `active` requires operator approval plus blast-radius statement.
  4. Forbidden actions (the pack's `forbidden` list) are confirmed not in play for this run.
- **Hard-refusal categories** (operator override does not unlock these without explicit written agreement attached to the run):
  - Volumetric denial-of-service (network or application-layer flooding).
  - Mass internet scanning beyond program scope.
  - Unattended worms or self-propagating code.
  - Persistent backdoors (any payload that survives the test session) without written agreement.
  - Real-user impersonation, account takeover beyond attacker-owned + project-owned-victim accounts.
  - Bulk exfiltration of customer data beyond proof-minimum.
- Examples in our catalog: `web_hunter` (gated), `race_hunter` (gated, intrusive), `cache_smuggling` (gated, intrusive), `ad_attacker` (active), `c2_operator` (active, intrusive, pentest-only).

### Risk-tier and OPSEC metadata

Every active pack carries two additional metadata fields adopted across Phase 9:

- **`risk_tier`** ∈ {`safe`, `active`, `intrusive`} — what's the worst that can happen if the pack runs to completion against an authorized target?
  - `safe`: read-only or observation-only. WAF won't trigger.
  - `active`: produces requests / probes that the target's logs will see; WAF may rate-limit.
  - `intrusive`: produces requests likely to trigger alerts, lockouts, or operator notifications on the target side.
- **`opsec`** ∈ {`quiet`, `moderate`, `loud`} — operator detectability profile.
  - `quiet`: single probe per parameter; low-signature; no rate amplification.
  - `moderate`: bounded probe matrix; per-target rate-limiting; coordinated with engagement window.
  - `loud`: high-rate scanning, brute-force, or sustained probing; only with explicit operator approval and engagement-window coordination.

When the run requests stealth (e.g. red-team engagement under formal RoE that constrains detection volume), the orchestrator selects packs with matching `opsec` tags. Packs without the metadata default to `risk_tier: active` and `opsec: moderate` for safety.

### Operator override

Operators can override hard-refusal categories ONLY when:
- The engagement has explicit written authorization for that category.
- The authorization is attached to the run state as a permission record.
- The blast-radius statement is written before the action.
- A cleanup plan exists.

Without all four, the refusal stands. The runtime refuses; no narrative argument unlocks it.
