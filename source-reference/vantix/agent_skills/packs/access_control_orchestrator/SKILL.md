---
name: access_control_orchestrator
description: Sequences the IDOR/access-control family end-to-end with feedback gates so each stage only runs when the prior surfaced a candidate.
---
# Access Control Orchestrator

The access-control finding family is split across several single-purpose packs
(`object_id_enumerator`, `authz_matrix_tester`, `parameter_mutator`,
`access_control_bypass`, `export_authz_tester`). Run alone, each covers one
mechanism; nothing makes them a designed path, so agents compose them ad-hoc and
miss the ordering that matters (you cannot test cross-user access before you have
collected IDs; you should not burn the 403-bypass matrix until a direct attempt
was actually denied). This pack is the deterministic sequencer for that family.

Composes with `shared/scope_guard.md`, `shared/evidence_rules.md`, `shared/execution_policy.md`,
`packs/object_id_enumerator/SKILL.md`, `packs/authz_matrix_tester/SKILL.md`,
`packs/parameter_mutator/SKILL.md`, `packs/access_control_bypass/SKILL.md`,
`packs/export_authz_tester/SKILL.md`, `packs/triage_validation/SKILL.md`.

## When to Use

- Multi-user or multi-tenant target with object IDs in URLs/APIs/bodies.
- A direct object reference or role-scoped action is in scope and two test
  accounts (or two roles) are available.
- An autopilot/web run routed an `authz` / `idor` surface and you need the full
  family, not a single pack.

## Operating Rules

- Honor `packs/scope_guard/SKILL.md` first; two-account IDOR testing needs explicit
  program permission — document it before stage 2.
- Each stage is gated: only advance a candidate ID/endpoint when the prior stage
  produced a concrete signal. Do not run every pack on every endpoint.
- Stop immediately and report Critical if another user's sensitive data is
  reached; request cleanup per `shared/evidence_rules.md`.
- One designed path, not parallel spray: collect → baseline authz → mutate →
  bypass-on-deny → export → triage.

## Methodology

### Stage 1 — Collect (object_id_enumerator)

Run `packs/object_id_enumerator/SKILL.md` Phase 0–1b: harvest >=20 IDs from URLs,
APIs, GraphQL, exports, mobile/swagger, and classify the ID format. **Gate G1:**
proceed only if at least one predictable / cross-user-candidate ID exists; else
record negative evidence and exit.

### Stage 2 — Baseline authorization (authz_matrix_tester)

For the candidate objects, run `packs/authz_matrix_tester/SKILL.md` to establish
the (role, action, owner, method) baseline and direct cross-user/cross-org
attempts. **Gate G2:** classify each as access-granted / metadata-leak /
hard-denied. Granted/leak → Stage 5 (triage) directly. Hard-denied → Stage 3.

### Stage 3 — Mutate (parameter_mutator)

For hard-denied candidates, run `packs/parameter_mutator/SKILL.md` 14-variant
mutation plus the ID format/derivation attacks. **Gate G3:** any
semantic-divergence variant → Stage 5; still uniformly denied → Stage 4.

### Stage 4 — Bypass on denial (access_control_bypass)

Only for still-denied candidates, run `packs/access_control_bypass/SKILL.md`
(path/header/method/content-type/version matrix) against the *same* object.
**Gate G4:** bypass that yields the object → Stage 5; clean denial across the
full matrix → record as properly enforced (negative evidence).

### Stage 5 — Export & bulk authz (export_authz_tester)

For any confirmed or near-miss, run `packs/export_authz_tester/SKILL.md` to check
whether export/download/pagination endpoints leak the same objects in bulk
(often higher severity than the single-object reference).

### Stage 6 — Triage (triage_validation)

Route every surfaced candidate through `packs/triage_validation/SKILL.md`
7-Question gate before any report. Kill intended-behavior / no-impact paths here.

## Submission Gates

Run `packs/triage_validation/SKILL.md` 7-Question gate. Then specifically:

- [ ] Two-account (or two-role) proof with both request/response captured.
- [ ] Stage path recorded (which gate advanced the candidate — direct vs mutated
      vs bypassed) so the root cause is unambiguous.
- [ ] Bulk/export surface checked, not just the single object.
- [ ] Negative evidence recorded for the matrix arms that correctly denied.

## Evidence

Store under the run artifact root, named
`access_control_orchestrator_<target>_<timestamp>/`:

- `01_ids.txt` — collected IDs + format classification (Stage 1).
- `02_authz_matrix.md` — baseline (role, action, owner, method) verdicts.
- `03_path.md` — per-candidate stage path and the gate that advanced it.
- `04_finding.md` — confirmed access-control finding with two-account proof.
- `README.md` — verified-vs-not table per `shared/evidence_rules.md`.

## Exclusions

- No destructive actions or modification of other users' data.
- No DoS / brute-force enumeration that degrades the service.
- No out-of-scope assets; no automated pivot beyond the authorized program.

## See Also

- `agent_skills/packs/object_id_enumerator/SKILL.md`
- `agent_skills/packs/authz_matrix_tester/SKILL.md`
- `agent_skills/packs/parameter_mutator/SKILL.md`
- `agent_skills/packs/access_control_bypass/SKILL.md`
- `agent_skills/packs/export_authz_tester/SKILL.md`
- `agent_skills/packs/triage_validation/SKILL.md`
- `agent_skills/shared/scope_guard.md`
- `agent_skills/shared/evidence_rules.md`
