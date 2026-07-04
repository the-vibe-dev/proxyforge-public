---
name: api_hunt_orchestrator
description: Sequences the API hunting family end-to-end (schema-drift discovery, core API authz, GraphQL/gRPC/SOAP style-specific passes, sequence mining, triage) routed by detected API style.
---
# API Hunt Orchestrator

API testing capability is spread across `api_schema_drift_hunter`, `api_security`,
`graphql_hunter`, `grpc_protobuf_hunter`, `soap_xml_hunter`, and
`api_sequence_miner`. Each is strong in isolation but there is no single path that
discovers the API contract first, tests core authz, then branches into the
style-specific matrix only when that style is present. This pack is that
deterministic, style-routed sequencer.

Composes with `shared/scope_guard.md`, `shared/evidence_rules.md`, `shared/execution_policy.md`,
`packs/api_schema_drift_hunter/SKILL.md`, `packs/api_security/SKILL.md`,
`packs/graphql_hunter/SKILL.md`, `packs/grpc_protobuf_hunter/SKILL.md`,
`packs/soap_xml_hunter/SKILL.md`, `packs/api_sequence_miner/SKILL.md`,
`packs/triage_validation/SKILL.md`.

## When to Use

- Target exposes a REST/GraphQL/gRPC/SOAP API (schema, OpenAPI, SDL, or .proto
  discoverable, or API traffic observed).
- An autopilot/web run routed an `api_rest` / `graphql` surface and you need the
  full family rather than a single pack.

## Operating Rules

- Run `packs/scope_guard/SKILL.md` first; respect rate limits per
  `shared/execution_policy.md`.
- Discover the contract before mutating it — schema drift first so later stages
  test real (including undocumented) operations.
- Branch by detected style; do not run the GraphQL matrix on a pure REST API.
- Every candidate goes through triage before any report.

## Methodology

### Stage 1 — Contract & drift (api_schema_drift_hunter)

Run `packs/api_schema_drift_hunter/SKILL.md`: recover OpenAPI/SDL/.proto, diff
documented vs. observed routes, surface undocumented/legacy/version-skewed
endpoints. **Gate G1:** produce the operation inventory (documented + drift).

### Stage 2 — Core API authorization (api_security)

For every operation (including drift-discovered), run
`packs/api_security/SKILL.md`: authn/authz, object-level authz, mass assignment,
method/verb tampering. **Gate G2:** classify each operation; candidates → Stage 4
triage queue.

### Stage 3 — Style-specific matrix (routed)

Branch on detected API style (run all that apply):

- GraphQL → `packs/graphql_hunter/SKILL.md` (introspection, node() IDOR, alias
  batching, depth, persisted-query abuse).
- gRPC/protobuf → `packs/grpc_protobuf_hunter/SKILL.md` (reflection, message
  tampering, REST-vs-RPC authz gap).
- SOAP/XML → `packs/soap_xml_hunter/SKILL.md` (XXE, WS-Security, action spoofing).

**Gate G3:** style passes only run when that style is present; otherwise record
not-applicable.

### Stage 4 — Sequence mining (api_sequence_miner)

Run `packs/api_sequence_miner/SKILL.md` on multi-step flows (create→approve→use,
invite→accept) to find state/ordering authz gaps single-request tests miss.

### Stage 5 — Triage (triage_validation)

Route every candidate through `packs/triage_validation/SKILL.md` 7-Question gate.

## Submission Gates

Run `packs/triage_validation/SKILL.md` 7-Question gate. Then specifically:

- [ ] Operation inventory includes drift-discovered endpoints, not just docs.
- [ ] Authz proof uses two principals where the bug is cross-user.
- [ ] Style-specific arm recorded as run or not-applicable (no silent skips).
- [ ] Multi-step sequence bugs include the full request chain.

## Evidence

Store under the run artifact root, named
`api_hunt_orchestrator_<target>_<timestamp>/`:

- `01_operations.md` — documented + drift operation inventory (Stage 1).
- `02_authz.md` — per-operation authz verdicts (Stage 2).
- `03_style.md` — style-specific matrix results / not-applicable notes.
- `04_finding.md` — confirmed API finding with full request chain.
- `README.md` — verified-vs-not table per `shared/evidence_rules.md`.

## Exclusions

- No destructive operations against real data.
- No DoS (depth bombs / batch floods only against a lab or with explicit
  permission and bounded payloads).
- No out-of-scope assets.

## See Also

- `agent_skills/packs/api_schema_drift_hunter/SKILL.md`
- `agent_skills/packs/api_security/SKILL.md`
- `agent_skills/packs/graphql_hunter/SKILL.md`
- `agent_skills/packs/grpc_protobuf_hunter/SKILL.md`
- `agent_skills/packs/soap_xml_hunter/SKILL.md`
- `agent_skills/packs/api_sequence_miner/SKILL.md`
- `agent_skills/packs/triage_validation/SKILL.md`
- `agent_skills/shared/scope_guard.md`
- `agent_skills/shared/evidence_rules.md`
