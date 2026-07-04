---
name: agent_memory_integrity_hunter
description: Poisoned memory, false learning promotion, cross-run contamination, stale bug assumptions, prompt-injected 'known facts', evidence-free finding recall.
---
# Agent Memory Integrity Hunter

Poisoned memory, false learning promotion, cross-run contamination, stale bug assumptions, prompt-injected 'known facts', evidence-free finding recall.

Composes with `packs/skeptic_validator/SKILL.md`, `packs/triage_validation/SKILL.md`, `packs/report_generator/SKILL.md`, `shared/scope_guard.md`, `shared/evidence_rules.md`.

## When to Use

- Tool output stored as 'fact' in memory; attacker controls tool input; memory poisoned.
- Learning system promotes patterns from poisoned runs; future agents act on fake learning.
- Memory not workspace-scoped; one tenant's memory influences another.
- Agent recalls a 'finding' from memory without re-checking current state; stale recommendation.
- Prompt-injected 'authoritative source' becomes a memory fact agents trust later.

## Operating Rules

- Scope first. Per `shared/scope_guard.md`, every target / asset / endpoint touched must be in-scope; assets that are CDN, third-party-hosted, or shared services need explicit authorization before active probing.
- Read-first, mutate-never. Default to passive observation. Active probing only after operator-confirmed scope.
- Evidence over claim. Every candidate finding must carry: baseline request/response, mutated request/response, the specific diff, the impact statement, and the negative control proving it is not a public/anonymous behavior.
- Time-box per surface. Default 30–60 minutes per surface × bug class. If no signal in the time-box, rotate.
- Skeptic-gate every candidate. Per `packs/skeptic_validator/SKILL.md`, before promoting to triage.

## Phase 0: Readiness

1. Confirm the in-scope surface (target / asset / endpoint family) and program-specific exclusions.
2. Capture a baseline: an authenticated session for at least two personas (where applicable) and a baseline request/response per surface.
3. Inventory the relevant artifacts for this bug class (see hypotheses below).

## Phase 1: Discovery

For each in-scope surface, enumerate the candidate artifacts this pack targets. Cross-reference with prior findings (per `shared/memory_protocol.md`) to skip already-tested surfaces.

## Phase 2: Mutation / Probing

Apply the hypothesis-specific mutations. For each, capture:

- The exact request / payload / configuration used
- The baseline response (or behavior) without the mutation
- The mutated response (or behavior)
- The semantic diff (status / size / content / state-change)
- Negative control: same mutation by an unauthenticated user (proves auth boundary).

## Phase 3: Skeptic Gate + Triage

Route every UPHELD candidate through `packs/skeptic_validator/SKILL.md` (15-pattern hard-exclusion list) and `packs/triage_validation/SKILL.md` (7-Question gate). Dismissed candidates emit a negative-evidence note.

## Phase 4: Report

For findings that clear skeptic + triage, delegate to `packs/report_generator/SKILL.md` for platform-specific drafting. Include the chain-of-custody evidence (request/response pairs, screenshots, decoded artifacts) from Phase 2.

## Theories This Pack Owns

- `agent_memory_integrity_hunter.memory-poisoning-via-tool-output`
- `agent_memory_integrity_hunter.learning-promotion-abuse`
- `agent_memory_integrity_hunter.cross-run-contamination`
- `agent_memory_integrity_hunter.evidence-free-recall`
- `agent_memory_integrity_hunter.prompt-injected-known-fact`

## Tooling

Optional external tools: memory-inspector. The pack also works with vanilla `curl` + manual inspection.

## See Also

- `packs/skeptic_validator/SKILL.md` — adversarial review gate
- `packs/triage_validation/SKILL.md` — 7Q + pre-submission gates
- `packs/report_generator/SKILL.md` — platform-specific report drafting
- `packs/exploit_chainer/SKILL.md` — chain expansion for validated findings
- `shared/scope_guard.md`, `shared/evidence_rules.md`

## Exclusions

- No destructive.
- No out of scope.
- No production memory modification.
