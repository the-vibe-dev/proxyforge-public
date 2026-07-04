---
name: fuzzer
description: Campaign-level fuzzing: corpus minimization, harness generation, crash dedupe, coverage plateau detection, sanitizer triage (ASAN/UBSAN/MSAN), regression corpus, replay proof.
---
# Fuzz Campaign Intelligence

Campaign-level fuzzing: corpus minimization, harness generation, crash dedupe, coverage plateau detection, sanitizer triage (ASAN/UBSAN/MSAN), regression corpus, replay proof.

Composes with `packs/skeptic_validator/SKILL.md`, `packs/triage_validation/SKILL.md`, `packs/report_generator/SKILL.md`, `shared/scope_guard.md`, `shared/evidence_rules.md`.

## When to Use

- Seed corpus has redundant inputs; minimization improves coverage-per-execution.
- Crashes group by symbolized stack signature; one bug shows as N crashes if dedupe is missing.
- Coverage plateau >2h with no new edges → pivot to different harness / dictionary / structure-aware.
- ASAN reports use-after-free / heap overflow / stack overflow; each has distinct exploit potential.
- Crashing input added to regression corpus; future builds re-run to catch reintroduction.

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

For local CVE hunting, confirm the target is installed on an operator-owned
node or VM before any active run. Use `aitts` for authorized VM/light triage
work and `staging-backend` for heavy native parser fuzzing when available. Do
not fuzz public services or production targets. Resolve nodes by canonical
name/capability via `agent_skills/shared/compute_nodes.md` (or `vantix node
pick --cap`); never hardcode a host/IP.

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

For sanitizer-backed CVE candidates, do not promote on "crashed once." Require:

- exact upstream commit or release;
- sanitizer build flags and runtime command;
- deterministic standalone reproducer using public APIs when possible;
- minimized input;
- root-cause source re-read;
- duplicate check against upstream issues, CVEs, advisory databases, and recent commits;
- patch-test or fix hypothesis when feasible;
- `skeptic_validator`, `referee_arbiter`, and `final_boss_gate` records before submit-ready.

If a one-line local patch stops the crash, save it as root-cause evidence, not
as polished upstream remediation unless the maintainer asks for a patch.

## Phase 4: Report

For findings that clear skeptic + triage, delegate to `packs/report_generator/SKILL.md` for platform-specific drafting. Include the chain-of-custody evidence (request/response pairs, screenshots, decoded artifacts) from Phase 2.

## Theories This Pack Owns

- `fuzzer.corpus-redundancy`
- `fuzzer.crash-dedupe-by-stack`
- `fuzzer.coverage-plateau-pivot`
- `fuzzer.sanitizer-triage-asan`
- `fuzzer.regression-corpus-pinning`
- `fuzzer.embedded-nul-parser-copy`
- `fuzzer.emit-after-copy-roundtrip`

## Tooling

Optional external tools: jazzer, libfuzzer, afl++, honggfuzz. The pack also works with vanilla `curl` + manual inspection.

## See Also

- `packs/skeptic_validator/SKILL.md` — adversarial review gate
- `packs/triage_validation/SKILL.md` — 7Q + pre-submission gates
- `packs/report_generator/SKILL.md` — platform-specific report drafting
- `packs/exploit_chainer/SKILL.md` — chain expansion for validated findings
- `shared/scope_guard.md`, `shared/evidence_rules.md`

## Exclusions

- No destructive.
- No production target fuzz.
- No out of scope.
- No corpus with secrets.
