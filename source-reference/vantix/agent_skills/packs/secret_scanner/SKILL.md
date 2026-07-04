---
name: secret_scanner
description: Leaked credentials discovery with provider-specific confidence scoring, verification-safe classification, and revocation guidance for AWS / GCP / Azure / Stripe / Slack / GitHub / Postgres / SSH / API keys.
---
# Secrets Verification & Validation Scanner

Leaked credentials discovery with provider-specific confidence scoring, verification-safe classification, and revocation guidance for AWS / GCP / Azure / Stripe / Slack / GitHub / Postgres / SSH / API keys.

Composes with `packs/skeptic_validator/SKILL.md`, `packs/triage_validation/SKILL.md`, `packs/report_generator/SKILL.md`, `shared/scope_guard.md`, `shared/evidence_rules.md`.

## When to Use

- JS bundle / source map / repo / Docker image contains a live issuer-verifiable token.
- Rotated secret remains in git history and is still accepted by the issuer.
- Credential matches provider format AND verification returns a positive signal.
- Committed .env / config file leaks credentials to a live service.
- CI artifact (build log, test output) leaks short-lived but exploitable credentials.

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

- `secret_scanner.verified-key-in-bundle`
- `secret_scanner.stale-git-history-secret`
- `secret_scanner.provider-verified-credential`
- `secret_scanner.env-file-credential`
- `secret_scanner.ci-artifact-credential`
- `secret_scanner.revocation-pathway-unclear`

## Tooling

Optional external tools: trufflehog, gitleaks, noseyparker. The pack also works with vanilla `curl` + manual inspection.

## See Also

- `packs/skeptic_validator/SKILL.md` — adversarial review gate
- `packs/triage_validation/SKILL.md` — 7Q + pre-submission gates
- `packs/report_generator/SKILL.md` — platform-specific report drafting
- `packs/exploit_chainer/SKILL.md` — chain expansion for validated findings
- `shared/scope_guard.md`, `shared/evidence_rules.md`

## Exclusions

- No destructive.
- No pivot off key beyond existence proof.
- No out of scope.
- No production data modification.
