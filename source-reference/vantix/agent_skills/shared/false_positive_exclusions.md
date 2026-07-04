# False-Positive Exclusion Taxonomy

Consolidated, **context-aware** exclusion rules shared by `skeptic_validator`,
`triage_validation`, `final_boss_gate`, and source-review. The point is not to
suppress real bugs — every rule has an explicit *keep-it* exception that fires
when the evidence actually shows a crossed boundary or an exploit path.

Dense-first: `vantix lookup tag:false-positive-exclusions` (or
`learn_engine.py lookup tag:false-positive-exclusions --format prompt`).

## How to apply

For each candidate finding, walk the classes below. If a class matches **and**
its keep-exception does **not**, mark the candidate excluded with the named
reason and write negative evidence. If any keep-exception fires, do not
exclude — route to normal validation. Uncertain → do not exclude (the
downstream gates are stricter; never drop a real bug on a guess).

## Exclusion classes

1. **Generic DoS / resource exhaustion.** "Could exhaust CPU/memory",
   "unbounded loop/recursion", "resource exhaustion" with no concrete attacker
   capability. *Keep if*: program scope explicitly accepts DoS, or an
   amplification factor + concrete trigger + impact is demonstrated.
2. **Missing-rate-limit alone.** "No/insufficient rate limiting",
   "implement rate limiting". *Keep if*: chained to a concrete impact (e.g.,
   credential stuffing with a working account-takeover, OTP brute with a
   demonstrated bypass).
3. **Resource-management hygiene.** Unclosed file/connection/socket,
   "potential memory/connection leak", "release resource". Not a security
   finding by itself. *Keep if*: leads to an exploitable auth/state confusion.
4. **Low-impact open redirect alone.** Unvalidated redirect with no chained
   impact. *Keep if*: chained to OAuth/token theft, SSRF, or credential
   delivery (then it is the chain that is reported, not the redirect).
5. **ReDoS / regex-injection without applicability.** Generic "regex DoS".
   *Keep if*: attacker-controlled pattern on a hot path with a measured
   catastrophic-backtracking PoC inside scope.
6. **Memory-safety class in memory-safe context.** Buffer/stack/heap overflow,
   OOB read/write, UAF/double-free, integer overflow, segfault claims.
   *Exclude when* the implicated file/component is a memory-safe runtime
   (Python/JS/TS/Go/Java/Ruby/C#/Rust-safe) and no native/unsafe boundary is
   shown. *Keep if*: the file is C/C++/native, or an `unsafe`/FFI/native
   boundary is crossed, or a sanitizer-confirmed reproducer exists.
7. **SSRF in non-server / static client context.** "SSRF" flagged in static
   HTML, client-only JS, or markup with no server-side fetch. *Keep if*: a
   server-side request is actually constructed from attacker input.
8. **Findings in docs/markdown/fixtures/tests.** Match in `*.md`,
   documentation, example fixtures, or test data. *Keep if*: the doc/fixture
   is shipped and parsed at runtime as real input.
9. **Intended-behavior / observability.** Proof only shows documented logging,
   serialization, reflection, routing, or parsing behavior — no crossed
   security boundary. *Keep if*: the logged/serialized value is a secret that
   is independently usable.
10. **Label-not-evidence.** Severity/CWE/CVSS labels doing the work instead of
    an exploit/PoC; "could expand exposure surface" with no attacker
    capability. *Keep if*: a concrete reproduction is attached.
11. **Non-forgeable / transit-visible artifact framed as a leak.** A
    request-bound, time-bound, non-replayable, or intentionally
    transit-visible value called a "secret". *Keep if*: the artifact is
    independently usable, replayable, long-lived, and privileged.

## Output contract

On exclude: `{excluded: true, class: <1-11>, reason: <string>,
keep_exception_checked: true}` → write `negative_evidence` Fact; do not
promote. On keep: continue to `triage_validation` / `final_boss_gate`.

## See also
- `agent_skills/packs/skeptic_validator/SKILL.md`
- `agent_skills/packs/final_boss_gate/SKILL.md`
- `agent_skills/shared/pre_submission_self_audit.md`
