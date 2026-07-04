# Diff / PR Security Review

Tight, diff-scoped source review that finds **only vulnerabilities introduced
by the change under review**, at HIGH confidence, with low false-positive
noise. Complements `variant_hunter` (CVE/patch-driven) and the source-review
surface. Review-only — no exploitation.

Dense-first: `vantix lookup tag:diff-security-review`.

## Scope rule

Report only security defects *newly added by this diff/PR*. Do not raise
pre-existing issues, style, or general code review. Local-network-only
reachability can still be HIGH severity.

## Three phases

1. **Repository context research.** Use code search to learn how the changed
   code is called, what trust boundary it sits on, what frameworks/sanitizers
   are already in place, and what the surrounding invariants are. Without
   context, a diff line is not judgeable.
2. **Comparative analysis.** Diff old vs new behavior: what input is now
   reachable, what check was removed/weakened, what sink is newly fed, what
   authz/tenant boundary changed. Name the exact added/changed lines.
3. **Vulnerability assessment.** For each candidate: trace input → sink,
   confirm the boundary crossed, assign severity from concrete impact (not a
   CWE label), and apply `false_positive_exclusions.md` before keeping it.

## Static-scan composition (single pass)

When auditing source, compose one normalized pass rather than ad-hoc tools:
secrets → SAST (injection/authz/crypto sinks) → SCA (dependency CVEs) → IaC
(cloud/k8s misconfig) → behavioral/architectural gate (trust-boundary,
auth-state, multi-tenant). Normalize every finding to a common shape
(`{class, file, line, sink, input_source, severity, evidence, exploit_path}`)
so the validation funnel and report layer consume one contract.

## Output contract

Structured list; each finding: `title, severity (HIGH|MEDIUM|LOW),
file:line, input_source, sink, why_introduced_by_this_diff,
exploit_path, recommendation`. HIGH only unless explicitly asked for
lower tiers. Then route each kept finding into the validation funnel.

## See also
- `agent_skills/packs/variant_hunter/SKILL.md`
- `agent_skills/shared/false_positive_exclusions.md`
- `agent_skills/packs/exploit_precision/SKILL.md`
