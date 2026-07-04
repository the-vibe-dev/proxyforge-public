# Operating Rules for Authorized Bug-Bounty Testing

Cross-cutting rules every recon, threat-model, hunting, validation, and
report agent inherits. Distilled from the bug-bounty methodology corpus
(§0); the full backing reference is
`docs/agent-learning/bug-bounty-methodology-playbook.md`. These compose
with `scope_guard.md`, `evidence_rules.md`, and
`pre_submission_self_audit.md` — they do not replace them.

Treat these methods as authorized-testing workflows, not as instructions
to attack arbitrary third parties.

1. **Scope first.** Never test a host, account, mobile/desktop app, API,
   WebSocket, or cloud asset until scope is confirmed. Defer to
   `scope_guard.md` / `authorization_anchor.md` for durable authorization.
2. **Use owned accounts and controlled tenants.** For IDOR,
   access-control, CSRF, CORS, OAuth, and XSS impact testing, use accounts
   created for testing. Never test against real users or customer data.
3. **Do not exploit beyond proof-of-concept.** Demonstrate impact with
   controlled data and the minimum necessary requests.
4. **Respect rate limits and program rules.** Prefer passive recon and
   low-volume validation. High-speed brute forcing is off by default.
5. **Do not evade defensive controls outside authorization.** Rotating
   infrastructure, distributed scanning, WAF-bypass research, or
   large-scale fuzzing require explicit approval and a strict rate plan.
6. **Prioritize reproducibility and impact.** A report must show the
   attack path, affected asset, violated trust boundary, failed security
   control, realistic victim, and the sensitive data or capability at
   risk.
7. **Record uncertainty.** Label every inference drawn from partial
   evidence and list the validation step that would confirm it.
8. **Prefer defense-in-depth learning.** The goal is not only to find a
   bug but to identify which control failed and how to fix the class.

**Stop conditions:** out-of-scope target, destructive/irreversible action
required, real user data in the blast radius, or program rules violated —
halt and surface to the operator.
