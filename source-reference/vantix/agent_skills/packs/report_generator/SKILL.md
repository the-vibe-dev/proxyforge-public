---
name: report_generator
description: Report Generator: evidence-backed report and executive summary writing.
---
# Report Generator

## Use When
evidence-backed report and executive summary writing. Apply this pack for roles: reporter.

## Operating Rules
- Follow SecHive shared scope, evidence, memory, and execution policy.
- Produce dense, machine-reviewable notes with fields: `obs`, `evidence`, `risk`, `next`, `blocked`.
- Mark uncertainty explicitly; do not promote scanner hits to findings without validation.
- If execution is allowed, propose the least intrusive action first with noise level and evidence path.

## Role Focus
Write concise findings with impact, evidence, reproduction, remediation, and verification.

## External Disclosure Hygiene

Before writing any external report, rewrite internal notes into a clean
researcher-facing disclosure. Do not copy local orchestration language into the
report.

Do not include:

- local node names, private hostnames, private IPs, usernames, home directory
  paths, cloud account IDs, internal queue IDs, or internal job IDs;
- internal agent names, model names, gate status, agent verdicts, provider
  failures, scoring notes, or workflow commentary;
- internal repository paths unless the report is for local handoff. External
  reports should use attachment filenames such as `asan_repro.txt`, not
  `docs/local/...`;
- raw secrets, tokens, cookies, credentials, customer data, or employee data;
- unverified CVE IDs, unverified bounty claims, hype language, or unsupported
  impact claims.

Normalize internal details:

- `Node: staging-backend` -> remove or `Test environment: local ASAN build`.
- `/home/<user>/...` -> omit or `local test workspace`.
- `docs/local/.../asan_repro.err` -> `attached evidence file: asan_repro.txt`.
- `Hunter/Skeptic/Referee/Final Boss: UPHOLD` -> omit.
- `Vantix/Codex/Claude/provider blocked` -> omit.
- `our agent found` -> `I found` or passive voice.

For native/parser memory-safety disclosures, use this structure unless the
target program requires another format:

1. Title.
2. Summary.
3. Affected Versions / Commit.
4. Environment.
5. Reproduction Steps.
6. Minimized Reproducer.
7. Observed Result.
8. Expected Result.
9. Root Cause.
10. Impact.
11. Duplicate / Prior Art Check.
12. Suggested Fix.
13. Suggested Regression Test.
14. Safety Notes.
15. Attachments.
16. Redaction Checklist.

Keep severity conservative. For parser OOB read/crash/DoS with plausible
attacker-controlled input, Medium is usually appropriate. Use High only for
demonstrated sensitive memory disclosure, code execution, sandbox escape,
privilege escalation, or another direct high-impact boundary crossing. Never
claim RCE, root/system compromise, or bounty value unless proven.

## Production-Impact Gate For Memory Safety

Do not treat "ASAN-only" as production impact. A sanitizer finding can prove a
library memory-safety bug exists, but stronger impact wording requires at least
one non-sanitized or downstream proof:

- production-build crash, signal, abort, core dump, or application-level failure;
- production-build memory disclosure with synthetic sentinel bytes in observable output;
- production-build corruption that changes output, state, control flow, or later operations;
- local reproduction in a public downstream consumer through normal usage;
- vendor/program policy that explicitly accepts sanitizer-only memory-safety reports.

If a bug uses normal public library APIs and is an accepted memory-safety class
such as OOB read/write, UAF, double free, or memory corruption, bank it as
`banked_low_impact` when there is no production crash/leak/corruption and no
confirmed downstream impact. It may be reported as `submit_ready_library_only`
only when a maintainer/vendor/program accepts bounded library-level sanitizer
reports or the operator intentionally wants a low-impact upstream hardening
report. In that case the report must say:

> The minimized input triggers a sanitizer-confirmed heap out-of-bounds read
> through normal library parser entrypoints and object emission. In
> non-sanitized builds, I did not observe a visible crash or memory disclosure,
> so I am bounding impact to a library-level memory-safety issue unless
> downstream consumers or maintainers identify a production-impacting path.

Do not claim production denial of service, remote denial of service, downstream
package-manager impact, downstream application impact, memory disclosure, code
execution, privilege escalation, or boundary escape without direct evidence.

## Objective Proof Reporting
- Separate validated vulnerabilities from objective completion. A vulnerability can be real even when the requested proof artifact or customer success criterion remains unmet.
- If evidence is encoded, transformed, truncated, or requires a decode command, report both the raw value and decoded value plus the exact command used.
- Do not label a decoded secret as the requested proof unless it matches the run's explicit verifier, proof regex, proof needle, or objective pattern.
- When objective proof is unmet, still write machine-readable findings for validated vulnerabilities and clearly mark the proof gap as a blocker or residual risk.
- When one testing perspective succeeds and another fails, report the success as validated and create a follow-up reproduction or source-explanation task rather than flattening the run into a generic partial.
- For blind proof, include baseline/probe/repeat artifacts, deltas, confidence, and noise notes.
- For chained proof, show each capability, prerequisite, request, response, and the next unlock that was tested or left unresolved.
- For bug bounty reports, include a `Proof Boundary` section that states what
  is proven at runtime, what is candidate or inferred only, what failed, and
  what is intentionally not claimed.
- Do not write `full account takeover`, `full ATO`, `complete chain`,
  `critical`, `verified exploit`, or downstream-consumption language unless
  video, screenshots, request/response artifacts, and final impact proof exist
  for every claimed link.
- If the evidence package lacks a reproducible full-path video for UI/auth/
  session/account/mobile/browser chains, keep the report as a draft or
  candidate and request the missing proof instead of polishing the claim.

## Pre-Submission Audit
Run `shared/pre_submission_self_audit.md` before promoting any report to submission. The
four-step audit checks: (1) every specific factual claim has named source-provenance,
(2) severity equals the bounded analysis (not the precedent's class), (3) anticipated
triage counter-arguments are addressed or absorbed, (4) program-specific rules are met
(channel scope, PoC format, baseline disclosure, dupe handling, out-of-scope categories).
Skipping the audit has cost submissions in past sessions.

## VRP Review And Polishing References

For VRP reports, the reporter must load the local policy packet before final
drafting:

- `vrp_best.md`: general submission standard, strong report anatomy, invalid
  patterns, impact wording, duplicate clearance, and final checklist.
- `chrome_vrp.md`: Chrome Browser / Chromium / d8 report structure, channel
  eligibility, PoC attachment/minimization, ASAN/MTE/crash evidence, UI and
  memory-safety requirements.
- `web_vrp.md`: web, mobile, service, and browser-extension scope traps,
  attacker/victim account proof, product-specific impact, and evidence
  expectations.

Use these files to polish title, summary, scope, preconditions, reproduction,
expected/actual result, security impact, evidence, safety notes, and duplicate
review. Do not output a submission-ready VRP report if the relevant packet has
not been applied. Instead, write the missing policy check as a blocker.

## Platform-Specific Templates

Different programs expect different formats. Use the template that matches the destination platform. All templates compose with the 7-Question gate (`packs/triage_validation/SKILL.md`) and the pre-submission self-audit (`shared/pre_submission_self_audit.md`) — those run **before** any of these templates produce a final submission.

### Standard web/API platform template

```
Title: [Bug Class] in [Endpoint] allows [Actor] to [Impact]

## Summary
One sentence. What can the attacker do that they couldn't before?

## Steps to Reproduce
1. Authenticate as <test_account> (session-id-hash: <12-char>)
2. Send the following request:
   ```
   POST /api/v2/orders/123 HTTP/1.1
   Host: target.com
   Authorization: Bearer <redacted>
   Content-Type: application/json

   {"price":1}
   ```
3. Observe the response:
   ```
   HTTP/1.1 200 OK
   ...
   {"price":1,"status":"placed"}
   ```

## Impact
Concrete real-world consequence. PII read, fund loss, ATO. Quantify if possible.

## Proof Boundary
What is proven at runtime; what is candidate/inferred; what failed; what is NOT claimed.

## CVSS 3.1
Vector: AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N
Score: 6.5 (Medium)

## Remediation
One concrete sentence. Name the check or invariant that should hold.

## Attachments
poc.har, screenshot.png, video.mp4 (UI flows require video).
```

### Numbered-steps / VRT variant

Some platforms accept the standard format with two adjustments: a
Vulnerability Rating Taxonomy (VRT) category must be named explicitly,
and Steps to Reproduce must include explicit numbered steps with one
action per line (not a paragraph).

```
Title: [VRT Category] — [Endpoint] — [Impact]

## VRT Category
P2 — IDOR — Direct Object Reference (Internal)

## Summary, Steps to Reproduce, Impact, Proof Boundary, CVSS, Remediation, Attachments
(same as the standard template)
```

### Tiered-severity variant

Some platforms require:

- A "Severity" field with a 5-tier rating (Exceptional / Critical / High / Medium / Low) **in addition** to CVSS.
- The program-specific URL identifier for the affected asset.
- A mandatory "Researcher Comment" field for context the triager won't have.

```
Title: [Bug Class] @ [Asset URL]

## Severity
High (CVSS 8.1)

## Asset
https://app.target.com/api/v2

## Summary, Reproduction, Impact, Proof Boundary, Remediation, Attachments
(same shape as the standard template)

## Researcher Comment
Context: discovered while exercising the post-login flow under test_account_a; the bypass requires no exotic precondition. Tested in EU region; production environment.
```

### Smart-contract / DeFi variant

DeFi smart-contract reports have a different shape — they are PoC-led and require an executable PoC, not just curl-style steps.

```
Title: [Bug Class] in [Contract] on [Chain] — [Impact]

## Severity (DeFi tier scale)
Critical / High / Medium / Low / None

## Affected Contract
Chain: Ethereum
Address: 0x... (source verified on the chain's block explorer: yes)
Function: vote(uint256 tokenId)
Line: 142 in src/Voter.sol

## Bug Description
One paragraph. Root cause. Reference the bug class (`accounting_desync`, `oracle_no_staleness`, etc.).

## Attack Scenario
Step-by-step what an attacker does, with the exact tx sequence.

## Impact
Funds at risk: $X. Affected users: Y. Realistic loss scenario: Z.

## PoC
Attached Foundry project. Reproduces against fork at block N.

```
forge test --match-test test_exploit -vvvv --fork-url $MAINNET_RPC
```

Expected output: assertion `assertGt(attacker.balance, INITIAL)` passes.

## Recommendation
Concrete fix — name the check, the modifier, the invariant.

## References
- Similar pattern: <prior public disclosure if any>
- Class write-up: <link or omit>
```

### Self-hosted / VDP variant

For programs that channel through a bug-bounty platform but are technically VDP (no bounty), use the numbered-steps variant template and add:

```
## Submitter Note
This is a VDP submission — no bounty expected. Submitted for responsible disclosure under the program's published safe-harbor.
```

This sets triage expectations and avoids back-and-forth about payout.

## Rejection-Aware Drafting

`triage_validation/SKILL.md` § "Rejection Pattern Analysis" lists the ten most common reasons reports get rejected across bug-bounty platforms. Each draft should be cross-checked against the list before submission. The drafting workflow integrates the check:

1. **Before Title**: search the program's prior-disclosure feed for the endpoint + class. If a similar report exists, this report duplicates or extends — say so explicitly in the Summary ("This report extends report #X with a chain to ATO that the prior report didn't explore").
2. **In the Steps to Reproduce**: every request is copy-paste. Triagers reproduce by pasting; if the request doesn't work, the report is rejected.
3. **In the Impact**: write the consequence concretely. Avoid "could potentially", "may allow", "in theory". Each appearance is a rejection pattern #3 (severity overclaim) or #7 (preconditions unrealistic) risk.
4. **In the Proof Boundary**: name what is proven at runtime vs candidate / inferred. Triagers reward this calibration; they punish overclaim.
5. **In the Communication**: no hostility. No pressure for higher payout in the initial report. No accusations of incompetence. Tone rejections are real and recoverable only with extensive apology + rewrite.
6. **In the Severity / CVSS**: bounded analysis (`shared/pre_submission_self_audit.md` Step 2). When in doubt, downgrade. Triage upgrading is fine; triage downgrading damages trust.

### Specific patterns to avoid in draft text

| Anti-pattern | Why it triggers rejection | Replacement |
|---|---|---|
| "Critical impact — full ATO" | When the actual repro requires user click + cookie + page state, this overclaims. | "ATO when victim clicks attacker-crafted OAuth URL (UI:R). CVSS 8.1 High." |
| "This endpoint is vulnerable to SQL injection" | Generic class assertion without PoC reproduces as informational. | "Endpoint `/api/v2/orders?id=1' OR '1'='1` returns the response body of all orders (PoC in Steps 3-4)." |
| "The fix is to validate input" | Generic remediation doesn't name a check. | "Add a per-user authz check in OrderController.show() before returning the Order; or replace `User.find_by_id` with `current_user.orders.find_by_id`." |
| "I noticed your application has..." | Casual / unprofessional intro. | Direct: "TARGET / ENDPOINT / METHOD / IMPACT" header followed by Summary. |
| "Hope this gets a Critical reward" | Pressure on bounty decision. | Omit. Bounty discussion happens after triage decides severity. |

### Bounty-range references (calibration, not promise)

See `triage_validation/SKILL.md` § "Severity Calibration with Bounty Range Examples" for realistic per-tier ranges. Use these to defend severity, not to ask for a specific payout.

## Tone Rules

- **Never** write "could potentially," "may allow," "in theory," "theoretically possible." If you cannot demonstrate the impact, the report is not ready.
- **Never** write "full ATO," "complete chain," "verified exploit" unless every link is proven with runtime evidence per `shared/evidence_rules.md`.
- Match severity to the *bounded* impact (`shared/pre_submission_self_audit.md` Step 2), not to the precedent's class. Overclaiming triggers triage skepticism that can dismiss the entire finding.
- Steps to Reproduce are copy-pasteable. The triager can paste the curl, get the same response. No manual translation required.

## Corpus Report Template (§16)

Backing reference: `docs/agent-learning/bug-bounty-methodology-playbook.md`
§16 (learning sources `corpus.bb.idor_ac`, `corpus.bb.client_side_injection`,
`corpus.bb.ato_xss`); retrieve via
`learn_engine.py --root . lookup tag:report-13-section-template --format prompt`.

A triage-ready report carries: impact-bearing title; scope evidence;
one-paragraph summary of the boundary/control that failed; affected
users/data (victim class + crown jewel); prerequisites; minimal controlled
repro; expected vs actual; impact + nightmare scenario; security controls
bypassed/missing; evidence (requests/responses, screenshots, object IDs);
remediation for the class; and a safe-testing note confirming no real user
data was accessed.

- **Client-side-injection rule:** never submit "alert executed" alone —
  include delivery path, victim class, impact path, controls analyzed, and
  why it is not self-XSS.
- **IDOR/access-control rule:** include attacker + victim test accounts,
  object-ownership evidence, role/permission evidence, the original
  authorized request, the modified unauthorized request, the response and
  resulting state, and impact tied to sensitive data or capability.

## Exclusions
No out-of-scope, destructive, persistence, DoS, credential-stuffing, or secret-disclosure actions.
