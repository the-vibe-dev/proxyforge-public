# Evidence Rules

- Preserve raw output and parsed conclusions separately.
- Store evidence under the run artifact workspace.
- Use sanitized names: `{tool}_{target}_{timestamp}`.
- Never store secrets, personal keys, private topology, or client data in tracked files.
- Link every finding/vector to evidence or mark it unconfirmed.
- Mark source-only, scanner-only, emulator-only, dummy-response, or inferred
  downstream behavior as `candidate`, not confirmed.
- For UI, auth, session, account, payment, mobile, browser, or multi-step
  chains, require a screen recording plus screenshots of the critical
  transitions before submission.
- Preserve full request/response evidence for every claimed chain link:
  method, URL, status, relevant headers, relevant body fields, and timestamps.
  Redact secrets without destroying structure needed for reproduction.
- A finding is not `full chain`, `ATO`, `critical`, or `verified` unless the
  evidence proves attacker-side acquisition, downstream consumption when
  claimed, and the final privileged or impact state.
- Store large videos, screenshots, HARs, captures, and proof packs in the
  configured artifact root or NAS endpoint, but keep evidence decisions and
  report promotion rules in repo-local playbooks.

## Source Provenance for Specific Factual Claims

Every specific factual claim in a draft report — version number, commit hash,
line number, endpoint, response body excerpt, timestamp, file path, memory
address, CVE number, payout precedent, author attribution — must be tied to a
named source. Specific claims without source-provenance are a hazard: in long
sessions, neither author nor reviewer can later distinguish verified facts
from plausibility-filled facts.

- During drafting, attach an inline provenance marker to every specific
  factual claim. Example: `Stable 148.0.7778.167 (verified 2026-05-13 via
  chromiumdash.appspot.com/fetch_releases)`.
- Provenance markers stay in the working draft and in the bundle's
  `evidence/README.md` "verified vs not" table even if they are trimmed from
  the final submission body for readability.
- Build evidence bundles with an explicit "verified vs not" table. List every
  specific claim, its source, and whether it was directly verified or
  inferred. Mark inferences clearly so triage can re-verify the load-bearing
  ones.
- If a specific claim cannot be re-verified before submission, either downgrade
  it to a less-specific framing ("approximately N", "the affected line range",
  "the precedent fix author/commit area") or remove it. Do not submit specific
  factual claims that the author cannot vouch for.
- The pre-submission self-audit (see `pre_submission_self_audit.md`) Step 1
  enforces this rule. Run that audit before every submission.

## Session-Identity Tagging

For any authenticated hunt — anything that loads a session, JWT, OAuth token, API key, or other credential and replays it across multiple tool invocations — the audit trail must identify *which session* produced each request, without ever writing the raw token to disk.

- Compute a stable 12-character truncated SHA-256 hash of the credential at session-load time. Store it in the run state under `session_id_hash`.
- Every audit-log entry, evidence file name, and finding annotation references `session_id_hash`, never the raw token.
- The raw token lives in process memory or in an operator-controlled secret store (env var, agent_ops secret), never in tracked files or evidence bundles.
- When two sessions (low-priv, high-priv) are active, tag each with its own hash and label (`session_a_low_priv`, `session_b_admin`) in the run state. Cross-identity findings must reference both hashes so the report can demonstrate the bug holds across the privilege boundary.
- When the session expires or is rotated, generate a new hash. Do not edit prior audit entries.
- A logged-out / no-auth replay is recorded with `session_id_hash: anonymous`. Necessary for IDOR/auth-bypass differentiation.

This rule supports the Q8 "Identity check" step in `agent_skills/packs/triage_validation/SKILL.md` — IDOR / BOLA / priv-esc findings that fail the cross-identity check are the single most common N/A cause, and the session-id hash is what makes the check reproducible.

## Verifying-What-You-Wrote Discipline

In sessions that produce long heredocs or multi-edit reports, the author can
forget what was written hours earlier. Two checks reduce this risk:

- Prefer **shorter atomic writes** with focused content over multi-page
  heredocs. A 50-line write is auditable; a 300-line write contains specifics
  the author will not later recall composing.
- After any large write, **re-read the output** before continuing. Catch any
  specific factual claim that the author cannot account for, in the same
  session that produced it. Do not let those claims accumulate into the next
  session as untraceable lore.
