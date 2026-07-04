# Pre-Submission Self-Audit Checklist

Run this **immediately before** submitting any bug bounty report to a program. The checklist exists because two failure modes recur across long sessions:

1. **Source-provenance drift** — specific factual claims (version numbers, commit hashes, line numbers, response bodies, timestamps, endpoint paths) get into a report draft without an inline tag of which tool call produced them. Hours later, the author cannot distinguish verified facts from plausibility-filled facts. Anything in this category must be re-verified or removed.

2. **Severity anchoring** — the report's stated severity gets anchored to a precedent's severity (e.g., "this is the same bug class as bug 501739206 which was triaged High → so this is High"). Anchoring skips the bounded-impact analysis. The result is overclaim that triggers triage skepticism, sometimes severe enough to dismiss the whole finding.

The five steps below catch these failure modes. Do not submit without completing
all five explicitly.

**Sequencing:** the 7-Question kill-fast gate in `agent_skills/packs/triage_validation/SKILL.md` runs **before** this audit. The 7Q gate filters out weak findings cheaply; this audit assumes the finding has already cleared the gate and focuses on provenance and bounded severity for a submission that is going out. If you have not run the 7Q gate yet, do that first — it catches the early kills (out of scope, on the never-submit list, no working PoC) in 5 minutes; running this audit on a finding the 7Q gate would have killed is wasted work.

---

## Step 1 — Re-read the report end-to-end with source-provenance audit

Read the report linearly, top to bottom. For every specific factual claim — every number, hash, line number, name, endpoint, version, timestamp, file path, response body excerpt — ask out loud or in writing:

> *Do I remember producing this from a verified tool call this session, and can I name the tool call?*

For each claim, exactly one of three outcomes:

- **Verified** — I can name the tool call (file read, web fetch, git command, capture parse) that produced this value. Leave it.
- **Re-verify** — I can probably re-verify cheaply now. Do it. Either confirm and tag inline, or downgrade to "approximate" / "see triage".
- **Remove** — I cannot verify and cannot cheaply re-verify. Remove the specific claim and replace with a less-specific framing (e.g., "approximately N" or "see line range" instead of an exact line number).

**Common provenance failures:**

- Chrome / browser version numbers
- Commit hashes
- Source-file line numbers (especially when source is on a remote/NAS share)
- mojom interface method names if you didn't read the .mojom file
- Memory addresses, register values, ASAN stack frame line numbers
- Date stamps in third-party docs
- CVE numbers
- Bounty payout precedents quoted as "$N range"
- Author names attributed to commits

**Inline provenance markers help future-you.** When writing the report, prefer:

```
Stable 148.0.7778.167 / 65db666ac2cf205fcc36db8bb5b9cd87f94808ac
  (verified 2026-05-13 via chromiumdash.appspot.com/fetch_releases)
```

over:

```
Stable 148.0.7778.167 / 65db666ac2cf205fcc36db8bb5b9cd87f94808ac
```

The marker is dropped from the final submission body if it clutters, but it should be in the working draft and the bundle's `evidence/README.md` "verified vs not" table.

---

## Step 2 — Re-derive severity using bounded analysis

Before reading the report's stated severity, re-derive severity from scratch using this four-step bounded process:

1. **Exact capability.** In one sentence, what does the bug let an attacker do? Be specific. "Read X" not "data leak." "Append to Y" not "log tampering."

2. **Lowest-plausible impact.** Assuming the program's defenses-in-depth catch typical cases, what is the SMALLEST credible real-world harm? For a typical user, in a typical configuration, with public-knowledge data, what's the floor?

3. **Upper bound.** What's the worst plausible target / configuration where the bug really matters? Name the specific class of victim (e.g., enterprise-policy extension users, sideloaded-extension developers).

4. **Comparison to claimed precedent on IMPACT, not on bug class.** If you've cited a precedent fix, explicitly compare what the precedent fix prevented vs. what THIS bug enables. State the differences out loud:
   - Precedent enabled X; this bug enables Y. Are X and Y comparable?
   - Precedent allowed state mutation; this bug allows read. Read ≠ mutate in severity terms.
   - Precedent affected default-reachable surface; this bug requires precondition Z.

Now read the report's stated severity. If the bounded analysis is LOWER than the stated severity, lower it. Severity overclaim is more harmful than understating because it triggers triage skepticism that can dismiss the finding entirely.

**The stated severity must be the bounded severity, not the upper bound and not the precedent's severity.**

---

## Step 3 — Triage-Says-Lower preemption

For every severity claim and every impact claim, ask:

> *If a competent, skeptical triage engineer at the program were to read this and disagree with the rating, what's the SPECIFIC counter-argument they would make?*

Examples:

- "The data this reads is already publicly downloadable" — common counter-argument for cross-account / cross-extension data reads of distributable artifacts (Chrome Web Store CRX files, npm packages, Docker images, etc.).
- "This requires X precondition that's harder than the report implies" — common for compromised-renderer / compromised-account / pre-authentication claims.
- "Downstream code catches this" — common for defense-in-depth gaps that aren't direct bypasses.
- "This is a fork-only / dev-flag / experimental-feature path" — common for surfaces that aren't in the program's reward scope.

For each anticipated counter-argument:

- Either **address it in the report explicitly** (a "What this bug is NOT" section, or honest preconditions in §Preconditions)
- Or **downgrade severity** to be defensible against the counter-argument
- Or **strengthen evidence** to falsify the counter-argument (e.g., demonstrate the precondition is met, demonstrate downstream catches don't apply)

The goal is: triage's eventual response should not surprise you. If they downgrade, you should be able to say "yes, that's exactly the case I noted in §Severity argument, here's why we still think the lower bound is real."

---

## Step 4 — Run the program-specific checks

Most bug bounty programs have program-specific rules that auto-disqualify or auto-downgrade reports. The audit must catch these before submission, not after.

**Generic per-program checks** (consult the program's actual rules page):

- **Channel / version scope** — Is the bug in a channel/version the program actually rewards? (Chrome VRP: Stable, Beta, Dev — Canary-only with trunk age <7 days is not eligible. Web/API programs: typically the program's "in scope" list.)
- **Duplicate handling** — Is there an existing report or public disclosure that covers this exact bug? "First actionable report" wins; later reports are ineligible.
- **Out-of-scope behaviors** — Common out-of-scope categories: rate-limit DoS, self-XSS, phishing-only, unsafe-flag-only, dev-mode-only, experimental features (e.g., Chrome VRP: WebNN, SwiftShader, V8 experimental, `--single-process`). If your bug touches any of these, either remove from scope or explain why this specific instance is still in scope.
- **PoC quality requirements** — Some programs require minimized attached PoC files (Chrome VRP: `poc.html` or `index.html`, attached not linked). Others require video for UI flows (e.g., wallet / financial programs).
- **Chrome supported-PoC requirement** — Chrome VRP requires reproduction in
  Chrome, `d8`, or a supported binary. Do not submit when the only proof is a
  modified Chromium unit test, modified browser test, custom harness, CDP-only
  flow, or shell-wrapper-only reproduction. Those are local triage artifacts,
  not submission PoCs.
- **Baseline disclosure** — At minimum, version number and channel/build on which the bug was discovered and reproduced. Reports without this are auto-downgraded.
- **Initial comment requirement** — Some trackers close reports with empty initial descriptions.
- **Researcher-policy compliance** — Did you actually only test owned accounts? Did you avoid third-party data? Re-read your own evidence.

---

## Step 5 — Chrome VRP hard PoC gate

Run this step for any Chrome Browser / Chromium / `d8` / Chrome-component
submission.

The submission is blocked unless at least one supported proof exists:

- attached `poc.html`, `index.html`, or `poc.js` that reproduces in unmodified
  Chrome Stable/Beta/Dev or an eligible feature configuration;
- unmodified `d8`, `pdfium_test`, or another Chrome-supported binary repro with
  exact command line;
- symbolized ASAN/MTE output or `chrome://crashes` ID from a supported path for
  memory-safety bugs;
- MojoJS proof for compromised-renderer bugs when applicable;
- eligible renderer patch only when MojoJS is insufficient, with process guards
  and a clear explanation.

Block submission if:

- the only crash exists after adding/modifying `*_unittest.cc`,
  `*_browsertest.cc`, or test fixtures;
- the report asks triage to apply a test patch to reproduce;
- Chrome is run only through a custom harness, CDP controller, shell wrapper, or
  unsupported mode such as `--single-process`;
- the report does not include the primary PoC files as individual attachments.

If blocked, write `PROOF-GAP: needs supported Chrome/d8/supported-binary PoC`
in the bundle README and do not file.

---

## Output gates

You may submit when:

- [ ] All specific factual claims in the report have known provenance (Step 1)
- [ ] Stated severity equals bounded severity from the four-step derivation (Step 2)
- [ ] Anticipated triage counter-arguments are either addressed in the report or absorbed into a lower severity (Step 3)
- [ ] Program-specific rules in Step 4 have been checked against this specific report
- [ ] Chrome-only: the hard PoC gate in Step 5 passes, or the report is not a Chrome VRP submission

If any box is unchecked, do not submit. Either fix it or explicitly note in `bundle/README.md` why submitting anyway is the right call.

---

## See also

- `agent_skills/shared/evidence_rules.md` — source-provenance and evidence storage rules
- `agent_skills/packs/vrp_hunt_discipline/SKILL.md` — Chrome VRP-specific submission rules and conventions
- `agent_skills/packs/bug_bounty/SKILL.md` — generic bug bounty discipline and scope rules
- `agent_skills/packs/report_generator/SKILL.md` — report drafting conventions

---

## Why this exists (post-mortem context)

This checklist was added 2026-05-13 after a session in which:

1. A submission report contained a "Channel Matrix" table with specific Chrome version numbers and commit hashes that the author could not later remember verifying. The data happened to be accurate (verified live against chromiumdash.appspot.com during the audit) but the author had no internal record of the original verification. **If the data had been wrong, the report's credibility would have been destroyed.**

2. The same report's severity hypothesis was initially overstated as "High / Critical-adjacent" based on bug-class similarity to a precedent fix. Bounded-impact analysis later showed the realistic severity was Medium because (a) data exposure was public for typical CWS-distributed extension targets, (b) the bug class was read/append rather than the precedent's state-mutation. **Submitting at the overstated severity would have invited triage downgrade and credibility damage.**

The four-step audit above is designed to catch both failure modes before submission. It takes 10–15 minutes; the cost of skipping it is the loss of a submission's credibility and possibly the bounty.
