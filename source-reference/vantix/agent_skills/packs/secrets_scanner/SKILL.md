---
name: secrets_scanner
description: Passive scanner for leaked credentials across filesystems, git history, JS bundles, and GitHub orgs. Wraps trufflehog (verified-only), gitleaks, and noseyparker with a regex fallback. Prefers verified hits; refuses to pivot off found keys.
---
# Secrets Scanner

A leaked API key in a JS bundle is one of the highest-ROI bug bounty findings — verified cloud-provider, messaging, payment, or AI-service tokens routinely pay $1k–$10k+. The catch: programs reject unverified or known-public-only keys, so submitting noise destroys validity ratio.

This pack runs verified-only when possible, falls back gracefully, and refuses to pivot off found credentials beyond proving existence. It complements `packs/credential_tester/SKILL.md` (active credential testing) — this pack is the passive discovery side.

Composes with `shared/scope_guard.md` (the source artifact must be in-scope), `shared/evidence_rules.md` (no secrets in tracked files), and `packs/triage_validation/SKILL.md` (submission gates).

## When to Use

- A recon run produced a JS bundle directory and you want to scan it.
- The target has a public GitHub org and you want to scan repos + commit history.
- You have access to an artifact filesystem (a CI build output, a leaked backup) under proper scope.
- A finding draft references an "API key in source" — run this pack to verify the key before submitting.

## Operating Rules

- Run verified-only mode by default. Unverified hits become candidates, not findings.
- Never write a discovered key to a tracked file. Evidence storage goes under the artifact root with explicit redaction in summaries.
- Do not pivot off a found key beyond proving it works once with a minimal canonical curl. Most programs treat further enumeration on the cloud account as out-of-scope.
- A finding is "leaked credentials." Avoid combining the find with downstream cloud findings into one report — those are separate bugs, separate payouts.
- Re-verify the key still works at submission time. Keys rotate; a key that was live two days ago may now be revoked.

## Mode Selection

| Mode | Target | Scanner preference |
|---|---|---|
| Filesystem | A directory tree (extracted bundles, decompressed archive) | `trufflehog` → `gitleaks` → regex |
| Git history | A repo URL or local clone | `trufflehog --git` → `gitleaks` → `noseyparker` → regex |
| JS bundle | A recon directory containing crawled `.js` files | `trufflehog filesystem --only-verified` → regex |
| GitHub org | An org name (with `GITHUB_TOKEN` env) | `trufflehog github --org=<org> --only-verified` |

Tool registration lives in `agent_ops/config/tool_registry.yaml`. The pack does not invoke scanners directly; it instructs the executor under the run's existing tool-execution authorization.

## Scanner Strengths

| Scanner | Strength | Caveat |
|---|---|---|
| `trufflehog` | Verifies live keys against issuer APIs (AWS / Slack / Stripe / GH / GCP / many more) | `--only-verified` is mandatory for submissions |
| `noseyparker` | Fast on massive git histories with low false-positive rate | No live verification — verify hits separately |
| `gitleaks` | Opinionated default rule pack, solid for repos | Higher false-positive rate; verify each hit |
| Regex fallback | Always available; minimal coverage | Manual triage required; most hits will be false positives |

## Verification Workflow

Most bug bounty programs require you to demonstrate the key works without abusing it. The canonical reference is `streaak/keyhacks` — one curl per provider:

| Provider | Canonical proof |
|---|---|
| AWS access key | `aws sts get-caller-identity` (returns ARN — no resource access) |
| GCP service account | `gcloud auth activate-service-account` → `gcloud projects list` |
| Slack bot token | `curl -H "Authorization: Bearer $T" https://slack.com/api/auth.test` |
| Stripe | `curl -u "$T:" https://api.stripe.com/v1/charges?limit=1` |
| GitHub PAT | `curl -H "Authorization: token $T" https://api.github.com/user` |
| Twilio | `curl -u "$SID:$TOKEN" https://api.twilio.com/2010-04-01/Accounts.json` |
| OpenAI | `curl -H "Authorization: Bearer $T" https://api.openai.com/v1/models` |
| Mailgun | `curl -s --user "api:$T" https://api.mailgun.net/v3/domains` |
| SendGrid | `curl -H "Authorization: Bearer $T" https://api.sendgrid.com/v3/user/profile` |

Each verifies existence and permission without listing resources or sending mail. Stop there. Do not enumerate further.

## Where Secrets Hide

- **JS bundles** — concatenated/minified `.js` from CDNs, source maps if available, hidden in `__webpack_require__` factories.
- **Frontend env injections** — `window.__INITIAL_STATE__`, `process.env.NEXT_PUBLIC_*`, inline `<script>` blocks.
- **CI/CD configs** — `.github/workflows/*.yml`, `.gitlab-ci.yml`, `Dockerfile`, `docker-compose.yml`.
- **Mobile bundles** — `strings` output on APK / IPA, `resources.arsc`, decompiled `*.smali` / `*.swift`.
- **Public repos** — historical commits to `.env`, `config.json`, `secrets.yaml`. Check the full git history, not just HEAD.
- **Wayback / archives** — old asset URLs that included tokens in query strings; check `web.archive.org` and `gau` output.
- **Public S3 / GCS / Azure buckets** — config dumps, backups, `.env` files.
- **Browser extension manifests** — `default_key`, `oauth2.client_id`, hardcoded API endpoints.

## Submission Gates

Run `packs/triage_validation/SKILL.md` 7-Question gate, then:

- [ ] Verified mode produced a hit (or you have re-verified an unverified hit manually).
- [ ] The hosting asset (JS bundle URL, repo, bucket) is on the program's in-scope list.
- [ ] You demonstrated the key works with a canonical existence-proof curl.
- [ ] You did NOT enumerate cloud resources, list buckets, send messages, charge cards, etc.
- [ ] The report quantifies what permissions the key carries (IAM read, write, admin) based on the existence-proof response alone.
- [ ] The key is still live at submission time (re-verify within minutes of submitting).

## Evidence

Store under the run artifact root, named `secrets_<source>_<timestamp>/`:

- `01_source.txt` — the URL or path where the key was discovered, plus the surrounding code/text context (with the key redacted in this file).
- `02_scanner.jsonl` — raw scanner output. The key value lives here only, not in summaries.
- `03_existence_proof.txt` — the canonical curl request + response. Redact the key value; preserve everything else.
- `04_permission_summary.txt` — what the existence-proof response reveals about the key's scope (IAM ARN, account ID, plan tier, etc.).
- `README.md` — verified-vs-not table per `shared/evidence_rules.md`.

## Exclusions

- No cloud resource enumeration beyond the canonical existence-proof.
- No sending messages, emails, or invoices.
- No reading buckets, databases, or files beyond what the existence-proof response includes.
- No persistence: do not store the key in shell history, environment files, or password managers beyond the run artifact root.
- No social engineering or contact of the target's customers / users.

## See Also

- `agent_skills/packs/credential_tester/SKILL.md` — active credential testing (the complementary pack)
- `agent_skills/packs/triage_validation/SKILL.md` — pre-submission gates
- `agent_skills/shared/evidence_rules.md` — no-secrets-in-tracked-files discipline
- `agent_skills/shared/scope_guard.md` — scope verification of source artifacts
- External: `streaak/keyhacks` — per-provider canonical existence-proof curls
- External: `truffles3curity/trufflehog` — verified-only scanning details
