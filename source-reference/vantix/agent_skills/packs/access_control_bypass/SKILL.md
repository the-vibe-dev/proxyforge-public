---
name: access_control_bypass
description: 403/401 bypass matrix covering header injection, path encoding, suffix tricks, and method tampering. Targets misconfigured reverse-proxy plus origin stacks where the ACL is enforced inconsistently.
---
# Access Control Bypass

A 403 or 401 on `/admin`, `/api/internal/*`, `/debug`, or a similar privileged route is one of the highest-density payout opportunities in modern bug bounty: when an edge proxy enforces the ACL but the origin trusts header-injected rewrites, the bypass typically lands in a privileged endpoint that chains into IDOR, RCE, or data exposure.

This pack composes with `shared/scope_guard.md` (every probe is in-scope), `packs/web_hunter/SKILL.md` (general route discovery), and `packs/triage_validation/SKILL.md` (the bypass alone is rarely the finding — the chain is).

## When to Use

- Recon found routes returning 403 / 401 / 404-but-suspicious responses to anonymous requests.
- A privileged route is enforced at the edge (Cloudflare, Akamai, nginx, ALB) but the origin behind it is a different stack.
- A 403 response has unusual characteristics: short body, custom error JSON, missing `Content-Length`, or a header set the origin would set but the edge wouldn't.
- A disclosed report on the program (or a sibling program) showed a header-rewrite bypass — sibling-test similar paths.

## Operating Rules

- Confirm scope before any probe. Bypass requests can trigger WAF / IDS alerts; many programs treat aggressive bypass attempts as out-of-scope or grounds for ban.
- A bypass alone is rarely the finding. The finding is what's behind the door. Bypass to a route that does nothing useful = informational at best.
- Do not chain bypass into modifying data or escalating privileges without a separate authorization for that action. Demonstrate access; stop.
- Treat each new "successful" status code skeptically — many endpoints return 200 with a generic error body. Verify the response is real content, not a soft-deny.

## Technique Matrix

The matrix is structured by where the divergence between proxy and origin lives. Try classes in roughly this order; each successive class is more invasive than the last.

### Class 1: Header injection (the highest-paying class)

The proxy enforces ACL on the public URL, but the origin trusts header-injected rewrites or client-IP overrides.

| Header | Value | Why it works |
|---|---|---|
| `X-Original-URL` | `/admin` | Spring Boot, IBM WebSphere — origin uses this to rewrite |
| `X-Rewrite-URL` | `/admin` | Older Spring Security misconfig |
| `X-Override-URL` | `/admin` | Custom middleware patterns |
| `X-Forwarded-For` | `127.0.0.1`, `localhost` | Edge proxy ACL checks client IP, origin trusts XFF |
| `X-Real-IP` | `127.0.0.1` | Same as XFF on different stacks |
| `X-Client-IP` | `127.0.0.1` | Same |
| `X-Custom-IP-Authorization` | `127.0.0.1` | Same |
| `X-Originating-IP` | `127.0.0.1` | Same |
| `X-Forwarded-Host` | `localhost` | Same |
| `Referer` | `https://target.com/admin` | Some ACLs whitelist referrer |
| `Authorization` | `Bearer null`, `Basic Og==` | Some stacks treat any auth header as "authenticated" |

### Class 2: Path encoding

The proxy normalizes the path differently than the origin, allowing the ACL to be bypassed at the proxy and re-resolved at the origin.

| Path | Why |
|---|---|
| `/admin/` | Trailing slash mismatch |
| `/admin/.` | Same-segment loop, normalized away by origin |
| `/admin/%2e` | Encoded dot, treated as a segment by the proxy |
| `/admin/%20` | Trailing space |
| `/admin/%09` | Trailing tab |
| `/admin/..;/` | Java/Tomcat path parameter trick |
| `/admin;param=value` | Path parameter (Tomcat) |
| `/admin#` | Fragment, dropped by proxy but kept in path |
| `/admin?` | Empty query string |
| `/admin//` | Double slash, normalized by some proxies |
| `/.admin` | Leading dot |
| `/admin.html` | Suffix that origin maps back to `/admin` |
| `/admin.json` | API-style suffix |
| `/%2fadmin` | Encoded slash |
| `/%252fadmin` | Double-encoded slash |
| `/AdMiN` | Case-sensitivity difference |

### Class 3: Method tampering

The ACL is keyed on HTTP method. The origin accepts the same route under a different method.

| Original | Try | Why |
|---|---|---|
| GET | POST, PUT, PATCH, DELETE, OPTIONS, HEAD, TRACE | Origin may handle write methods |
| POST | GET, PUT | API endpoints sometimes expose both |
| Any | `CONNECT`, `PROPFIND`, `MKCOL` (WebDAV verbs) | Rarely filtered by edge ACLs |

`TRACE` deserves special attention: if the origin echoes the request, it can be used to read headers normally hidden from the client.

### Class 4: Hostname / port swap

The ACL is keyed on hostname. The origin serves the same content on a different vhost.

- Try `<base>.cf` / `<base>.tk` if the target uses a CDN that defaults to allowing arbitrary vhosts.
- Try the origin IP directly with `Host: target.com`.
- Try `Host: target.com:443` (port in Host header — some stacks parse this differently).

This usually requires origin-IP discovery first (see `packs/recon_advisor/SKILL.md`).

### Class 5: Auth token tricks

- Replay a logged-in session against the ACL-blocked route. A 403-to-logged-in often unmasks as a permissions check, not the protection you assumed.
- Strip the cookie and replay — some routes that 403 to anonymous return 200 to logged-out (counterintuitive, but common when the ACL is "must be logged out").
- Replace the auth header with a malformed but parseable token (`Bearer X.Y.Z` where each segment is a forged base64 chunk).

## Discovery Workflow

1. **Enumerate 403 / 401 routes** — from existing recon (`httpx -mc 401,403,404 -fr`).
2. **Triage the response** — short body, custom JSON, redirect to login = candidate. Generic edge-provider blocked page = skip.
3. **Run the matrix** — `byp4xx` if installed, otherwise the curl battery above. The matrix is roughly 50–80 requests per URL; do not blast in parallel.
4. **Confirm a hit** — a "different" response is not automatic success. Verify the body is real privileged content, not a soft-deny.
5. **Probe behind the door** — once inside, immediately handoff to `packs/web_hunter/SKILL.md` for the chain.

## When It Pays

- 403 on `/admin`, `/api/internal/*`, `/debug` → admin-panel exposure.
- 401 on a GET endpoint behind misconfigured nginx → `X-Original-URL` bypass is common for nginx + Spring Boot stacks.
- 403 on an API endpoint that the SPA reaches without issue → ACL is misconfigured on the API gateway.
- A bypass that lands in a privileged endpoint typically chains into IDOR, mass assignment, or RCE behind the door.

Standalone "I bypassed the ACL but the route 404s on me anyway" is informational. The finding is what's reachable behind the bypass.

## Submission Gates

Run `packs/triage_validation/SKILL.md` 7-Question gate, then:

- [ ] The bypass actually returns privileged content (not a redirect, not a soft-deny, not a 200 with a generic error body).
- [ ] You demonstrated *what* the privileged content allows the attacker to do (read PII, modify settings, etc.).
- [ ] The bypass request is reproducible from scratch (the full curl is in Steps to Reproduce).
- [ ] If the chain pivots into IDOR / data read, the chain evidence is in the bundle.
- [ ] The "Remediation" section names the specific header / path normalization rule that should be enforced consistently at the proxy and origin.

## Evidence

Store under the run artifact root, named `bypass_<route>_<timestamp>/`:

- `01_baseline.txt` — original 403/401 request + response.
- `02_bypass_request.txt` — the working bypass request (full curl) + response.
- `03_privileged_content.txt` or `03_screenshot.png` — proof the response is real privileged content.
- `04_chain_proof/` (optional) — what was reachable behind the bypass.
- `README.md` — verified-vs-not table per `shared/evidence_rules.md`.

## Exclusions

- No modifying data, escalating privileges, or persisting access via the bypass.
- No high-rate scanning that triggers WAF lockouts on the target's edge.
- No bypass attempts on out-of-scope assets — confirm scope first.
- No social engineering, no DoS, no real-user impact.

## See Also

- `agent_skills/packs/web_hunter/SKILL.md` — general route discovery and exploitation behind the bypass
- `agent_skills/packs/triage_validation/SKILL.md` — submission gates and chain requirements
- `agent_skills/packs/recon_advisor/SKILL.md` — origin-IP discovery for hostname-swap bypass
- `agent_skills/packs/exploit_chainer/SKILL.md` — chaining bypass into IDOR / data exposure
- `agent_skills/shared/evidence_rules.md` — evidence discipline
