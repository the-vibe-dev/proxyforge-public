---
name: cache_smuggling
description: HTTP request smuggling (CL.TE / TE.CL / H2.CL / H2.TE), web cache poisoning via unkeyed inputs, web cache deception, fat-GET attacks, cache key gadget hunting. High-payout class — few hunters relative to surface.
---
# HTTP Smuggling and Cache Poisoning

Two distinct but adjacent attack families. HTTP request smuggling exploits parser-divergence between a front-end proxy and the origin server to inject requests into another user's connection. Web cache poisoning makes a cache store an attacker-influenced response that other users then fetch. Both have produced sustained High–Critical findings on the largest programs (Akamai, Cloudflare-fronted apps, AWS CloudFront, Fastly).

Programs handle this class carefully — proof must be contained, no real-user impact, no shared-cache pollution beyond the minimum to demonstrate. The probe phase is read-only; exploitation requires program-specific consent on most platforms.

Composes with `shared/scope_guard.md` (front-end + origin are often separate scopes), `packs/web_hunter/SKILL.md`, `packs/access_control_bypass/SKILL.md` (smuggling-front-end-auth-bypass is a chain), `packs/triage_validation/SKILL.md` (programs vary widely on class scope — check before exploiting).

## When to Use

- Target sits behind a CDN (Cloudflare, Akamai, Fastly, CloudFront) or a reverse proxy (Nginx, HAProxy, Apache, Varnish).
- Target speaks HTTP/2 at the edge but the origin chain may downgrade to HTTP/1.1.
- Response timing differences appear with different `Transfer-Encoding` / `Content-Length` configurations.
- A cache layer is present (long TTLs, `Cache-Control: public`, `Age:` headers in responses).
- An authenticated path renders user data and a static asset with similar prefix exists (`/account` + `/account.css`).

## Operating Rules

- Probes are read-only and use timing/error-response signals — no actual smuggled exploitation until the bug is confirmed and the program scope permits.
- Cache poisoning must be ultra-contained: poison your own cache key (use a unique header value or a unique path component that no real user will hit), demonstrate the poison, prove the impact, immediately request the program to flush.
- Never poison a cache key reachable by real users.
- Web cache deception: never use a victim's session in the PoC. Use two project-owned accounts: attacker session generates the deception URL, victim project-owned session visits it — confirm response carries attacker data.

## Phase 0: Front-End and Cache Fingerprint

```bash
# Identify CDN / edge
curl -sI https://target.com/ | grep -iE 'server|via|x-cache|cf-ray|x-amz-cf-id|x-served-by|x-fastly|akamai'

# HTTP version at edge
nghttp -v -n https://target.com/ 2>&1 | head -3

# Cache hints
curl -sI https://target.com/path | grep -iE 'cache-control|age|x-cache|x-cache-hits|vary'
```

Common indicators:

| Indicator | Implication |
|---|---|
| `Server: cloudflare` + `cf-cache-status` | Cloudflare front; check cache key gadgets |
| `Via: 1.1 varnish` | Varnish cache; classic poisoning target |
| `X-Cache: HIT` / `MISS` | Cache layer present and exposing state |
| `Age: <n>` | Cached response, TTL inferable |
| `x-amz-cf-id` | CloudFront |
| `x-served-by` + Fastly hostnames | Fastly |
| `Vary: <headers>` | Cache keyed on these headers (good news — controlled) |
| No `Vary` but response varies with headers | Cache key gadget candidate |

## Phase 1: HTTP Request Smuggling

### Concept

Front-end proxy receives the request and forwards to the origin. If the two disagree on where one request ends and the next begins, the attacker can prepend a smuggled request to the *next* user's connection.

### Variants

| Variant | Front-end uses | Origin uses |
|---|---|---|
| CL.TE | Content-Length | Transfer-Encoding |
| TE.CL | Transfer-Encoding | Content-Length |
| TE.TE | Both parse TE; one obfuscated form bypasses one of them |
| H2.CL | HTTP/2 :header form translated to HTTP/1.1 — origin uses CL |
| H2.TE | HTTP/2 :header form translated to HTTP/1.1 — origin uses TE |

### Timing-based probe (read-only)

The probe sends a malformed request and times the response. If the front-end forwards and the origin hangs (expecting more body), the request takes a long time → smuggling-vulnerable.

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

If CL.TE: front-end uses CL=13, forwards the whole body. Origin uses TE: sees `0\r\n\r\n` (end of chunked), the trailing `SMUGGLED` is the start of the next request. The next legitimate user's request gets `SMUGGLED` prepended. Probe times out on the front-end side because the origin is waiting for the rest.

### H2.CL / H2.TE — HTTP/2 downgrade attacks

When the edge speaks HTTP/2 but translates to HTTP/1.1 for the origin, the translation can leave header CRLFs unsanitized. Attacker sends a header value containing `\r\n` that becomes a real header at the origin.

```
:method = POST
:path = /
:authority = target.com
content-length = 0
poison-header = foo\r\nTransfer-Encoding: chunked\r\nSmuggle-Sentinel: 1
```

If the translator passes the raw value, the origin sees:

```
POST / HTTP/1.1
Host: target.com
Content-Length: 0
poison-header: foo
Transfer-Encoding: chunked
Smuggle-Sentinel: 1
...
```

Now TE vs CL desync applies.

### Tooling

- `smuggler` (community Python): canonical probe tool. `python3 smuggler.py -u https://target.com/` produces a per-variant report.
- `nghttp2-client` for crafting H2.CL / H2.TE manually.
- intercepting-proxy HTTP request smuggler extension if available.

### Impact escalation

Standalone smuggling is occasionally informational. The chain is the value:

- **Front-end auth bypass**: smuggle a request that, when prepended to the next user's connection, hijacks their auth context.
- **Cache poisoning via smuggle**: smuggle a request that returns a malicious response cached against another user's URL.
- **Stored XSS via smuggle**: smuggle a request that updates a state shared with other users; their next render includes attacker content.

## Phase 2: Web Cache Poisoning (Unkeyed Inputs)

### Concept

A cache stores responses keyed on `(method, host, path, [Vary headers])`. If a request header NOT in the cache key influences the response, an attacker injects that header, and the modified response is cached for everyone hitting that path.

### Probe matrix

For each candidate path, send variations of headers commonly mishandled:

```bash
for header in \
  "X-Forwarded-Host: attacker.com" \
  "X-Forwarded-Proto: http" \
  "X-Forwarded-Scheme: http" \
  "X-Original-URL: /admin" \
  "X-Rewrite-URL: /admin" \
  "X-HTTP-Method-Override: POST" \
  "X-Forwarded-For: 127.0.0.1" \
  "Forwarded: host=attacker.com" \
  "X-Host: attacker.com" \
  "X-Forwarded-Server: attacker.com" \
  "X-Host-Override: attacker.com" \
  ; do
  curl -s "https://target.com/" -H "$header" > "/tmp/poison_${header%%:*}.html"
done

# Compare to baseline; diff for any header-influenced changes
diff <(curl -s https://target.com/) /tmp/poison_X-Forwarded-Host.html | head -30
```

### Param-miner approach (canonical)

A param-miner-style probe systematically brute-forces header names and parameter names that influence responses. Without one, the manual matrix above covers the most common 20 headers; an open-source web-cache-vulnerability-scanner covers more programmatically.

### Cache key gadget hunting

Once a header is found to influence the response, the question is: is it in the cache key?

- Check the `Vary` response header — if the unkeyed-input header is listed, the cache is safe.
- If not in `Vary`, fire the request without the header → fetch from cache → does the cached response still reflect the influence? If yes, the cache was poisoned.

### Fat-GET attack

Some caches key on the URL but not on the body — and some servers accept POST-style bodies in GET requests. Attacker sends a GET with a body containing a parameter that influences the response (e.g., user-specific data). The cache stores the response under the URL key, ignoring the body — next user sees the attacker's data.

```bash
curl -X GET "https://target.com/api/me" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data "userId=victim"
```

If the response varies based on the body and the cache ignores it: fat-GET cache poisoning.

### Parameter cloaking

`;` and `#` parsing differs between cache and origin. `target.com/?param1=cache_key;param2=attacker_value` may be keyed as `target.com/?param1=cache_key` by the cache but parsed as both by the origin → response varies but cache doesn't see it.

## Phase 3: Web Cache Deception

### Concept

Authenticated `/account` renders user data. Cache treats `/account.css` (or `.js`, `.png`, `.jpg`) as static and caches it aggressively. Attacker forces victim to visit `/account.css?nocache=ATTACKER` — server renders the authenticated page; cache stores it under `/account.css?nocache=ATTACKER`. Attacker fetches the same URL, gets the cached authenticated response — including the victim's user data.

### Probe

```bash
# Baseline: authenticated /account
curl -s -H "Cookie: session=<own-session>" https://target.com/account > own_account.html

# Cache deception attempt
curl -s -H "Cookie: session=<own-session>" https://target.com/account.css > own_account_css.html

# If they're the same content, deception works
diff own_account.html own_account_css.html | head -5
```

If the response for `/account.css` returns the rendered account page (HTML, not CSS), deception is possible. Then:

```bash
# Get a unique URL
DECEPTION_URL="https://target.com/account.css?dec=$(uuidgen)"

# Trick: project-owned-victim visits it (under their session, in their browser)
# Then attacker fetches without session
curl -s "$DECEPTION_URL" > attacker_view.html

# Verify the response contains project-owned-victim's data
grep -E '(victim-email|victim-internal-id|victim-balance)' attacker_view.html
```

### Common deception paths

- `/account.css`, `/account.js`, `/account.png` — generic static extensions.
- `/account/avatar.jpg` — vendor-specific.
- `/account?foo=.css` — query-string extension trick (some caches key on the extension at end of URL).
- `/account/../static/x.css` — path traversal into static.

## Phase 4: HTTP/2 Downgrade Smuggling (Modern)

The current hot variant. Most CDNs translate HTTP/2 to HTTP/1.1 for upstream. Translation gaps:

- **Header value with `\r\n`** → splits into multiple HTTP/1.1 headers.
- **Pseudo-header (`:path`) with characters** that HTTP/1.1 forbids → behavior varies.
- **Connection: keep-alive** sent from H2 client (HTTP/2 forbids it) → some translators forward it, some don't.

These attacks require a real HTTP/2 client with frame-level control. `nghttp2-client` and `h2csmuggler` are the standard tools.

## Submission Gates

Run `packs/triage_validation/SKILL.md` 7-Question gate. Then for this class specifically:

- [ ] The probe phase showed reliable timing or response-divergence evidence.
- [ ] The exploit produced a concrete cross-user impact: cache served attacker content to a project-owned-victim session, smuggle reached another user's response, or deception leaked authenticated data.
- [ ] Cache impact was contained to a unique key the operator controls; no real-user cache pollution.
- [ ] If smuggling, the chain reaches a privileged action behind the front-end (auth bypass, cross-user data, stored XSS) — standalone "I can desync the parsers" is often informational.
- [ ] Cleanup: cache flushed (operator-requested), all unique deception URLs documented.

## Evidence

Store under the run artifact root, named `cachesmuggle_<target>_<timestamp>/`:

- `01_fingerprint.txt` — edge, cache layer, HTTP version negotiation.
- `02_probe_smuggler.txt` — `smuggler` output showing detected variant.
- `03_baseline.har` — clean request/response.
- `04_smuggle_attempt.har` or `04_poison_attempt.har` — the malicious request.
- `05_victim_view.har` — project-owned-victim's view post-attack showing the impact.
- `06_cache_state.txt` — `X-Cache: HIT` and `Age:` showing the poisoned response was cached.
- `07_cleanup.md` — flush requests, unique keys documented.
- `README.md` — verified-vs-not table per `shared/evidence_rules.md`.

## Exclusions

- No production cache pollution. Use unique cache keys (random path components, unique header values) so no real user can hit the poisoned response.
- No smuggling attacks that affect real users' requests. Use project-owned sessions only; document timing carefully so the test window is bounded.
- No DoS-grade smuggling (response splitting that crashes the front-end). Probe-and-stop.
- No exploitation when the program scope excludes this class (some explicitly do — read the policy).
- Notify the program when a poisoned cache key may need flushing; do not leave attacker-controlled responses cached indefinitely.

## See Also

- `agent_skills/packs/web_hunter/SKILL.md` — discovery of cacheable paths and cache layers
- `agent_skills/packs/access_control_bypass/SKILL.md` — smuggle-to-front-end-auth-bypass chain
- `agent_skills/packs/triage_validation/SKILL.md` — program-specific scope check (DoS-adjacent)
- `agent_skills/packs/exploit_chainer/SKILL.md` — smuggling and cache pivots in the A→B database
- External tools: `defparam/smuggler`, `Hahwul/web-cache-vulnerability-scanner`
