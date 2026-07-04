---
name: asset_graph_builder
description: Walks the complete asset chain from program scope through root domains, subdomains, IPs, ASN/cloud ownership, URLs, APIs, JS files, mobile apps, repos, and historical surfaces. Every asset is scored for confidence and validated against scope. Outputs scope.md, assets.json, and per-asset evidence links.
---
# Asset Graph Builder

The difference between a tight hunt and scope creep is a single curated asset list. This pack walks the entire chain: program scope → root domains → subdomains → IPs → ASN → URLs → APIs → JS files → mobile apps → repos → historical URLs → login surfaces. Each asset is validated against explicit inclusions/exclusions and scored for confidence. The output is a single source of truth: `assets.json` with evidence links, a per-asset scope determination, and a confidence score that guides prioritization.

This pack composes with `shared/scope_guard.md`, `packs/recon_advisor/SKILL.md`, `packs/js_bundle_analyzer/SKILL.md`, and leverages `mcp_vantix_recon_intel` when available.

## When to Use

- Starting a new hunt: build the asset map before any active testing.
- Pivoting from a finding: ensure the new asset is in the same program or a legitimate sibling.
- Scope clarification: did the program explicitly exclude this class? Is this only CDN/shared infra?
- Re-scoping mid-hunt: new subdomains or APIs discovered during crawl need rapid in/out assessment.

## Operating Rules

- **Canonical scope**: read `shared/scope_guard.md` first. If a scope conflicts with the program's written policy, the written policy wins.
- **Confidence scoring**: every asset gets 0–100. High-confidence (80+) assets are directly in scope. Medium (50–79) are related but need clarification. Low (<50) are probably third-party or shared infra.
- **Evidence links**: link every asset to the source that discovered it. "subdomain.com was found in crt.sh on 2026-05-14" is better than "subdomain.com is in scope."
- **No active testing yet**: this is pure enumeration and classification. No port scans, no HTTP requests beyond crawling, no exploitation.

## Phase 0: Scope Anchoring

Read the program's scope document from `shared/scope_guard.md` and the platform's published scope page.

**Questions to answer:**

1. What are the explicit root domains? (e.g., example.com, api.example.com, CDN excludes?)
2. What is explicitly out of scope? (e.g., third-party services, shared hosting, legacy domains)
3. Are wildcard subdomains included? (*.example.com or only certain prefixes?)
4. Are IP ranges or ASNs specified?
5. Are mobile apps in scope? Web-only?
6. Are internal/staging domains mentioned?

**Output:**

```
scope.md
--------
## Explicit Inclusions
- example.com (apex domain)
- *.example.com (wildcard)
- api.example-alt.org

## Explicit Exclusions
- cdn.example.com (third-party CDN)
- mail.example.com (managed by a third-party email provider)
- staging-old.example.com (decommissioned)

## Ambiguous / Needs Clarification
- example-v2.com (related brand?)
```

## Phase 1: Root Domain Enumeration

List every root domain mentioned in scope.

**Data sources:**
- Program scope document
- Domain registration records (if public)
- Parent company domain registry

**Output:**

```json
{
  "root_domains": [
    {
      "domain": "example.com",
      "scope": "explicit_inclusion",
      "source": "program_scope",
      "discovered_at": "2026-05-14"
    }
  ]
}
```

## Phase 2: Subdomain Enumeration

For each root domain, enumerate subdomains via passive + active methods.

**Passive (no DNS queries, no IP contact):**
- certificate transparency log search
- DNS history archives (requires API key)
- internet-wide scan datasets (requires API key)

**Active (DNS queries only, no HTTP):**
- `subfinder` (passive sources aggregated)
- `amass passive` (passive sources)
- `httpx -l domains.txt -silent` (only to check HTTP/S, not ports)

**Per-subdomain assessment:**

```json
{
  "subdomain": "api.example.com",
  "root_domain": "example.com",
  "discovered_via": ["crt.sh", "chaos"],
  "ip_addresses": ["192.0.2.1"],
  "asn": "AS12345",
  "cloud_provider": "AWS",
  "scope": "explicit_inclusion",
  "confidence": 95,
  "evidence_link": "https://crt.sh/?q=example.com"
}
```

**Confidence factors:**
- Explicit match to scope: +40 points
- Same root domain as explicit inclusion: +25 points
- Matches program's naming convention (api-, dev-, staging-): +10 points
- On shared infrastructure (AWS, Google Cloud): -15 points (needs confirmation)
- Matches exclusion patterns: -100 (mark as out-of-scope immediately)

## Phase 3: IP Resolution + ASN Classification

For each subdomain, resolve to IP and classify by ASN and cloud provider.

**Tools:**
- `dig`, `nslookup`, or `httpx -l domains.txt -http-code`
- `whois -h asn.cymru.com <IP>` for ASN lookup
- CloudFlare IP range matching (if applicable)

**Output:**

```json
{
  "subdomain": "api.example.com",
  "ipv4": ["192.0.2.1"],
  "ipv6": ["2001:db8::1"],
  "asn": "AS12345",
  "asn_owner": "Example ISP",
  "cloud_provider": "AWS",
  "cloud_region": "us-east-1",
  "cdn_provider": null,
  "scope_classification": "owned_by_program",
  "confidence": 90
}
```

**Key question:** Is this IP owned/operated by the program or a third-party vendor? Program-owned raises confidence. Shared CDN (CloudFlare, Akamai, AWS CloudFront) lowers it unless explicitly included.

## Phase 4: URL Crawl + JS Extraction

For each subdomain, crawl the site and extract all JavaScript files, CSS, and HTML asset references.

**Crawl scope:** same-origin BFS, max 100 pages per domain, 15s timeout.

**JS extraction:** pull every `.js` reference from HTML, extract inline scripts, identify bundled files.

**API endpoint discovery:** grep for `/api/*`, `/v1/*`, `/v2/*` patterns in JS and HTML.

**Output:**

```json
{
  "subdomain": "api.example.com",
  "crawled_urls": 15,
  "discovered_endpoints": [
    {
      "path": "/api/v1/users",
      "methods": ["GET", "POST"],
      "auth_required": true,
      "source": "crawl+js_analysis"
    }
  ],
  "javascript_files": [
    {
      "url": "https://api.example.com/static/bundle.abc123.js",
      "size_kb": 250,
      "external_apis_referenced": ["https://analytics.example.com", "https://cdn.cloudflare.com"]
    }
  ]
}
```

## Phase 5: API Endpoint Extraction

Parse JavaScript, HTML, and crawled responses to extract all API endpoints, including GraphQL, REST, and WebSocket.

**Sources:**
- Hardcoded URLs in JS
- `fetch()` and `axios()` calls
- GraphQL introspection (`GET /graphql?query=__schema`)
- OpenAPI/Swagger specs
- API documentation links

**Output:**

```json
{
  "apis": [
    {
      "base_url": "https://api.example.com/v1",
      "type": "rest",
      "endpoints": ["/users", "/orders", "/payments"],
      "auth_method": "Bearer token",
      "discovered_via": "js_analysis"
    },
    {
      "base_url": "https://api.example.com/graphql",
      "type": "graphql",
      "introspectable": true,
      "discovered_via": "introspection_query"
    }
  ]
}
```

## Phase 6: Mobile App Discovery

Search for official mobile apps (iOS, Android) and validate they connect to in-scope APIs.

**Data sources:**
- App Store (Apple) for iOS apps by developer
- Google Play for Android apps by developer
- APKPure, APK Mirror (alternative mirrors, public)
- GitHub release artifacts
- Fastlane snapshot metadata

**Per-app validation:**

```json
{
  "platform": "iOS",
  "app_name": "Example App",
  "bundle_id": "com.example.app",
  "app_store_url": "https://apps.apple.com/app/example/id123456789",
  "api_base_urls": ["https://api.example.com"],
  "scope": "explicit_inclusion",
  "confidence": 85
}
```

**Confidence:** official app by program developer = high (85+). Third-party wrapper or UnofficialApp = low (30).

## Phase 7: Public Repo Discovery

Search GitHub, GitLab, and Bitbucket for repositories owned by the program's organization or containing the program's domain in commits/README.

**Approach:**
- `org:<organization-name>` on GitHub
- Grep all repos for hardcoded API URLs, domain names, secrets
- Check commit history for recent activity

**Output:**

```json
{
  "platform": "github",
  "organization": "example",
  "repos": [
    {
      "name": "example-api",
      "url": "https://github.com/example/example-api",
      "default_branch": "main",
      "last_updated": "2026-05-10",
      "contains_api_endpoints": true,
      "contains_secrets": false,
      "public": true,
      "scope": "explicit_inclusion",
      "confidence": 95
    }
  ]
}
```

## Phase 8: Historical URLs

Search Wayback Machine, Commoncrawl, and SecurityTrails for historical captures of the program's domains. Identifies retired endpoints and legacy API versions.

**Tools:**
- `wayback-machine-cli` or manual `https://web.archive.org/web/*/example.com/*`
- Commoncrawl index API
- SecurityTrails historical DNS

**Output:**

```json
{
  "domain": "api.example.com",
  "historical_captures": [
    {
      "url": "https://api.example.com/v0/users",
      "last_seen": "2024-06-15",
      "wayback_url": "https://web.archive.org/web/20240615000000*/api.example.com/v0/users",
      "status_code": 200,
      "likely_active": false
    }
  ]
}
```

## Phase 9: Login Surface Enumeration

Identify all authentication entry points: login pages, registration, password reset, 2FA, OAuth providers.

**Discovery:**
- Crawl root domain for login links (`/login`, `/signin`, `/auth`, `/register`)
- Check for OAuth integrations (Google, GitHub, SAML)
- Look for SSO / LDAP indicators

**Output:**

```json
{
  "domain": "example.com",
  "auth_surfaces": [
    {
      "type": "form_login",
      "url": "https://example.com/login",
      "methods": ["POST /login"],
      "fields": ["username", "password"],
      "scope": "explicit_inclusion"
    },
    {
      "type": "oauth",
      "provider": "google",
      "client_id": "xxx.apps.googleusercontent.com",
      "scope": "third_party"
    }
  ]
}
```

## Phase 10: Asset Scoring + Emit assets.json

Score every asset on three dimensions:

1. **Scope confidence (0–100)**: How certain are we this is in scope?
2. **Risk (Critical/High/Medium/Low)**: How valuable to test first?
3. **Related asset chain**: What is this asset linked to?

**Scope confidence factors:**
- Explicit inclusion: +50
- Same root domain: +20
- Matches program naming pattern: +15
- On program-owned infrastructure: +10
- On shared CDN: -20
- Explicit exclusion match: -100

**Risk factors:**
- Contains authentication surface: Critical
- Exposes API endpoints: High
- Serves JS/CSS with hardcoded URLs: Medium
- Historical only (no current evidence of live status): Low

**Final assets.json:**

```json
{
  "program": "example_program",
  "generated_at": "2026-05-14T12:00:00Z",
  "assets": [
    {
      "id": "asset_001",
      "type": "domain",
      "value": "api.example.com",
      "scope_confidence": 95,
      "scope_status": "explicit_inclusion",
      "risk_tier": "high",
      "discovered_via": ["crt.sh", "crawl"],
      "evidence_links": [
        "https://crt.sh/?q=example.com"
      ],
      "related_assets": ["asset_002"],
      "testing_priority": 1
    }
  ],
  "summary": {
    "total_assets": 45,
    "high_confidence": 32,
    "medium_confidence": 10,
    "low_confidence": 3,
    "critical_risk_count": 5,
    "hunting_ready": true
  }
}
```

## Tooling

- **Passive subdomain enum**: `subfinder`, `amass passive`
- **Certificate transparency**: `crt.sh` (web), `certspotter`
- **DNS history**: SecurityTrails (requires API key), `dnsdumpster`
- **IP lookup**: `whois`, `asn-cymru.com`
- **Crawling**: `httpx` with `-crawl` mode, `katana`
- **JS extraction**: `js-bundle-analyzer` (from packs)
- **Repo search**: `gh search repos`, manual GitHub search
- **Wayback**: `wayback-machine-cli`, manual web.archive.org
- **Scope validation**: `shared/scope_guard.md` context, program's explicit scope doc

## See Also

- `agent_skills/shared/scope_guard.md` — canonical scope context
- `agent_skills/packs/recon_advisor/SKILL.md` — broader recon workflow
- `agent_skills/packs/js_bundle_analyzer/SKILL.md` — detailed JS extraction
- `agent_skills/packs/web_hunter/SKILL.md` — how to hunt discovered endpoints
- External tools: `subfinder`, `amass`, `httpx`, `detection-engine`, `wafw00f`

## Exclusions

- No active port scanning (nmap, masscan).
- No exploitation or payload delivery.
- No crawling third-party services unless explicitly in scope.
- No aggressive DNS enumeration (zone transfers) without explicit permission.
- Do not test historical URLs directly without confirming they are still live.
