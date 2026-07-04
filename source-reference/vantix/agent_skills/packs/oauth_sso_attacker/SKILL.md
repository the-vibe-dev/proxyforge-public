---
name: oauth_sso_attacker
description: OAuth 2.0, OIDC, and SAML attack methodology. Redirect_uri attacks, PKCE downgrade, kid/jku/x5u confusion, XSW, comment injection, NameID mutation, federation pivots. Single highest auth-bug density on most programs.
---
# OAuth / SSO / SAML Attacker

Federated authentication is where the highest-density auth bugs live. A single misconfigured `redirect_uri` validator, a single missing `kid` check, a single XSW variant — any one of these typically chains directly into ATO across an entire platform. Per-bug payouts run High–Critical because the impact is "every user of every connected app."

This pack composes with `shared/scope_guard.md` (federation surfaces often cross asset boundaries — verify scope explicitly), `shared/evidence_rules.md` (Q8 identity check matters more here than anywhere — must show attacker-controlled session reading victim-controlled identity), `packs/triage_validation/SKILL.md` (some classes like "OAuth `client_secret` in mobile app" are on the never-submit list), and `packs/exploit_chainer/SKILL.md` (SSO bypass → application admin is a Critical chain).

## When to Use

- Target has any OAuth 2.0 / OIDC implementation (federated login with common identity providers, "Connect with...", any third-party app integration).
- Target federates auth via SAML (SSO sign-in button leading to an IdP).
- Target exposes `.well-known/openid-configuration` or any IdP metadata URL.
- A JWT appears in cookies, headers, or response bodies and you want to attack signature verification.
- After any `subdomain takeover` finding — check if the claimed subdomain is registered as an OAuth `redirect_uri`.

## Operating Rules

- Federation crosses asset boundaries. Confirm scope for *both* the relying party (target app) and the identity provider before testing the IdP side. Many programs scope the RP but not the IdP.
- Never test with a real user's account — only attacker-owned accounts on both sides of the federation. Use a project-owned IdP account if testing IdP-side bugs.
- Stop at proof of compromise. Do not pivot from a stolen token into the victim's data beyond reading enough to demonstrate the impact (own email shown is enough).
- Token replay across environments (prod vs staging) is the most common scope violation in this class. Stay on the asset that's in scope.

## OAuth 2.0 / OIDC Attack Surface

### A. `redirect_uri` validation

The single highest-paying class in OAuth. The authorize endpoint's `redirect_uri` validator MUST be strict-match. Common gaps:

| Gap | Probe | Result |
|---|---|---|
| Prefix match | Register `https://target.com/callback`; try `https://target.com/callback.attacker.com` | ATO if accepted |
| Subpath match | Try `https://target.com/callback/../../attacker.com` | ATO if normalized at edge but not at auth |
| Query allowed | Try `https://target.com/callback?next=//attacker.com` + chain with open redirect | ATO |
| Fragment allowed | Try `https://target.com/callback#@attacker.com` | Browser fragment-tail goes to attacker |
| Localhost loose | Try `http://localhost:31337` then `http://localhost.attacker.com` | ATO on apps that allow loopback |
| IP literals | Try `http://127.0.0.1@attacker.com` | URL-parsing differential |
| Wildcard registration | Test if `*.target.com` was registered → claim a subdomain | ATO via takeover chain |
| Loose port match | Register `:443`; try `:443@attacker.com:80` | Some validators ignore port |
| Encoded slash | `https://target.com%252fcallback@attacker.com` | URL-parsing differential |

For each probe: send the malformed `redirect_uri` to `/authorize` and observe. Pass = authz code delivered to attacker domain (or 302 leaks the code in `Referer`).

### B. `state` parameter

- Missing `state` → CSRF on the OAuth callback (attacker links victim through their own auth code).
- Predictable `state` → same as missing.
- `state` not validated server-side → omit it and see if the callback still succeeds.

### C. PKCE downgrade

For public clients (mobile, SPA) that registered with PKCE-required:

- Omit `code_challenge` from `/authorize` — does the server still issue a code?
- Use `code_challenge_method=plain` (deprecated, sometimes still accepted) → PKCE is moot.
- Submit `/token` exchange with a different `code_verifier` than was used in the challenge — does it succeed?

PKCE bypass enables code interception (attacker who phishes the code can redeem it).

### D. Authorization-code interception via open redirect

Chain: open redirect on target + OAuth flow that uses target's redirect as a hop → code lands at attacker. See `packs/exploit_chainer/SKILL.md` chain DB.

### E. `client_secret` exposure

- Mobile app decompilation: search APK/IPA for the secret string.
- JS bundle: search for OAuth flow code containing the secret.
- Public GitHub repo: search for the registered `client_id` value, look for secrets near it.
- API responses: some apps leak the secret in error responses or debug endpoints.

A leaked confidential-client `client_secret` enables attacker-side code-to-token exchange. On the never-submit list when the client was registered as public (mobile, SPA) — programs treat that as expected. Confidential-client secret leaks are valid findings.

### F. Refresh-token rotation gaps

- Submit the same refresh token twice → second use should fail (rotation enforced) or be revoked (replay protection).
- Steal a refresh token in any way → does revocation of the access token also revoke the refresh chain?

### G. Scope creep on consent

- Modify the `scope` parameter in `/authorize` to request more than the UI displays — does the server honor it without re-prompting consent?
- Some implementations cache previous consent decisions; widening scope is silently honored.

## OIDC-Specific Attacks

### A. `iss` confusion across federation endpoints

A relying party that accepts multiple IdPs (Google + Microsoft + custom) and uses a single JWT verifier — does the verifier check `iss` against the `aud`-specific allowed-issuer list? If not, a token issued by IdP-A for app-A can be accepted for app-B.

### B. `aud` audience confusion

- Token issued for one client_id, accepted by an endpoint registered to a different client_id at the same IdP.
- Test by acquiring a token for client-A (your own RP), then submitting it to client-B (the target).

### C. `nonce` replay

OIDC ID tokens carry a `nonce` that must equal the one sent in `/authorize`. Replay attacks:

- Re-use the same ID token in a new session — does the consumer reject it (because the nonce doesn't match a stored value)?
- Some implementations only validate nonce on first use, allowing replay.

### D. ID-token-signature-none acceptance

Submit a JWT with `alg: none` and no signature. RFC compliance forbids this; many implementations forbid it; some still accept it. Test every ID-token-consuming endpoint.

### E. JWKS rotation poisoning

- Force a JWKS refresh by issuing a token with a kid the relying party hasn't seen — does the RP fetch the JWKS again? If so, can the attacker control where the fetch goes?

### F. `kid` / `jku` / `x5u` confusion

These are the highest-paying JWT attacks today:

- **kid injection**: token header `kid` is concatenated into a file path or DB query — path traversal (`../../etc/passwd`) or SQLi.
- **kid points to attacker key**: if the verifier looks up the public key by `kid` from an attacker-influenceable source (e.g., a cache the attacker can poison), the attacker controls the key.
- **jku confusion**: JWT header includes `jku` (JWKS URL); verifier fetches the URL and uses the returned key. If the verifier doesn't enforce an allowlist on the JKU host, attacker hosts a JWKS and the token is "valid."
- **x5u confusion**: same as jku for X.509 cert URLs.

All three: header is attacker-controlled in unsigned form before signature verification. The vuln is "verifier trusts data from the unsigned header to choose the verification key."

## SAML Attack Surface

SAML is notorious for verification gaps. Programs frequently pay High–Critical for SSO bypass via SAML.

### A. XML Signature Wrapping (XSW)

Eight known variants. Core idea: signature validates over one part of the XML, but the consumer reads identity from a different part the attacker injected.

| Variant | What it does |
|---|---|
| XSW1 | Wrap signed Assertion in an Extensions element; inject new unsigned Assertion |
| XSW2 | Sibling injection at Response level |
| XSW3 | Inject Assertion as Response child; signed Assertion becomes its child |
| XSW4 | XSW3 + move signed Assertion inside attacker's Assertion |
| XSW5 | Move signed Assertion to non-standard location, copy attacker Assertion to standard |
| XSW6 | Bare signature without `<ds:Reference URI>` |
| XSW7 | Wrap in an empty signed sibling |
| XSW8 | Re-use the signed Assertion's signature for an attacker assertion via reference manipulation |

Test each by intercepting the SAML response in the SSO flow, mutating, and replaying.

### B. Comment injection in `NameID`

Identity:

```
<saml:NameID>admin<!---->@victim.com</saml:NameID>
```

Signature verifier sees `admin<!---->@victim.com` (one string); some application identity layers parse XML and read `admin@victim.com` (comment-stripped) — identity confusion → identity assumption.

### C. Signature stripping

If `WantAssertionsSigned=false` in the IdP metadata or the RP doesn't enforce signing, strip the signature entirely. Some RPs accept unsigned assertions.

### D. Signature exclusion

Move the Signature element outside the area the verifier inspects (similar to XSW6/7), so verification finds no signature and silently passes.

### E. NameID format mutation

Change `NameID Format="...:emailAddress"` to `:persistent` or `:unspecified` — some apps key user lookup off NameID without re-validating format.

### F. Replay across IdPs

Token issued by IdP-A is accepted by app-B that trusts both IdP-A and IdP-B, but only when scoped to app-A's expected issuer.

### G. Response-encryption bypass

If SAML responses are encrypted (`EncryptedAssertion`), test whether unencrypted responses are also accepted by the RP. Many RPs accept either form.

## Federation Pivots (chain into ATO)

The bug is rarely just "SSO bypass" — it's "SSO bypass to application admin." Document the pivot:

| Pivot | How |
|---|---|
| Federated group claims → app role | If the federated assertion includes `groups: [admin]` and the app trusts it, modify the claim. |
| Auto-provisioning | First sign-in creates a user; control of the federated identity controls the new account. |
| Identity-linking abuse | Some apps link the federated identity to an existing local account by email — register a federated identity with the victim's email. |
| Just-In-Time provisioning + group sync | App receives groups from the assertion and writes them to a local table — full RBAC takeover. |

## Submission Gates

Run `packs/triage_validation/SKILL.md` 7-Question gate. Then for this class:

- [ ] The chain reaches a real privileged action in the application, not just "the IdP accepted my forged token."
- [ ] The PoC works with only attacker-owned identities — no real users were impacted.
- [ ] If the attack involved JWT forgery, the signed token is preserved in evidence with the forged key alongside.
- [ ] If the attack involved SAML mutation, both the original signed response and the mutated response are preserved.
- [ ] The pivot to application impact (admin action, PII read, fund transfer) is reproducible end-to-end.

## Evidence

Store under the run artifact root, named `oauth_sso_<target>_<timestamp>/`:

- `01_discovery.txt` — IdP metadata URL contents, OAuth `/.well-known` config, JWKS, structured scopes if applicable.
- `02_baseline_flow.har` — a normal auth flow, captured.
- `03_attack_flow.har` — the malicious flow, captured.
- `04_payload/` — mutated SAML XML, forged JWT, malformed `redirect_uri` requests.
- `05_pivot_evidence/` — the privileged action reached after auth, with response showing impact.
- `README.md` — verified-vs-not table per `shared/evidence_rules.md`.

## Exclusions

- No impersonation of a real user. Project-owned accounts on both sides.
- No persistent registration of attacker identities. Clean up registered OAuth clients, federated identities, and test users after the report is closed.
- No "OAuth client_secret in mobile app" submissions (never-submit list — programs treat it as expected for public clients unless the program explicitly says otherwise).
- No testing against shared identity providers directly — the bug is in how the RP consumes assertions, not in the IdP itself, unless the IdP is the target.

## See Also

- `agent_skills/packs/triage_validation/SKILL.md` — pre-submission gates (Q8 identity check is critical for SSO findings)
- `agent_skills/packs/exploit_chainer/SKILL.md` — SSO pivot → admin chains in the A→B database
- `agent_skills/packs/web_hunter/SKILL.md` — pivot points after gaining a session
- `agent_skills/shared/evidence_rules.md` — session-identity tagging discipline
- See `agent_skills/packs/api_security/SKILL.md` for the JWT / SAML XSW companion methodology.
