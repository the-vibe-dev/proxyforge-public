# ProxyForge OAST Provider Guide

> OAST = Out-of-band Application Security Testing.
> This guide covers how ProxyForge generates, signs, injects, and correlates OAST payloads.

## What is OAST and why it matters

Some vulnerabilities — SSRF, blind XXE, log4Shell, deserialization gadgets — produce no visible response
difference when triggered. The only way to confirm exploitation is through an **out-of-band channel**: the
target server reaches out to an attacker-controlled listener.

OAST replaces guesswork with a cryptographic proof: a unique signed token is embedded in the probe,
the target calls back to a listener you control, and ProxyForge correlates the interaction to the
originating scanner exchange and promotes it to a verified finding.

## How ProxyForge signs OAST tokens

Each OAST payload carries an HMAC-SHA256 token derived from the project ID and the payload ID:

```
token = HMAC-SHA256(key=projectSecret, msg="<projectId>:<payloadId>").hex[:24]
```

The token is embedded in the callback URL. When a callback arrives, `correlateCallback(token, projectId)`
looks up the token in the in-memory payload store and confirms it belongs to the correct project. This
prevents cross-project token spoofing and lets you run multiple concurrent projects against different
listeners without collision.

## Configuring a BYO OAST listener

ProxyForge ships a built-in local HTTP listener (`CallbackListenerService`) suitable for localhost testing.
For internet-reachable or DNS-based callbacks you need an external listener.

To wire in your own listener, create a listener profile and pass it to `CallbackListenerService.start()`:

```json
{
  "id": "my-oast-listener",
  "mode": "local-http",
  "host": "0.0.0.0",
  "publicBaseUrl": "https://oast.yourdomain.com",
  "protocols": ["http", "dns"],
  "httpPort": 8443,
  "dnsPort": 5353,
  "signingKeyId": "my-project-secret"
}
```

`publicBaseUrl` is the externally routable base URL injected into probe payloads. ProxyForge never
assumes the listener and the scanner run on the same host.

## `oastBaseUrl` and `oastToken` in MutationContext

When the active scanner generates payload variants for OAST-capable families (SSRF, log4Shell,
deserialization), it populates `MutationContext`:

```typescript
interface MutationContext {
  family: PayloadFamily;
  baseValue: string;
  insertionPointKind: InsertionPointKind;
  oastBaseUrl?: string;   // e.g. "https://oast.yourdomain.com"
  oastToken?: string;     // HMAC token for this probe
  // ...
}
```

Payload variants with `requiresOast: true` are silently skipped when `oastBaseUrl` is absent, so
non-OAST scans degrade gracefully without errors.

## `oastPayloadBroker.ts` API (electron/scanner/oastPayloadBroker.ts)

| Function | Description |
|----------|-------------|
| `createOastPayload(projectId, checkId, insertionPointId, exchangeId, oastBaseUrl, protocol, projectSecret)` | Mints a signed payload, stores it, returns `OastPayload` |
| `recordOastInteraction(payloadId, rawInteraction, sourceIp?, requestLine?)` | Records a callback interaction; marks payload `triggered` |
| `correlateCallback(token, projectId)` | Looks up a payload by token + project; returns payload or null |
| `getInteractionsForPayload(payloadId)` | Returns all interactions for a payload |
| `buildOastProofPayload(payload, interaction)` | Produces a `{ verified, evidence[] }` proof object |

## OAST payload lifecycle

```
1. create    — createOastPayload() mints token, stores OastPayload{status:'pending'}
2. inject    — token URL embedded in probe (e.g. ?url=https://oast.host/<token>)
3. callback  — target server fetches or resolves the token URL / hostname
4. correlate — correlateCallback(token, projectId) matches interaction → payload
5. promote   — buildOastProofPayload() confirms verification; scanner promotes to Finding
```

Status transitions: `pending` → `triggered` (on first `recordOastInteraction`). Payloads that
never trigger can be swept by an expiry pass using their `createdAt` timestamp.

## Example: confirmed SSRF finding

After a successful OAST SSRF probe the promoted finding looks like:

```json
{
  "kind": "proxyforge-scanner-oast-issue-promotion-package",
  "reportReady": true,
  "issue": {
    "checkId": "oast-ssrf",
    "confidence": "confirmed",
    "title": "Out-of-band callback was triggered"
  },
  "requirements": {
    "sourceExchangeLinked": true,
    "scannerExchangeLinked": true,
    "callbackPayloadLinked": true,
    "callbackInteractionLinked": true,
    "oastTokenObserved": true,
    "rawScannerRequestPreserved": true,
    "rawScannerResponsePreserved": true,
    "rawCallbackInteractionPreserved": true,
    "reportPhaseOnlyRedaction": true
  }
}
```

All raw material (request, response, callback body) is preserved at full fidelity until
**report export time**, at which point credentials are redacted. This satisfies the
`reportPhaseOnlyRedaction` gate required for audit-grade evidence packages.

## Related tests

- `tests/scanner-oast-ssrf.mjs` — full E2E: probe → callback → project-store correlation
- `tests/callback-listener-service.mjs` — local HTTP listener lifecycle
- `tests/oast-provider-diversity.mjs` — multiple simultaneous listener profiles
- `tests/project-store-oast-workflow.mjs` — payload/interaction persistence round-trip
