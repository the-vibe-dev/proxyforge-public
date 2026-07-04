---
name: browser_extension_tester
description: Manifest analysis, permission review, content script injection, native messaging, storage leaks, and CSP bypass hunting for Chrome/Firefox extensions.
---
# Browser Extension Tester

Browser extensions operate with elevated privileges and often request permissions that dwarf the web's sandbox. A single permission-abuse or message-handling bug can grant unauthenticated scripts control over browsing history, cookies, tabs, or native applications. This pack composes with `packs/web_hunter/SKILL.md` (web-facing endpoints in extensions) and `packs/triage_validation/SKILL.md` (PoC packaging).

## When to Use

- Extension source code is available (in-scope bounty or open-source project).
- Extension has published manifest with public permissions and content script declarations.
- Program explicitly allows extension auditing (some programs scope it out as "research use only").
- Extension interacts with native applications, storage systems, or third-party websites.

## Operating Rules

- Scope: verify the program permits extension testing. Some programs restrict to "approved versions only" or exclude extensions entirely.
- PoC construction: prove the vulnerability in isolation without side-effecting other browser state. Use incognito profiles or dedicated test VMs.
- Cleanup: avoid lingering browser state from test runs. Remove test data from extension storage between tests.

## Phase 0: Manifest & Permission Audit

1. Locate `manifest.json` (v2 or v3 syntax differs; check version field).
2. Extract declared permissions, host_permissions, and optional_permissions.
3. For each permission, ask: does the extension's core functionality actually require this?
4. Flag: `clipboardRead`, `nativeMessaging`, `downloads`, `executeScript`, `tabs` are high-risk.
5. Check `content_scripts` → `matches` pattern for over-broad matching (e.g., `<all_urls>`).
6. List `web_accessible_resources` (v2) or `web_accessible_resources[*].resources` (v3); these are injectable from any webpage.
7. Check `externally_connectable` → `matches` and `ids` for loose matching or public app IDs.

## Phase 1: Content Script Injection

Content scripts execute in the context of web pages. Vulnerabilities arise when:

1. A content script receives input (via `postMessage` or `chrome.runtime.sendMessage`) from the webpage without validation.
2. The script uses that input in a DOM operation (`innerHTML`, `eval`, `dangerouslySetInnerHTML`).
3. The script trusts the input's origin without `e.origin` check.

Test:

- Load the target webpage in the extension's context.
- Inject test payloads via `window.postMessage({ payload: '<img src=x onerror=alert(1)>' }, '*')` from the page's JavaScript console.
- Observe if the payload reflects into the DOM.
- Document the source → sink data flow in the manifest/code review.

## Phase 2: Native Messaging & Message Handler Fuzzing

Native messaging handlers often deserialize untrusted input. Fuzz the handler:

1. Identify the native host name in manifest (`native_messaging_host`).
2. Construct malformed `chrome.runtime.sendMessage` payloads:
   - Missing required fields (e.g., no `type` when handler expects it).
   - Unexpected field types (e.g., `{"count": "not_a_number"}` when the handler expects an integer).
   - Boundary values (e.g., oversized strings, negative counts, null values).
   - Nested object injection (e.g., `{"config": {"nested": {"__proto__": {...}}}}`).
3. Monitor native process stderr for crashes, exceptions, or exploitable behavior.
4. Document crashes with exact payload + expected vs. actual behavior.

## Phase 3: Storage & Secrets Audit

1. Enumerate all `chrome.storage` calls (local, sync, managed).
2. For each stored key, check if it holds sensitive data: auth tokens, private keys, session cookies, passwords.
3. Verify encryption at rest: does the extension encrypt before storing?
4. Check for cleartext dumps in DevTools (open extension background script, inspect Storage tab).
5. Test persistence: restart the browser and confirm sensitive data survives (proves it's stored insecurely).

Document: exact key names, data types, no-encryption evidence.

## Phase 4: CSP Review & web_accessible_resources

1. Check for `default-src` or `script-src` CSP directives in the manifest or pages served by the extension.
2. Identify `web_accessible_resources` — these can be injected into any webpage.
3. Test if an injected resource can bypass CSP or facilitate XSS in the extension context.
4. For v3, check if resource exposure requires `matches` filtering; if absent or loose, escalate.

## Phase 5: Origin Confusion & Message Source Validation

1. Content scripts receive messages from both the webpage and the extension background.
2. Fuzz the `e.source` and `e.origin` checks:
   - Send a message with spoofed origin (if the code doesn't validate `e.origin`).
   - Send a message from a cross-origin iframe (some checks ignore nested contexts).
   - Send a message with missing or malformed origin header.
3. Document whether the handler accepts messages from unexpected sources.

## Submission Gates

- [ ] Manifest analysis completed with permission risk summary.
- [ ] Proof-of-concept reproduces the injection or message handling flaw without false positives.
- [ ] PoC includes exact payload, test steps, and expected vs. actual behavior.
- [ ] No persistent state left in test browsers (storage cleaned, no side effects on real websites).
- [ ] If native messaging is involved, crash reproducibility and symbolization included.

## Evidence Storage

Store under `ext_<name>_<timestamp>/`:

- `01_manifest.json` — target extension manifest.
- `02_permission_audit.md` — risk analysis per permission.
- `03_content_script_injection_poc.html` — test payload and result.
- `04_native_msg_fuzzing.log` — fuzzing inputs and native process output.
- `05_storage_audit.md` — keys, data types, encryption status.
- `06_csp_review.md` — CSP directives and web_accessible_resources analysis.
- `07_message_source_poc.md` — origin confusion test and result.
- `README.md` — summary per `shared/evidence_rules.md`.

## See Also

- `agent_skills/packs/web_hunter/SKILL.md` — discovery of web-facing extension endpoints
- `agent_skills/packs/triage_validation/SKILL.md` — PoC validation and submission gates

## Exclusions

- No modification of extension code without explicit scope permission.
- No actual takeover of user data or browsing history (PoC is demonstration only).
- No attack vectors requiring user social engineering outside the extension's documented behavior.
