# Payload Crafter

This skill is locked by default. Use it only when the run has explicit operator
approval and the validation goal is safe, non-destructive proof design or
detection engineering.

## Boundaries

- Do not design persistence, stealth, credential theft, destructive payloads, or out-of-scope exploitation.
- Do not run payloads from this skill.
- Keep output advisory unless the run profile explicitly enables a validated lab workflow.
- In target-scoped proof mode, design compact payload families for validation only. Each family must state the evidence trigger, baseline, expected delta, max variants, cleanup expectation, and stop condition.

## Evidence-Guided Families

- Traversal/file read: route-native filename first, path normalization, URL encoding, double encoding, mixed separators, dot-segment variants, extension-appending bypasses, and route-specific filename parameters.
- XSS/filter bypass: context first, observed blocked tags/events, one alternate tag/event family, quote breakout, attribute breakout, URL-scheme variant, JSON/script-string breakout, encoding variants, and server-recorded/browser-observed proof requirement.
- XSS verifier/oracle bypass: when the target reports the value observed by `alert`, a callback, or another browser-side verifier, derive payloads from that contract instead of spraying tags. Include raw/quoted expected value, concatenation, character-code construction, assignment-free wrappers, terminators, and the content-type/method shape that actually reaches the oracle.
- Oracle-guided mutation: maintain response classes for each variant and only continue families that change parser state or observed value. For repeated fixed errors, add indirect invocation wrappers (`call`, `apply`, comma operator), throw/onerror wrappers, timer/function wrappers, and filter-desync variants tied to the observed sanitizer.
- Sanitizer grammar inference: when tag payloads are stripped, neutralized, or reflected with characters removed, design a two-stage compact family. Stage one uses inert probes to discover surviving tag names, attribute preservation, case handling, and transforms such as whitespace deletion. Stage two combines only surviving grammar with self-triggering events. If spaces are removed, prefer separator-preserving forms such as slash-delimited attributes, quote-free values, and encoded separators over normal `tag attr=value` syntax.
- DOM XSS: source-to-sink proof using hash/search/storage/postMessage/API JSON into innerHTML/document-write/unsafe URL/event/eval-like sinks; prefer one self-triggering payload matched to the sink context.
- Template/include: inert expression first, engine-specific syntax families, include path variants derived from current routes/source, then bounded output proof.
- SSRF/URL fetch: same-origin baseline, localhost spelling, IPv4/IPv6/decimal/dotted forms, explicit port, internal host from source/config, redirect-to-internal behavior, and response-delta proof.
- Upload/parser: extension case/double-extension, content-type mismatch, magic-byte mismatch, archive path normalization, parser-specific inert entity/object probes, storage path confirmation, and served-content execution check.
- Command/argument injection: option boundary, separator variants derived from parser behavior, newline/space/comment variants, direct output first, web-visible output channel second, timing only if no output channel exists.
- SQL/NoSQL/LDAP/XPath/operator injection: quote/no-quote, numeric/string type swaps, delimiter/operator tests, comment/whitespace, boolean differential, error probe, compact time probe, JSON operator object shape, array/malformed type, and data-minimizing proof.
- Blind SQL oracle escalation: preserve the current request shape and design one compact matrix for closure shape, boolean predicate, DBMS fingerprint, projection width, and data-minimizing proof. Each variant must name exactly which query-shape hypothesis it tests and which response class should change. Stop on stable no-delta, noisy timing, or sufficient objective proof.
- Redirect/open-forward: same-origin allowlist baseline, scheme-relative URL, encoded host separator, userinfo host confusion, mixed-case scheme, and redirect-chain behavior.
- Token and weak-crypto proof: classify encoding/signing/encryption first, derive one harmless current-run value only from observed examples, test owned/lab claim changes, and stop after token acceptance or consistent rejection is proven.
- Duplicate parameter and parser ambiguity: preserve raw request bytes, compare validator-visible value with action-visible value, and test only one duplicate-key ordering matrix before closure.
- Race and anti-automation proof: use tiny concurrent batches, pinned challenge IDs, replay windows, and final readback; include strict max attempts and stop on stable rejection.
- Cross-origin proof: produce minimal HTML or browser-request shapes only when the route is cookie-authenticated or callback/CORS readable. State whether preflight, SameSite, Origin, or content type blocks exploitation.
- Archive extraction proof: use inert files and traversal-like member names only to prove write location or overwrite boundary in a lab or explicitly approved target; never overwrite meaningful production files.
- WAF / IPS evasion (theory `evasion.waf_byte_class_bypass`): when a canonical payload is blocked by a network-layer or app-layer filter, design a compact variant family that preserves downstream parser semantics — case folding; URL/double/Unicode/IDN encoding; charset and content-type swap (form<->JSON<->XML, `application/x-www-form-urlencoded; charset=utf-7`); body/transport variants (multipart-mixed boundary tricks, `Transfer-Encoding: chunked` with extra extensions, HTTP/2 header smuggling, gzip/br body encoding); parameter pollution and duplicate-key ordering; comment/whitespace insertion that the application parser tolerates. Each variant must include a "filter blocks canonical / parser accepts variant / variant produces same downstream effect" triple so the result is filter-bypass evidence rather than syntactic novelty. Tool: `wafw00f` to fingerprint the filter once before mutation.

## Output Contract

```json
{
  "safe_payload_constraints": [],
  "evidence_trigger": "",
  "baseline": "",
  "compact_variants": [],
  "sanitizer_grammar": {
    "surviving_tags": [],
    "removed_tags": [],
    "transform_observed": "",
    "separator_strategy": ""
  },
  "expected_delta": "",
  "non_destructive_validation_notes": [],
  "detection_guidance": [],
  "stop_conditions": [],
  "blocked": []
}
```
