---
name: export_authz_tester
description: Test CSV/PDF exports, invoices, receipts, reports, and downloads for authorization bypass via stale tokens, cross-user access, and post-deletion retrieval.
---
# Export Authz Tester

Applications frequently generate downloadable exports (CSV, PDF, ZIP) on-demand or via scheduled jobs. The export URL or token grants access for a limited time or user. The attack surface spans token reuse (can you use an export URL after logout?), cross-user access (can User B use User A's export URL?), permission removal (can you download after your role changes?), and object lifecycle (can you download an invoice after the order is deleted?). This attack surface is often overlooked because export endpoints are rarely tested in authorization suites.

This pack composes with `packs/authz_matrix_tester/SKILL.md`, `packs/api_security/SKILL.md`, and `shared/evidence_rules.md`.

## When to Use

- The application offers downloadable exports (CSV, PDF, ZIP, Excel).
- Exports are generated on-demand or via temporary links.
- Exports contain user-specific or permission-gated data.
- The application uses tokens, signed URLs, or session binding for export access.

## Operating Rules

- **Token lifecycle**: document the export token's TTL, usage count, and revocation policy.
- **Session binding**: test whether the export URL is bound to a specific session or user.
- **Role changes**: test whether an export granted to "Manager" is still accessible after the user is downgraded to "Viewer".
- **Object lifecycle**: test whether an export is valid after the related object (order, invoice, report) is deleted or status changes.
- **Scope**: confirm export testing is in scope and does not involve exfiltrating PII beyond the proof-of-concept.

## Phase 1: Export Endpoint Inventory

Map every export and download endpoint:

1. **CSV exports**: user list, transaction list, report data, billing history.
2. **PDF invoices / receipts**: order invoice, payment receipt, tax document.
3. **Generated reports**: performance report, audit log, analytics export.
4. **Support attachments**: ticket attachment, evidence file, backup.
5. **Signed URLs**: temporary links, pre-signed S3 URLs, time-bound download tokens.
6. **Email attachments**: invoice attached to email, report sent via email.

For each, document:
- Access URL or token generation endpoint.
- Token TTL (if applicable).
- Permission model (user-specific, role-based, org-wide).
- Whether the URL/token is logged or tracked.

## Phase 2: Token and Session Tests

### A. Download After Logout

- User A generates an export (e.g., invoice CSV).
- Server returns a token or signed URL.
- User A logs out (session is invalidated).
- User A (or another user with the URL) attempts to download using the token/URL.
- Expected: rejection (session invalid or token revoked).
- Bug: download succeeds; export is accessible without authentication.

### B. Cross-User Download

- User A generates an export (e.g., transaction report).
- Server returns a token or signed URL.
- User B is given the token/URL.
- User B attempts to download.
- Expected: rejection (not authorized).
- Bug: download succeeds; User B accesses User A's data.

### C. Download After Role Downgrade

- User A has role "Manager".
- User A generates an export (e.g., employee list).
- User A's role is downgraded to "Viewer".
- User A attempts to download the export using the original token.
- Expected: rejection (no longer Manager).
- Bug: download succeeds; User A accesses Manager-only data.

### D. Download After Permission Removal

- User A has permission to access Project X.
- User A generates an export of Project X data.
- User A's permission to Project X is revoked.
- User A attempts to download the export using the original token.
- Expected: rejection (permission revoked).
- Bug: download succeeds; User A accesses revoked data.

## Phase 3: Object Lifecycle Tests

### A. Download After Object Deletion

- User A creates an order and generates an invoice PDF.
- Server returns a token or URL.
- User A (or admin) deletes the order.
- User A attempts to download the invoice using the original token.
- Expected: rejection (object no longer exists).
- Bug: download succeeds; invoice is still available.

### B. Download After Status Change

- User A submits a draft report.
- Server generates an export token.
- User A marks the report as "final" (status change; access controls may change).
- User A attempts to download the export using the original token.
- Expected: token is re-validated; download succeeds or fails based on new status.
- Bug: old token is still valid; export reflects stale state.

## Phase 4: URL Enumeration and Range Requests

### A. Sequential Filename Guessing

- User A downloads an export: `/api/export/report-2024-05-14-123abc.pdf`.
- User A guesses the pattern and constructs: `/api/export/report-2024-05-14-123abd.pdf`.
- Expected: rejection or 404 (token/ID doesn't exist).
- Bug: access is granted; another user's export is downloaded.

### B. Range Request

- User A downloads an export via token: `/api/export?token=xyz`.
- User A sends a `Range: bytes=0-1000` header.
- Expected: rejection (range requests not supported on token-protected resources) or 206 with the requested range.
- Bug: partial content is served without re-validating the token.

## Phase 5: Email and Attachment Tests

### A. Download Invoice from Email

- User A receives an email with an invoice attachment (or a link in the email).
- User A's access to the invoice is removed (order deleted, permission revoked).
- User A attempts to access the invoice via the email link.
- Expected: rejection.
- Bug: invoice is still accessible.

### B. Email Attachment URL Reuse

- User A receives an email with an attachment URL: `https://cdn.example.com/attachments/invoice-xyz`.
- User A forwards the email to User B.
- User B accesses the URL.
- Expected: rejection or 403 (User B not authorized).
- Bug: User B downloads the attachment.

## Evidence Capture

For each test, document:

1. **Baseline**: export generation request and response, token/URL issued.
2. **Permission state**: before the test (role, object ownership, access grants).
3. **Mutation**: logout, role change, object deletion, or permission removal.
4. **Download attempt**: request with token/URL and server response.
5. **Post-state**: whether download succeeded and what data was exposed.

Store under `export_authz_<test>_<timestamp>/`:
- `01_baseline.txt` — export generation and token issuance.
- `02_permission_state.txt` — role, access, ownership before mutation.
- `03_mutation.txt` — logout, role change, deletion, or permission removal.
- `04_download_attempt.txt` — download request with response.
- `05_data_exposure.txt` — what was downloaded and by whom.

## Submission Gates

Run `packs/triage_validation/SKILL.md` 7-Question gate. Then:

- [ ] The export endpoint is in scope and permission-gated.
- [ ] The baseline export and token/URL issuance is documented.
- [ ] The permission state before and after the mutation is documented.
- [ ] The download attempt shows the token/URL is still accepted post-mutation.
- [ ] The data exposure is clear (what PII or business data was accessed).
- [ ] The finding is reproducible across multiple exports.

## Exclusions

- Do not download and retain sensitive PII beyond the proof-of-concept.
- Do not test export endpoints out of scope.
- Do not enumerate thousands of export URLs (that's a separate DoS/enumeration finding).
- Do not access other users' exports in bulk without explicit authorization for testing.

## See Also

- `agent_skills/packs/authz_matrix_tester/SKILL.md` — authorization testing across all endpoints.
- `agent_skills/packs/api_security/SKILL.md` — session and token lifecycle.
