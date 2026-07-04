---
name: mfa_passkey_webauthn_hunter
description: MFA implementations have subtle failure modes. WebAuthn RP ID binding prevents cross-origin replay but mismatch checks are often lenient. Recovery codes leak to brute force. Backup factor enrollment races. Passkey fallback workflows downgrade to SMS/email. TOTP windows are too wide. This pack tests each failure class with targeted probes and distinguishes implementation bugs from user-error assumptions.
---
# MFA Passkey WebAuthn Hunter

MFA failures cluster into a few repeatable patterns: WebAuthn configuration mistakes (RP ID, origin binding), recovery factor enumeration and brute force, state transition races (add backup factor while MFA enrollment is in progress), fallback-path downgrades (passkey → SMS), and TOTP acceptance windows that are too lenient.

This pack probes each class with targeted tests and documents the failure mode for submission.

Composes with `packs/auth_state_machine_hunter/SKILL.md` (MFA setup/removal state), `packs/session_boundary_hunter/SKILL.md` (session after MFA bypass), `packs/triage_validation/SKILL.md`.

## When to Use

- Target implements MFA with passkey (WebAuthn), TOTP, SMS, email, or push notifications.
- Recovery codes or backup factors are available.
- Multi-step MFA enrollment or modification flows exist.
- Fallback authentication methods exist (e.g., user forgets passkey, uses SMS).

## Operating Rules

- WebAuthn testing requires browser context (RP ID binding is origin-specific); API-only tools will not catch origin-confusion bugs.
- Recovery-code enumeration must respect rate-limits; do not brute-force production accounts.
- Backup factor enrollment races require precise timing; test with concurrent requests.
- TOTP enumeration: only test against test accounts with known TOTP seeds.
- Do not lock out production accounts via failed MFA attempts.

## Phase 0: MFA Inventory

List all MFA methods, enrollment/authentication/deactivation flows, recovery factors:

```
Primary Methods:
  - WebAuthn (passkeys)
  - TOTP (authenticator app)
  - SMS (delivered via SMS gateway)
  - Email (code delivered to registered email)
  - Push notification (app-based approval)

Recovery / Backup:
  - Recovery codes (printed during enrollment)
  - Backup email address
  - Backup phone number
  - Account recovery via security questions

State Transitions:
  - /mfa/register-webauthn
  - /mfa/verify-webauthn
  - /mfa/register-totp
  - /mfa/verify-totp
  - /mfa/recover-codes → list recovery codes
  - /mfa/disable-method → remove MFA
  - /mfa/add-backup-factor
```

## Phase 1: WebAuthn RP ID and Origin Binding

WebAuthn's security rests on RP ID + origin validation. Test for lenient checks:

### Test A: Subdomain Variance

```
Registered: api.example.com
Try assert on: api.example.com (same) ✓
Try assert on: API.EXAMPLE.COM (case) ?
Try assert on: api.example.com:443 (port) ?
Try assert on: api.example.com/ (trailing slash) ?
```

### Test B: Subdomain Equivalence

```
Registered: api.example.com
Try assert on: app.example.com (different subdomain) ?
Try assert on: example.com (parent domain) ?
```

### Test C: Origin Binding Absence

Register passkey as attacker on attacker.com, then:
```
POST victim.com/auth/webauthn-assert {credential}
→ Expected: 400 RP ID mismatch, actual: 200 success?
```

## Phase 2: Recovery Code Enumeration

Recovery codes are often short and enumerable. Test:

### Test A: Format and Entropy

Generate recovery codes during test MFA enrollment. Check:
- Length: 6 digits, 8 chars, UUID?
- Character set: [0-9], [a-z0-9], [a-z0-9-]?
- Format: sequential, random, batch-generated?

Sample: `6 codes from 3 different enrollments → detect pattern`.

### Test B: Brute Enumeration

```
User authenticated, MFA challenge pending.
POST /mfa/verify-recovery-code {code: "000000"}
→ Rate limit? Timeout on N failures?
```

If no rate-limit: enumerate 1M codes and find valid ones.

### Test C: Concurrent Recovery Code Use

```
Recovery code "ABC123" issued.
Send two concurrent requests:
POST /mfa/verify-recovery-code {code: "ABC123"} × 2
→ Expected: one succeeds, one fails (code consumed), actual: both succeed?
```

## Phase 3: Backup Factor Enrollment Race

During MFA setup, can attacker add their own backup factor?

```
User starts MFA enrollment:
POST /mfa/register-totp {userId}
→ {secret: "...", qrcode: "..."}  [not yet verified]

Attacker (as same user):
POST /mfa/add-backup-phone {phone: attacker@example.com}
→ {backupPhoneAdded: true}  [no verification required?]

User completes TOTP verification. Now MFA has two factors:
- TOTP (user's device)
- Backup phone (attacker@example.com)

Attacker recovers account using backup phone.
```

## Phase 4: Fallback Downgrade

Passkey enrollment, but fallback to SMS:

```
User enrolls passkey. Attacker:
POST /mfa/authenticate-start {email: victim@example.com}
→ {methods: [webauthn, totp, sms]}

Use SMS fallback instead:
POST /mfa/verify-sms-code {code: <6-digit>}
→ {authenticated: true}

Passkey enrollment was circumvented; accessed account via SMS only.
```

## Phase 5: TOTP Window Abuse

TOTP accepts current code + grace window. Wide windows leak entropy:

```
Current TOTP code: 123456, valid until now+30s
Test with:
- 123456 (current) ✓
- 345678 (next minute) ? [should fail]
- 901234 (previous minute) ? [1-window back, acceptable]
- 567890 (2 windows back, -60s) ? [should fail if window=30]
```

If window is too wide: brute-guess 6-digit codes within window → 100 attempts instead of 10.

## Phase 6: Push Notification Fatigue

If MFA uses push notifications:

```
POST /mfa/authenticate-start {email: victim@example.com, method: push}
→ Attacker user receives push notifications

POST /mfa/push-response {pushId, approved: true} × 1000 times (rapid)
→ Rate-limit? TOCTOU window? Does user's approval eventually process?
```

Attacker floods user with push notifications; one approval succeeds, account compromised.

## Output Format

Produce under the run artifact root, named `mfa_webauthn_<target>_<timestamp>/`:

- `01_mfa_inventory.txt` — methods, endpoints, recovery factors.
- `02_webauthn_rp_tests.txt` — origin binding, RP ID variance results.
- `03_recovery_code_analysis.txt` — format, entropy, brute-force rate limit.
- `04_backup_factor_race.txt` — concurrent enrollment + backup factor add.
- `05_fallback_downgrade.txt` — passkey enrollment vs. SMS fallback bypass.
- `06_totp_window_test.txt` — codes tested, window size inferred, brute feasibility.
- `07_push_fatigue.txt` — notification spam results.
- `README.md` — summary, exploitability, impact.

## Submission Gates

Run `packs/triage_validation/SKILL.md` 7-Question gate. Then:

- [ ] MFA bypass is demonstrated (not just a vulnerability assessment).
- [ ] Recovery method is not the primary exploit (recovery is expected to bypass MFA on account reset).
- [ ] Fallback method is tested, not just configured.
- [ ] WebAuthn tests are run in browser context (origin binding is not testable via API).
- [ ] TOTP/code brute is documented with window width and attempt count.

## See Also

- `agent_skills/packs/auth_state_machine_hunter/SKILL.md` — MFA setup/removal state.
- `agent_skills/packs/session_boundary_hunter/SKILL.md` — session handling after MFA.
- MFA enrollment, recovery, and OTP-handling best practices.

## Exclusions

- No actual account lockout of production users.
- No brute-force against hardened recovery-code endpoints without rate-limit proof first.
- No social engineering of users to approve push notifications (test only with attacker-controlled accounts).
