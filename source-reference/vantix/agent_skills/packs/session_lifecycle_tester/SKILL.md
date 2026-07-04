---
name: session_lifecycle_tester
description: Test session invalidation across state transitions to detect lingering access after security changes.
---
# Session Lifecycle Tester

Session management bugs are subtle but high-impact. A user changes their password or enables MFA expecting old sessions to be invalidated; if the application forgets to clear the session table, an attacker retains access. Similarly, single-use tokens (reset, email-confirm, invite) that are reused multiple times enable account takeover chains. This pack tests 9 lifecycle events and 6 token-reuse scenarios, detecting sessions that linger past their expected expiry.

Composes with `packs/api_security/SKILL.md`, `packs/web_hunter/SKILL.md`, `packs/triage_validation/SKILL.md`, `packs/skeptic_validator/SKILL.md`.

## When to Use

- Target supports passwords, MFA, API tokens, or refresh tokens.
- Session/token management endpoints exist (login, logout, password-change, MFA, token-rotate).
- The program permits testing with account state changes and token capture.
- Multiple authentication schemes coexist (session + JWT, session + OAuth, API key + OAuth).

## Operating Rules

- Use a dedicated test account. Do not use your real account for session capture/replay tests.
- Capture tokens before and after each state change. Store them in a controlled manner (don't leak to logs).
- Replay captured tokens only on the test account's resources, not on other users' data.
- Document the exact timestamp and state change for each token capture.
- Stop immediately if a token grants access to other users' data. Report as Critical.

## Phase 0: Token Type Inventory

Identify every token the application issues:

1. **Session cookie**: name, path, domain, secure, httponly, sameSite, expiry.
2. **JWT**: algorithm, iss, aud, sub, exp, iat, custom claims.
3. **API key**: format, rotation policy, expiry, scope.
4. **Refresh token**: format, rotation behavior, expiry.
5. **Single-use tokens**: reset-password, email-confirmation, invite, verification.

For each, document:

- How it's issued (login, API call, email link).
- How it's invalidated (logout, expiry, rotation, manual revocation).
- Where it's stored (cookie, localStorage, bearer header).

## Phase 1: Session Invalidation at State Change

For each state change, test if old tokens are invalidated:

### Test 1: Password Change

1. Log in with test account; capture session token.
2. Change password via PATCH /api/account/password.
3. Immediately use the old token to call an authenticated endpoint (GET /api/me).
4. Expected: 401 Unauthorized.
5. Actual: Record status code.
6. Repeat the test 3+ times to rule out timing issues.

### Test 2: MFA Enable

1. Log in without MFA; capture session token.
2. Enable MFA (PATCH /api/account/settings, mfaEnabled=true).
3. Use the pre-MFA session token to call an authenticated endpoint.
4. Expected: 401 or MFA challenge (e.g., 403 with `require_mfa`).
5. Actual: Record status code.

### Test 3: Email Address Change

1. Log in; capture session token.
2. Change email (PATCH /api/user, email=new@example.com).
3. Use the old token on an authenticated endpoint.
4. Expected: 401 (email change often invalidates sessions).
5. Actual: Record status code.

### Test 4: Logout

1. Log in; capture session token.
2. Logout (POST /api/auth/logout).
3. Immediately use the old token.
4. Expected: 401.
5. Actual: Record status code. Some applications allow a brief window after logout; document this.

### Test 5: Token Rotation / Key Rotation

1. Log in; capture session/JWT token.
2. Rotate the session encryption key (if available via admin panel) or API key (POST /api/account/rotate-api-key).
3. Use the old token.
4. Expected: 401.
5. Actual: Record status code.

## Phase 2: Refresh Token Lifecycle

For applications with separate refresh tokens:

1. Log in; capture refresh token.
2. Call /api/auth/refresh with the refresh token; capture new access token.
3. Change password.
4. Call /api/auth/refresh again with the old refresh token.
5. Expected: 401 (refresh token invalidated).
6. Actual: Record status code.

Also test refresh-token rotation:

1. Call /api/auth/refresh; get new access token and new refresh token.
2. Call /api/auth/refresh again with the *previous* refresh token (one generation older).
3. Expected: 401.
4. Actual: Record status code. Some applications rotate but accept the previous generation; document this.

## Phase 3: Single-Use Token Reuse

For password-reset, email-confirmation, and invite tokens:

### Reset Token

1. Request password reset: POST /api/auth/forgot-password, email=test@example.com.
2. Capture the reset token from the email.
3. Use it to reset the password (POST /api/auth/reset-password, token=X, newPassword=Y).
4. Immediately attempt to use the same token again to reset to a different password.
5. Expected: 401 or "token invalid" error.
6. Actual: Record status code.

### Email Confirmation Token

1. Register a new account; email contains confirmation token.
2. Confirm the email (POST /api/auth/confirm-email, token=X).
3. Attempt to confirm again with the same token.
4. Expected: 400 or "already confirmed" error.
5. Actual: Record status code.

### Invite Token

1. Invite a user to an organization (POST /api/org/invite, email=invitee@example.com).
2. Capture the invite token.
3. Accept the invite (POST /api/invites/accept, token=X).
4. Attempt to accept the same invite again (simulating the attacker replaying the acceptance).
5. Expected: 400 or "invite already accepted" error.
6. Actual: Record status code.

## Phase 4: JWT & OAuth Confusion

For applications using JWT or OAuth:

1. Obtain a JWT from the login endpoint (e.g., `Authorization: Bearer eyJ0eXAiOiJKV1QifQ...`).
2. Attempt to use it as a refresh token (if the application accepts refresh tokens).
3. Decode the JWT; check iss (issuer), aud (audience), sub (subject), exp (expiry).
4. On another endpoint (e.g., /api/user vs /api/admin), attempt to use the same JWT.
5. Expected: 403 or "invalid audience" error.
6. Actual: Record status code.

Also test audience downgrade:

- If you have an admin JWT, can you use it on a user-scoped endpoint?
- If you have an API-scope JWT, can you use it on a user-profile endpoint?

## Submission Gates

- [ ] Token inventory documents every session/token type with format and expiry policy.
- [ ] State-change test: password change, MFA enable, email change, logout, token rotation all tested.
- [ ] Session invalidation test: 5+ attempts post-state-change show consistent 401 (or document partial invalidation).
- [ ] Refresh token test: old refresh token rejected after password change.
- [ ] Single-use token test: reset, confirmation, invite tokens all tested for reuse.
- [ ] JWT/OAuth confusion test: audience/issuer confusion tested if applicable.
- [ ] Evidence includes before/after token capture, state change timestamp, and replay response status code.

## See Also

- `packs/api_security/SKILL.md` — authentication and token validation.
- `packs/authz_matrix_tester/SKILL.md` — privilege escalation via session reuse.
- `packs/triage_validation/SKILL.md` — 7-question gate.

## Exclusions

- Do not test on production user accounts beyond proof-of-concept.
- Do not attempt to exploit session bugs to escalate to other users' accounts in submission (prove the bug exists; do not exploit it to the fullest extent).
- Do not exhaust password-reset or MFA attempt limits during testing.
