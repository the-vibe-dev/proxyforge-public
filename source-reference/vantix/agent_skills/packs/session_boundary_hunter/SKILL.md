---
name: session_boundary_hunter
description: Session boundary bugs arise when logout, role change, password change, or email change do not invalidate existing sessions or tokens. Refresh tokens are replayed. Access tokens retain old privileges. Session cookies are set too broadly (wrong domain/path). SameSite is misconfigured. This pack tests invalidation on every privilege-altering event and measures token lifetime and rotation correctness.
---
# Session Boundary Hunter

Session management has a narrow contract: when a user logs out, changes password, upgrades/downgrades role, or changes email, the server must invalidate or refresh all existing sessions. Attackers exploit windows where invalidation is incomplete or delayed.

This pack maps session lifecycle, tests invalidation completeness at each boundary event, and identifies long-lived or replayable tokens.

Composes with `packs/auth_state_machine_hunter/SKILL.md` (logout and state transitions), `packs/session_boundary_hunter/SKILL.md` (privilege changes), `packs/triage_validation/SKILL.md`.

## When to Use

- Target uses refresh tokens, access tokens, or session cookies.
- Users can change password, email, phone, or role.
- Admin or privilege escalation paths exist.
- Logout is implemented.
- Multi-device session management exists.

## Operating Rules

- Capture all session tokens at each state: access token, refresh token, session cookie.
- Test invalidation on each boundary event: logout, password change, role change, email change.
- Test token reuse: can an old access token be replayed after the user should be logged out?
- Document negative evidence: which invalidations are working correctly?
- Cleanup: do not leave test sessions active; explicitly log out and verify invalidation.

## Phase 0: Session Token Inventory

Log in, capture every token issued and its properties:

```
Login:
  POST /auth/login {email, password}
  → accessToken: JWT {sub: userId, exp: now+15m, scopes: [user]}
  → refreshToken: opaque string or JWT {sub: userId, exp: now+30d}
  → sessionCookie: name=session, value=<>, SameSite=Strict, HttpOnly, Domain=.example.com

Refresh:
  POST /auth/refresh {refreshToken}
  → accessToken: JWT {sub: userId, exp: now+15m, scopes: [user]}
  → refreshToken: <same or rotated?>
```

Extract for each token:
- Name, format (JWT or opaque).
- Lifetime (TTL).
- Scopes / claims.
- Consumption rule (single-use or replayable?).

## Phase 1: Logout Invalidation

Test that logout invalidates all tokens:

```
1. Log in, capture accessToken, refreshToken, sessionCookie.
2. POST /auth/logout
   → Response: {success: true}
3. Attempt to use old tokens:
   POST /api/profile {headers: {Authorization: "Bearer <old_accessToken>"}}
   → Expected: 401 unauthorized, actual: 200 success?
   
   POST /auth/refresh {refreshToken: <old_refreshToken>}
   → Expected: 400 invalid token, actual: 200 success?

   GET /api/profile {cookies: {session: <old_sessionCookie>}}
   → Expected: 401 unauthorized, actual: 200 success?
```

Document which tokens are invalidated and which persist.

## Phase 2: Privilege Escalation Post-Role-Change

User with role=user promoted to role=admin:

```
1. Log in as user, capture accessToken {scopes: [user]}.
2. Admin promotes user account to admin via backend (or user self-promotes if bug).
3. Attempt admin action:
   POST /api/admin/delete-user {userId: X} {headers: {Authorization: "Bearer <old_accessToken>"}}
   → Expected: 403 forbidden (token still says role=user), actual: 204 deleted?
```

If bug exists: old access token retains user role; admin action succeeds until token expires.

## Phase 3: Password Change Session Invalidation

User changes password:

```
1. Log in, capture accessToken + refreshToken.
2. POST /auth/change-password {oldPassword, newPassword}
   → {success: true}
3. Try old tokens:
   POST /api/profile {headers: {Authorization: "Bearer <old_accessToken>"}}
   → Expected: 401 (password change invalidates sessions), actual: 200 success?
   
   POST /auth/refresh {refreshToken: <old_refreshToken>}
   → Expected: 400 (old refresh token rejected), actual: 200 new token?
```

## Phase 4: Email/Phone Change Boundary

User changes registered email or phone:

```
1. Log in, capture tokens.
2. POST /auth/change-email {newEmail: attacker@example.com}
   → {success: true}
3. Check:
   - Does old email still receive logout/password-reset notifications?
   - Can attacker use old tokens? (Should invalidate.)
```

## Phase 5: Session Fixation

Pre-set session ID before login:

```
1. Attacker: GET /auth/login
   → sessionCookie: value=ABC123 (attacker-supplied or attacker-guessed)
2. Victim: POST /auth/login {email, password} with cookie session=ABC123
   → Response does not change sessionId
3. Attacker uses session=ABC123 → logged in as victim
```

Test: does session ID change after successful login?

```
Before: sessionCookie value = ABC123
After login: sessionCookie value = ABC123 (FAIL) or DEF456 (PASS)
```

## Phase 6: Device Session Management

If the app shows "active sessions" or device-binding:

```
User logged in on devices: phone, laptop, tablet.
/api/sessions → lists: {device1, device2, device3}

Attacker:
DELETE /api/sessions/{device1-id}
→ Expected: 403 (can only delete own session) or 204 (removes phone device)

Can attacker delete victim's sessions? Can attacker see victim's device list?
```

## Phase 7: Refresh Token Rotation

Test if refresh tokens are rotated on each use:

```
1. Log in, get refreshToken_v1
2. POST /auth/refresh {refreshToken: refreshToken_v1}
   → Returns refreshToken_v2 (rotated, good)
   → Returns refreshToken_v1 (not rotated, bad — same token replayable forever)
3. Replay refreshToken_v1 again
   → Expected: 400 (single-use), actual: 200 (replayable)?
```

## Phase 8: Cookie Domain and SameSite

Inspect sessionCookie:

```
Set-Cookie: session=<value>; Domain=.example.com; Path=/; SameSite=Strict; HttpOnly
```

Check:
- Domain: `.example.com` (all subdomains) vs. `api.example.com` (specific subdomain)?
  - If `.example.com`: can untrusted subdomain steal the cookie?
- Path: `/` (all paths) vs. `/api/` (specific path)?
- SameSite: Strict, Lax, or None?
  - If None, is Secure flag set (HTTPS only)?
- HttpOnly: present? If missing, JavaScript can steal the cookie.

## Output Format

Produce under the run artifact root, named `session_boundary_<target>_<timestamp>/`:

- `01_token_inventory.csv` — token_name | format | lifetime | scopes | consumption_rule.
- `02_logout_invalidation.txt` — which tokens accepted, which rejected post-logout.
- `03_role_change_stale_privilege.txt` — old token usable after privilege downgrade?
- `04_password_change_invalidation.txt` — are sessions invalidated?
- `05_session_fixation_test.txt` — does session ID change post-login?
- `06_device_session_management.txt` — device list visibility, deletion permissions.
- `07_refresh_token_rotation.txt` — is refresh token single-use or replayable?
- `08_cookie_security.txt` — domain, path, samesite, httponly analysis.
- `README.md` — summary, worst finding, exploitation chain.

## Submission Gates

Run `packs/triage_validation/SKILL.md` 7-Question gate. Then:

- [ ] Token invalidation is tested post-logout with actual replay attempt (not just assertion).
- [ ] Privilege stale-ness window is measured: old token usable for how long after downgrade?
- [ ] Refresh token rotation (or lack thereof) is documented with replay proof.
- [ ] Session fixation test confirms whether session ID changes post-login.
- [ ] Cookie security (domain, path, samesite) is extracted from actual responses.

## See Also

- `agent_skills/packs/auth_state_machine_hunter/SKILL.md` — logout and password-change state.
- `agent_skills/packs/tenant_isolation_hunter/SKILL.md` — session scope across orgs/workspaces.
- Session management hardening guidance.

## Exclusions

- No brute-forcing session IDs (that's a separate DoS / weak-randomness class).
- No exploiting unrelated app vulns to trigger role change (focus on session handling after legitimate role change).
- No destroying production user sessions; use test accounts only.
