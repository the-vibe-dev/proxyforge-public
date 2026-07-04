---
name: auth_state_machine_hunter
description: Authentication bugs hide in state transitions between endpoints. Register→verify→login→authenticated, logout→invalidated. Change password, email, phone, MFA setup, account recovery—each transition has a state window where an attacker can skip, replay, or diverge. Maps full flow graph, identifies replayable transitions, tests negative cases, and outputs token/session lifecycle tables.
---
# Auth State Machine Hunter

Most authentication bugs are not in individual endpoints but in the transitions between them. A user follows: register → email-verify → login → authenticated. Each step has state preconditions and post-conditions. The bug is in the gap: "I've been verified but not yet logged in," "I'm authenticated but password-change hasn't invalidated my old session," "I logged out but the refresh token still works."

This pack builds the full state graph for the target's authentication flow, documents token/session lifecycle at each state, tests transitions out of order, and identifies windows where almost-authenticated users can escalate or where recently-authenticated transitions fail to invalidate old credentials.

Composes with `packs/skeptic_validator/SKILL.md`, `packs/triage_validation/SKILL.md`, `packs/session_boundary_hunter/SKILL.md` (session fixation and invalidation bugs).

## When to Use

- Target has a multi-step auth flow: registration → verification → login.
- Password reset, email change, phone number change, or account recovery flows exist.
- MFA is optional or can be enabled/disabled.
- Session management is present: tokens, refresh tokens, cookies with TTL.
- Invite-based account creation or org membership changes exist.

## Operating Rules

- Map the happy path first: trace every auth request/response, capture tokens at each state.
- Identify state predicates: what does the server check before allowing the next transition?
- Test reordering: skip a step, replay an old step, send two conflicting steps.
- Document negative evidence: which state transitions are correctly rejected? This proves the server has state guards.
- Cleanup: any account created during testing should be deleted or marked clearly as test.

## Phase 0: Auth Flow Cartography

Extract every auth-related endpoint and draw a dependency graph:

```
/register → POST body: {email, password}
           Response: {userId, registrationToken}
           State: user exists, not verified, no session

/verify-email → POST body: {registrationToken, code}
               Response: {verified: true}
               State: user verified, not logged in, token consumed

/login → POST body: {email, password}
        Response: {accessToken, refreshToken, sessionId}
        State: user authenticated, session active

/logout → POST
         Response: {success: true}
         State: user authenticated → unauthenticated, session invalidated
```

Extract from:
- Proxy logs (intercepting web proxy): full request/response sequences.
- API docs / OpenAPI specs.
- JS bundles: search for `/auth/`, `/login`, `/register`, `/password-reset`, `/mfa`.
- Mobile app decompilation (APK, IPA): auth flows in native code.

## Phase 1: Token and Session Lifecycle Inventory

For each state, document what tokens/cookies exist, their format, and lifetime:

```
State: pre-verified
  - registrationToken: JWT {exp: now+1h, userId: X}
  - cookie: none
  - session: none

State: verified (after POST /verify-email)
  - registrationToken: consumed (deleted or exp+0)
  - cookie: none
  - session: none

State: authenticated (after POST /login)
  - accessToken: JWT {exp: now+15m, userId: X, scopes}
  - refreshToken: opaque {exp: now+30d, userId: X}
  - sessionCookie: SameSite=Strict, HttpOnly, exp: now+1h
  - refreshTokenCookie: if applicable
```

## Phase 2: Transition Negative Tests

For each transition, test the failure case and the replay case:

### A. Skip Verification

```
POST /register {email, password}
→ {registrationToken, userId}

# Now try /login with email+password, skipping /verify-email
POST /login {email, password}
→ Expected: 403 unverified, actual: success?
```

Payload: user reaches authenticated state without completing verification.

### B. Replay Registration Token

```
POST /verify-email {registrationToken, code}  # first time
→ {verified: true}

# Immediately, replay the same request
POST /verify-email {registrationToken, code}  # second time
→ Expected: 400 token expired, actual: 200 ok?
```

Payload: registration token accepted multiple times.

### C. Password Reset Reuse

```
POST /auth/forgot-password {email}
→ {resetToken}

POST /auth/reset-password {resetToken, newPassword}
→ {success: true}

# Immediately, use the same resetToken again
POST /auth/reset-password {resetToken, anotherPassword}
→ Expected: 400 token consumed, actual: success?
```

Payload: password reset token not invalidated after first use.

### D. Simultaneous Email + Password Change

```
# User is authenticated, attempt two conflicting changes in parallel
POST /auth/change-email {email: newuser@example.com} (no password prompt)
POST /auth/change-password {oldPassword, newPassword}
→ If both succeed: email changed, password changed, but which takes precedence?
   Logout and try old vs new email/password; inconsistent state.
```

Payload: race in state transition leaves account in partial state.

### E. MFA Removal Without Reauth

```
User is authenticated with MFA enabled.
DELETE /auth/mfa
→ Expected: 403 require current MFA / password, actual: 204 deleted?
```

Payload: disable MFA without step-up auth.

### F. Account Recovery Privilege Leak

```
User was compromised, runs account recovery (via backup email or phone).
POST /auth/recover-account {email, recoveryCode}
→ {success: true, accountRestored: true}

Check: user role, org membership, API keys—were they reset or preserved?
Expected: privileges reset/downgraded, actual: admin role persists?
```

## Phase 3: State Divergence Tests

Send conflicting or overlapping state transitions and capture the resulting inconsistency:

```
Scenario: register, then during verify window, request password reset
POST /register {email}
→ registrationToken issued

Before verification, in parallel:
POST /auth/forgot-password {email}
→ resetToken issued

Can attacker now use resetToken to set password before email is verified?
Or can both tokens coexist? State divergence: "almost verified" + "reset pending."
```

Document the resulting account state and whether it violates assumptions.

## Phase 4: Output Format

Produce under the run artifact root, named `auth_flow_<target>_<timestamp>/`:

- `01_flow_graph.txt` — ASCII state machine. States, transitions, preconditions.
- `02_token_lifecycle.csv` — state | token_name | format | exp_time | consumption_rule.
- `03_negative_tests.txt` — each transition, expected-vs-actual. Which ones fail correctly?
- `04_divergence_tests.txt` — concurrent/reordered transitions that leave state inconsistent.
- `05_replayable_transitions.txt` — which tokens/requests can be replayed successfully?
- `README.md` — summary, worst finding, cleanup status.

## Submission Gates

Run `packs/triage_validation/SKILL.md` 7-Question gate. Then:

- [ ] State graph is complete and all transitions tested.
- [ ] Negative cases show which transitions are protected.
- [ ] Replayable token/request is documented with baseline (1 use) vs. divergence (N uses).
- [ ] Token lifecycle is accurate: does server invalidate on logout? On state change?
- [ ] Almost-authenticated state does not grant privileges or bypass steps.

## See Also

- `agent_skills/packs/session_boundary_hunter/SKILL.md` — session invalidation, fixation, refresh-token rotation.
- `agent_skills/packs/mfa_passkey_webauthn_hunter/SKILL.md` — MFA state transitions, enrollment, bypass.
- `agent_skills/packs/triage_validation/SKILL.md` — submission gates.

## Exclusions

- No credential spray or brute force.
- No exploiting unrelated vulns (e.g., SQL injection in forgot-password, then using that to reach auth state).
- No actual account takeover of users outside scope.
