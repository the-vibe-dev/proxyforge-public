---
name: authz_matrix_tester
description: Authorization matrix testing across 13 role types and 16 actions to detect privilege escalation and permission bypass.
---
# Authorization Matrix Tester

Authorization bypass is the highest-volume bug class in SaaS and B2B. Most programs build RBAC by hand; most hand-rolled implementations miss edge cases. This pack methodically covers the 13 × 16 × 4 permission state space, catching privilege escalation, cross-org leaks, and role-confusion bugs that miss static analysis.

Composes with `packs/api_security/SKILL.md`, `packs/web_hunter/SKILL.md`, `packs/triage_validation/SKILL.md`, `packs/skeptic_validator/SKILL.md`.

## When to Use

- Target uses role-based access control (RBAC), attribute-based access control (ABAC), or object-level ACLs.
- At least 3 roles exist in the application (e.g., owner, admin, member, billing-user, read-only).
- The program permits testing with multiple accounts and role-switching.
- Actions are repetitive (CRUD, invite, approve, export, audit) — any action testable across multiple roles.

## Operating Rules

- Create disposable accounts for each role, tied to separate email addresses owned by the researcher.
- Test objects you own. Never attempt to modify objects owned by other users unless the authorization model explicitly permits it.
- Document the exact role assignment for each test account (via role-assignment API, admin panel, or invite flow).
- Do not remain in higher-privilege roles longer than needed; drop to viewer-only for hypothesis isolation.
- Store baseline role permissions (what each role *should* access) before running tests.

## Phase 0: Role Inventory

Build the role table:

1. List every role available in the target (owner, admin, manager, billing-user, read-only, support, custom, inherited).
2. For each role, fetch the published authorization policy (docs, admin panel, audit logs).
3. Categorize by privilege tier: full-admin > organization-admin > team-lead > member > viewer > public.
4. Record state: active, suspended, removed, invited-not-accepted, external.
5. Document transitions: how does a user move from invited → active → removed.

## Phase 1: Action Inventory

For each endpoint and operation, enumerate the action:

- **Read**: GET /resource, fetch single record, list endpoint, export, download, view audit log, view billing.
- **Create**: POST /resource, invite user, create API key, generate report, approve request.
- **Update**: PATCH /resource, change role, change email, update plan, modify permissions, change owner.
- **Delete**: DELETE /resource, remove user, revoke token, cancel plan, archive.
- **Change state**: activate, suspend, approve, reject, transition workflow.
- **Audit/Export**: download data, view logs, export to CSV, generate invoice, view activity.

Build a 16-action baseline: the 4 CRUD + 3 state-change + 3 permission-management + 3 audit + 3 miscellaneous per target.

## Phase 2: Permission Matrix

For each (role, action, object-owner, http-method) quadruple, test the outcome:

1. Log in with the test account for the role.
2. Attempt the action on an object you own (if object-owner = self) or don't own (if object-owner = other).
3. Record: allowed, denied-403, denied-404 (leak indicator), requires-higher-role, error-silent (accepted but no effect).
4. Repeat with PUT, POST, PATCH, DELETE variants of the same intent.

Document per-cell: (role, action, owner, method) → verdict + HTTP status + response body excerpt.

## Phase 3: Role Transition & State Change

For each role type that can transition:

- **Invited, not yet accepted**: Does the user have access before accepting? Can they invite others? Can they approve resource requests?
- **Active**: Normal case; baseline.
- **Suspended**: Should all actions be denied. Check GET, POST, DELETE all return 403 or are silently ignored.
- **Removed/Deactivated**: Same — confirm actions are fully denied and user has no residual access.
- **External collaborator**: Check that permissions are *not* inherited from the primary organization.

## Phase 4: Object Ownership & Cross-User Tests

For objects that have an owner field:

1. User A creates object X (owner = A).
2. User B (different role, no ownership) attempts: read X, update X, delete X, change owner of X to B.
3. Check each outcome against the authorization model.
4. Special case: User B is invited to the object with a specific role (e.g., "editor") — test that role-on-invitation overrides the RBAC tier.

## Phase 5: Evidence & Severity

Per finding:

- **Critical**: Lower privilege (read-only) user modifies higher-privilege action (billing, approval, role-change).
- **High**: User can access objects from other organizations or deleted/archived objects.
- **Medium**: State-machine gap (invited user gains temporary escalation, or removed user retains brief access).
- **Low**: Information leak (denied actions leak existence of objects via 404 vs 403).

Generate per-endpoint table:

```
| Role | Action | Object Owner | Method | Expected | Actual | Status |
|------|--------|--------------|--------|----------|--------|--------|
| read-only | update plan | self | PATCH | 403 | 200 | FAILED |
```

## Submission Gates

- [ ] Role inventory includes all 13+ role types with documented privilege tiers.
- [ ] Action inventory covers 16+ distinct operations (4 CRUD, state-change, permissions, audit).
- [ ] Permission matrix tested for at least 3 roles × 10 actions × 2 ownership states.
- [ ] Role transitions (invited, active, suspended, removed) all tested for at least one action per state.
- [ ] Evidence table shows baseline (expected) vs actual behavior with HTTP status codes.
- [ ] Cleanup: removed test data or documented persistence for triage.

## See Also

- `packs/api_security/SKILL.md` — API authn fundamentals and OAuth scope confusion.
- `packs/object_id_enumerator/SKILL.md` — testing object access across the identity space.
- `packs/session_lifecycle_tester/SKILL.md` — token invalidation and state transition bugs that interact with RBAC.
- `packs/triage_validation/SKILL.md` — 7-question gate before submission.

## Exclusions

- No deletion of production data. Test only on disposable objects or test environments.
- No DOS via role-change attempts (don't spam API key generation, invites, or approval endpoints).
- Respect published out-of-scope rules (some programs prohibit multi-account testing).
