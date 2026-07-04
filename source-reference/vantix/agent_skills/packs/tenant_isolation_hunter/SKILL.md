---
name: tenant_isolation_hunter
description: Multi-tenant SaaS applications are a critical attack surface for data isolation bugs. Users belong to organizations; each org owns objects (documents, configs, members, billing, logs). Isolation failures allow user from org_a to access org_b's data, accept stale invitations, abuse admin boundaries, or leak shared configs. This pack systematically probes org-boundary enforcement at the API, state transition, and search layers.
---
# Tenant Isolation Hunter

Tenant isolation bugs are disproportionately high-value on SaaS platforms. A single isolation failure allows an attacker to exfiltrate data from all organizations or escalate to billing/infrastructure admin. This pack probes every layer: object ownership validation, invitation state, role boundaries within an org, shared resource access, search indexing, and audit trail visibility.

Composes with `packs/auth_state_machine_hunter/SKILL.md` (invitation acceptance flows), `packs/session_boundary_hunter/SKILL.md` (role scope after org switch), `packs/triage_validation/SKILL.md`.

## When to Use

- Target is a multi-tenant SaaS app (workspace/team-collaboration platforms, payment dashboards, code-hosting org spaces, etc.).
- Users belong to one or more organizations/workspaces.
- Invitation-based membership exists.
- Role assignment (admin, member, guest) exists within organizations.
- Cross-org search, audit logs, or shared provider configs are possible.

## Operating Rules

- Use test accounts from different organizations to verify isolation.
- Do not access real customer organizations; focus on test orgs only.
- Document positive (correct isolation) and negative (boundary bypass) evidence.
- Test both API-layer isolation and UI-layer isolation (API may enforce where UI doesn't).
- Cleanup: ensure test accounts and invitations are removed after testing.

## Phase 0: Tenant Architecture Inventory

Map the multi-tenant structure:

```
User Account:
  - Email: alice@example.com
  - Orgs: [org_alpha, org_beta]
  - Roles: {org_alpha: admin, org_beta: member}

Org Object:
  - ID: org_alpha
  - Name: "Alpha Corp"
  - Objects: [document_1, document_2, ..., users, roles, settings, audit_log, billing]
  - Admins: [alice@example.com]
  - Members: [bob@example.com, charlie@example.com]

Request Context:
  - /api/orgs/{orgId}/documents → requires org-membership check
  - /api/profile → user scope, not org scope
  - /api/orgs → list orgs the user belongs to
```

Extract:
- How is org context set? (URL path, header, query param?)
- Are objects explicitly tagged with org ownership?
- How does the API validate org membership?

## Phase 1: Cross-Org Object Access

Test direct object access with org_id from a different organization:

```
Alice is member of org_alpha and org_beta.

1. Fetch document from org_alpha:
   GET /api/orgs/org_alpha/documents/doc_1
   → {content: "...", orgId: org_alpha} ✓

2. Attempt to fetch document from org_beta with org_alpha's org_id:
   GET /api/orgs/org_alpha/documents/doc_1 (as org_beta member, missing permission)
   → Expected: 403 forbidden, actual: 200 ok?

3. Enumerate org_id space and attempt access:
   GET /api/orgs/org_unknown/documents/doc_1
   → Expected: 404 or 403, actual: document returns 200?
```

If accessible: data exfiltration via object enumeration.

## Phase 2: Invitation Acceptance Abuse

Test stale or revoked invitations:

```
1. Org admin sends invitation to alice@example.com:
   POST /api/orgs/org_alpha/invitations {email: alice@example.com, role: admin}
   → {invitationId: inv_123, expiresAt: now+7d}

2. Admin revokes the invitation:
   DELETE /api/orgs/org_alpha/invitations/inv_123
   → {success: true}

3. Alice attempts to accept the revoked invitation:
   POST /api/invitations/inv_123/accept
   → Expected: 400 invitation revoked, actual: 200 added to org?

4. Or, alice accepts after 7 days (after expiration):
   [wait 7 days]
   POST /api/invitations/inv_123/accept
   → Expected: 400 expired, actual: 200 added?
```

## Phase 3: Role Downgrade Stale Privilege

User is downgraded within an org; old access token retains privilege:

```
1. Alice is admin of org_alpha, logs in, gets accessToken {scopes: [admin], orgId: org_alpha}.
2. Another admin downgrades alice to member:
   PATCH /api/orgs/org_alpha/members/alice {role: member}
   → {success: true}
3. Alice attempts admin action with old token:
   DELETE /api/orgs/org_alpha/members/bob
   → Expected: 403 (token says member now), actual: 204 deleted?
```

## Phase 4: Org Invite Self-Elevation

Attacker creates invitation with elevated role:

```
Attacker:
1. Creates test account in org_a (minimal role).
2. POST /api/orgs/org_a/invitations {email: attacker_alt@example.com, role: admin}
   → {invitationId: inv_456}
3. Attacker uses alt account:
   POST /api/invitations/inv_456/accept
   → Expected: 403 (inviter doesn't have admin to grant admin), actual: 200 admin accepted?
```

Validate: does the API check inviter's role when creating invitation?

## Phase 5: Shared Provider Config Leakage

SSO / OAuth configs are sometimes stored as org resources:

```
Org admin configures GitHub OAuth:
POST /api/orgs/org_alpha/settings/oauth {provider: github, clientId: ..., clientSecret: ...}

Org member:
GET /api/orgs/org_alpha/settings
→ Expected: no clientSecret, actual: secret returned?

Or, another org:
GET /api/orgs/org_beta/settings
→ Expected: 403 or org_beta's settings, actual: org_alpha's secret returned?
```

If leaked: attacker can impersonate the org's OAuth client.

## Phase 6: Cross-Tenant Search Leakage

Global search includes results from other orgs:

```
Alice (org_alpha member) searches for "meeting":
GET /api/search?q=meeting
→ Results from org_alpha ✓
→ Results from org_beta (where Alice is not member) ✗
→ Results from org_unknown (public data, ok)

Check: does search filter by org membership?
```

## Phase 7: Audit Log Visibility

Audit logs should be org-specific:

```
Alice (org_alpha member):
GET /api/orgs/org_alpha/audit-logs
→ Logs of org_alpha actions ✓

Attempt:
GET /api/orgs/org_beta/audit-logs
→ Expected: 403 (not member), actual: 200 org_beta logs?

Or, global audit:
GET /api/admin/audit-logs
→ Expected: 403 (not admin), actual: all orgs' logs returned?
```

## Phase 8: Billing Admin Boundary

Billing admin has limited scope; test overshoot:

```
Billing admin can update subscription, payment method, view invoices.
Cannot: delete org, manage members, delete data.

Test:
DELETE /api/orgs/org_alpha  (billing admin attempts)
→ Expected: 403, actual: 204 deleted?

PATCH /api/orgs/org_alpha/members/admin_user {role: member}  (downgrade other admin)
→ Expected: 403, actual: 200 downgraded?
```

## Output Format

Produce under the run artifact root, named `tenant_isolation_<target>_<timestamp>/`:

- `01_tenant_architecture.txt` — org structure, object model, context-setting mechanism.
- `02_cross_org_object_access.txt` — enumeration results, accessible objects, forbidden-vs-allowed.
- `03_invitation_stale_abuse.txt` — accepted-vs-rejected, revoked-vs-still-usable, expiration behavior.
- `04_role_downgrade_stale_scope.txt` — token scope pre/post downgrade, usable-vs-rejected actions.
- `05_self_invitation_elevation.txt` — role assignment validation, inviter authority check.
- `06_provider_config_leakage.txt` — shared resources accessible cross-org?
- `07_search_audit_log_leakage.txt` — search and audit cross-org visibility.
- `08_billing_admin_boundary.txt` — privilege overshoot results.
- `README.md` — summary, data exfiltration chain, impact.

## Submission Gates

Run `packs/triage_validation/SKILL.md` 7-Question gate. Then:

- [ ] Cross-org access is demonstrated (not just a theoretical boundary).
- [ ] Invitation abuse is tested with actual acceptance (not just API inspection).
- [ ] Role downgrade stale-privilege window is measured: old token usable for how long?
- [ ] Self-elevation is tested with concrete role assignment validation failure.
- [ ] Shared config leakage is extracted and shown (client secrets, API keys, etc.).
- [ ] Search/audit cross-org leakage is confirmed with data from unauthorized orgs.

## See Also

- `agent_skills/packs/auth_state_machine_hunter/SKILL.md` — invitation acceptance state.
- `agent_skills/packs/session_boundary_hunter/SKILL.md` — role scope and token validity across orgs.
- Multi-tenant SaaS isolation guidance.

## Exclusions

- No accessing real customer data (unless within authorized test org).
- No modifying production org settings or member lists.
- No creating permanent damage; ensure all test data is cleaned up.
