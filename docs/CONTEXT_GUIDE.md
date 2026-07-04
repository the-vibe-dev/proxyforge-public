# Proxy Forge — Context & Auth Operator Guide

## Contexts

A **Context** groups a set of in-scope URLs with their associated auth methods,
users, custom pages, and anti-CSRF configuration.

```ts
import { createContext, isUrlInContext, getMatchingContext } from '../src/contextEngine';

const ctx = createContext({
  name: 'Admin Panel',
  scopePatterns: ['https://app.example.com/admin/*'],
  techStack: ['React', 'Node.js'],
});
```

**Scope patterns** are glob-style strings (`*` = wildcard) or regex strings
(prefix with `^`). The first matching context wins in `getMatchingContext`.

Use `dissolveContext(id, contexts)` to remove a context from a collection.

---

## Authentication Methods

Five auth method types are supported:

| Type         | Module                         | Use-case                              |
|--------------|--------------------------------|---------------------------------------|
| `form`       | `authMethods/formAuth.ts`      | HTML form login (POST)                |
| `json`       | `authMethods/jsonAuth.ts`      | REST JSON login (Bearer token)        |
| `http-basic` | `authMethods/httpBasic.ts`     | HTTP Basic Authorization header       |
| `manual`     | `authMethods/manualAuth.ts`    | Pin a captured session for replay     |
| `totp`       | `authMethods/totpAuth.ts`      | TOTP companion (HMAC-SHA1, RFC 6238)  |

```ts
import { createAuthMethod } from '../src/authMethods';
import { performFormAuth } from '../src/authMethods/formAuth';

const method = createAuthMethod('form', 'Admin Login', {
  loginUrl: 'https://app.example.com/login',
  usernameField: 'email',
  passwordField: 'pass',
  successRegex: 'dashboard',
});

const result = await performFormAuth(method.config as any, {
  username: 'admin@example.com',
  password: 's3cr3t',
});
```

---

## Users

Each context can have multiple **Users** — useful for authorization matrix testing.

```ts
import { createUser, setForcedUser, getForcedUser } from '../src/users/usersEngine';

const user = createUser({
  name: 'Alice (admin)',
  role: 'admin',
  authMethodId: method.id,
  credentials: { username: 'alice', password: 'p4ss' },
  contextIds: [ctx.id],
});

// Force all requests in this context to use Alice's session:
setForcedUser(ctx.id, user.id);
```

`isForcedUserMode(contextId)` returns `true` while a forced user is active.
`clearForcedUser(contextId)` reverts to the operator's own session.

---

## Custom Pages

Declare known page types to suppress scanner false positives.

```ts
import { addCustomPage, suppressFalsePositive } from '../src/customPages';

const pages: CustomPage[] = [];
addCustomPage({ contextId: ctx.id, pattern: 'https://app.example.com/missing*',
                class: 'not-found' }, pages);

// Returns true → scanner should suppress this finding
suppressFalsePositive('https://app.example.com/missing/foo', ctx.id, 200, pages);
```

Classes: `ok` | `not-found` | `error` | `auth-required`.

---

## Anti-CSRF

Register token names per context; the refresher harvests fresh values before replay.

```ts
import { registerAntiCsrfToken, getTokensForContext } from '../src/antiCsrf';
import { refreshAntiCsrfTokens } from '../src/antiCsrf/tokenRefresher';

registerAntiCsrfToken({ name: 'csrf_token', contextId: ctx.id,
                        refreshUrl: 'https://app.example.com/form' });

const freshTokens = await refreshAntiCsrfTokens(
  getTokensForContext(ctx.id),
  ctx.id,
  { rawRequest: '...', targetUrl: 'https://app.example.com/api', cookies: 'session=abc' },
);
// freshTokens → { csrf_token: '<live value>' }
```

---

## Global Mode

Controls whether active probes are sent at all.

```ts
import { setGlobalMode, isActiveProbeAllowed } from '../src/modes';

setGlobalMode('safe');
isActiveProbeAllowed(url, scope); // always false in safe mode

setGlobalMode('standard');
isActiveProbeAllowed('https://app.example.com/api', ['https://app.example.com/*']); // true
```

| Mode        | Behaviour                                                        |
|-------------|------------------------------------------------------------------|
| `safe`      | Passive only — no active probes                                  |
| `protected` | Probes restricted to in-scope URLs                               |
| `standard`  | Probes to in-scope URLs (default)                                |
| `attack`    | In-scope URLs always allowed; others require explicit allowlist  |
