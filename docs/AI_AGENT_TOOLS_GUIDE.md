# AI Agent Tools Guide

ProxyForge exposes two structured tools to the AI agent so it can act on captured traffic, not just suggest.

## Tools

### captured-traffic-sql

Read-only parametrised SELECT queries against the active project's exchange, issue, and scanner matrix tables.

**Authorization:** Mode ≥ Standard + explicit per-project opt-in.

**Example:**

```json
{
  "tool": "captured-traffic-sql",
  "sql": "SELECT url, status_code, response_time_ms FROM exchanges WHERE method = ? AND status_code = 401 ORDER BY response_time_ms DESC LIMIT 10",
  "params": ["POST"]
}
```

**Blocked:** INSERT, UPDATE, DELETE, DROP, and any reference to `audit_log`, `secrets`, `credentials`, or `session_tokens` tables.

### managed-browser-drive

Drives the in-app managed browser session: click, type, evaluate JS, screenshot, navigate.

**Authorization:** Mode ≥ Standard + explicit per-project opt-in + current page must be in-scope.

**Example:**

```json
{
  "tool": "managed-browser-drive",
  "action": { "type": "click", "selector": "#submit" }
}
```

**Blocked in Safe mode.** Navigation to out-of-scope URLs is refused. `evaluate` expressions containing `process.*`, `require()`, `fs.*`, or `child_process` are blocked.

## Enabling tools

In the AI panel, toggle the tool switches under **Agent Tools**. Per-project settings; disabled by default.

## Mode interactions

| Mode | captured-traffic-sql | managed-browser-drive |
|------|---------------------|----------------------|
| Safe | ✗ blocked | ✗ blocked |
| Protected | ✓ (in-scope only) | ✓ (in-scope only) |
| Standard | ✓ | ✓ |
| Attack | ✓ | ✓ |

## Tests

- `tests/ai-tool-traffic-sql-readonly.mjs`
- `tests/ai-tool-traffic-sql-injection-impossible.mjs`
- `tests/ai-tool-browser-drive-scope-gated.mjs`
- `tests/ai-tool-browser-drive-mode-safe-blocks.mjs`
