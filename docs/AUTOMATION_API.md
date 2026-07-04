# ProxyForge Automation API

A JSON-RPC protocol that lets external orchestrators — CI pipelines, shell scripts, AI agents,
or custom tooling — drive ProxyForge programmatically without coupling to the Electron UI.

---

## Endpoint

```
POST /rpc
Content-Type: application/json
Authorization: Bearer <token>
```

The token is generated at project start and printed to stdout (or retrievable via
`GET /token` with the local session cookie).

---

## Command Format

```json
{
  "op": "<AgentOpCode>",
  "requestId": "optional-correlation-id",
  "<param>": "<value>"
}
```

## Response Format

Success:

```json
{ "op": "scanner.run", "requestId": "abc", "ok": true, "data": { ... } }
```

Error:

```json
{ "op": "scanner.run", "requestId": "abc", "ok": false, "error": "Exchange not found", "code": 404 }
```

---

## Op Codes

All 16 ops are defined in `src/automation/agentProtocol.ts`.

| Op Code | Description | Required Params |
|---|---|---|
| `project.create` | Create a new project workspace | `name` |
| `project.open` | Open an existing project from disk | `path` |
| `proxy.start` | Start the intercepting proxy listener | `projectId`, `listen` (e.g. `"127.0.0.1:8080"`) |
| `proxy.stop` | Stop the proxy listener | `projectId` |
| `browser.launch` | Launch a managed Chromium instance pre-configured to trust the CA | `projectId` |
| `history.query` | Query captured HTTP exchange history | `projectId` · optional: `filter` |
| `repeater.send` | Replay a request from the Repeater engine | `projectId`, `request` (serialised HTTP object) |
| `scanner.run` | Run scanner checks against a captured exchange | `projectId`, `exchangeId` · optional: `checks` (array) |
| `scanner.matrix.fetch` | Retrieve a probe matrix by ID | `projectId`, `matrixId` |
| `oast.payload.create` | Allocate an OAST callback token for out-of-band detection | `projectId`, `purpose` |
| `oast.interactions.poll` | Poll for OAST interactions received since last poll | `projectId` |
| `exploit.template.run` | Execute an Anvil exploit template | `projectId`, `templateId`, `input` |
| `playbook.run` | Execute an automation recipe / playbook | `projectId`, `recipeId` |
| `issue.promote` | Promote one or more evidence items to a tracked issue | `projectId`, `evidenceIds` (array) |
| `report.export` | Export the project report in the specified format | `projectId`, `format` (`pdf`/`html`/`json`/`md`) |
| `extension.invoke` | Invoke a named hook on a loaded extension | `projectId`, `extensionId`, `hook` |

### `proxy.start` — `listen` format

```
"127.0.0.1:8080"         # localhost only
"0.0.0.0:8080"           # all interfaces (use with care)
```

### `scanner.run` — optional `checks` array

Omitting `checks` runs all enabled checks. Pass an array of check IDs to scope the scan:

```json
{ "op": "scanner.run", "projectId": "proj_1", "exchangeId": "ex_42", "checks": ["sqli-error", "xss-reflect"] }
```

---

## Event Stream

```
GET /events
Accept: text/event-stream
Authorization: Bearer <token>
```

Server-Sent Events stream. Each event is a JSON-encoded `AgentEvent`.

### Event Types

| Event | When fired |
|---|---|
| `proxy.exchange.captured` | A new HTTP exchange is intercepted |
| `scanner.probe.classified` | A scanner probe response is classified |
| `scanner.finding.created` | A scanner check produces a finding |
| `oast.callback.received` | An out-of-band callback hits the OAST listener |
| `issue.created` | A new issue is tracked in the project |
| `report.exported` | A report file is written to disk |
| `playbook.step.completed` | A playbook step finishes execution |

### Event envelope

```json
{
  "event": "scanner.finding.created",
  "timestamp": "2026-05-27T12:00:00.000Z",
  "projectId": "proj_1",
  "findingId": "finding_7",
  "severity": "high"
}
```

---

## Error Codes

| Code | Meaning |
|---|---|
| 400 | Malformed command or missing required field |
| 401 | Missing or invalid Bearer token |
| 404 | Referenced resource (project, exchange, etc.) not found |
| 409 | Conflict — e.g. proxy already running on that port |
| 500 | Internal engine error |

---

## Example: Full Scan Workflow

```bash
BASE="http://localhost:7331"
TOKEN="$(cat .pf-token)"
H="Authorization: Bearer $TOKEN"

# 1. Create project
PROJ=$(curl -s -H "$H" -d '{"op":"project.create","name":"ci-run-1"}' $BASE/rpc | jq -r .data.id)

# 2. Start proxy
curl -s -H "$H" -d "{\"op\":\"proxy.start\",\"projectId\":\"$PROJ\",\"listen\":\"127.0.0.1:8080\"}" $BASE/rpc

# 3. (Drive traffic through the proxy, then pick an exchange)
EX=$(curl -s -H "$H" -d "{\"op\":\"history.query\",\"projectId\":\"$PROJ\"}" $BASE/rpc | jq -r '.data.exchanges[0].id')

# 4. Run scanner
FINDING=$(curl -s -H "$H" -d "{\"op\":\"scanner.run\",\"projectId\":\"$PROJ\",\"exchangeId\":\"$EX\"}" $BASE/rpc | jq -r '.data.findingIds[0]')

# 5. Promote to issue
curl -s -H "$H" -d "{\"op\":\"issue.promote\",\"projectId\":\"$PROJ\",\"evidenceIds\":[\"$FINDING\"]}" $BASE/rpc

# 6. Export report
curl -s -H "$H" -d "{\"op\":\"report.export\",\"projectId\":\"$PROJ\",\"format\":\"html\"}" $BASE/rpc
```
