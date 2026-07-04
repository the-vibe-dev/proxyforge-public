# Automation API — Client Stubs

ProxyForge can generate typed client stubs from the JSON-RPC schema contract defined in
`src/automation/agentProtocol.ts` and `src/apiGenerators/index.ts`.

Stubs give you a strongly-typed starting point so you can drive scans from CI pipelines,
custom tooling, or AI agents without hand-rolling the HTTP layer.

---

## Quick-Start

| Language | Generator | Output File | Dependencies |
|---|---|---|---|
| Python | `pythonGenerator` | `proxyforge_client.py` | `requests` (stdlib `urllib` fallback) |
| Node.js / TypeScript | `nodeJsGenerator` | `proxyforgeClient.ts` | `node-fetch` or native `fetch` |
| Java | `javaGenerator` | `ProxyForgeClient.java` | `java.net.http` (JDK 11+) |
| Rust | `rustGenerator` | `proxyforge_client.rs` | `reqwest`, `serde_json` |
| Go | `goGenerator` | `proxyforge_client.go` | stdlib `net/http` only |
| PHP | `phpGenerator` | `ProxyForgeClient.php` | `curl` extension |
| Markdown / Wiki | `wikiGenerator` | `API_REFERENCE.md` | — |

Generate all stubs at once via the CLI (placeholder — wired in a future build):

```bash
pf generate-clients --base-url http://localhost:7331 --out ./clients
```

Or generate a single language:

```bash
pf generate-clients --lang python --base-url http://localhost:7331 --out ./clients
```

---

## Python

**Generate:**

```bash
pf generate-clients --lang python --out ./clients
```

**Constructor:**

```python
from proxyforge_client import ProxyForgeClient

client = ProxyForgeClient(base_url="http://localhost:7331", token="<bearer-token>")
```

**Example call:**

```python
project = client.project_create(name="my-scan")
client.proxy_start(project_id=project["id"], listen="127.0.0.1:8080")
result  = client.scanner_run(project_id=project["id"], exchange_id="ex_1")
print(result)
```

---

## Node.js / TypeScript

**Generate:**

```bash
pf generate-clients --lang nodejs --out ./clients
```

**Constructor:**

```typescript
import { ProxyForgeClient } from './proxyforgeClient';

const client = new ProxyForgeClient({ baseUrl: 'http://localhost:7331', token: '<bearer-token>' });
```

**Example call:**

```typescript
const { id: projectId } = await client.projectCreate({ name: 'my-scan' });
await client.proxyStart({ projectId, listen: '127.0.0.1:8080' });
const result = await client.scannerRun({ projectId, exchangeId: 'ex_1' });
```

---

## Java

**Generate:**

```bash
pf generate-clients --lang java --out ./clients
```

**Constructor:**

```java
import com.proxyforge.client.ProxyForgeClient;

var client = new ProxyForgeClient("http://localhost:7331", "<bearer-token>");
```

**Example call:**

```java
String projectId = client.projectCreate("my-scan").get("id").toString();
client.proxyStart(projectId, "127.0.0.1:8080");
Map<?, ?> result = client.scannerRun(projectId, "ex_1", null);
```

---

## Rust

**Generate:**

```bash
pf generate-clients --lang rust --out ./clients
```

**Constructor:**

```rust
use proxyforge_client::ProxyForgeClient;

let client = ProxyForgeClient::new("http://localhost:7331", "<bearer-token>");
```

**Example call:**

```rust
let project = client.project_create("my-scan").await?;
client.proxy_start(&project.id, "127.0.0.1:8080").await?;
let result = client.scanner_run(&project.id, "ex_1", None).await?;
```

---

## Go

**Generate:**

```bash
pf generate-clients --lang go --out ./clients
```

**Constructor:**

```go
import "proxyforge/client"

c := client.New("http://localhost:7331", "<bearer-token>")
```

**Example call:**

```go
proj, _ := c.ProjectCreate("my-scan")
c.ProxyStart(proj.ID, "127.0.0.1:8080")
result, _ := c.ScannerRun(proj.ID, "ex_1", nil)
```

---

## PHP

**Generate:**

```bash
pf generate-clients --lang php --out ./clients
```

**Constructor:**

```php
require_once 'ProxyForgeClient.php';

$client = new ProxyForgeClient('http://localhost:7331', '<bearer-token>');
```

**Example call:**

```php
$project = $client->projectCreate(['name' => 'my-scan']);
$client->proxyStart($project['id'], '127.0.0.1:8080');
$result  = $client->scannerRun($project['id'], 'ex_1');
```

---

## Markdown / Wiki

The `wiki` generator produces a human-readable `API_REFERENCE.md` listing every op code with its
required parameters and a cURL example. Useful for internal wikis or offline documentation.

**Generate:**

```bash
pf generate-clients --lang wiki --out ./docs
```

---

## OAST Integration

Any client that calls `oast.payload.create` receives a callback token. Pass this token as a
parameter value in subsequent requests (headers, query strings, body fields) to detect
out-of-band interactions:

```python
token_resp = client.oast_payload_create(project_id=pid, purpose="ssrf-probe")
nonce      = token_resp["token"]

# Inject nonce into target request, then poll
interactions = client.oast_interactions_poll(project_id=pid)
```

The polling interval is left to the caller; a 2–5 second interval is typical for interactive
scans, while CI pipelines may poll once after a fixed dwell time.
