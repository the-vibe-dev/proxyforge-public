// Markdown wiki / documentation generator — emits a human-readable API reference.
import type { GeneratorInput } from './index';
import { OP_SCHEMAS } from './index';

export function generateWiki(input: GeneratorInput): Array<{ filename: string; content: string }> {
  const baseUrl = input.baseUrl ?? 'http://127.0.0.1:8765';

  const opDocs = OP_SCHEMAS.map((op) => {
    const requiredList = op.required.map((r) => `- \`${r}\` *(string, required)*`).join('\n');
    const optionalList = (op.optional ?? []).map((r) => `- \`${r}\` *(string, optional)*`).join('\n');
    const paramsSection = [
      requiredList,
      optionalList ? '\n' + optionalList : '',
    ].filter(Boolean).join('');

    const exampleObj = Object.fromEntries([
      ['op', op.op],
      ...op.required.map((r) => [r, `<${r}>`]),
    ]);

    return `### \`${op.op}\`

${op.description}.

**Parameters**

${paramsSection || '_None_'}

**Example request**

\`\`\`json
${JSON.stringify(exampleObj, null, 2)}
\`\`\`

**Example response**

\`\`\`json
{ "ok": true, "result": {} }
\`\`\`
`;
  }).join('\n---\n\n');

  const content = `# ProxyForge JSON-RPC API Reference

> Auto-generated from the op schema. Do not edit by hand.

## Endpoint

All commands are sent as HTTP POST to:

\`\`\`
${baseUrl}/rpc
\`\`\`

**Headers**

| Header | Value |
|---|---|
| \`Content-Type\` | \`application/json\` |
| \`Authorization\` | \`Bearer <token>\` *(optional)* |

## Command structure

Every request body is a JSON object with at minimum an \`op\` field:

\`\`\`json
{ "op": "<operation>", "<param1>": "<value1>", ... }
\`\`\`

Every successful response body has \`ok: true\`:

\`\`\`json
{ "ok": true, "result": { ... } }
\`\`\`

Error responses have \`ok: false\` and an \`error\` string:

\`\`\`json
{ "ok": false, "error": "short message", "code": "ERROR_CODE" }
\`\`\`

---

## Operations

${opDocs}
## Event stream

Subscribe to \`GET ${baseUrl}/events\` (Server-Sent Events) to receive asynchronous notifications
from the proxy engine, scanner, and OAST callback system.

Each event is a JSON object with an \`event\` field and a \`data\` payload:

\`\`\`
event: proxy.exchange.captured
data: {"exchangeId":"abc","method":"GET","url":"https://example.com/"}
\`\`\`

See \`src/automation/agentProtocol.ts\` for the full \`AgentEvent\` type definitions.
`;

  return [{ filename: 'API_REFERENCE.md', content }];
}
