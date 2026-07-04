// Node.js ESM TypeScript client stub generator.
import type { GeneratorInput } from './index';
import { OP_SCHEMAS } from './index';

export function generateNodeJs(input: GeneratorInput): Array<{ filename: string; content: string }> {
  const baseUrl = input.baseUrl ?? 'http://127.0.0.1:8765';

  const methods = OP_SCHEMAS.map((op) => {
    const methodName = op.op.replace(/\./g, '_');
    const params = op.required.map((r) => `${r}: string`).join(', ');
    const body = JSON.stringify({ op: op.op, ...Object.fromEntries(op.required.map((r) => [r, `\${${r}}`])) });
    return `  async ${methodName}(${params}): Promise<unknown> { return this.send(\`${body.replace(/"/g, '\\"').replace(/\$\{/g, '${')}\`); }`;
  }).join('\n');

  const tsContent = `// ProxyForge API client — auto-generated. Do not edit by hand.
// Re-run the generator after updating the op schema.
import { fetch } from 'node:http';

export class ProxyForgeClient {
  private baseUrl: string;
  private token?: string;

  constructor(baseUrl = '${baseUrl}', token?: string) {
    this.baseUrl = baseUrl.replace(/\\/$/, '');
    this.token = token;
  }

  private async send(payloadJson: string): Promise<unknown> {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (this.token) headers['Authorization'] = \`Bearer \${this.token}\`;
    const res = await fetch(\`\${this.baseUrl}/rpc\`, { method: 'POST', headers, body: payloadJson });
    return res.json();
  }

${methods}
}
`;

  return [{ filename: 'proxyforge-client.ts', content: tsContent }];
}
