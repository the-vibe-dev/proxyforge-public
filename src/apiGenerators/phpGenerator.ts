// PHP client stub generator (PSR-4, Guzzle-compatible pattern).
import type { GeneratorInput } from './index';
import { OP_SCHEMAS } from './index';

export function generatePhp(input: GeneratorInput): Array<{ filename: string; content: string }> {
  const baseUrl = input.baseUrl ?? 'http://127.0.0.1:8765';
  const ns = (input.namespace ?? 'ProxyForge\\Client').replace(/-/g, '\\');

  const methods = OP_SCHEMAS.map((op) => {
    const methodName = op.op.split('.').map((p, i) => i === 0 ? p : p[0].toUpperCase() + p.slice(1)).join('');
    const params = op.required.map((r) => `string $${r}`).join(', ');
    const arr = op.required.map((r) => `'${r}' => $${r}`).join(', ');
    return `    public function ${methodName}(${params}): array
    {
        return $this->send(['op' => '${op.op}', ${arr}]);
    }`;
  }).join('\n\n');

  const content = `<?php
// ProxyForge API client — auto-generated. Do not edit by hand.
namespace ${ns};

class ProxyForgeClient
{
    private string $baseUrl;
    private ?string $token;

    public function __construct(string $baseUrl = '${baseUrl}', ?string $token = null)
    {
        $this->baseUrl = rtrim($baseUrl, '/');
        $this->token = $token;
    }

    private function send(array $payload): array
    {
        $ch = curl_init($this->baseUrl . '/rpc');
        $headers = ['Content-Type: application/json'];
        if ($this->token) {
            $headers[] = 'Authorization: Bearer ' . $this->token;
        }
        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => json_encode($payload),
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 30,
        ]);
        $resp = curl_exec($ch);
        curl_close($ch);
        return json_decode($resp, true) ?? [];
    }

${methods}
}
`;

  return [{ filename: 'ProxyForgeClient.php', content }];
}
