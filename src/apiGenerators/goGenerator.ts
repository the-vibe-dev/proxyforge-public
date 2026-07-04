// Go client stub generator (modules + encoding/json).
import type { GeneratorInput } from './index';
import { OP_SCHEMAS } from './index';

export function generateGo(input: GeneratorInput): Array<{ filename: string; content: string }> {
  const baseUrl = input.baseUrl ?? 'http://127.0.0.1:8765';
  const pkg = input.namespace ?? 'proxyforge';

  const methods = OP_SCHEMAS.map((op) => {
    const methodName = op.op.split('.').map((p) => p[0].toUpperCase() + p.slice(1)).join('');
    const params = op.required.map((r) => `${r} string`).join(', ');
    const mapLiteral = op.required.map((r) => `"${r}": ${r}`).join(', ');
    return `func (c *Client) ${methodName}(${params}) (map[string]interface{}, error) {
\treturn c.send(map[string]interface{}{"op": "${op.op}", ${mapLiteral}})
}`;
  }).join('\n\n');

  const content = `// ProxyForge API client — auto-generated. Do not edit by hand.
package ${pkg}

import (
\t"bytes"
\t"encoding/json"
\t"fmt"
\t"net/http"
)

type Client struct {
\tBaseURL string
\tToken   string
\thc      *http.Client
}

func NewClient(baseURL, token string) *Client {
\treturn &Client{BaseURL: baseURL, Token: token, hc: &http.Client{}}
}

func Default() *Client { return NewClient("${baseUrl}", "") }

func (c *Client) send(payload map[string]interface{}) (map[string]interface{}, error) {
\tbody, _ := json.Marshal(payload)
\treq, _ := http.NewRequest("POST", c.BaseURL+"/rpc", bytes.NewReader(body))
\treq.Header.Set("Content-Type", "application/json")
\tif c.Token != "" {
\t\treq.Header.Set("Authorization", "Bearer "+c.Token)
\t}
\tresp, err := c.hc.Do(req)
\tif err != nil {
\t\treturn nil, fmt.Errorf("proxyforge: request failed: %w", err)
\t}
\tdefer resp.Body.Close()
\tvar result map[string]interface{}
\tjson.NewDecoder(resp.Body).Decode(&result)
\treturn result, nil
}

${methods}
`;

  return [{ filename: 'proxyforge_client.go', content }];
}
