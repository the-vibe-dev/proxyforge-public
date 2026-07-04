// Rust client stub generator (serde + reqwest pattern — no runtime deps in generator).
import type { GeneratorInput } from './index';
import { OP_SCHEMAS } from './index';

export function generateRust(input: GeneratorInput): Array<{ filename: string; content: string }> {
  const baseUrl = input.baseUrl ?? 'http://127.0.0.1:8765';

  const methods = OP_SCHEMAS.map((op) => {
    const methodName = op.op.replace(/\./g, '_');
    const params = op.required.map((r) => `${r}: &str`).join(', ');
    const fields = op.required.map((r) => `"${r}": ${r}`).join(', ');
    return `    pub async fn ${methodName}(&self, ${params}) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let payload = serde_json::json!({"op": "${op.op}", ${fields}});
        self.send(payload).await
    }`;
  }).join('\n\n');

  const content = `// ProxyForge API client — auto-generated. Do not edit by hand.
use serde_json::Value;

pub struct ProxyForgeClient {
    base_url: String,
    token: Option<String>,
    client: reqwest::Client,
}

impl ProxyForgeClient {
    pub fn new(base_url: &str, token: Option<&str>) -> Self {
        Self {
            base_url: base_url.to_string(),
            token: token.map(|t| t.to_string()),
            client: reqwest::Client::new(),
        }
    }

    pub fn default() -> Self { Self::new("${baseUrl}", None) }

    async fn send(&self, payload: Value) -> Result<Value, Box<dyn std::error::Error>> {
        let mut req = self.client.post(format!("{}/rpc", self.base_url))
            .json(&payload);
        if let Some(token) = &self.token {
            req = req.header("Authorization", format!("Bearer {}", token));
        }
        Ok(req.send().await?.json().await?)
    }

${methods}
}
`;

  return [{ filename: 'proxyforge_client.rs', content }];
}
