// Java client stub generator (Gradle module, jakarta.json + records).
import type { GeneratorInput } from './index';
import { OP_SCHEMAS } from './index';

export function generateJava(input: GeneratorInput): Array<{ filename: string; content: string }> {
  const baseUrl = input.baseUrl ?? 'http://127.0.0.1:8765';
  const pkg = (input.namespace ?? 'com.proxyforge.client').replace(/-/g, '.');

  const methods = OP_SCHEMAS.map((op) => {
    const methodName = op.op.replace(/\./g, '_');
    const params = op.required.map((r) => `String ${r}`).join(', ');
    // Build the Java string-concatenation expression for the JSON body.
    // e.g. for required=['projectId','listen']:
    //   "{"+"\"op\":\"proxy.start\""+","+"\"projectId\":\""+projectId+"\""...+"}"
    const opPart = '"\\"op\\":\\"' + op.op + '\\""';
    const requiredParts = op.required.map((r) => '","' + '+"\\"' + r + '\\":\\""+' + r + '+"\\"');
    const bodyExpr = '"{"' + '+' + opPart + requiredParts.join('') + '+"}"';
    return [
      '  public JsonObject ' + methodName + '(' + params + ') throws IOException {',
      '    String body = ' + bodyExpr + ';',
      '    return send(body);',
      '  }',
    ].join('\n');
  }).join('\n\n');

  const content = `// ProxyForge API client — auto-generated. Do not edit by hand.
package ${pkg};

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import jakarta.json.*;

public class ProxyForgeClient {
  private final String baseUrl;
  private final String token;

  public ProxyForgeClient(String baseUrl, String token) {
    this.baseUrl = baseUrl;
    this.token = token;
  }

  public ProxyForgeClient() { this("${baseUrl}", null); }

  private JsonObject send(String body) throws IOException {
    URL url = new URL(baseUrl + "/rpc");
    HttpURLConnection conn = (HttpURLConnection) url.openConnection();
    conn.setRequestMethod("POST");
    conn.setRequestProperty("Content-Type", "application/json");
    if (token != null) conn.setRequestProperty("Authorization", "Bearer " + token);
    conn.setDoOutput(true);
    try (OutputStream os = conn.getOutputStream()) {
      os.write(body.getBytes(StandardCharsets.UTF_8));
    }
    try (InputStream is = conn.getInputStream();
         JsonReader jr = Json.createReader(is)) {
      return jr.readObject();
    }
  }

${methods}
}
`;

  return [{ filename: 'ProxyForgeClient.java', content }];
}
