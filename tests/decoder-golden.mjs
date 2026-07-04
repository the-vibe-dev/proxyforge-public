import { strict as assert } from 'node:assert';
import { createHash, webcrypto } from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { createRequire } from 'node:module';
import vm from 'node:vm';

const require = createRequire(import.meta.url);
const ts = require('typescript');

function createDocumentStub() {
  return {
    createElement() {
      let html = '';
      return {
        set innerHTML(value) {
          html = String(value);
        },
        get value() {
          return html
            .replace(/&quot;/g, '"')
            .replace(/&#39;/g, "'")
            .replace(/&lt;/g, '<')
            .replace(/&gt;/g, '>')
            .replace(/&amp;/g, '&');
        },
      };
    },
  };
}

async function loadDecoderEngine() {
  const enginePath = path.resolve('src/decoderEngine.ts');
  const source = await fs.readFile(enginePath, 'utf8');
  const transpiled = ts.transpileModule(source, {
    compilerOptions: {
      module: ts.ModuleKind.CommonJS,
      target: ts.ScriptTarget.ES2022,
      esModuleInterop: true,
    },
    fileName: enginePath,
  }).outputText;
  const module = { exports: {} };
  const sandbox = {
    module,
    exports: module.exports,
    TextDecoder,
    TextEncoder,
    atob: globalThis.atob,
    btoa: globalThis.btoa,
    crypto: globalThis.crypto ?? webcrypto,
    document: createDocumentStub(),
  };
  vm.runInNewContext(transpiled, sandbox, { filename: enginePath });
  return module.exports;
}

function base64(value) {
  return Buffer.from(value, 'utf8').toString('base64');
}

function base64urlJson(value) {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
}

function htmlDelimitedHex(value) {
  return Buffer.from(value, 'utf8').toString('hex').match(/.{2}/g).join(' &amp; ');
}

const profileJson = JSON.stringify({ scope: '*.shop.local', role: 'support_admin', account: 'acct_123' });
const profileExpected = [
  '{',
  '  "account": "acct_123",',
  '  "role": "support_admin",',
  '  "scope": "*.shop.local"',
  '}',
].join('\n');
const jwt = [
  base64urlJson({ typ: 'JWT', alg: 'HS256' }),
  base64urlJson({ sub: 'acct_123', role: 'support_admin' }),
  'preview-signature',
].join('.');
const jwtExpected = [
  'Header',
  '{',
  '  "alg": "HS256",',
  '  "typ": "JWT"',
  '}',
  '',
  'Payload',
  '{',
  '  "role": "support_admin",',
  '  "sub": "acct_123"',
  '}',
  '',
  'Signature: preview-signature',
].join('\n');
const secretText = 'Authorization: Bearer agent-secret-token\nCookie: session=agent-secret-session';
const secretHash = createHash('sha256').update(secretText).digest('hex');
const prettyInput = '{"z":2,"a":1}';
const prettyExpected = '{\n  "a": 1,\n  "z": 2\n}';
const encodedPrettyExpected = base64(encodeURIComponent(prettyExpected));

const decoderEngine = await loadDecoderEngine();
assert.equal(typeof decoderEngine.runDecoderTransformChain, 'function', 'Decoder transform chain runner should be exported');
assert.equal(typeof decoderEngine.buildDecoderGoldenCorpusPackage, 'function', 'Decoder golden corpus package builder should be exported');

const directChain = await decoderEngine.runDecoderTransformChain({
  name: 'URL/Base64/JSON recursive decode',
  input: encodeURIComponent(base64(profileJson)),
  transformIds: ['url-decode', 'base64-decode', 'json-pretty'],
  createdAt: '2026-05-25T14:00:00.000Z',
});
assert.equal(directChain.kind, 'proxyforge-decoder-transform-chain-run');
assert.equal(directChain.ok, true);
assert.equal(directChain.finalOutput, profileExpected);
assert.match(directChain.content, /url-decode|base64-decode|json-pretty|redact-only-during-report-export/);

const failedChain = await decoderEngine.runDecoderTransformChain({
  name: 'Invalid Base64 guard',
  input: '%%%%',
  transformIds: ['base64-decode', 'json-pretty'],
  createdAt: '2026-05-25T14:00:00.000Z',
});
assert.equal(failedChain.ok, false);
assert.equal(failedChain.failedStepIndex, 1);
assert.equal(failedChain.finalOutput, '%%%%');
assert.match(failedChain.summary, /stopped at step 1/i);

const cases = [
  {
    id: 'url-base64-json',
    name: 'URL encoded Base64 JSON profile',
    input: encodeURIComponent(base64(profileJson)),
    transformIds: ['url-decode', 'base64-decode', 'json-pretty'],
    expectedOutput: profileExpected,
    operationalSecretSamples: ['Authorization: Bearer agent-secret-token'],
  },
  {
    id: 'html-hex-json',
    name: 'HTML-delimited hex JSON body',
    input: htmlDelimitedHex('{"op":"refund","guard":"amp-safe"}'),
    transformIds: ['html-decode', 'hex-decode', 'json-pretty'],
    expectedOutput: '{\n  "guard": "amp-safe",\n  "op": "refund"\n}',
    operationalSecretSamples: ['Cookie: session=agent-secret-session'],
  },
  {
    id: 'jwt-decode',
    name: 'JWT/JWS compact decode',
    input: jwt,
    transformIds: ['jwt-decode'],
    expectedOutput: jwtExpected,
  },
  {
    id: 'decode-and-hash',
    name: 'Base64 operational secret hash',
    input: base64(secretText),
    transformIds: ['base64-decode', 'sha-256'],
    expectedOutput: secretHash,
    operationalSecretSamples: ['X-API-Key: agent-secret-key'],
  },
  {
    id: 'format-url-base64-encode',
    name: 'Pretty JSON then URL/Base64 encode',
    input: prettyInput,
    transformIds: ['json-pretty', 'url-encode', 'base64-encode'],
    expectedOutput: encodedPrettyExpected,
  },
];

const goldenPackage = await decoderEngine.buildDecoderGoldenCorpusPackage(cases, '2026-05-25T14:05:00.000Z');
assert.equal(goldenPackage.kind, 'proxyforge-decoder-golden-corpus-package');
assert.equal(goldenPackage.caseCount, cases.length);
assert.equal(goldenPackage.passedCount, cases.length);
assert.equal(goldenPackage.failedCount, 0);
assert.equal(goldenPackage.reportReady, true);
for (const [name, covered] of Object.entries(goldenPackage.requirements)) {
  assert.equal(covered, true, `Decoder golden corpus requirement ${name} should be covered`);
}
assert.match(goldenPackage.content, /agent-secret-token|agent-secret-session|agent-secret-key/);
assert.match(goldenPackage.content, /execution-full-fidelity-secrets-preserved/);
assert.match(goldenPackage.content, /redact-only-during-report-export/);
assert.match(goldenPackage.summary, /5\/5 Decoder transform-chain golden cases passed/);

const artifactDir = path.resolve('.gitignored/test-artifacts/decoder-golden');
await fs.mkdir(artifactDir, { recursive: true });
await fs.writeFile(
  path.join(artifactDir, 'decoder-golden-corpus.json'),
  JSON.stringify(goldenPackage, null, 2),
);
console.log('decoder-golden: transform chain corpus passed and artifact written');
