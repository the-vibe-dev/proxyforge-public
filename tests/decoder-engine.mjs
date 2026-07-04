import { strict as assert } from 'node:assert';
import { webcrypto } from 'node:crypto';
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

function stringify(value) {
  return typeof value === 'string' ? value : JSON.stringify(value);
}

function base64url(bytes) {
  return Buffer.from(bytes).toString('base64url');
}

async function buildDirectJwe(payload, keyBytes, header = { typ: 'JWE', alg: 'dir', enc: 'A256GCM' }) {
  const protectedHeader = Buffer.from(JSON.stringify(header), 'utf8').toString('base64url');
  const iv = Uint8Array.from([3, 8, 13, 21, 34, 55, 89, 144, 1, 2, 3, 5]);
  const key = await webcrypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt']);
  const encrypted = new Uint8Array(await webcrypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: new TextEncoder().encode(protectedHeader), tagLength: 128 },
    key,
    new TextEncoder().encode(payload),
  ));
  const ciphertext = encrypted.slice(0, encrypted.length - 16);
  const tag = encrypted.slice(encrypted.length - 16);
  return [protectedHeader, '', base64url(iv), base64url(ciphertext), base64url(tag)].join('.');
}

async function callOptionalHelper(moduleExports, name, args) {
  const helper = moduleExports[name];
  if (typeof helper !== 'function') return false;
  return helper(...args);
}

async function assertOptionalHelper(moduleExports, name, args, expectedPattern) {
  const result = await callOptionalHelper(moduleExports, name, args);
  if (!result) return false;
  const serialized = stringify(result);
  assert.match(serialized, expectedPattern, `${name} should expose advanced Decoder parity evidence`);
  return result;
}

const decoderEngine = await loadDecoderEngine();
const { decoderTransforms, runDecoderTransform } = decoderEngine;

assert(Array.isArray(decoderTransforms), 'decoderTransforms should be exported');
assert.equal(typeof runDecoderTransform, 'function', 'runDecoderTransform should be exported');
for (const id of ['base64-decode', 'url-decode', 'hex-decode', 'json-pretty', 'jwt-decode', 'sha-256', 'canonicalize']) {
  assert(decoderTransforms.some((transform) => transform.id === id), `${id} transform should be registered`);
}

const profile = JSON.stringify({ role: 'support_admin', scope: '*.shop.local' });
const encodedProfile = Buffer.from(profile, 'utf8').toString('base64');
const decoded = await runDecoderTransform('base64-decode', encodedProfile);
assert.equal(decoded.ok, true);
assert.match(decoded.output, /support_admin/);
assert.match(decoded.notes.join(' '), /Base64/i);

const recursivePayload = encodeURIComponent(encodedProfile);
const canonical = await runDecoderTransform('canonicalize', recursivePayload);
assert.equal(canonical.ok, true);
assert.match(canonical.output, /support_admin|shop\.local/);
assert.match(canonical.notes.join(' '), /URL|Base64|JSON|canonical/i);

const jwt = [
  Buffer.from(JSON.stringify({ typ: 'JWT', alg: 'HS256' }), 'utf8').toString('base64url'),
  Buffer.from(JSON.stringify({ sub: 'acct_123', role: 'support_admin' }), 'utf8').toString('base64url'),
  'preview-signature',
].join('.');
const jwtDecoded = await runDecoderTransform('jwt-decode', jwt);
assert.equal(jwtDecoded.ok, true);
assert.match(jwtDecoded.output, /Header/);
assert.match(jwtDecoded.output, /Payload/);
assert.match(jwtDecoded.output, /support_admin/);
assert.match(jwtDecoded.output, /Signature/);

const hexDecoded = await runDecoderTransform('hex-decode', Buffer.from('refund=42', 'utf8').toString('hex'));
assert.equal(hexDecoded.ok, true);
assert.equal(hexDecoded.output, 'refund=42');

const pretty = await runDecoderTransform('json-pretty', '{"z":2,"a":1}');
assert.equal(pretty.ok, true);
assert(pretty.output.indexOf('"a"') < pretty.output.indexOf('"z"'), 'json-pretty should sort object keys');

const hash = await runDecoderTransform('sha-256', profile);
assert.equal(hash.ok, true);
assert.match(hash.output, /^[a-f0-9]{64}$/);

const invalidBase64 = await runDecoderTransform('base64-decode', '%%%%');
assert.equal(invalidBase64.ok, false);
assert.equal(invalidBase64.output, '%%%%');
assert.match(invalidBase64.notes.join(' '), /valid Base64/i);

const analysis = await assertOptionalHelper(decoderEngine, 'analyzeDecoderInput', [recursivePayload], /base64|url|json|confidence|recipe|encoding/i);
const recipe =
  await assertOptionalHelper(decoderEngine, 'buildDecoderSmartRecipe', [recursivePayload, 'Advanced Decoder parity'], /url|base64|recursive|recipe|transform/i)
  || await assertOptionalHelper(decoderEngine, 'buildRecursiveTransformRecipe', [recursivePayload], /url|base64|recursive|recipe|transform/i);
const jwtWorkspace =
  await assertOptionalHelper(decoderEngine, 'buildDecoderJwtWorkspace', [jwt], /jwt|jws|jwe|signature|HS256|claims|signing/i)
  || await assertOptionalHelper(decoderEngine, 'buildJwtSigningPreview', [jwt, { algorithm: 'HS256', secret: 'preview-secret' }], /jwt|jws|jwe|signature|HS256|claims/i);
let editedJwtWorkspace = jwtWorkspace || undefined;
let editedJweWorkspace;
if (typeof decoderEngine.buildDecoderJwtWorkspace === 'function') {
  editedJwtWorkspace = await decoderEngine.buildDecoderJwtWorkspace(
    jwt,
    JSON.stringify({ typ: 'JWT', alg: 'HS256' }, null, 2),
    JSON.stringify({ sub: 'acct_123', role: 'admin', scope: 'refunds.write' }, null, 2),
    'preview-secret',
  );
  assert.equal(editedJwtWorkspace.tokenType, 'jws');
  assert.equal(editedJwtWorkspace.status, 'signed-preview');
  assert.equal(editedJwtWorkspace.algorithm, 'HS256');
  assert.match(editedJwtWorkspace.payloadJson, /refunds\.write/);
  assert.equal(editedJwtWorkspace.signedTokenPreview.split('.').length, 3);
  assert.notEqual(editedJwtWorkspace.signedTokenPreview, jwt);
  assert.match(editedJwtWorkspace.summary, /JWT\/JWS workspace ready/i);

  const jwe = [
    Buffer.from(JSON.stringify({ typ: 'JWE', alg: 'dir', enc: 'A256GCM' }), 'utf8').toString('base64url'),
    'encrypted-key',
    'initialization-vector',
    'ciphertext',
    'authentication-tag',
  ].join('.');
  const jweWorkspace = await decoderEngine.buildDecoderJwtWorkspace(jwe);
  assert.equal(jweWorkspace.tokenType, 'jwe');
  assert.equal(jweWorkspace.status, 'jwe-key-required');
  assert.equal(jweWorkspace.signedTokenPreview, jwe);
  assert.match(jweWorkspace.headerJson, /A256GCM|dir/);
  assert.match(jweWorkspace.payloadJson, /requires an operator-supplied direct AES-GCM key/i);
  assert.match(jweWorkspace.notes.join(' '), /preserved|supply a 32-byte direct key/i);
  assert.equal(jweWorkspace.reportReady, true);

  const jweKey = Uint8Array.from(Array.from({ length: 32 }, (_value, index) => index + 1));
  const jweKeyMaterial = `base64url:${base64url(jweKey)}`;
  const encryptedClaims = JSON.stringify({ sub: 'acct_123', scope: 'profile.read', role: 'viewer' });
  const directJwe = await buildDirectJwe(encryptedClaims, jweKey);
  const decryptedJweWorkspace = await decoderEngine.buildDecoderJwtWorkspace(directJwe, undefined, undefined, jweKeyMaterial);
  assert.equal(decryptedJweWorkspace.tokenType, 'jwe');
  assert.equal(decryptedJweWorkspace.status, 'jwe-decrypted');
  assert.equal(decryptedJweWorkspace.signedTokenPreview, directJwe);
  assert.match(decryptedJweWorkspace.headerJson, /A256GCM|dir/);
  assert.match(decryptedJweWorkspace.payloadJson, /profile\.read|viewer/);
  assert.match(decryptedJweWorkspace.notes.join(' '), /Decrypted the compact JWE payload/i);

  editedJweWorkspace = await decoderEngine.buildDecoderJwtWorkspace(
    directJwe,
    undefined,
    JSON.stringify({ sub: 'acct_123', scope: 'refunds.write', role: 'support_admin' }),
    jweKeyMaterial,
  );
  assert.equal(editedJweWorkspace.status, 'jwe-reencrypted');
  assert.notEqual(editedJweWorkspace.signedTokenPreview, directJwe);
  assert.equal(editedJweWorkspace.signedTokenPreview.split('.').length, 5);
  assert.equal(editedJweWorkspace.signedTokenPreview.split('.')[1], '');
  assert.match(editedJweWorkspace.summary, /decrypted, edited, and re-encrypted/i);

  const roundTripJweWorkspace = await decoderEngine.buildDecoderJwtWorkspace(editedJweWorkspace.signedTokenPreview, undefined, undefined, jweKeyMaterial);
  assert.equal(roundTripJweWorkspace.status, 'jwe-decrypted');
  assert.match(roundTripJweWorkspace.payloadJson, /refunds\.write|support_admin/);
}
const binaryInspection = await assertOptionalHelper(
  decoderEngine,
  'inspectDecoderBinary',
  [Buffer.from('refund=42', 'utf8').toString('hex')],
  /hex|byte|offset|ascii|refund|printable/i,
);
await assertOptionalHelper(decoderEngine, 'analyzeHashEncoding', [recursivePayload], /sha|base64|hex|encoding|hash/i);

let libraryPackage = false;
if (typeof decoderEngine.buildDecoderTransformLibraryPackage === 'function') {
  libraryPackage = decoderEngine.buildDecoderTransformLibraryPackage(
    recipe ? [recipe] : [],
    analysis ? [analysis] : [],
    jwtWorkspace ? [jwtWorkspace] : [],
    binaryInspection ? [binaryInspection] : [],
    '2026-05-24T12:00:00.000Z',
  );
  assert.match(stringify(libraryPackage), /proxyforge-decoder|transform|recipe|package|library/i);
} else {
  libraryPackage = await assertOptionalHelper(decoderEngine, 'buildDecoderTransformPackage', [{
    name: 'Advanced Decoder parity',
    transforms: ['url-decode', 'base64-decode', 'json-pretty'],
    evidence: [{ title: 'support_admin recursive decode', output: profile }],
  }], /proxyforge-decoder|transform|recipe|package|digest/i);
}

let reportExport = false;
if (typeof decoderEngine.buildDecoderReportExport === 'function') {
  reportExport = decoderEngine.buildDecoderReportExport(
    analysis || undefined,
    recipe || undefined,
    editedJwtWorkspace || jwtWorkspace || undefined,
    binaryInspection || undefined,
    libraryPackage || undefined,
    'issue-decoder-advanced',
    '2026-05-24T12:05:00.000Z',
  );
  assert.match(stringify(reportExport), /Decoder|evidence|report|recipe|JWT|binary|hash|handoff/i);
} else {
  await assertOptionalHelper(decoderEngine, 'buildDecoderReportEvidence', [{
    title: 'Advanced Decoder parity evidence',
    recipe: ['url-decode', 'base64-decode', 'json-pretty'],
    jwt,
    binaryHex: Buffer.from('refund=42', 'utf8').toString('hex'),
  }], /Decoder|evidence|report|recipe|JWT|binary|hash/i);
}

assert.equal(typeof decoderEngine.buildDecoderParityEvidencePackage, 'function', 'Decoder parity evidence package builder should be exported');
const decoderParityPackage = decoderEngine.buildDecoderParityEvidencePackage({
  analysis: analysis || undefined,
  recipe: recipe || undefined,
  jwtWorkspace: editedJwtWorkspace || jwtWorkspace || undefined,
  jweWorkspace: editedJweWorkspace,
  binaryInspection: binaryInspection || undefined,
  libraryPackage: libraryPackage || undefined,
  reportExport: reportExport || undefined,
  operationalSecretSamples: [
    'Authorization: Bearer decoder-live-token',
    'Cookie: session=decoder-live-cookie',
    'JWE-Key: base64url:executor-direct-aes-key-material',
    'HS256-Secret: preview-secret',
  ],
  exportedAt: '2026-05-24T12:10:00.000Z',
});
assert.equal(decoderParityPackage.kind, 'proxyforge-decoder-parity-evidence-package');
assert.equal(decoderParityPackage.reportReady, true);
for (const [name, covered] of Object.entries(decoderParityPackage.requirements)) {
  assert.equal(covered, true, `Decoder parity requirement ${name} should be covered`);
}
assert.match(decoderParityPackage.content, /base64url:executor-direct-aes-key-material|preview-secret/);
assert.match(decoderParityPackage.content, /redact-only-during-report-export/);
assert(decoderParityPackage.transformCategories.every((category) => category.count > 0), 'all Decoder transform categories should be represented');

const decoderArtifactDir = path.resolve('.gitignored/test-artifacts/decoder-engine');
await fs.mkdir(decoderArtifactDir, { recursive: true });
await fs.writeFile(
  path.join(decoderArtifactDir, 'decoder-parity-evidence-package.json'),
  JSON.stringify(decoderParityPackage, null, 2),
);
console.log('decoder-engine: parity evidence package covered and written');
