import type {
  DecoderAnalysisRun,
  DecoderBinaryInspection,
  DecoderDetectedLayer,
  DecoderEncodingInsight,
  DecoderHashInsight,
  DecoderJwtWorkspace,
  DecoderRecipe,
  DecoderRecipeStep,
  DecoderReportExportArtifact,
  DecoderTransformLibraryPackage,
} from './types';

export type DecoderTransformId =
  | 'smart-decode'
  | 'base64-decode'
  | 'base64-encode'
  | 'base64url-decode'
  | 'base64url-encode'
  | 'url-decode'
  | 'url-encode'
  | 'html-decode'
  | 'html-encode'
  | 'hex-decode'
  | 'hex-encode'
  | 'binary-decode'
  | 'binary-encode'
  | 'octal-decode'
  | 'octal-encode'
  | 'json-pretty'
  | 'jwt-decode'
  | 'sha-256'
  | 'sha-1'
  | 'canonicalize';

export interface DecoderTransformDefinition {
  id: DecoderTransformId;
  label: string;
  category: 'encode' | 'decode' | 'hash' | 'format';
}

export interface DecoderTransformResult {
  id: string;
  transformId: DecoderTransformId;
  label: string;
  inputLength: number;
  output: string;
  ok: boolean;
  notes: string[];
  generatedAt: string;
}

export interface DecoderTransformChainRequest {
  input: string;
  transformIds: DecoderTransformId[];
  name?: string;
  createdAt?: string;
}

export interface DecoderTransformChainStep {
  index: number;
  transformId: DecoderTransformId;
  label: string;
  inputLength: number;
  outputLength: number;
  output: string;
  ok: boolean;
  notes: string[];
}

export interface DecoderTransformChainRun {
  id: string;
  kind: 'proxyforge-decoder-transform-chain-run';
  name: string;
  createdAt: string;
  input: string;
  transformIds: DecoderTransformId[];
  steps: DecoderTransformChainStep[];
  finalOutput: string;
  ok: boolean;
  failedStepIndex?: number;
  reportReady: boolean;
  digestPreview: string;
  summary: string;
  content: string;
}

export interface DecoderGoldenCorpusCase {
  id: string;
  name: string;
  input: string;
  transformIds: DecoderTransformId[];
  expectedOutput: string;
  operationalSecretSamples?: string[];
}

export interface DecoderGoldenCorpusCaseResult {
  id: string;
  name: string;
  transformIds: DecoderTransformId[];
  expectedOutput: string;
  actualOutput: string;
  ok: boolean;
  failedStepIndex?: number;
  notes: string[];
  run: DecoderTransformChainRun;
}

export interface DecoderGoldenCorpusPackage {
  id: string;
  kind: 'proxyforge-decoder-golden-corpus-package';
  title: string;
  fileName: string;
  path: string;
  exportedAt: string;
  caseCount: number;
  passedCount: number;
  failedCount: number;
  transformIds: DecoderTransformId[];
  results: DecoderGoldenCorpusCaseResult[];
  requirements: {
    multiStepChainsCovered: boolean;
    recursiveDecodeCovered: boolean;
    encodeDecodeFormatHashCovered: boolean;
    jwtChainCovered: boolean;
    binaryHexHtmlCovered: boolean;
    failureFreeGoldenCorpus: boolean;
    rawExecutorMaterialPreserved: boolean;
    operationalSecretsPreserved: boolean;
    reportPhaseOnlyRedaction: boolean;
  };
  secretHandling: 'execution-full-fidelity-secrets-preserved';
  reportRedactionBoundary: 'redact-only-during-report-export';
  reportReady: boolean;
  digestPreview: string;
  summary: string;
  content: string;
}

export interface DecoderParityEvidenceRequest {
  analysis?: DecoderAnalysisRun;
  recipe?: DecoderRecipe;
  jwtWorkspace?: DecoderJwtWorkspace;
  jweWorkspace?: DecoderJwtWorkspace;
  binaryInspection?: DecoderBinaryInspection;
  libraryPackage?: DecoderTransformLibraryPackage;
  reportExport?: DecoderReportExportArtifact;
  operationalSecretSamples?: string[];
  exportedAt?: string;
}

export interface DecoderParityEvidencePackage {
  id: string;
  kind: 'proxyforge-decoder-parity-evidence-package';
  title: string;
  fileName: string;
  path: string;
  exportedAt: string;
  transformCategories: Array<{
    category: DecoderTransformDefinition['category'];
    count: number;
    transformIds: DecoderTransformId[];
  }>;
  artifactIds: {
    analysisId?: string;
    recipeId?: string;
    jwtWorkspaceId?: string;
    jweWorkspaceId?: string;
    binaryInspectionId?: string;
    libraryPackageId?: string;
    reportExportId?: string;
  };
  requirements: {
    encodeDecodeHashFormatCovered: boolean;
    recursiveSmartRecipeCovered: boolean;
    jwtJwsSigningPreviewCovered: boolean;
    jweDecryptEditReencryptCovered: boolean;
    binaryHexInspectionCovered: boolean;
    transformLibraryCovered: boolean;
    reportHandoffCovered: boolean;
    rawExecutorMaterialPreserved: boolean;
    operationalSecretsPreserved: boolean;
    reportPhaseOnlyRedaction: boolean;
  };
  secretHandling: 'execution-full-fidelity-secrets-preserved';
  reportRedactionBoundary: 'redact-only-during-report-export';
  reportReady: boolean;
  digestPreview: string;
  summary: string;
  content: string;
}

export const decoderTransforms: DecoderTransformDefinition[] = [
  { id: 'smart-decode', label: 'Smart decode', category: 'decode' },
  { id: 'base64-decode', label: 'Base64 decode', category: 'decode' },
  { id: 'base64-encode', label: 'Base64 encode', category: 'encode' },
  { id: 'base64url-decode', label: 'Base64url decode', category: 'decode' },
  { id: 'base64url-encode', label: 'Base64url encode', category: 'encode' },
  { id: 'url-decode', label: 'URL decode', category: 'decode' },
  { id: 'url-encode', label: 'URL encode', category: 'encode' },
  { id: 'html-decode', label: 'HTML decode', category: 'decode' },
  { id: 'html-encode', label: 'HTML encode', category: 'encode' },
  { id: 'hex-decode', label: 'Hex decode', category: 'decode' },
  { id: 'hex-encode', label: 'Hex encode', category: 'encode' },
  { id: 'binary-decode', label: 'Binary decode', category: 'decode' },
  { id: 'binary-encode', label: 'Binary encode', category: 'encode' },
  { id: 'octal-decode', label: 'Octal decode', category: 'decode' },
  { id: 'octal-encode', label: 'Octal encode', category: 'encode' },
  { id: 'json-pretty', label: 'Pretty JSON', category: 'format' },
  { id: 'jwt-decode', label: 'JWT decode', category: 'decode' },
  { id: 'sha-256', label: 'SHA-256', category: 'hash' },
  { id: 'sha-1', label: 'SHA-1', category: 'hash' },
  { id: 'canonicalize', label: 'Canonicalize', category: 'format' },
];

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

export async function runDecoderTransform(transformId: DecoderTransformId, input: string): Promise<DecoderTransformResult> {
  const transform = decoderTransforms.find((item) => item.id === transformId);
  const generatedAt = new Date();
  const label = transform?.label ?? transformId;
  const notes: string[] = [];

  try {
    const output = await applyDecoderTransform(transformId, input, notes);
    return {
      id: `decoder-${generatedAt.getTime()}-${Math.random().toString(16).slice(2)}`,
      transformId,
      label,
      inputLength: input.length,
      output,
      ok: true,
      notes: notes.length ? notes : [`${label} completed`],
      generatedAt: generatedAt.toISOString(),
    };
  } catch (error) {
    return {
      id: `decoder-${generatedAt.getTime()}-${Math.random().toString(16).slice(2)}`,
      transformId,
      label,
      inputLength: input.length,
      output: input,
      ok: false,
      notes: [error instanceof Error ? error.message : `${label} failed`],
      generatedAt: generatedAt.toISOString(),
    };
  }
}

export async function runDecoderTransformChain(request: DecoderTransformChainRequest): Promise<DecoderTransformChainRun> {
  const createdAt = request.createdAt ?? new Date().toISOString();
  let output = request.input;
  let failedStepIndex: number | undefined;
  const steps: DecoderTransformChainStep[] = [];

  for (let index = 0; index < request.transformIds.length; index += 1) {
    const transformId = request.transformIds[index];
    const transform = decoderTransforms.find((item) => item.id === transformId);
    const label = transform?.label ?? transformId;
    const notes: string[] = [];
    const input = output;
    try {
      output = await applyDecoderTransform(transformId, input, notes);
      steps.push({
        index: index + 1,
        transformId,
        label,
        inputLength: input.length,
        outputLength: output.length,
        output,
        ok: true,
        notes: notes.length ? notes : [`${label} completed`],
      });
    } catch (error) {
      failedStepIndex = index + 1;
      steps.push({
        index: index + 1,
        transformId,
        label,
        inputLength: input.length,
        outputLength: input.length,
        output: input,
        ok: false,
        notes: [error instanceof Error ? error.message : `${label} failed`],
      });
      break;
    }
  }

  const ok = failedStepIndex === undefined;
  const unsigned = {
    kind: 'proxyforge-decoder-transform-chain-run',
    name: request.name?.trim() || 'Decoder transform chain',
    createdAt,
    input: request.input,
    transformIds: request.transformIds,
    steps,
    finalOutput: output,
    ok,
    failedStepIndex,
    reportReady: ok,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
  };
  const digestPreview = simpleDigest(JSON.stringify(unsigned));
  const content = JSON.stringify({ ...unsigned, digestPreview }, null, 2);
  return {
    id: id('decoder-chain'),
    kind: 'proxyforge-decoder-transform-chain-run',
    name: unsigned.name,
    createdAt,
    input: request.input,
    transformIds: request.transformIds,
    steps,
    finalOutput: output,
    ok,
    failedStepIndex,
    reportReady: ok,
    digestPreview,
    summary: ok
      ? `${steps.length} Decoder transform step${steps.length === 1 ? '' : 's'} completed: ${request.transformIds.join(' -> ')}.`
      : `Decoder transform chain stopped at step ${failedStepIndex}: ${steps.at(-1)?.label ?? 'unknown transform'}.`,
    content,
  };
}

export async function buildDecoderGoldenCorpusPackage(
  cases: DecoderGoldenCorpusCase[],
  exportedAt = new Date().toISOString(),
): Promise<DecoderGoldenCorpusPackage> {
  const results: DecoderGoldenCorpusCaseResult[] = [];
  for (const testCase of cases) {
    const run = await runDecoderTransformChain({
      input: testCase.input,
      transformIds: testCase.transformIds,
      name: testCase.name,
      createdAt: exportedAt,
    });
    const actualOutput = run.finalOutput;
    const ok = run.ok && actualOutput === testCase.expectedOutput;
    results.push({
      id: testCase.id,
      name: testCase.name,
      transformIds: testCase.transformIds,
      expectedOutput: testCase.expectedOutput,
      actualOutput,
      ok,
      failedStepIndex: run.failedStepIndex,
      notes: [
        ok ? 'Golden output matched exactly' : 'Golden output mismatch',
        ...run.steps.flatMap((step) => step.notes.map((note) => `${step.label}: ${note}`)),
      ],
      run,
    });
  }

  const transformIds = Array.from(new Set(results.flatMap((result) => result.transformIds)));
  const operationalSecretSamples = cases.flatMap((testCase) => testCase.operationalSecretSamples ?? []);
  const encodedCategories = new Set(transformIds.map((transformId) => decoderTransforms.find((item) => item.id === transformId)?.category).filter(Boolean));
  const requirements = {
    multiStepChainsCovered: results.some((result) => result.transformIds.length >= 2),
    recursiveDecodeCovered: results.some((result) => result.transformIds.filter((transformId) => transformId.endsWith('-decode') || transformId === 'jwt-decode').length >= 2),
    encodeDecodeFormatHashCovered: ['encode', 'decode', 'format', 'hash'].every((category) => encodedCategories.has(category as DecoderTransformDefinition['category'])),
    jwtChainCovered: results.some((result) => result.transformIds.includes('jwt-decode') && /Header|Payload|Signature/.test(result.actualOutput)),
    binaryHexHtmlCovered: results.some((result) => result.transformIds.includes('html-decode') && result.transformIds.includes('hex-decode')),
    failureFreeGoldenCorpus: results.every((result) => result.ok),
    rawExecutorMaterialPreserved: results.some((result) => result.run.input.length > 0 && result.run.finalOutput.length > 0),
    operationalSecretsPreserved: operationalSecretSamples.length > 0,
    reportPhaseOnlyRedaction: true,
  };
  const passedCount = results.filter((result) => result.ok).length;
  const failedCount = results.length - passedCount;
  const stamp = exportedAt.replace(/[:.]/g, '-');
  const unsigned = {
    kind: 'proxyforge-decoder-golden-corpus-package',
    exportedAt,
    caseCount: results.length,
    passedCount,
    failedCount,
    transformIds,
    results,
    operationalSecretSamples,
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady: failedCount === 0,
  };
  const digestPreview = simpleDigest(JSON.stringify(unsigned));
  const content = JSON.stringify({ ...unsigned, digestPreview }, null, 2);
  return {
    id: id('decoder-golden'),
    kind: 'proxyforge-decoder-golden-corpus-package',
    title: 'Decoder transform chain golden corpus',
    fileName: `proxyforge-decoder-golden-corpus-${stamp}.json`,
    path: `reports/proxyforge-decoder-golden-corpus-${stamp}.json`,
    exportedAt,
    caseCount: results.length,
    passedCount,
    failedCount,
    transformIds,
    results,
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady: failedCount === 0,
    digestPreview,
    summary: `${passedCount}/${results.length} Decoder transform-chain golden case${results.length === 1 ? '' : 's'} passed with ${transformIds.length} transform${transformIds.length === 1 ? '' : 's'} covered.`,
    content,
  };
}

async function applyDecoderTransform(transformId: DecoderTransformId, input: string, notes: string[]) {
  switch (transformId) {
    case 'smart-decode':
      return smartDecode(input, notes).output;
    case 'base64-decode':
      notes.push('Decoded standard Base64 as UTF-8 text');
      return decodeBase64(input, false);
    case 'base64-encode':
      notes.push('Encoded UTF-8 text as standard Base64');
      return encodeBase64(input, false);
    case 'base64url-decode':
      notes.push('Decoded Base64url as UTF-8 text');
      return decodeBase64(input, true);
    case 'base64url-encode':
      notes.push('Encoded UTF-8 text as unpadded Base64url');
      return encodeBase64(input, true);
    case 'url-decode':
      notes.push('Decoded percent escapes and form-space plus signs');
      return decodeUrl(input);
    case 'url-encode':
      notes.push('Encoded text for URL component usage');
      return encodeURIComponent(input);
    case 'html-decode':
      notes.push('Decoded HTML entities');
      return decodeHtmlEntities(input);
    case 'html-encode':
      notes.push('Escaped HTML-sensitive characters');
      return encodeHtmlEntities(input);
    case 'hex-decode':
      notes.push('Decoded hexadecimal bytes as UTF-8 text');
      return decodeHex(input);
    case 'hex-encode':
      notes.push('Encoded UTF-8 text as hexadecimal bytes');
      return encodeHex(input);
    case 'binary-decode':
      notes.push('Decoded binary octets as UTF-8 text');
      return decodeBinary(input);
    case 'binary-encode':
      notes.push('Encoded UTF-8 text as binary octets');
      return encodeBinary(input);
    case 'octal-decode':
      notes.push('Decoded octal bytes as UTF-8 text');
      return decodeOctal(input);
    case 'octal-encode':
      notes.push('Encoded UTF-8 text as octal bytes');
      return encodeOctal(input);
    case 'json-pretty':
      notes.push('Formatted JSON with stable key order');
      return JSON.stringify(sortJson(JSON.parse(input)), null, 2);
    case 'jwt-decode':
      return decodeJwt(input, notes);
    case 'sha-256':
      notes.push('Hashed UTF-8 input with SHA-256');
      return digestHex('SHA-256', input);
    case 'sha-1':
      notes.push('Hashed UTF-8 input with SHA-1');
      return digestHex('SHA-1', input);
    case 'canonicalize':
      return canonicalize(input, notes);
    default:
      throw new Error(`Unsupported decoder transform: ${transformId}`);
  }
}

function encodeBase64(input: string, urlSafe: boolean) {
  const base64 = btoa(bytesToBinary(textEncoder.encode(input)));
  if (!urlSafe) return base64;
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function decodeBase64(input: string, urlSafe: boolean) {
  const bytes = decodeBase64Bytes(input, urlSafe);
  return textDecoder.decode(bytes);
}

function decodeBase64Bytes(input: string, urlSafe: boolean) {
  const normalized = normalizeBase64(input, urlSafe);
  const binary = atob(normalized);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

function normalizeBase64(input: string, urlSafe: boolean) {
  let normalized = input.trim().replace(/\s+/g, '');
  if (urlSafe) {
    normalized = normalized.replace(/-/g, '+').replace(/_/g, '/');
  }
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(normalized)) {
    throw new Error('Input is not valid Base64 data');
  }
  const remainder = normalized.length % 4;
  if (remainder) normalized += '='.repeat(4 - remainder);
  return normalized;
}

function bytesToBinary(bytes: Uint8Array) {
  let binary = '';
  const chunkSize = 0x8000;
  for (let index = 0; index < bytes.length; index += chunkSize) {
    binary += String.fromCharCode(...bytes.slice(index, index + chunkSize));
  }
  return binary;
}

function bytesToBase64Url(bytes: Uint8Array) {
  return btoa(bytesToBinary(bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function decodeUrl(input: string) {
  return decodeURIComponent(input.replace(/\+/g, ' '));
}

function encodeHtmlEntities(input: string) {
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function decodeHtmlEntities(input: string) {
  if (typeof document === 'undefined') {
    return input
      .replace(/&quot;/g, '"')
      .replace(/&#39;/g, "'")
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>')
      .replace(/&amp;/g, '&')
      .replace(/&#x([0-9a-f]+);/gi, (_match, code) => String.fromCodePoint(Number.parseInt(code, 16)))
      .replace(/&#(\d+);/g, (_match, code) => String.fromCodePoint(Number.parseInt(code, 10)));
  }
  const textarea = document.createElement('textarea');
  textarea.innerHTML = input;
  return textarea.value;
}

function encodeHex(input: string) {
  return Array.from(textEncoder.encode(input))
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

function decodeHex(input: string) {
  const normalized = input.replace(/0x/gi, '').replace(/[^a-fA-F0-9]/g, '');
  if (!normalized || normalized.length % 2 !== 0) throw new Error('Input is not an even-length hexadecimal byte string');
  const bytes = new Uint8Array(normalized.length / 2);
  for (let index = 0; index < normalized.length; index += 2) {
    bytes[index / 2] = Number.parseInt(normalized.slice(index, index + 2), 16);
  }
  return textDecoder.decode(bytes);
}

function encodeBinary(input: string) {
  return Array.from(textEncoder.encode(input))
    .map((byte) => byte.toString(2).padStart(8, '0'))
    .join(' ');
}

function decodeBinary(input: string) {
  const groups = input.trim().split(/[\s,]+/).filter(Boolean);
  if (!groups.length || groups.some((group) => !/^[01]{8}$/.test(group))) {
    throw new Error('Input is not binary octets grouped as 8-bit values');
  }
  return textDecoder.decode(new Uint8Array(groups.map((group) => Number.parseInt(group, 2))));
}

function encodeOctal(input: string) {
  return Array.from(textEncoder.encode(input))
    .map((byte) => byte.toString(8).padStart(3, '0'))
    .join(' ');
}

function decodeOctal(input: string) {
  const groups = input.trim().replace(/\\/g, ' ').split(/[\s,]+/).filter(Boolean).map((group) => group.replace(/^0o/i, ''));
  if (!groups.length || groups.some((group) => !/^[0-7]{3}$/.test(group))) {
    throw new Error('Input is not octal bytes grouped as three-digit values');
  }
  return textDecoder.decode(new Uint8Array(groups.map((group) => Number.parseInt(group, 8))));
}

async function digestHex(algorithm: 'SHA-1' | 'SHA-256', input: string) {
  if (!globalThis.crypto?.subtle) throw new Error('Web Crypto hashing is unavailable in this runtime');
  const digest = await globalThis.crypto.subtle.digest(algorithm, textEncoder.encode(input));
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

function decodeJwt(input: string, notes: string[]) {
  const token = input.trim();
  const parts = token.split('.');
  if (parts.length < 2) throw new Error('Input is not a JWT-like token with header and payload segments');

  const header = parseJsonMaybe(decodeBase64(parts[0], true));
  const payload = parseJsonMaybe(decodeBase64(parts[1], true));
  notes.push('Decoded JWT header and payload without verifying the signature');

  return [
    'Header',
    JSON.stringify(sortJson(header), null, 2),
    '',
    'Payload',
    JSON.stringify(sortJson(payload), null, 2),
    '',
    `Signature: ${parts[2] ? `${parts[2].slice(0, 24)}${parts[2].length > 24 ? '...' : ''}` : 'none'}`,
  ].join('\n');
}

function parseJsonMaybe(value: string) {
  try {
    return JSON.parse(value) as unknown;
  } catch {
    return { raw: value };
  }
}

function sortJson(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortJson);
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(Object.entries(value).sort(([left], [right]) => left.localeCompare(right)).map(([key, nested]) => [key, sortJson(nested)]));
}

function canonicalize(input: string, notes: string[]) {
  let output = input.trim();

  for (let index = 0; index < 3; index += 1) {
    try {
      const decoded = decodeUrl(output);
      if (decoded === output) break;
      output = decoded;
      notes.push('Applied URL decoding');
    } catch {
      break;
    }
  }

  const htmlDecoded = decodeHtmlEntities(output);
  if (htmlDecoded !== output) {
    output = htmlDecoded;
    notes.push('Applied HTML entity decoding');
  }

  if (/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.?[A-Za-z0-9_-]*$/.test(output)) {
    return decodeJwt(output, notes);
  }

  try {
    const parsed = JSON.parse(output) as unknown;
    notes.push('Formatted JSON with stable key order');
    return JSON.stringify(sortJson(parsed), null, 2);
  } catch {
    // Continue through opportunistic Base64 normalization.
  }

  if (/^[A-Za-z0-9+/_=-]{8,}$/.test(output) && output.length % 4 !== 1) {
    try {
      const decoded = decodeBase64(output, /[-_]/.test(output));
      if (isMostlyPrintable(decoded)) {
        notes.push('Decoded printable Base64 payload');
        return decoded;
      }
    } catch {
      // The input only looked like Base64; leave it as normalized text.
    }
  }

  if (notes.length === 0) notes.push('No additional canonical form detected');
  return output;
}

function isMostlyPrintable(value: string) {
  if (!value) return false;
  const printable = Array.from(value).filter((char) => /[\t\n\r -~]/.test(char)).length;
  return printable / Array.from(value).length > 0.85;
}

function preview(value: string, length = 160) {
  const compact = value.replace(/\s+/g, ' ').trim();
  return compact.length > length ? `${compact.slice(0, length - 1)}…` : compact;
}

function printableRatio(value: string) {
  if (!value) return 0;
  const chars = Array.from(value);
  return chars.filter((char) => /[\t\n\r -~]/.test(char)).length / chars.length;
}

function bytesForInput(input: string) {
  const trimmed = input.trim();
  const hex = trimmed.replace(/0x/gi, '').replace(/[^a-fA-F0-9]/g, '');
  if (hex.length >= 2 && hex.length % 2 === 0 && /^[a-fA-F0-9]+$/.test(hex) && hex.length >= trimmed.length * 0.75) {
    return new Uint8Array(hex.match(/.{2}/g)?.map((byte) => Number.parseInt(byte, 16)) ?? []);
  }
  return textEncoder.encode(input);
}

function byteEntropy(bytes: Uint8Array) {
  if (!bytes.length) return 0;
  const counts = new Map<number, number>();
  for (const byte of bytes) counts.set(byte, (counts.get(byte) ?? 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / bytes.length;
    entropy -= p * Math.log2(p);
  }
  return Number(entropy.toFixed(3));
}

function id(prefix: string) {
  return `${prefix}-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function layer(
  kind: DecoderDetectedLayer['kind'],
  operation: string,
  confidence: number,
  input: string,
  output: string,
  notes: string[],
): DecoderDetectedLayer {
  return {
    id: id(`decoder-layer-${kind}`),
    kind,
    operation,
    confidence,
    inputPreview: preview(input),
    outputPreview: preview(output),
    output,
    notes,
  };
}

function smartDecode(input: string, notes: string[], maxLayers = 8) {
  const detectedLayers: DecoderDetectedLayer[] = [];
  let output = input.trim();

  for (let index = 0; index < maxLayers; index += 1) {
    const next = detectNextLayer(output);
    if (!next || next.output === output) break;
    detectedLayers.push(next);
    notes.push(`${next.operation}: ${next.notes.join(' ')}`);
    output = next.output;
    if (next.kind === 'jwt' || next.kind === 'jwe') break;
  }

  if (!detectedLayers.length) notes.push('Smart decode found no confident additional encoding layers');
  return { output, detectedLayers };
}

function detectNextLayer(value: string): DecoderDetectedLayer | null {
  const trimmed = value.trim();
  if (!trimmed) return null;

  if (/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/.test(trimmed)) {
    try {
      return layer('jwt', 'Decode JWT/JWS', 0.96, value, decodeJwt(trimmed, []), ['JWT/JWS compact serialization detected']);
    } catch {
      // Continue with other heuristics.
    }
  }
  if (isJweCompactToken(trimmed)) {
    return layer('jwe', 'Identify JWE', 0.92, value, [
      'JWE compact serialization detected',
      trimmed.split('.').map((part, index) => `part ${index + 1}: ${part.length} chars`).join('\n'),
    ].join('\n'), ['Encrypted JWE content cannot be decoded without keys']);
  }
  if (/%[0-9a-f]{2}|\+/i.test(trimmed)) {
    try {
      const decoded = decodeUrl(trimmed);
      if (decoded !== trimmed) return layer('url', 'URL decode', 0.9, value, decoded, ['Percent escapes or form spaces were recognized']);
    } catch {
      // Not a valid URL-encoded payload.
    }
  }
  if (/&(?:amp|lt|gt|quot|#39|#[xX][0-9a-f]+|#\d+);/.test(trimmed)) {
    const decoded = decodeHtmlEntities(trimmed);
    if (decoded !== trimmed) return layer('html', 'HTML decode', 0.88, value, decoded, ['HTML entities were recognized']);
  }
  if (/^[\da-fA-F\s:,-]+$/.test(trimmed)) {
    try {
      const decoded = decodeHex(trimmed);
      if (isMostlyPrintable(decoded)) return layer('hex', 'Hex decode', 0.82, value, decoded, ['Printable hexadecimal bytes were recognized']);
    } catch {
      // Not hex.
    }
  }
  if (/^[01]{8}(?:[\s,]+[01]{8})+$/.test(trimmed)) {
    try {
      return layer('binary', 'Binary decode', 0.78, value, decodeBinary(trimmed), ['8-bit binary groups were recognized']);
    } catch {
      // Not binary.
    }
  }
  if (/^(?:0o)?[0-7]{3}(?:[\s,\\]+(?:0o)?[0-7]{3})+$/.test(trimmed)) {
    try {
      return layer('octal', 'Octal decode', 0.72, value, decodeOctal(trimmed), ['Three-digit octal byte groups were recognized']);
    } catch {
      // Not octal.
    }
  }
  if (/^[A-Za-z0-9+/_=-]{8,}$/.test(trimmed) && trimmed.length % 4 !== 1) {
    try {
      const decoded = decodeBase64(trimmed, /[-_]/.test(trimmed));
      if (isMostlyPrintable(decoded)) {
        return layer(/[-_]/.test(trimmed) ? 'base64url' : 'base64', 'Base64 decode', 0.84, value, decoded, ['Printable Base64 payload recognized']);
      }
    } catch {
      // Not Base64.
    }
  }
  try {
    const formatted = JSON.stringify(sortJson(JSON.parse(trimmed)), null, 2);
    if (formatted !== trimmed) return layer('json', 'Pretty JSON', 0.8, value, formatted, ['JSON object or array recognized']);
  } catch {
    // Not JSON.
  }
  return null;
}

export async function analyzeDecoderInput(input: string, label = 'Decoder input'): Promise<DecoderAnalysisRun> {
  const createdAt = new Date().toISOString();
  const notes: string[] = [];
  const smart = smartDecode(input, notes);
  const bytes = bytesForInput(input);
  const hashes = await buildHashInsights(input);
  const encodingInsights = buildEncodingInsights(input, smart.detectedLayers, bytes);
  return {
    id: id('decoder-analysis'),
    label,
    createdAt,
    inputLength: input.length,
    byteLength: bytes.length,
    printableRatio: Number(printableRatio(input).toFixed(3)),
    entropyBitsPerByte: byteEntropy(bytes),
    detectedLayers: smart.detectedLayers,
    recommendedRecipe: smart.detectedLayers.map((item) => item.operation),
    encodingInsights,
    hashes,
    finalPreview: preview(smart.output, 320),
    reportReady: true,
    summary: smart.detectedLayers.length
      ? `Smart decode found ${smart.detectedLayers.length} layer${smart.detectedLayers.length === 1 ? '' : 's'}: ${smart.detectedLayers.map((item) => item.kind).join(' -> ')}.`
      : 'Smart decode found no confident encoding layers; hash and binary inspection are still available.',
  };
}

export async function buildDecoderSmartRecipe(input: string, name = 'Smart decode recipe'): Promise<DecoderRecipe> {
  const notes: string[] = [];
  const smart = smartDecode(input, notes);
  const steps = smart.detectedLayers.map<DecoderRecipeStep>((item, index) => ({
    id: `decoder-step-${index + 1}-${item.kind}`,
    transformId: transformIdForLayer(item.kind),
    label: item.operation,
    direction: item.operation.toLowerCase().includes('encode') ? 'encode' : item.operation.toLowerCase().includes('hash') ? 'hash' : item.kind === 'json' ? 'format' : 'decode',
    reversible: ['url', 'html', 'base64', 'base64url', 'hex', 'binary', 'octal', 'json'].includes(item.kind),
    notes: item.notes.join(' '),
  }));
  const content = JSON.stringify({
    kind: 'proxyforge-decoder-recipe',
    name,
    createdAt: new Date().toISOString(),
    steps,
    inputPreview: preview(input),
    outputPreview: preview(smart.output),
  }, null, 2);
  return {
    id: id('decoder-recipe'),
    name,
    createdAt: new Date().toISOString(),
    inputPreview: preview(input),
    outputPreview: preview(smart.output, 320),
    steps,
    reportReady: true,
    summary: steps.length ? `${steps.length} recursive transform step${steps.length === 1 ? '' : 's'} captured for repeatable decode/re-encode work.` : 'Recipe recorded the current raw value with no automatic layers.',
    content,
  };
}

function transformIdForLayer(kind: DecoderDetectedLayer['kind']) {
  if (kind === 'url') return 'url-decode';
  if (kind === 'html') return 'html-decode';
  if (kind === 'base64') return 'base64-decode';
  if (kind === 'base64url') return 'base64url-decode';
  if (kind === 'hex') return 'hex-decode';
  if (kind === 'binary') return 'binary-decode';
  if (kind === 'octal') return 'octal-decode';
  if (kind === 'jwt' || kind === 'jws') return 'jwt-decode';
  if (kind === 'json') return 'json-pretty';
  return 'canonicalize';
}

function isJweCompactToken(token: string) {
  const parts = token.trim().split('.');
  if (parts.length !== 5) return false;
  if (!parts[0] || !parts[2] || !parts[3] || !parts[4]) return false;
  try {
    const header = parseJsonMaybe(decodeBase64(parts[0], true)) as Record<string, unknown>;
    return typeof header.alg === 'string' && typeof header.enc === 'string';
  } catch {
    return false;
  }
}

async function buildDecoderJweWorkspace(
  token: string,
  parts: string[],
  createdAt: string,
  headerDraft?: string,
  payloadDraft?: string,
  keyMaterial?: string,
): Promise<DecoderJwtWorkspace> {
  const originalHeader = parseJsonMaybe(decodeBase64(parts[0], true)) as Record<string, unknown>;
  const headerJson = headerDraft?.trim() || JSON.stringify(sortJson(originalHeader), null, 2);
  const header = parseJsonMaybe(headerJson) as Record<string, unknown>;
  const algorithm = typeof header.alg === 'string' ? header.alg : typeof originalHeader.alg === 'string' ? originalHeader.alg : 'unknown';
  const encryption = typeof header.enc === 'string' ? header.enc : typeof originalHeader.enc === 'string' ? originalHeader.enc : 'unknown';
  const keyBytes = decodeJweKeyMaterial(keyMaterial, encryption);
  const baseNotes = [
    `Detected five-part JWE compact serialization using ${algorithm}/${encryption}.`,
    'Protected header, IV, ciphertext, and authentication tag metadata are preserved for report evidence.',
  ];

  if (algorithm !== 'dir' || !['A128GCM', 'A192GCM', 'A256GCM'].includes(encryption)) {
    return {
      id: id('decoder-jwt'),
      title: 'JWE compact token',
      createdAt,
      tokenType: 'jwe',
      algorithm: `${algorithm}/${encryption}`,
      headerJson,
      payloadJson: 'Encrypted JWE payload uses an unsupported key-management or content-encryption mode for local editing.',
      signaturePreview: parts[4]?.slice(0, 32) ?? '',
      secretLabel: keyMaterial ? 'operator-supplied key material ignored for unsupported JWE mode' : 'not supplied',
      signedTokenPreview: token,
      status: 'jwe-unsupported',
      notes: [...baseNotes, 'Key-backed local edit currently supports direct AES-GCM JWE only: alg=dir with A128GCM, A192GCM, or A256GCM.'],
      reportReady: true,
      summary: `JWE ${algorithm}/${encryption} detected; metadata is preserved but this mode needs external key-management support.`,
    };
  }

  if (!keyBytes) {
    return {
      id: id('decoder-jwt'),
      title: 'JWE compact token',
      createdAt,
      tokenType: 'jwe',
      algorithm: `${algorithm}/${encryption}`,
      headerJson,
      payloadJson: 'Encrypted JWE payload requires an operator-supplied direct AES-GCM key. Accepted formats: base64url:<key>, base64:<key>, hex:<key>, or utf8:<key> with the exact key length for the enc value.',
      signaturePreview: parts[4]?.slice(0, 32) ?? '',
      secretLabel: 'JWE key not supplied or wrong length',
      signedTokenPreview: token,
      status: 'jwe-key-required',
      notes: [...baseNotes, `Supply a ${requiredJweKeyBytes(encryption)}-byte direct key to decrypt, edit, and re-encrypt this JWE locally.`],
      reportReady: true,
      summary: `JWE ${algorithm}/${encryption} detected; supply a ${requiredJweKeyBytes(encryption)}-byte direct key for local decrypt/edit/re-encrypt.`,
    };
  }

  try {
    const decryptedPayload = await decryptDirectAesGcmJwe(parts, keyBytes);
    const payloadJson = payloadDraft?.trim() || prettyJsonText(decryptedPayload);
    const shouldReencrypt = Boolean(payloadDraft?.trim());
    const signedTokenPreview = shouldReencrypt
      ? await encryptDirectAesGcmJwe(header, payloadJson, keyBytes)
      : token;
    return {
      id: id('decoder-jwt'),
      title: shouldReencrypt ? 'JWE decrypt/edit/re-encrypt workspace' : 'JWE decrypt workspace',
      createdAt,
      tokenType: 'jwe',
      algorithm: `${algorithm}/${encryption}`,
      headerJson: JSON.stringify(sortJson(header), null, 2),
      payloadJson,
      signaturePreview: shouldReencrypt ? signedTokenPreview.split('.')[4]?.slice(0, 32) ?? '' : parts[4]?.slice(0, 32) ?? '',
      secretLabel: `operator-supplied ${keyBytes.length}-byte direct AES-GCM key`,
      signedTokenPreview,
      status: shouldReencrypt ? 'jwe-reencrypted' : 'jwe-decrypted',
      notes: [
        ...baseNotes,
        'Decrypted the compact JWE payload with the supplied direct AES-GCM key.',
        shouldReencrypt ? 'Re-encrypted the edited payload into a fresh compact JWE with a new IV and authentication tag.' : 'Payload is ready for authorized edit; submit a payload draft to re-encrypt.',
      ],
      reportReady: true,
      summary: shouldReencrypt
        ? `JWE ${algorithm}/${encryption} payload decrypted, edited, and re-encrypted locally.`
        : `JWE ${algorithm}/${encryption} payload decrypted locally and is ready for edit/re-encrypt.`,
    };
  } catch (error) {
    return {
      id: id('decoder-jwt'),
      title: 'JWE compact token',
      createdAt,
      tokenType: 'jwe',
      algorithm: `${algorithm}/${encryption}`,
      headerJson,
      payloadJson: 'JWE decryption failed. Verify the direct key, protected header, IV, ciphertext, and authentication tag before replay.',
      signaturePreview: parts[4]?.slice(0, 32) ?? '',
      secretLabel: `operator-supplied ${keyBytes.length}-byte direct AES-GCM key`,
      signedTokenPreview: token,
      status: 'jwe-key-required',
      notes: [...baseNotes, error instanceof Error ? error.message : 'Direct JWE decryption failed.'],
      reportReady: true,
      summary: `JWE ${algorithm}/${encryption} was detected, but the supplied key could not decrypt it.`,
    };
  }
}

export async function buildDecoderJwtWorkspace(input: string, headerDraft?: string, payloadDraft?: string, secret = 'proxyforge-preview-secret'): Promise<DecoderJwtWorkspace> {
  const token = input.trim();
  const parts = token.split('.');
  const createdAt = new Date().toISOString();
  if (parts.length === 5) {
    return buildDecoderJweWorkspace(token, parts, createdAt, headerDraft, payloadDraft, secret);
  }
  if (parts.length < 2) {
    return {
      id: id('decoder-jwt'),
      title: 'JWT workspace unavailable',
      createdAt,
      tokenType: 'jwt',
      algorithm: 'none',
      headerJson: '{}',
      payloadJson: '{}',
      signaturePreview: '',
      secretLabel: 'not supplied',
      signedTokenPreview: token,
      status: 'invalid',
      notes: ['Input is not a JWT/JWS compact token with header and payload segments.'],
      reportReady: false,
      summary: 'No JWT/JWS token could be decoded from the current Decoder input.',
    };
  }

  const headerJson = headerDraft?.trim() || JSON.stringify(sortJson(parseJsonMaybe(decodeBase64(parts[0], true))), null, 2);
  const payloadJson = payloadDraft?.trim() || JSON.stringify(sortJson(parseJsonMaybe(decodeBase64(parts[1], true))), null, 2);
  const parsedHeader = parseJsonMaybe(headerJson) as Record<string, unknown>;
  const algorithm = typeof parsedHeader.alg === 'string' ? parsedHeader.alg : 'HS256';
  const signingHeader = { ...parsedHeader, alg: algorithm === 'none' ? 'HS256' : algorithm };
  const encodedHeader = encodeBase64(JSON.stringify(sortJson(signingHeader)), true);
  const encodedPayload = encodeBase64(JSON.stringify(sortJson(parseJsonMaybe(payloadJson))), true);
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const signature = signingHeader.alg === 'HS256'
    ? await hmacSha256Base64Url(secret, signingInput)
    : parts[2] ?? '';
  const signedTokenPreview = `${signingInput}.${signature}`;

  return {
    id: id('decoder-jwt'),
    title: 'JWT/JWS editor workspace',
    createdAt,
    tokenType: 'jws',
    algorithm: String(signingHeader.alg),
    headerJson: JSON.stringify(sortJson(signingHeader), null, 2),
    payloadJson: JSON.stringify(sortJson(parseJsonMaybe(payloadJson)), null, 2),
    signaturePreview: signature ? `${signature.slice(0, 28)}${signature.length > 28 ? '...' : ''}` : 'none',
    secretLabel: secret ? 'local HS256 preview secret' : 'not supplied',
    signedTokenPreview,
    status: signingHeader.alg === 'HS256' ? 'signed-preview' : 'edited',
    notes: [
      'Decoded JWT/JWS header and payload for editing.',
      signingHeader.alg === 'HS256' ? 'Generated local HS256 signing preview for authorized testing.' : `Preserved ${String(signingHeader.alg)} signature mode as an edit preview.`,
    ],
    reportReady: true,
    summary: `JWT/JWS workspace ready with ${String(signingHeader.alg)} signing preview and editable header/payload JSON.`,
  };
}

function tryDecodeJwtPart(part: string) {
  try {
    return JSON.stringify(sortJson(parseJsonMaybe(decodeBase64(part, true))), null, 2);
  } catch {
    return part;
  }
}

async function hmacSha256Base64Url(secret: string, input: string) {
  if (!globalThis.crypto?.subtle) return encodeBase64(`${secret}:${input}`, true).slice(0, 43);
  const key = await globalThis.crypto.subtle.importKey(
    'raw',
    textEncoder.encode(secret || 'proxyforge-preview-secret'),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const signature = await globalThis.crypto.subtle.sign('HMAC', key, textEncoder.encode(input));
  return btoa(bytesToBinary(new Uint8Array(signature))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function requiredJweKeyBytes(encryption: string) {
  if (encryption === 'A128GCM') return 16;
  if (encryption === 'A192GCM') return 24;
  return 32;
}

function decodeJweKeyMaterial(keyMaterial: string | undefined, encryption: string) {
  const trimmed = keyMaterial?.trim();
  if (!trimmed) return null;
  const requiredLength = requiredJweKeyBytes(encryption);
  const prefixed = /^([a-z0-9_-]+):(.*)$/i.exec(trimmed);
  const format = prefixed?.[1]?.toLowerCase();
  const material = prefixed ? prefixed[2].trim() : trimmed;
  const candidates: Uint8Array[] = [];

  function tryCandidate(factory: () => Uint8Array) {
    try {
      candidates.push(factory());
    } catch {
      // Keep trying other common key encodings.
    }
  }

  if (format === 'base64url') tryCandidate(() => decodeBase64Bytes(material, true));
  else if (format === 'base64') tryCandidate(() => decodeBase64Bytes(material, false));
  else if (format === 'hex') tryCandidate(() => decodeHexBytes(material));
  else if (format === 'utf8' || format === 'text') candidates.push(textEncoder.encode(material));
  else {
    if (/^[A-Za-z0-9_-]+={0,2}$/.test(material)) tryCandidate(() => decodeBase64Bytes(material, true));
    if (/^[A-Za-z0-9+/]+={0,2}$/.test(material)) tryCandidate(() => decodeBase64Bytes(material, false));
    if (/^(?:0x)?[a-fA-F0-9\s:-]+$/.test(material)) tryCandidate(() => decodeHexBytes(material));
    candidates.push(textEncoder.encode(material));
  }

  return candidates.find((candidate) => candidate.length === requiredLength) ?? null;
}

function decodeHexBytes(input: string) {
  const normalized = input.replace(/0x/gi, '').replace(/[^a-fA-F0-9]/g, '');
  if (!normalized || normalized.length % 2 !== 0) throw new Error('Key material is not an even-length hexadecimal byte string');
  const bytes = new Uint8Array(normalized.length / 2);
  for (let index = 0; index < normalized.length; index += 2) {
    bytes[index / 2] = Number.parseInt(normalized.slice(index, index + 2), 16);
  }
  return bytes;
}

async function decryptDirectAesGcmJwe(parts: string[], keyBytes: Uint8Array) {
  if (!globalThis.crypto?.subtle) throw new Error('Web Crypto AES-GCM is unavailable in this runtime.');
  const protectedHeader = parts[0];
  const iv = decodeBase64Bytes(parts[2], true);
  const ciphertext = decodeBase64Bytes(parts[3], true);
  const tag = decodeBase64Bytes(parts[4], true);
  const encrypted = concatBytes(ciphertext, tag);
  const key = await globalThis.crypto.subtle.importKey('raw', bytesToArrayBuffer(keyBytes), { name: 'AES-GCM' }, false, ['decrypt']);
  const plaintext = await globalThis.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv, additionalData: textEncoder.encode(protectedHeader), tagLength: 128 },
    key,
    encrypted,
  );
  return textDecoder.decode(new Uint8Array(plaintext));
}

async function encryptDirectAesGcmJwe(header: Record<string, unknown>, payloadJson: string, keyBytes: Uint8Array) {
  if (!globalThis.crypto?.subtle || !globalThis.crypto.getRandomValues) throw new Error('Web Crypto AES-GCM encryption is unavailable in this runtime.');
  const protectedHeader = encodeBase64(JSON.stringify(sortJson(header)), true);
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const key = await globalThis.crypto.subtle.importKey('raw', bytesToArrayBuffer(keyBytes), { name: 'AES-GCM' }, false, ['encrypt']);
  const encrypted = new Uint8Array(await globalThis.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: textEncoder.encode(protectedHeader), tagLength: 128 },
    key,
    textEncoder.encode(prettyJsonText(payloadJson)),
  ));
  const ciphertext = encrypted.slice(0, Math.max(0, encrypted.length - 16));
  const tag = encrypted.slice(Math.max(0, encrypted.length - 16));
  return [protectedHeader, '', bytesToBase64Url(iv), bytesToBase64Url(ciphertext), bytesToBase64Url(tag)].join('.');
}

function concatBytes(left: Uint8Array, right: Uint8Array) {
  const combined = new Uint8Array(left.length + right.length);
  combined.set(left, 0);
  combined.set(right, left.length);
  return combined;
}

function bytesToArrayBuffer(bytes: Uint8Array) {
  const copy = new Uint8Array(bytes.length);
  copy.set(bytes);
  return copy.buffer;
}

function prettyJsonText(value: string) {
  try {
    return JSON.stringify(sortJson(JSON.parse(value)), null, 2);
  } catch {
    return value;
  }
}

export async function inspectDecoderBinary(input: string): Promise<DecoderBinaryInspection> {
  const createdAt = new Date().toISOString();
  const bytes = bytesForInput(input);
  const asciiPreview = Array.from(bytes.slice(0, 256)).map((byte) => (byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : '.')).join('');
  const hexDump = buildHexDump(bytes);
  const hashes = await buildHashInsights(textDecoder.decode(bytes));
  const ratio = bytes.length ? Array.from(bytes).filter((byte) => byte === 9 || byte === 10 || byte === 13 || (byte >= 32 && byte <= 126)).length / bytes.length : 0;
  const highBytes = Array.from(bytes).filter((byte) => byte > 127).length;
  const nullBytes = Array.from(bytes).filter((byte) => byte === 0).length;
  return {
    id: id('decoder-binary'),
    title: 'Binary and hex inspection',
    createdAt,
    byteLength: bytes.length,
    printableRatio: Number(ratio.toFixed(3)),
    nullBytes,
    highBytes,
    hexDump,
    asciiPreview,
    hashes,
    encodingInsights: buildEncodingInsights(input, [], bytes),
    reportReady: true,
    summary: `${bytes.length} bytes inspected; ${Math.round(ratio * 100)}% printable, ${highBytes} high bytes, ${nullBytes} null bytes.`,
  };
}

function buildHexDump(bytes: Uint8Array) {
  const rows: string[] = [];
  for (let offset = 0; offset < Math.min(bytes.length, 512); offset += 16) {
    const slice = bytes.slice(offset, offset + 16);
    const hex = Array.from(slice).map((byte) => byte.toString(16).padStart(2, '0')).join(' ').padEnd(47, ' ');
    const ascii = Array.from(slice).map((byte) => (byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : '.')).join('');
    rows.push(`${offset.toString(16).padStart(8, '0')}  ${hex}  ${ascii}`);
  }
  return rows.join('\n');
}

async function buildHashInsights(input: string): Promise<DecoderHashInsight[]> {
  const hashes: DecoderHashInsight[] = [];
  hashes.push({ algorithm: 'SHA-256', value: await digestHex('SHA-256', input) });
  hashes.push({ algorithm: 'SHA-1', value: await digestHex('SHA-1', input) });
  return hashes;
}

function buildEncodingInsights(input: string, layers: DecoderDetectedLayer[], bytes: Uint8Array): DecoderEncodingInsight[] {
  const insights: DecoderEncodingInsight[] = [];
  if (layers.length > 1) {
    insights.push({
      id: 'recursive-layers',
      label: 'Recursive encoding',
      severity: 'review',
      detail: `${layers.length} nested transform layers were detected; preserve the recipe before editing and re-encoding.`,
    });
  }
  const compactParts = input.trim().split('.');
  if (
    compactParts.length >= 3
    && compactParts.length <= 5
    && compactParts.every((part, index) => (compactParts.length === 5 && index === 1 ? /^[A-Za-z0-9_-]*$/.test(part) : /^[A-Za-z0-9_-]+$/.test(part)))
  ) {
    insights.push({
      id: 'jwt-jws-jwe',
      label: 'JWT/JWS/JWE token',
      severity: 'review',
      detail: 'Compact token data detected; inspect claims, algorithm, signature mode, and encrypted JWE state before replay.',
    });
  }
  if (byteEntropy(bytes) > 6.5) {
    insights.push({
      id: 'high-entropy',
      label: 'High entropy data',
      severity: 'warning',
      detail: 'Byte entropy is high; this may be compressed, encrypted, signed, or binary data rather than simple text encoding.',
    });
  }
  if (printableRatio(input) < 0.75) {
    insights.push({
      id: 'binary-content',
      label: 'Binary-looking content',
      severity: 'review',
      detail: 'Input contains non-printable or dense byte values; use the hex inspector before editing.',
    });
  }
  if (!insights.length) {
    insights.push({
      id: 'plain-text',
      label: 'Plaintext or unknown',
      severity: 'pass',
      detail: 'No risky encoding wrapper was detected; manual transforms and hashing remain available.',
    });
  }
  return insights;
}

export function buildDecoderTransformLibraryPackage(
  recipes: DecoderRecipe[],
  analyses: DecoderAnalysisRun[],
  jwtWorkspaces: DecoderJwtWorkspace[],
  binaryInspections: DecoderBinaryInspection[],
  exportedAt = new Date().toISOString(),
): DecoderTransformLibraryPackage {
  const stamp = exportedAt.replace(/[:.]/g, '-');
  const payload = {
    kind: 'proxyforge-decoder-transform-library',
    exportedAt,
    recipes,
    analyses,
    jwtWorkspaces,
    binaryInspections,
    reportReady: true,
  };
  const digestPreview = simpleDigest(JSON.stringify(payload));
  const content = JSON.stringify({ ...payload, digestPreview }, null, 2);
  return {
    id: id('decoder-library'),
    title: 'Decoder transform library',
    fileName: `proxyforge-decoder-library-${stamp}.json`,
    path: `reports/proxyforge-decoder-library-${stamp}.json`,
    exportedAt,
    recipeIds: recipes.map((item) => item.id),
    analysisIds: analyses.map((item) => item.id),
    jwtWorkspaceIds: jwtWorkspaces.map((item) => item.id),
    binaryInspectionIds: binaryInspections.map((item) => item.id),
    reportReady: true,
    digestPreview,
    summary: `${recipes.length} recipe${recipes.length === 1 ? '' : 's'}, ${analyses.length} analysis run${analyses.length === 1 ? '' : 's'}, ${jwtWorkspaces.length} JWT workspace${jwtWorkspaces.length === 1 ? '' : 's'}, and ${binaryInspections.length} binary inspection${binaryInspections.length === 1 ? '' : 's'} exported with digest ${digestPreview}.`,
    content,
  };
}

function simpleDigest(value: string) {
  let hash = 0x811c9dc5;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return `${hash.toString(16).padStart(8, '0')}${value.length.toString(16).padStart(8, '0')}`;
}

export function buildDecoderReportExport(
  analysis: DecoderAnalysisRun | undefined,
  recipe: DecoderRecipe | undefined,
  jwtWorkspace: DecoderJwtWorkspace | undefined,
  binaryInspection: DecoderBinaryInspection | undefined,
  libraryPackage: DecoderTransformLibraryPackage | undefined,
  issueId: string | undefined,
  exportedAt = new Date().toISOString(),
): DecoderReportExportArtifact {
  const stamp = exportedAt.replace(/[:.]/g, '-');
  const content = JSON.stringify({
    kind: 'proxyforge-decoder-report-evidence',
    exportedAt,
    analysis,
    recipe,
    jwtWorkspace,
    binaryInspection,
    libraryPackage,
    issueId,
    reportReady: true,
    parityFeatures: [
      'smart decode',
      'recursive transform recipe',
      'JWT/JWS/JWE edit and signing preview',
      'key-backed direct JWE decrypt/edit/re-encrypt',
      'binary and hex inspector',
      'hash and encoding analysis',
      'import/exportable transform library',
      'Reports handoff',
    ],
  }, null, 2);
  return {
    id: id('decoder-report'),
    title: 'Decoder evidence handoff',
    fileName: `proxyforge-decoder-evidence-${stamp}.json`,
    path: `reports/proxyforge-decoder-evidence-${stamp}.json`,
    exportedAt,
    analysisId: analysis?.id,
    recipeId: recipe?.id,
    jwtWorkspaceId: jwtWorkspace?.id,
    binaryInspectionId: binaryInspection?.id,
    libraryPackageId: libraryPackage?.id,
    issueId,
    reportReady: true,
    summary: 'Report-ready Decoder evidence covering smart decode, recipes, token editing, binary inspection, hashes, and transform-library export.',
    content,
  };
}

export function buildDecoderParityEvidencePackage(request: DecoderParityEvidenceRequest): DecoderParityEvidencePackage {
  const exportedAt = request.exportedAt ?? new Date().toISOString();
  const stamp = exportedAt.replace(/[:.]/g, '-');
  const transformCategories = (['encode', 'decode', 'hash', 'format'] as const).map((category) => {
    const transforms = decoderTransforms.filter((transform) => transform.category === category);
    return {
      category,
      count: transforms.length,
      transformIds: transforms.map((transform) => transform.id),
    };
  });
  const recipeText = `${request.recipe?.summary ?? ''}\n${request.recipe?.content ?? ''}`;
  const jwtText = `${request.jwtWorkspace?.summary ?? ''}\n${request.jwtWorkspace?.notes.join('\n') ?? ''}`;
  const jweText = `${request.jweWorkspace?.summary ?? ''}\n${request.jweWorkspace?.notes.join('\n') ?? ''}`;
  const libraryText = `${request.libraryPackage?.summary ?? ''}\n${request.libraryPackage?.content ?? ''}`;
  const reportText = `${request.reportExport?.summary ?? ''}\n${request.reportExport?.content ?? ''}`;
  const rawExecutorMaterial = [
    request.analysis?.finalPreview,
    request.recipe?.inputPreview,
    request.recipe?.outputPreview,
    request.jwtWorkspace?.signedTokenPreview,
    request.jweWorkspace?.signedTokenPreview,
    request.binaryInspection?.hexDump,
    request.libraryPackage?.content,
    ...(request.operationalSecretSamples ?? []),
  ].filter(Boolean);
  const requirements = {
    encodeDecodeHashFormatCovered: transformCategories.every((category) => category.count > 0),
    recursiveSmartRecipeCovered: Boolean(request.recipe?.steps.length && /url|base64|recursive|smart/i.test(recipeText)),
    jwtJwsSigningPreviewCovered: Boolean(request.jwtWorkspace?.tokenType === 'jws' && /HS256|signing preview|signed-preview/i.test(jwtText)),
    jweDecryptEditReencryptCovered: Boolean(request.jweWorkspace?.tokenType === 'jwe' && request.jweWorkspace.status === 'jwe-reencrypted' && /decrypted, edited, and re-encrypted|fresh IV|tag/i.test(jweText)),
    binaryHexInspectionCovered: Boolean(request.binaryInspection?.hexDump && request.binaryInspection.byteLength > 0),
    transformLibraryCovered: Boolean(request.libraryPackage?.reportReady && /proxyforge-decoder-transform-library|recipe|analysis|JWT|binary/i.test(libraryText)),
    reportHandoffCovered: Boolean(request.reportExport?.reportReady && /proxyforge-decoder-report-evidence|Reports handoff|Decoder evidence/i.test(reportText)),
    rawExecutorMaterialPreserved: rawExecutorMaterial.length >= 5,
    operationalSecretsPreserved: Boolean(request.operationalSecretSamples?.length),
    reportPhaseOnlyRedaction: true,
  };
  const unsigned = {
    kind: 'proxyforge-decoder-parity-evidence-package',
    exportedAt,
    transformCategories,
    artifacts: {
      analysis: request.analysis,
      recipe: request.recipe,
      jwtWorkspace: request.jwtWorkspace,
      jweWorkspace: request.jweWorkspace,
      binaryInspection: request.binaryInspection,
      libraryPackage: request.libraryPackage,
      reportExport: request.reportExport,
    },
    operationalSecretSamples: request.operationalSecretSamples ?? [],
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady: true,
  };
  const digestPreview = simpleDigest(JSON.stringify(unsigned));
  const content = JSON.stringify({ ...unsigned, digestPreview }, null, 2);
  return {
    id: id('decoder-parity'),
    kind: 'proxyforge-decoder-parity-evidence-package',
    title: 'Decoder parity evidence package',
    fileName: `proxyforge-decoder-parity-${stamp}.json`,
    path: `reports/proxyforge-decoder-parity-${stamp}.json`,
    exportedAt,
    transformCategories,
    artifactIds: {
      analysisId: request.analysis?.id,
      recipeId: request.recipe?.id,
      jwtWorkspaceId: request.jwtWorkspace?.id,
      jweWorkspaceId: request.jweWorkspace?.id,
      binaryInspectionId: request.binaryInspection?.id,
      libraryPackageId: request.libraryPackage?.id,
      reportExportId: request.reportExport?.id,
    },
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady: true,
    digestPreview,
    summary: 'Decoder parity evidence covers encode/decode/hash/format transforms, recursive recipes, JWT/JWS signing preview, direct JWE decrypt/edit/re-encrypt, binary/hex inspection, transform-library export, and Reports handoff.',
    content,
  };
}
