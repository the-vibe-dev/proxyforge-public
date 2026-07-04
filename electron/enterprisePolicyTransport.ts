import crypto from 'node:crypto';
import http from 'node:http';
import https from 'node:https';
import { URL } from 'node:url';

export interface EnterprisePolicyTransportConfig {
  endpoint: string;
  authHeaderName: string;
  credentialLabel: string;
}

export interface EnterprisePolicyPackage {
  version?: number;
  kind?: string;
  digestSha256?: string;
  [key: string]: unknown;
}

export interface EnterprisePolicyPushRequest {
  transport: EnterprisePolicyTransportConfig;
  policyPackage: EnterprisePolicyPackage;
  timeoutMs?: number;
  authHeaderValue?: string;
}

export interface EnterprisePolicyPullRequest {
  transport: EnterprisePolicyTransportConfig;
  timeoutMs?: number;
  authHeaderValue?: string;
}

export interface EnterprisePolicyTransportResult {
  endpoint: string;
  method: 'GET' | 'POST';
  statusCode: number;
  completedAt: string;
  digestSha256: string;
  receiptId?: string;
  responseBody: string;
  message: string;
}

export interface EnterprisePolicyPullResult extends EnterprisePolicyTransportResult {
  policyPackage: EnterprisePolicyPackage;
}

interface HttpResult {
  statusCode: number;
  headers: http.IncomingHttpHeaders;
  body: string;
}

const MAX_RESPONSE_BYTES = 4 * 1024 * 1024;

export class EnterprisePolicyTransportService {
  async push(request: EnterprisePolicyPushRequest): Promise<EnterprisePolicyTransportResult> {
    validatePolicyPackage(request.policyPackage);
    const endpoint = normalizeEndpoint(request.transport.endpoint);
    const body = JSON.stringify(request.policyPackage);
    const digestSha256 = request.policyPackage.digestSha256 ?? digestPolicyPackage(request.policyPackage);
    const response = await requestJson(endpoint, {
      method: 'POST',
      body,
      timeoutMs: request.timeoutMs,
      headers: buildHeaders(request.transport, request.authHeaderValue, digestSha256),
    });
    const receipt = parseJsonMaybe(response.body);
    return {
      endpoint: endpoint.toString(),
      method: 'POST',
      statusCode: response.statusCode,
      completedAt: new Date().toISOString(),
      digestSha256,
      receiptId: extractReceiptId(receipt),
      responseBody: response.body,
      message: `Pushed enterprise policy ${digestSha256.slice(0, 12)} with HTTP ${response.statusCode}.`,
    };
  }

  async pull(request: EnterprisePolicyPullRequest): Promise<EnterprisePolicyPullResult> {
    const endpoint = normalizeEndpoint(request.transport.endpoint);
    const response = await requestJson(endpoint, {
      method: 'GET',
      timeoutMs: request.timeoutMs,
      headers: buildHeaders(request.transport, request.authHeaderValue),
    });
    const parsed = parseJsonMaybe(response.body);
    const policyPackage = extractPolicyPackage(parsed);
    validatePolicyPackage(policyPackage);
    const digestSha256 = policyPackage.digestSha256 ?? digestPolicyPackage(policyPackage);
    return {
      endpoint: endpoint.toString(),
      method: 'GET',
      statusCode: response.statusCode,
      completedAt: new Date().toISOString(),
      digestSha256,
      receiptId: extractReceiptId(parsed),
      responseBody: response.body,
      policyPackage: {
        ...policyPackage,
        digestSha256,
      },
      message: `Pulled enterprise policy ${digestSha256.slice(0, 12)} with HTTP ${response.statusCode}.`,
    };
  }
}

function normalizeEndpoint(endpoint: string) {
  const parsed = new URL(endpoint.trim());
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error('Enterprise policy endpoint must be an http or https URL.');
  }
  return parsed;
}

function validatePolicyPackage(policyPackage: EnterprisePolicyPackage) {
  if (!policyPackage || typeof policyPackage !== 'object') throw new Error('Enterprise policy package is empty.');
  if (policyPackage.kind !== 'proxyforge-enterprise-policy') {
    throw new Error('Expected proxyforge-enterprise-policy package.');
  }
}

function buildHeaders(transport: EnterprisePolicyTransportConfig, authHeaderValue?: string, digestSha256?: string): Record<string, string> {
  const headers: Record<string, string> = {
    accept: 'application/json',
    'content-type': 'application/json',
  };
  if (digestSha256) headers['x-proxyforge-policy-digest'] = digestSha256;
  if (transport.credentialLabel?.trim()) headers['x-proxyforge-credential-label'] = transport.credentialLabel.trim();
  const authHeaderName = transport.authHeaderName?.trim();
  if (authHeaderName && authHeaderValue) {
    if (!/^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/.test(authHeaderName)) throw new Error(`Invalid auth header name: ${authHeaderName}`);
    headers[authHeaderName] = authHeaderValue;
  }
  return headers;
}

function requestJson(endpoint: URL, options: { method: 'GET' | 'POST'; body?: string; timeoutMs?: number; headers: Record<string, string> }): Promise<HttpResult> {
  const client = endpoint.protocol === 'https:' ? https : http;
  return new Promise((resolve, reject) => {
    const request = client.request(endpoint, {
      method: options.method,
      timeout: normalizeTimeout(options.timeoutMs),
      headers: {
        ...options.headers,
        ...(options.body ? { 'content-length': Buffer.byteLength(options.body) } : {}),
      },
    }, (response) => {
      const chunks: Buffer[] = [];
      let total = 0;
      response.on('data', (chunk: Buffer) => {
        total += chunk.length;
        if (total > MAX_RESPONSE_BYTES) {
          request.destroy(new Error('Enterprise policy response exceeded 4 MiB.'));
          return;
        }
        chunks.push(chunk);
      });
      response.on('end', () => {
        const statusCode = response.statusCode ?? 0;
        const body = Buffer.concat(chunks).toString('utf8');
        if (statusCode < 200 || statusCode >= 300) {
          reject(new Error(`Enterprise policy endpoint returned HTTP ${statusCode}: ${body.slice(0, 300)}`));
          return;
        }
        resolve({ statusCode, headers: response.headers, body });
      });
    });
    request.on('timeout', () => request.destroy(new Error('Enterprise policy request timed out.')));
    request.on('error', reject);
    if (options.body) request.write(options.body);
    request.end();
  });
}

function normalizeTimeout(timeoutMs?: number) {
  const parsed = Number(timeoutMs);
  if (!Number.isFinite(parsed)) return 15000;
  return Math.max(1000, Math.min(120000, parsed));
}

function parseJsonMaybe(value: string): unknown {
  if (!value.trim()) return {};
  try {
    return JSON.parse(value);
  } catch {
    throw new Error('Enterprise policy endpoint did not return valid JSON.');
  }
}

function extractPolicyPackage(value: unknown): EnterprisePolicyPackage {
  if (isPolicyPackage(value)) return value;
  if (value && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    for (const key of ['policyPackage', 'package', 'data', 'policy']) {
      const candidate = record[key];
      if (isPolicyPackage(candidate)) return candidate;
    }
  }
  throw new Error('Enterprise policy response did not include a proxyforge-enterprise-policy package.');
}

function isPolicyPackage(value: unknown): value is EnterprisePolicyPackage {
  return Boolean(value && typeof value === 'object' && (value as EnterprisePolicyPackage).kind === 'proxyforge-enterprise-policy');
}

function extractReceiptId(value: unknown) {
  if (!value || typeof value !== 'object') return undefined;
  const record = value as Record<string, unknown>;
  const id = record.receiptId ?? record.id ?? record.requestId;
  return typeof id === 'string' && id.trim() ? id : undefined;
}

function digestPolicyPackage(policyPackage: EnterprisePolicyPackage) {
  const { digestSha256: _digestSha256, ...unsigned } = policyPackage;
  return crypto.createHash('sha256').update(canonicalize(unsigned)).digest('hex');
}

function canonicalize(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  if (value && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${canonicalize(record[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}
