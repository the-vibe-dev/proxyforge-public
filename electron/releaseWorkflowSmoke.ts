#!/usr/bin/env node
import dgram from 'node:dgram';
import fs from 'node:fs/promises';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import path from 'node:path';
import tls from 'node:tls';
import { CallbackListenerService, type CallbackPayload, type CallbackListenerProfile } from './callbackListenerService';
import { CertificateAuthorityManager } from './certManager';
import { ProxyEngine } from './proxyEngine';
import { ReportEngine, type ReportArtifact, type ReportExchange, type ReportIssue, type ReportSection } from './reportEngine';

interface SmokeCheck {
  name: string;
  status: 'passed' | 'failed';
  durationMs: number;
  message: string;
  data?: Record<string, unknown>;
}

interface SmokeSummary {
  kind: 'proxyforge-release-runtime-workflow-smoke';
  schemaVersion: 1;
  generatedAt: string;
  durationMs: number;
  status: 'passed' | 'failed';
  outDir: string;
  checks: SmokeCheck[];
  proxy: {
    port?: number;
    exchangeCount: number;
    httpCaptured: boolean;
    httpsCaptured: boolean;
  };
  certificate: {
    ready: boolean;
    fingerprintSha256?: string;
    rootCertificatePath?: string;
    hostCertificateCount: number;
  };
  oast: {
    interactionCount: number;
    newInteractionCount: number;
    protocols: string[];
    ports: Record<string, number>;
    tokensPreserved: boolean;
  };
  reports: {
    count: number;
    formats: string[];
    artifactStats: Array<{
      path: string;
      exists: boolean;
      sizeBytes: number;
    }>;
    operationalCapturePath?: string;
    operationalSecretsPreserved: boolean;
    reportSecretsRedacted: boolean;
  };
}

const startedAt = Date.now();
const SYNTHETIC_AUTH = 'Bearer proxyforge-runtime-secret-token';
const SYNTHETIC_COOKIE = 'session=proxyforge-runtime-secret-cookie';
const SYNTHETIC_API_KEY = 'proxyforge-runtime-secret-api-key';

async function main() {
  const flags = parseArgs(process.argv.slice(2));
  const outDir = path.resolve(String(flags.outDir ?? flags['out-dir'] ?? path.join(process.cwd(), 'test-results', 'release-runtime-workflow')));
  try {
    const summary = await runWorkflow(outDir);
    process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
    process.exitCode = summary.status === 'passed' ? 0 : 1;
  } catch (error) {
    const summary: SmokeSummary = {
      kind: 'proxyforge-release-runtime-workflow-smoke',
      schemaVersion: 1,
      generatedAt: new Date().toISOString(),
      durationMs: Date.now() - startedAt,
      status: 'failed',
      outDir,
      checks: [{
        name: 'runtime-workflow',
        status: 'failed',
        durationMs: Date.now() - startedAt,
        message: error instanceof Error ? error.message : String(error),
      }],
      proxy: { exchangeCount: 0, httpCaptured: false, httpsCaptured: false },
      certificate: { ready: false, hostCertificateCount: 0 },
      oast: { interactionCount: 0, newInteractionCount: 0, protocols: [], ports: {}, tokensPreserved: false },
      reports: { count: 0, formats: [], artifactStats: [], operationalSecretsPreserved: false, reportSecretsRedacted: false },
    };
    process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
    process.exitCode = 1;
  }
}

async function runWorkflow(outDir: string): Promise<SmokeSummary> {
  await fs.mkdir(outDir, { recursive: true });
  const checks: SmokeCheck[] = [];
  const exchanges: any[] = [];
  const caManager = new CertificateAuthorityManager(path.join(outDir, 'certs'));
  let proxy: ProxyEngine | null = null;
  let httpTarget: http.Server | null = null;
  let httpsTarget: https.Server | null = null;
  const callbackService = new CallbackListenerService();
  let proxyPort: number | undefined;

  let caReady = false;
  let caFingerprint: string | undefined;
  let caRootPath: string | undefined;
  let caHostCertificateCount = 0;
  let oastResult = {
    interactionCount: 0,
    newInteractionCount: 0,
    protocols: [] as string[],
    ports: {} as Record<string, number>,
    tokensPreserved: false,
  };
  let reportArtifacts: ReportArtifact[] = [];
  let operationalCapturePath: string | undefined;
  let operationalSecretsPreserved = false;
  let reportSecretsRedacted = false;

  try {
    const root = await runChecked(checks, 'certificate-authority', async () => {
      const exported = await caManager.exportRootPem();
      await caManager.secureContextForHost('localhost');
      const status = await caManager.status();
      if (!status.ready || !status.fingerprintSha256 || status.hostCertificateCount < 1) {
        throw new Error('Project CA did not produce root and host certificate material.');
      }
      caReady = status.ready;
      caFingerprint = status.fingerprintSha256;
      caRootPath = status.rootCertificatePath;
      caHostCertificateCount = status.hostCertificateCount;
      return {
        message: `Project CA ready with ${status.hostCertificateCount} host certificate(s).`,
        data: {
          fingerprintSha256: status.fingerprintSha256,
          rootCertificatePath: status.rootCertificatePath,
          hostCertificateCount: status.hostCertificateCount,
        },
        value: exported,
      };
    });

    httpTarget = http.createServer((request, response) => {
      response.writeHead(200, {
        'content-type': 'application/json',
        'x-proxyforge-runtime-target': 'http',
      });
      response.end(JSON.stringify({
        ok: true,
        transport: 'http',
        path: request.url,
        auth: request.headers.authorization ? 'present' : 'missing',
      }));
    });
    const httpPort = await listenTcp(httpTarget);

    proxy = new ProxyEngine((exchange) => exchanges.push(exchange), caManager);
    // Runtime smoke uses a private loopback CA fixture; production defaults remain strict unless a run explicitly opts out.
    proxy.setUpstreamTlsValidation('relaxed');
    proxyPort = await freePort();
    await proxy.start(proxyPort);

    await runChecked(checks, 'proxy-http-capture', async () => {
      const targetUrl = `http://127.0.0.1:${httpPort}/runtime?proof=proxy`;
      const response = await requestViaProxy(proxyPort as number, targetUrl);
      const captured = await waitFor(() => exchanges.find((exchange) => exchange.path === '/runtime?proof=proxy'));
      if (response.statusCode !== 200 || !captured) throw new Error('HTTP proxy capture did not record the loopback request.');
      if (!String(captured.requestRaw).includes(SYNTHETIC_AUTH)) throw new Error('Operational capture did not preserve the synthetic Authorization header.');
      return {
        message: 'HTTP proxy listener captured a loopback request with full operational headers.',
        data: {
          proxyPort,
          targetPort: httpPort,
          statusCode: response.statusCode,
          exchangeId: captured.id,
        },
      };
    });

    await runChecked(checks, 'https-mitm-capture', async () => {
      const hostCert = await fs.readFile(path.join(outDir, 'certs', 'projects', 'default-project', 'hosts', 'localhost.pem'), 'utf8');
      const hostKey = await fs.readFile(path.join(outDir, 'certs', 'projects', 'default-project', 'hosts', 'localhost.key.pem'), 'utf8');
      httpsTarget = https.createServer({ cert: hostCert, key: hostKey }, (request, response) => {
        response.writeHead(200, {
          'content-type': 'application/json',
          'cache-control': 'no-store',
          'x-proxyforge-runtime-target': 'https',
        });
        response.end(JSON.stringify({ ok: true, transport: 'https', path: request.url }));
      });
      const httpsPort = await listenTcp(httpsTarget);
      const response = await requestThroughMitm(proxyPort as number, httpsPort, root.pem, '/secure?proof=mitm');
      const captured = await waitFor(() => exchanges.find((exchange) => exchange.path === '/secure?proof=mitm' && exchange.tags?.includes('https')));
      if (!response.includes('"transport":"https"') || !captured) throw new Error('HTTPS MITM capture did not record decrypted traffic.');
      return {
        message: 'HTTPS MITM captured decrypted loopback traffic with the packaged project CA.',
        data: {
          proxyPort,
          targetPort: httpsPort,
          exchangeId: captured.id,
          tags: captured.tags,
        },
      };
    });

    await runChecked(checks, 'local-oast-listeners', async () => {
      oastResult = await runOastSmoke(callbackService);
      if (oastResult.interactionCount !== 3 || !oastResult.tokensPreserved) {
        throw new Error('Local OAST listeners did not capture HTTP, DNS, and SMTP interactions.');
      }
      return {
        message: 'Local HTTP, DNS, and SMTP callback listeners captured correlated interactions.',
        data: oastResult,
      };
    });

    await runChecked(checks, 'report-export-redaction', async () => {
      operationalCapturePath = path.join(outDir, 'proxyforge-runtime-operational-capture.json');
      await fs.writeFile(operationalCapturePath, JSON.stringify({ exchanges }, null, 2), 'utf8');
      const operationalCapture = await fs.readFile(operationalCapturePath, 'utf8');
      operationalSecretsPreserved = operationalCapture.includes(SYNTHETIC_AUTH)
        && operationalCapture.includes(SYNTHETIC_COOKIE)
        && operationalCapture.includes(SYNTHETIC_API_KEY);
      if (!operationalSecretsPreserved) throw new Error('Operational capture did not retain synthetic secrets before report export.');

      const engine = new ReportEngine(path.join(outDir, 'reports'));
      const issues = buildReportIssues(exchanges);
      const request = {
        projectName: 'ProxyForge Packaged Runtime Workflow Smoke',
        scopeAllowlist: ['127.0.0.1', 'localhost'],
        issues,
        exchanges: exchanges as ReportExchange[],
        sections: ['executive', 'technical', 'remediation', 'evidence', 'appendix'] as ReportSection[],
        brandName: 'ProxyForge Release Smoke',
        preparedFor: 'Packaged Runtime Verification',
        engagementId: `RELEASE-${new Date().toISOString().slice(0, 10)}`,
        signerName: 'ProxyForge Release Smoke',
        signingKeyId: 'release-smoke',
        signingSecret: 'synthetic-release-smoke-signing-key',
      };
      reportArtifacts = [];
      for (const format of ['json', 'markdown', 'html', 'pdf', 'bundle'] as const) {
        reportArtifacts.push(await engine.exportReport({
          ...request,
          format,
          templateId: format === 'bundle' ? 'evidence-bundle' : 'technical-remediation',
          signEvidenceBundle: format === 'bundle',
        }));
      }
      const reportContents = reportArtifacts.map((artifact) => artifact.content).join('\n');
      reportSecretsRedacted = !reportContents.includes(SYNTHETIC_AUTH)
        && !reportContents.includes(SYNTHETIC_COOKIE)
        && !reportContents.includes(SYNTHETIC_API_KEY)
        && /redacted/i.test(reportContents);
      if (!reportSecretsRedacted) throw new Error('Report artifacts did not redact synthetic operational secrets.');
      return {
        message: 'Report export wrote JSON, Markdown, HTML, PDF, and bundle artifacts with report-phase redaction.',
        data: {
          formats: reportArtifacts.map((artifact) => artifact.format),
          issueCount: issues.length,
          exchangeCount: exchanges.length,
        },
      };
    });
  } finally {
    await callbackService.stopAll();
    if (proxy) await proxy.stop();
    if (httpsTarget) await closeServer(httpsTarget);
    if (httpTarget) await closeServer(httpTarget);
  }

  const httpCaptured = exchanges.some((exchange) => exchange.path === '/runtime?proof=proxy');
  const httpsCaptured = exchanges.some((exchange) => exchange.path === '/secure?proof=mitm' && exchange.tags?.includes('https'));
  const artifactStats = await statsFor([
    operationalCapturePath,
    ...reportArtifacts.map((artifact) => artifact.path),
  ].filter((item): item is string => Boolean(item)));
  const status = checks.every((check) => check.status === 'passed') ? 'passed' : 'failed';
  return {
    kind: 'proxyforge-release-runtime-workflow-smoke',
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    durationMs: Date.now() - startedAt,
    status,
    outDir,
    checks,
    proxy: {
      port: proxyPort,
      exchangeCount: exchanges.length,
      httpCaptured,
      httpsCaptured,
    },
    certificate: {
      ready: caReady,
      fingerprintSha256: caFingerprint,
      rootCertificatePath: caRootPath,
      hostCertificateCount: caHostCertificateCount,
    },
    oast: oastResult,
    reports: {
      count: reportArtifacts.length,
      formats: reportArtifacts.map((artifact) => artifact.format),
      artifactStats,
      operationalCapturePath,
      operationalSecretsPreserved,
      reportSecretsRedacted,
    },
  };
}

async function runChecked<T>(
  checks: SmokeCheck[],
  name: string,
  action: () => Promise<{ message: string; data?: Record<string, unknown>; value?: T }>,
): Promise<T> {
  const started = Date.now();
  try {
    const result = await action();
    checks.push({
      name,
      status: 'passed',
      durationMs: Date.now() - started,
      message: result.message,
      data: result.data,
    });
    return result.value as T;
  } catch (error) {
    checks.push({
      name,
      status: 'failed',
      durationMs: Date.now() - started,
      message: error instanceof Error ? error.message : String(error),
    });
    throw error;
  }
}

async function runOastSmoke(service: CallbackListenerService) {
  const profile: CallbackListenerProfile = {
    id: `release-runtime-listener-${Date.now()}`,
    name: 'Release runtime callback listener',
    createdAt: new Date().toISOString(),
    mode: 'hybrid-local',
    status: 'planned',
    host: '127.0.0.1',
    publicBaseUrl: 'oast.local',
    protocols: ['dns', 'http', 'smtp'],
    httpPort: 0,
    dnsPort: 0,
    smtpPort: 0,
    pollIntervalSeconds: 5,
    retentionHours: 24,
    signingKeyId: 'release-runtime-key',
    ciCommand: 'proxyforge oast poll --listener release-runtime-listener',
    healthChecks: [],
    summary: 'Release runtime listener smoke profile',
    content: '{}',
  };
  const payloads: CallbackPayload[] = [
    callbackPayload('release-http-payload', 'pf-release-http', 'http', 'https://pf-release-http.oast.local/probe'),
    callbackPayload('release-dns-payload', 'pf-release-dns', 'dns', 'pf-release-dns.oast.local'),
    callbackPayload('release-smtp-payload', 'pf-release-mail', 'smtp', 'pf-release-mail@oast.local'),
  ];
  const status = await service.start(profile, payloads);
  await sendHttpCallback(status.ports.http ?? 0, 'pf-release-http');
  await sendDnsCallback(status.ports.dns ?? 0, 'pf-release-dns.oast.local');
  await sendSmtpCallback(status.ports.smtp ?? 0, 'pf-release-mail@oast.local');
  await delay(100);
  const poll = service.poll(profile.id, payloads);
  const serialized = JSON.stringify(poll);
  return {
    interactionCount: poll.interactions.length,
    newInteractionCount: poll.newInteractionIds.length,
    protocols: Array.from(new Set(poll.interactions.map((interaction) => interaction.protocol))),
    ports: {
      http: status.ports.http ?? 0,
      dns: status.ports.dns ?? 0,
      smtp: status.ports.smtp ?? 0,
    },
    tokensPreserved: serialized.includes('pf-release-http')
      && serialized.includes('pf-release-dns')
      && serialized.includes('pf-release-mail'),
  };
}

function callbackPayload(id: string, token: string, protocol: 'http' | 'dns' | 'smtp', endpoint: string): CallbackPayload {
  return {
    id,
    token,
    label: `${protocol} release runtime callback`,
    protocol,
    endpoint,
    createdAt: new Date().toISOString(),
    status: 'waiting',
    sourceHost: 'runtime.local',
    sourcePath: '/release-smoke',
    notes: 'Release runtime listener smoke payload',
  };
}

function buildReportIssues(exchanges: any[]): ReportIssue[] {
  const firstHttp = exchanges.find((exchange) => exchange.path === '/runtime?proof=proxy');
  const firstHttps = exchanges.find((exchange) => exchange.path === '/secure?proof=mitm');
  return [
    {
      id: 'release-runtime-http-proxy-capture',
      title: 'Packaged runtime captured HTTP proxy traffic',
      severity: 'info',
      host: firstHttp?.host ?? '127.0.0.1',
      path: firstHttp?.path ?? '/runtime?proof=proxy',
      confidence: 'firm',
      status: 'open',
      detail: 'The packaged runtime proxy listener captured a loopback HTTP request with operational headers intact before report export.',
      remediation: 'Keep listener binding, history capture, and report redaction gates covered in release smoke.',
    },
    {
      id: 'release-runtime-https-mitm-capture',
      title: 'Packaged runtime decrypted HTTPS with project CA',
      severity: 'info',
      host: firstHttps?.host ?? 'localhost',
      path: firstHttps?.path ?? '/secure?proof=mitm',
      confidence: 'firm',
      status: 'open',
      detail: 'The packaged runtime generated a project CA and host certificate, then captured decrypted HTTPS loopback traffic through CONNECT MITM.',
      remediation: 'Keep project-scoped CA material isolated and require explicit browser trust installation in production workflows.',
    },
  ];
}

function requestViaProxy(proxyPort: number, targetUrl: string): Promise<{ statusCode: number; body: string }> {
  return new Promise((resolve, reject) => {
    const request = http.request({
      host: '127.0.0.1',
      port: proxyPort,
      method: 'GET',
      agent: false,
      path: targetUrl,
      headers: {
        Host: new URL(targetUrl).host,
        Authorization: SYNTHETIC_AUTH,
        Cookie: SYNTHETIC_COOKIE,
        'X-API-Key': SYNTHETIC_API_KEY,
        Connection: 'close',
      },
    }, (response) => {
      const chunks: Buffer[] = [];
      response.on('data', (chunk: Buffer) => chunks.push(chunk));
      response.on('end', () => {
        resolve({
          statusCode: response.statusCode ?? 0,
          body: Buffer.concat(chunks).toString('utf8'),
        });
      });
    });
    request.on('error', reject);
    request.end();
  });
}

async function requestThroughMitm(proxyPort: number, upstreamPort: number, caPem: string, requestPath: string) {
  const socket = net.connect(proxyPort, '127.0.0.1');
  await once(socket, 'connect');
  socket.write(`CONNECT localhost:${upstreamPort} HTTP/1.1\r\nHost: localhost:${upstreamPort}\r\n\r\n`);
  const connectResponse = await readUntil(socket, '\r\n\r\n');
  if (!connectResponse.toString('utf8').includes('200 Connection Established')) {
    throw new Error('CONNECT tunnel was not established.');
  }

  const tlsSocket = tls.connect({
    socket,
    servername: 'localhost',
    ca: caPem,
    rejectUnauthorized: true,
  });
  await once(tlsSocket, 'secureConnect');
  tlsSocket.write([
    `GET ${requestPath} HTTP/1.1`,
    `Host: localhost:${upstreamPort}`,
    `Authorization: ${SYNTHETIC_AUTH}`,
    `Cookie: ${SYNTHETIC_COOKIE}`,
    `X-API-Key: ${SYNTHETIC_API_KEY}`,
    'Connection: close',
    '',
    '',
  ].join('\r\n'));
  const response = await readUntil(tlsSocket, '"transport":"https"');
  tlsSocket.destroy();
  return response.toString('utf8');
}

function sendHttpCallback(port: number, token: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const request = http.request({
      host: '127.0.0.1',
      port,
      path: `/probe?token=${token}`,
      method: 'POST',
      headers: {
        Host: `${token}.oast.local`,
        'User-Agent': 'release-runtime-callback-smoke',
      },
    }, (response) => {
      response.resume();
      response.on('end', resolve);
    });
    request.on('error', reject);
    request.end('runtime=http');
  });
}

function sendDnsCallback(port: number, name: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const socket = dgram.createSocket('udp4');
    const query = buildDnsQuery(name);
    const timer = setTimeout(() => {
      socket.close();
      reject(new Error('Timed out waiting for DNS callback response.'));
    }, 2000);
    socket.on('message', () => {
      clearTimeout(timer);
      socket.close();
      resolve();
    });
    socket.on('error', (error) => {
      clearTimeout(timer);
      socket.close();
      reject(error);
    });
    socket.send(query, port, '127.0.0.1');
  });
}

function sendSmtpCallback(port: number, recipient: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host: '127.0.0.1', port });
    let settled = false;
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error('Timed out waiting for SMTP callback.'));
    }, 2000);
    const settle = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.end();
      resolve();
    };
    socket.on('connect', () => {
      socket.write([
        'EHLO release.local',
        'MAIL FROM:<runtime@proxyforge.local>',
        `RCPT TO:<${recipient}>`,
        'DATA',
        'Subject: release runtime callback',
        '',
        'runtime=smtp',
        '.',
        'QUIT',
        '',
      ].join('\r\n'));
    });
    socket.on('data', (chunk) => {
      if (chunk.toString('utf8').includes('221')) settle();
    });
    socket.on('close', settle);
    socket.on('error', (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(error);
    });
  });
}

function buildDnsQuery(name: string) {
  const labels = name.split('.');
  const questionLength = labels.reduce((total, label) => total + 1 + Buffer.byteLength(label), 0) + 1 + 4;
  const query = Buffer.alloc(12 + questionLength);
  query.writeUInt16BE(0x1234, 0);
  query.writeUInt16BE(0x0100, 2);
  query.writeUInt16BE(1, 4);
  let offset = 12;
  for (const label of labels) {
    query[offset] = Buffer.byteLength(label);
    offset += 1;
    query.write(label, offset, 'ascii');
    offset += Buffer.byteLength(label);
  }
  query[offset] = 0;
  offset += 1;
  query.writeUInt16BE(1, offset);
  offset += 2;
  query.writeUInt16BE(1, offset);
  return query;
}

async function statsFor(filePaths: string[]) {
  const stats = [];
  for (const filePath of filePaths) {
    try {
      const stat = await fs.stat(filePath);
      stats.push({ path: filePath, exists: true, sizeBytes: stat.size });
    } catch {
      stats.push({ path: filePath, exists: false, sizeBytes: 0 });
    }
  }
  return stats;
}

async function listenTcp(server: http.Server | https.Server | net.Server): Promise<number> {
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('Server did not bind to a TCP port.');
  return address.port;
}

async function closeServer(server: http.Server | https.Server | net.Server) {
  await new Promise<void>((resolve, reject) => {
    server.close((error) => {
      if (error) reject(error);
      else resolve();
    });
  });
}

async function freePort() {
  const server = net.createServer();
  const port = await listenTcp(server);
  await closeServer(server);
  return port;
}

function once(emitter: NodeJS.EventEmitter, event: string): Promise<unknown> {
  return new Promise((resolve, reject) => {
    emitter.once(event, resolve);
    emitter.once('error', reject);
  });
}

function readUntil(stream: NodeJS.ReadableStream, needle: string): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    const timer = setTimeout(() => {
      cleanup();
      reject(new Error(`Timed out waiting for ${needle}.`));
    }, 5000);
    const onData = (chunk: Buffer) => {
      chunks.push(chunk);
      const buffer = Buffer.concat(chunks);
      if (buffer.toString('utf8').includes(needle)) {
        cleanup();
        resolve(buffer);
      }
    };
    const onError = (error: Error) => {
      cleanup();
      reject(error);
    };
    const cleanup = () => {
      clearTimeout(timer);
      stream.off('data', onData);
      stream.off('error', onError);
    };
    stream.on('data', onData);
    stream.on('error', onError);
  });
}

async function waitFor<T>(check: () => T | undefined, timeoutMs = 5000): Promise<T> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const value = check();
    if (value) return value;
    await delay(25);
  }
  throw new Error('Timed out waiting for runtime evidence.');
}

function delay(ms: number) {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

function parseArgs(argv: string[]) {
  const flags: Record<string, string | boolean> = {};
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token.startsWith('--')) continue;
    const key = token.slice(2);
    const next = argv[index + 1];
    if (!next || next.startsWith('--')) {
      flags[key] = true;
    } else {
      flags[key] = next;
      index += 1;
    }
  }
  return flags;
}

if (require.main === module) {
  void main();
}
