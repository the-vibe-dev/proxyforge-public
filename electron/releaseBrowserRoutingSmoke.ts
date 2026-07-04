#!/usr/bin/env node
import { spawn } from 'node:child_process';
import fs from 'node:fs/promises';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import path from 'node:path';
import { createHash } from 'node:crypto';
import forge from 'node-forge';
import { buildLaunchPlan, findBrowserCandidate, type ManagedBrowserFamily } from './browserLauncher';
import { CertificateAuthorityManager } from './certManager';
import { ProxyEngine } from './proxyEngine';

type SmokeStatus = 'passed' | 'blocked' | 'failed';

interface BrowserRoutingSummary {
  kind: 'proxyforge-release-browser-routing-smoke';
  schemaVersion: 1;
  generatedAt: string;
  durationMs: number;
  status: SmokeStatus;
  outDir: string;
  checks: Array<{
    name: string;
    status: SmokeStatus;
    durationMs: number;
    message: string;
    data?: Record<string, unknown>;
  }>;
  proxy: {
    port?: number;
    exchangeCount: number;
    browserCaptured: boolean;
  };
  browser: {
    requested: ManagedBrowserFamily;
    name?: string;
    command?: string;
    family?: string;
    profilePath?: string;
    targetUrl: string;
    exitCode?: number | null;
    proxyConfigured: boolean;
    certificateMode: 'not-tested' | 'ignore-errors-flag' | 'trusted-ca';
    trustStorePath?: string;
    trustStoreConfigured: boolean;
  };
  artifacts: Array<{
    path: string;
    exists: boolean;
    sizeBytes: number;
  }>;
}

interface InstalledTrustStore {
  trustStorePath: string;
  browserEnv: NodeJS.ProcessEnv;
  message: string;
  cleanupDescription: string;
  homeDir?: string;
  cleanup?: () => Promise<void>;
}

class BlockedSmokeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'BlockedSmokeError';
  }
}

const startedAt = Date.now();
const BROWSER_PROOF_PATH = '/browser?proof=routing';

async function main() {
  const flags = parseArgs(process.argv.slice(2));
  const outDir = path.resolve(String(flags.outDir ?? flags['out-dir'] ?? path.join(process.cwd(), 'test-results', 'release-browser-routing')));
  const browser = normalizeBrowser(String(flags.browser ?? 'auto'));
  const requireBrowser = flags.require !== false && flags['allow-blocked'] !== true;
  const trustStore = Boolean(flags.trustedCa ?? flags['trusted-ca'] ?? flags.trustStore ?? flags['trust-store']);
  const summary = await runBrowserRoutingSmoke(outDir, browser, trustStore);
  await writeStdout(`${JSON.stringify(summary, null, 2)}\n`);
  const exitCode = summary.status === 'failed' || (summary.status === 'blocked' && requireBrowser) ? 1 : 0;
  process.exit(exitCode);
}

async function runBrowserRoutingSmoke(outDir: string, requestedBrowser: ManagedBrowserFamily, trustStore: boolean): Promise<BrowserRoutingSummary> {
  await fs.mkdir(outDir, { recursive: true });
  const checks: BrowserRoutingSummary['checks'] = [];
  const exchanges: any[] = [];
  const targetHandler: http.RequestListener = (request, response) => {
    response.writeHead(200, {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store',
      'x-proxyforge-browser-routing': 'hit',
    });
    response.end(`<html><body>proxyforge-browser-routing-ok ${request.url}</body></html>`);
  };
  const target = trustStore
    ? https.createServer(createSelfSignedHttpsOptions(), targetHandler)
    : http.createServer(targetHandler);
  const caManager = new CertificateAuthorityManager(path.join(outDir, 'certs'));
  const proxy = new ProxyEngine((exchange) => exchanges.push(exchange), caManager);
  let targetPort = 0;
  let proxyPort = 0;
  const artifactPaths: string[] = [];
  let browserResult: Awaited<ReturnType<typeof runBrowser>> | null = null;
  let plan: Awaited<ReturnType<typeof buildLaunchPlan>> | null = null;
  let candidate: Awaited<ReturnType<typeof findBrowserCandidate>> | null = null;
  const profilePath = path.join(outDir, 'managed-browser-profile');
  let browserEnv: NodeJS.ProcessEnv | undefined;
  let trustStorePath: string | undefined;
  let cleanupTrustStore: (() => Promise<void>) | undefined;
  const targetUrl = '';

  try {
    await runChecked(checks, 'loopback-target', async () => {
      targetPort = await listenTcp(target);
      return {
        message: `Loopback browser target listening on 127.0.0.1:${targetPort}.`,
        data: { targetPort },
      };
    });

    await runChecked(checks, 'proxy-listener', async () => {
      proxyPort = await freePort();
      await proxy.start(proxyPort);
      return {
        message: `Proxy listener ready for browser routing on 127.0.0.1:${proxyPort}.`,
        data: { proxyPort },
      };
    });

    candidate = await preferredBrowserCandidate(requestedBrowser);
    if (!candidate) {
      checks.push({
        name: 'managed-browser-discovery',
        status: 'blocked',
        durationMs: 0,
        message: 'No Chromium, Chrome, or Edge executable was found on this host.',
        data: { requestedBrowser },
      });
      return await finalizeSummary({
        outDir,
        checks,
        status: 'blocked',
        exchanges,
        proxyPort,
        requestedBrowser,
        targetUrl: `http://127.0.0.1:${targetPort}${BROWSER_PROOF_PATH}`,
        plan,
        candidate,
        browserResult,
        artifactPaths,
        trustStorePath,
        trustStore,
      });
    }

    if (trustStore) {
      const trustResult = await runChecked(checks, 'browser-trust-store', async () => {
        const root = await caManager.ensureRoot();
        const exported = await caManager.exportRootPem();
        const trust = await installChromiumTrustStore(outDir, exported.path);
        trustStorePath = trust.trustStorePath;
        browserEnv = trust.browserEnv;
        cleanupTrustStore = trust.cleanup;
        return {
          message: trust.message,
          data: {
            rootCertificatePath: exported.path,
            fingerprintSha256: exported.fingerprintSha256,
            validUntil: root.validUntil,
            trustStorePath: trust.trustStorePath,
            browserHome: trust.homeDir,
            cleanup: trust.cleanupDescription,
          },
          value: trust,
        };
      });
      trustStorePath = trustResult.trustStorePath;
    }

    plan = await runChecked(checks, 'managed-browser-plan', async () => {
      const selectedCandidate = candidate as NonNullable<typeof candidate>;
      const nextPlan = await buildLaunchPlan({
        candidate: selectedCandidate,
        targetUrl: `${trustStore ? 'https' : 'http'}://127.0.0.1:${targetPort}${BROWSER_PROOF_PATH}`,
        proxyHost: '127.0.0.1',
        proxyPort,
        profilePath,
        ignoreCertificateErrors: !trustStore,
      });
      if (!nextPlan.args.some((arg) => arg === `--user-data-dir=${profilePath}`)) throw new Error('Browser plan did not isolate the profile path.');
      if (!nextPlan.args.some((arg) => arg.includes(`127.0.0.1:${proxyPort}`))) throw new Error('Browser plan did not include the ProxyForge proxy.');
      if (trustStore && nextPlan.args.some((arg) => arg === '--ignore-certificate-errors')) throw new Error('Trusted-CA browser plan still included --ignore-certificate-errors.');
      return {
        message: `${selectedCandidate.name} launch plan routes through ProxyForge with an isolated profile${trustStore ? ' and trusted project CA' : ''}.`,
        data: {
          browser: selectedCandidate.name,
          command: selectedCandidate.command,
          profilePath,
          proxyPort,
          certificateMode: trustStore ? 'trusted-ca' : 'ignore-errors-flag',
        },
        value: nextPlan,
      };
    });

    browserResult = await runChecked(checks, 'browser-proxy-routing', async () => {
      const result = await runBrowser(plan as NonNullable<typeof plan>, browserEnv);
      const captured = await waitFor(() => exchanges.find((exchange) => exchange.path === BROWSER_PROOF_PATH));
      if (result.status !== 0) {
        throw new Error(`Browser exited with ${result.status}: ${result.stderr.slice(0, 500)}`);
      }
      if (!result.stdout.includes('proxyforge-browser-routing-ok')) {
        throw new Error('Browser did not render the loopback routing proof page.');
      }
      if (!captured) throw new Error('ProxyForge did not capture the browser-routed request.');
      return {
        message: `${plan?.candidate.name ?? 'Browser'} routed ${trustStore ? 'trusted HTTPS' : 'loopback'} traffic through the packaged proxy listener.`,
        data: {
          exitCode: result.status,
          exchangeId: captured.id,
          userAgentCaptured: /user-agent:/i.test(String(captured.requestRaw)),
          certificateMode: trustStore ? 'trusted-ca' : 'ignore-errors-flag',
          source: captured.source,
          tags: captured.tags,
        },
        value: result,
      };
    });

    if (cleanupTrustStore) {
      await runChecked(checks, 'browser-trust-store-cleanup', async () => {
        await cleanupTrustStore?.();
        cleanupTrustStore = undefined;
        return {
          message: `Removed temporary trusted browser CA from ${trustStorePath}.`,
          data: { trustStorePath },
        };
      });
    }

    const capturePath = path.join(outDir, 'proxyforge-browser-routing-operational-capture.json');
    await fs.writeFile(capturePath, JSON.stringify({ exchanges }, null, 2), 'utf8');
    artifactPaths.push(capturePath);

    return await finalizeSummary({
      outDir,
      checks,
      status: checks.every((check) => check.status === 'passed') ? 'passed' : 'failed',
      exchanges,
      proxyPort,
      requestedBrowser,
      targetUrl: plan?.targetUrl ?? `http://127.0.0.1:${targetPort}${BROWSER_PROOF_PATH}`,
      plan,
      candidate,
      browserResult,
      artifactPaths,
      trustStorePath,
      trustStore,
    });
  } catch (error) {
    const blocked = error instanceof BlockedSmokeError;
    checks.push({
      name: 'browser-routing-smoke',
      status: blocked ? 'blocked' : 'failed',
      durationMs: 0,
      message: error instanceof Error ? error.message : String(error),
    });
    return await finalizeSummary({
      outDir,
      checks,
      status: blocked ? 'blocked' : 'failed',
      exchanges,
      proxyPort,
      requestedBrowser,
      targetUrl: plan?.targetUrl ?? targetUrl,
      plan,
      candidate,
      browserResult,
      artifactPaths,
      trustStorePath,
      trustStore,
    });
  } finally {
    await settleCleanup(proxy.stop(), 1500);
    await settleCleanup(closeServer(target), 1500);
    if (cleanupTrustStore) await settleCleanup(cleanupTrustStore(), 5000);
  }
}

async function preferredBrowserCandidate(requestedBrowser: ManagedBrowserFamily) {
  const families: ManagedBrowserFamily[] = requestedBrowser === 'auto'
    ? ['chromium', 'chrome', 'edge']
    : requestedBrowser === 'firefox'
      ? []
      : [requestedBrowser];
  for (const family of families) {
    const candidate = await findBrowserCandidate(family);
    if (candidate && candidate.family !== 'firefox') return candidate;
  }
  return null;
}

async function finalizeSummary(options: {
  outDir: string;
  checks: BrowserRoutingSummary['checks'];
  status: SmokeStatus;
  exchanges: any[];
  proxyPort: number;
  requestedBrowser: ManagedBrowserFamily;
  targetUrl: string;
  plan: Awaited<ReturnType<typeof buildLaunchPlan>> | null;
  candidate: Awaited<ReturnType<typeof findBrowserCandidate>> | null;
  browserResult: Awaited<ReturnType<typeof runBrowser>> | null;
  artifactPaths: string[];
  trustStorePath?: string;
  trustStore: boolean;
}): Promise<BrowserRoutingSummary> {
  const browserCaptured = options.exchanges.some((exchange) => exchange.path === BROWSER_PROOF_PATH);
  const summaryPath = path.join(options.outDir, 'proxyforge-browser-routing-summary.json');
  const artifacts = await statsFor(options.artifactPaths);
  const summary: BrowserRoutingSummary = {
    kind: 'proxyforge-release-browser-routing-smoke',
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    durationMs: Date.now() - startedAt,
    status: options.status,
    outDir: options.outDir,
    checks: options.checks,
    proxy: {
      port: options.proxyPort || undefined,
      exchangeCount: options.exchanges.length,
      browserCaptured,
    },
    browser: {
      requested: options.requestedBrowser,
      name: options.plan?.candidate.name ?? options.candidate?.name,
      command: options.plan?.candidate.command ?? options.candidate?.command,
      family: options.plan?.candidate.family ?? options.candidate?.family,
      profilePath: options.plan?.profilePath,
      targetUrl: options.plan?.targetUrl ?? options.targetUrl,
      exitCode: options.browserResult?.status,
      proxyConfigured: Boolean(options.plan?.args.some((arg) => /--proxy-server=/.test(arg))),
      certificateMode: options.trustStore ? 'trusted-ca' : 'ignore-errors-flag',
      trustStorePath: options.trustStorePath,
      trustStoreConfigured: options.trustStore ? Boolean(options.trustStorePath) : false,
    },
    artifacts,
  };
  await fs.writeFile(summaryPath, JSON.stringify(summary, null, 2), 'utf8');
  return {
    ...summary,
    artifacts: await statsFor([...options.artifactPaths, summaryPath]),
  };
}

async function runChecked<T>(
  checks: BrowserRoutingSummary['checks'],
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
    const blocked = error instanceof BlockedSmokeError;
    checks.push({
      name,
      status: blocked ? 'blocked' : 'failed',
      durationMs: Date.now() - started,
      message: error instanceof Error ? error.message : String(error),
    });
    throw error;
  }
}

function runBrowser(plan: Awaited<ReturnType<typeof buildLaunchPlan>>, env?: NodeJS.ProcessEnv): Promise<{ status: number | null; stdout: string; stderr: string }> {
  const targetArg = plan.args.at(-1) ?? plan.targetUrl;
  const args = [
    ...plan.args.slice(0, -1),
    '--headless=new',
    '--disable-gpu',
    '--disable-dev-shm-usage',
    '--disable-background-networking',
    '--disable-component-update',
    '--disable-domain-reliability',
    '--disable-extensions',
    '--disable-default-apps',
    '--no-first-run',
    '--disable-sync',
    '--disable-client-side-phishing-detection',
    '--safebrowsing-disable-auto-update',
    '--disable-features=OptimizationHints,AutofillServerCommunication,MediaRouter,DialMediaRouteProvider,InterestFeedContentSuggestions',
    '--no-sandbox',
    '--dump-dom',
    targetArg,
  ];
  return new Promise((resolve, reject) => {
    const child = spawn(plan.candidate.command, args, {
      cwd: process.cwd(),
      env: env ?? process.env,
      windowsHide: true,
    });
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => {
      child.kill();
      resolve({ status: null, stdout, stderr: `${stderr}\nTimed out waiting for browser routing smoke.` });
    }, 20000);
    child.stdout.on('data', (chunk: Buffer) => {
      stdout += chunk.toString('utf8');
    });
    child.stderr.on('data', (chunk: Buffer) => {
      stderr += chunk.toString('utf8');
    });
    child.on('error', (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.on('close', (status) => {
      clearTimeout(timer);
      resolve({ status, stdout, stderr });
    });
  });
}

async function installChromiumTrustStore(outDir: string, rootCertificatePath: string): Promise<InstalledTrustStore> {
  if (process.platform === 'win32') {
    return installWindowsCurrentUserTrustStore(rootCertificatePath);
  }
  const certutil = await findCommand('certutil');
  if (!certutil) {
    throw new Error('certutil is not available; install libnss3-tools to run the trusted-CA browser smoke.');
  }
  const homeDir = path.join(outDir, `browser-home-${process.pid}-${Date.now()}`);
  const trustStorePath = path.join(homeDir, '.pki', 'nssdb');
  await fs.mkdir(trustStorePath, { recursive: true });
  await runProcess(certutil, ['-N', '-d', `sql:${trustStorePath}`, '--empty-password'], {}, 10000);
  await runProcess(certutil, ['-A', '-d', `sql:${trustStorePath}`, '-t', 'C,,', '-n', 'ProxyForge Release Root CA', '-i', rootCertificatePath], {}, 10000);
  return {
    homeDir,
    trustStorePath,
    browserEnv: { ...process.env, HOME: homeDir },
    message: `Imported ProxyForge project CA into isolated Chromium NSS trust store ${trustStorePath}.`,
    cleanupDescription: 'Isolated HOME/NSS directory is retained as ignored release-smoke artifact.',
  };
}

async function installWindowsCurrentUserTrustStore(rootCertificatePath: string) {
  const certutil = await findWindowsSystemCommand('certutil.exe');
  if (!certutil) {
    throw new Error('Windows certutil.exe was not found under SystemRoot/System32 for the current-user trust-store smoke.');
  }
  const thumbprintSha1 = await certificateSha1Thumbprint(rootCertificatePath);
  const derPath = await writeCertificateDer(rootCertificatePath);
  const trustStorePath = `Cert:\\CurrentUser\\Root\\${thumbprintSha1}`;
  try {
    await runProcess(certutil, ['-user', '-addstore', '-f', 'Root', derPath], {}, 15000);
    await runProcess(certutil, ['-user', '-store', 'Root', thumbprintSha1], {}, 15000);
  } catch (error) {
    await settleCleanup(runProcess(certutil, ['-user', '-delstore', 'Root', thumbprintSha1], {}, 15000), 5000);
    if (isWindowsTrustStoreHostBlock(error)) {
      throw new BlockedSmokeError(`Windows current-user Root store rejected temporary CA import for this host/session: ${error instanceof Error ? error.message : String(error)}`);
    }
    throw error;
  }
  return {
    trustStorePath,
    browserEnv: process.env,
    message: `Imported ProxyForge project CA into Windows current-user Root store ${trustStorePath}.`,
    cleanupDescription: 'Removes the temporary ProxyForge release root CA from CurrentUser Root after the smoke.',
    cleanup: async () => {
      await runProcess(certutil, ['-user', '-delstore', 'Root', thumbprintSha1], {}, 15000);
    },
  };
}

async function certificateSha1Thumbprint(rootCertificatePath: string) {
  const pem = await fs.readFile(rootCertificatePath, 'utf8');
  const certificate = forge.pki.certificateFromPem(pem);
  const der = Buffer.from(forge.asn1.toDer(forge.pki.certificateToAsn1(certificate)).getBytes(), 'binary');
  return createHash('sha1').update(der).digest('hex').toUpperCase();
}

async function writeCertificateDer(rootCertificatePath: string) {
  const pem = await fs.readFile(rootCertificatePath, 'utf8');
  const certificate = forge.pki.certificateFromPem(pem);
  const der = Buffer.from(forge.asn1.toDer(forge.pki.certificateToAsn1(certificate)).getBytes(), 'binary');
  const derPath = path.join(path.dirname(rootCertificatePath), 'proxyforge-root-ca.cer');
  await fs.writeFile(derPath, der);
  return derPath;
}

async function findCommand(command: string) {
  const parts = (process.env.PATH ?? '').split(path.delimiter).filter(Boolean);
  for (const part of parts) {
    const candidate = path.join(part, command);
    try {
      await fs.access(candidate);
      return candidate;
    } catch {
      // Keep searching.
    }
  }
  return null;
}

async function findWindowsSystemCommand(command: string) {
  const roots = [process.env.SystemRoot, process.env.windir, 'C:\\Windows'].filter((root): root is string => Boolean(root));
  const candidates = roots.flatMap((root) => [
    path.join(root, 'System32', command),
    path.join(root, 'Sysnative', command),
  ]);
  for (const candidate of candidates) {
    try {
      await fs.access(candidate);
      return candidate;
    } catch {
      // Keep searching.
    }
  }
  return findCommand(command);
}

function runProcess(command: string, args: string[], env: NodeJS.ProcessEnv, timeoutMs: number): Promise<{ status: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: process.cwd(),
      env: { ...process.env, ...env },
      windowsHide: true,
    });
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error(`${command} timed out after ${timeoutMs}ms: ${processOutput(stdout, stderr).slice(0, 500)}`));
    }, timeoutMs);
    child.stdout.on('data', (chunk: Buffer) => {
      stdout += chunk.toString('utf8');
    });
    child.stderr.on('data', (chunk: Buffer) => {
      stderr += chunk.toString('utf8');
    });
    child.on('error', (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.on('close', (status) => {
      clearTimeout(timer);
      if (status === 0) resolve({ status, stdout, stderr });
      else reject(new Error(`${command} exited with ${status}: ${processOutput(stdout, stderr).slice(0, 500)}`));
    });
  });
}

function processOutput(stdout: string, stderr: string) {
  return `${stderr}\n${stdout}`.trim();
}

function isWindowsTrustStoreHostBlock(error: unknown) {
  const message = error instanceof Error ? error.message : String(error);
  return /ERROR_NOT_SUPPORTED|UI is not allowed|Access is denied|request is not supported/i.test(message);
}

function createSelfSignedHttpsOptions() {
  const keys = forge.pki.rsa.generateKeyPair({ bits: 2048, workers: -1 });
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = Date.now().toString(16);
  cert.validity.notBefore = new Date(Date.now() - 60_000);
  cert.validity.notAfter = new Date(Date.now() + 60 * 60 * 1000);
  cert.setSubject([{ name: 'commonName', value: '127.0.0.1' }]);
  cert.setIssuer([{ name: 'commonName', value: 'ProxyForge Browser Routing Upstream' }]);
  cert.setExtensions([
    { name: 'basicConstraints', cA: false },
    { name: 'keyUsage', digitalSignature: true, keyEncipherment: true },
    { name: 'extKeyUsage', serverAuth: true },
    { name: 'subjectAltName', altNames: [{ type: 7, ip: '127.0.0.1' }] },
  ]);
  cert.sign(keys.privateKey, forge.md.sha256.create());
  return {
    key: forge.pki.privateKeyToPem(keys.privateKey),
    cert: forge.pki.certificateToPem(cert),
  };
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

async function listenTcp(server: http.Server | net.Server): Promise<number> {
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('Server did not bind to a TCP port.');
  return address.port;
}

async function closeServer(server: http.Server | net.Server) {
  const httpServer = server as http.Server;
  httpServer.closeIdleConnections?.();
  httpServer.closeAllConnections?.();
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

async function waitFor<T>(check: () => T | undefined, timeoutMs = 5000): Promise<T> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const value = check();
    if (value) return value;
    await delay(25);
  }
  throw new Error('Timed out waiting for browser routing evidence.');
}

function delay(ms: number) {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

function writeStdout(value: string) {
  return new Promise<void>((resolve) => {
    process.stdout.write(value, () => resolve());
  });
}

async function settleCleanup(cleanup: Promise<unknown>, timeoutMs: number) {
  await Promise.race([
    cleanup.catch(() => undefined),
    delay(timeoutMs),
  ]);
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

function normalizeBrowser(value: string): ManagedBrowserFamily {
  if (value === 'chromium' || value === 'chrome' || value === 'edge' || value === 'firefox') return value;
  return 'auto';
}

if (require.main === module) {
  void main();
}
