import { createCipheriv, randomBytes } from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { buildBrowserCookieReadinessReport, extractBrowserCookies } from './browserCookies';

const SAMPLE_HOST = 'app.dpapi.local';
const SAMPLE_TARGET = `https://${SAMPLE_HOST}/dashboard`;
const SAMPLE_COOKIE_NAME = 'proxyforge_dpapi_session';
const SAMPLE_COOKIE_VALUE = 'dpapi-sample-session-value';

interface CookieDpapiSummary {
  kind: 'proxyforge-release-cookie-dpapi-smoke';
  schemaVersion: 1;
  generatedAt: string;
  durationMs: number;
  status: 'passed' | 'failed' | 'blocked';
  platform: NodeJS.Platform;
  outDir: string;
  profilePath: string;
  checks: Array<{
    name: string;
    status: 'passed' | 'failed' | 'blocked';
    durationMs: number;
    message: string;
    data?: Record<string, unknown>;
  }>;
  dpapi: {
    wrappedKeyCreated: boolean;
    readinessStatus?: string;
    currentUserScope: boolean;
  };
  extraction: {
    status?: string;
    cookieCount: number;
    decryptedCount: number;
    encryptedCount: number;
    cookieNames: string[];
    operationalCookieHeaderPreserved: boolean;
    summaryCookieValuesRedacted: boolean;
  };
  artifacts: Array<{
    path: string;
    exists: boolean;
    sizeBytes: number;
  }>;
}

async function main() {
  const startedAt = Date.now();
  const flags = parseArgs(process.argv.slice(2));
  const outDir = path.resolve(String(flags.outDir ?? flags['out-dir'] ?? path.join(process.cwd(), 'test-results', 'release-cookie-dpapi')));
  const summary = await runCookieDpapiSmoke(outDir, startedAt);
  await writeStdout(`${JSON.stringify(summary, null, 2)}\n`);
  process.exit(summary.status === 'passed' || summary.status === 'blocked' ? 0 : 1);
}

async function runCookieDpapiSmoke(outDir: string, startedAt: number): Promise<CookieDpapiSummary> {
  await fs.mkdir(outDir, { recursive: true });
  const checks: CookieDpapiSummary['checks'] = [];
  const artifacts: string[] = [];
  const profilePath = path.join(outDir, 'chromium-dpapi-profile');
  const cookieDbPath = path.join(profilePath, 'Default', 'Network', 'Cookies');
  let wrappedKeyCreated = false;
  let readinessStatus: string | undefined;
  let cookieCount = 0;
  let decryptedCount = 0;
  let encryptedCount = 0;
  let cookieNames: string[] = [];
  let operationalCookieHeaderPreserved = false;
  let summaryCookieValuesRedacted = true;

  if (process.platform !== 'win32') {
    checks.push({
      name: 'windows-host',
      status: 'blocked',
      durationMs: 0,
      message: 'Windows DPAPI sample-cookie smoke must run under the Windows user that owns the browser profile.',
      data: { platform: process.platform },
    });
    return finalizeSummary({
      startedAt,
      outDir,
      profilePath,
      checks,
      wrappedKeyCreated,
      readinessStatus,
      cookieCount,
      decryptedCount,
      encryptedCount,
      cookieNames,
      operationalCookieHeaderPreserved,
      summaryCookieValuesRedacted,
      artifacts,
    });
  }

  try {
    const fixture = await runChecked(checks, 'dpapi-chromium-fixture', async () => {
      await fs.mkdir(path.dirname(cookieDbPath), { recursive: true });
      const key = randomBytes(32);
      const protectedKey = await protectWindowsDpapi(key);
      wrappedKeyCreated = protectedKey.length > 0;
      const encryptedValue = encryptChromiumCookie(key, SAMPLE_COOKIE_VALUE);
      const localStatePath = path.join(profilePath, 'Local State');
      await fs.writeFile(localStatePath, JSON.stringify({
        os_crypt: {
          encrypted_key: Buffer.concat([Buffer.from('DPAPI'), protectedKey]).toString('base64'),
        },
      }, null, 2), 'utf8');
      await writeCookieDatabase(cookieDbPath, encryptedValue);
      return {
        message: 'Created a synthetic Chromium profile with a DPAPI-wrapped profile key and encrypted sample cookie.',
        data: {
          profilePath,
          localStatePath,
          cookieDbPath,
          protectedKeyBytes: protectedKey.length,
          encryptedCookieBytes: encryptedValue.length,
        },
        value: { localStatePath, cookieDbPath },
      };
    });
    artifacts.push(fixture.localStatePath, fixture.cookieDbPath);

    const extraction = await runChecked(checks, 'dpapi-cookie-extraction', async () => {
      const result = await extractBrowserCookies({
        targetUrl: SAMPLE_TARGET,
        browser: 'chromium',
        profilePath,
      });
      const readiness = await buildBrowserCookieReadinessReport({
        targetUrl: SAMPLE_TARGET,
        browser: 'chromium',
        profilePath,
      });
      const dpapi = readiness.capabilities.find((capability) => capability.id === 'chromium-windows-dpapi');
      readinessStatus = dpapi?.status;
      cookieCount = result.cookieCount;
      decryptedCount = result.decryptedCount;
      encryptedCount = result.encryptedCount;
      cookieNames = result.cookies.map((cookie) => cookie.name);
      operationalCookieHeaderPreserved = result.cookieHeader.includes(SAMPLE_COOKIE_VALUE);
      if (dpapi?.status !== 'ready') throw new Error(`DPAPI readiness status was ${dpapi?.status ?? 'missing'}, expected ready.`);
      if (result.status !== 'complete') throw new Error(`Cookie extraction status was ${result.status}, expected complete.`);
      if (!operationalCookieHeaderPreserved) throw new Error('DPAPI sample cookie value was not present in the operational cookie header.');
      if (decryptedCount < 1 || encryptedCount !== 0) throw new Error(`Expected decryptedCount >= 1 and encryptedCount 0, got decrypted=${decryptedCount}, encrypted=${encryptedCount}.`);
      const operationalPath = path.join(outDir, 'proxyforge-dpapi-cookie-operational-capture.json');
      await fs.writeFile(operationalPath, JSON.stringify({
        kind: 'proxyforge-dpapi-cookie-operational-capture',
        targetUrl: SAMPLE_TARGET,
        profilePath,
        extraction: result,
        readiness,
      }, null, 2), 'utf8');
      artifacts.push(operationalPath);
      return {
        message: `Extracted and decrypted ${decryptedCount} DPAPI-backed Chromium sample cookie value.`,
        data: {
          status: result.status,
          cookieCount,
          decryptedCount,
          encryptedCount,
          cookieNames,
          readinessStatus,
          operationalCapturePath: operationalPath,
        },
        value: { operationalPath },
      };
    });
    artifacts.push(extraction.operationalPath);
  } catch (error) {
    checks.push({
      name: 'cookie-dpapi-smoke',
      status: 'failed',
      durationMs: 0,
      message: error instanceof Error ? error.message : 'DPAPI sample-cookie smoke failed.',
    });
  }

  const summary = await finalizeSummary({
    startedAt,
    outDir,
    profilePath,
    checks,
    wrappedKeyCreated,
    readinessStatus,
    cookieCount,
    decryptedCount,
    encryptedCount,
    cookieNames,
    operationalCookieHeaderPreserved,
    summaryCookieValuesRedacted,
    artifacts,
  });
  summaryCookieValuesRedacted = !JSON.stringify(summary).includes(SAMPLE_COOKIE_VALUE);
  summary.extraction.summaryCookieValuesRedacted = summaryCookieValuesRedacted;
  await fs.writeFile(path.join(outDir, 'proxyforge-dpapi-cookie-summary.json'), JSON.stringify(summary, null, 2), 'utf8');
  summary.artifacts = await statsFor([...artifacts, path.join(outDir, 'proxyforge-dpapi-cookie-summary.json')]);
  summary.status = summary.checks.every((check) => check.status === 'passed')
    && summary.dpapi.wrappedKeyCreated
    && summary.dpapi.readinessStatus === 'ready'
    && summary.extraction.cookieCount >= 1
    && summary.extraction.decryptedCount >= 1
    && summary.extraction.encryptedCount === 0
    && summary.extraction.operationalCookieHeaderPreserved
    && summary.extraction.summaryCookieValuesRedacted
    ? 'passed'
    : 'failed';
  await fs.writeFile(path.join(outDir, 'proxyforge-dpapi-cookie-summary.json'), JSON.stringify(summary, null, 2), 'utf8');
  return summary;
}

async function finalizeSummary(options: {
  startedAt: number;
  outDir: string;
  profilePath: string;
  checks: CookieDpapiSummary['checks'];
  wrappedKeyCreated: boolean;
  readinessStatus?: string;
  cookieCount: number;
  decryptedCount: number;
  encryptedCount: number;
  cookieNames: string[];
  operationalCookieHeaderPreserved: boolean;
  summaryCookieValuesRedacted: boolean;
  artifacts: string[];
}): Promise<CookieDpapiSummary> {
  const blocked = options.checks.some((check) => check.status === 'blocked');
  return {
    kind: 'proxyforge-release-cookie-dpapi-smoke',
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    durationMs: Date.now() - options.startedAt,
    status: blocked ? 'blocked' : 'failed',
    platform: process.platform,
    outDir: options.outDir,
    profilePath: options.profilePath,
    checks: options.checks,
    dpapi: {
      wrappedKeyCreated: options.wrappedKeyCreated,
      readinessStatus: options.readinessStatus,
      currentUserScope: process.platform === 'win32',
    },
    extraction: {
      status: options.cookieCount > 0 ? 'complete' : undefined,
      cookieCount: options.cookieCount,
      decryptedCount: options.decryptedCount,
      encryptedCount: options.encryptedCount,
      cookieNames: options.cookieNames,
      operationalCookieHeaderPreserved: options.operationalCookieHeaderPreserved,
      summaryCookieValuesRedacted: options.summaryCookieValuesRedacted,
    },
    artifacts: await statsFor(options.artifacts),
  };
}

async function runChecked<T>(
  checks: CookieDpapiSummary['checks'],
  name: string,
  action: () => Promise<{ message: string; data?: Record<string, unknown>; value: T }>,
): Promise<T> {
  const startedAt = Date.now();
  try {
    const result = await action();
    checks.push({
      name,
      status: 'passed',
      durationMs: Date.now() - startedAt,
      message: result.message,
      data: result.data,
    });
    return result.value;
  } catch (error) {
    checks.push({
      name,
      status: 'failed',
      durationMs: Date.now() - startedAt,
      message: error instanceof Error ? error.message : `${name} failed.`,
    });
    throw error;
  }
}

async function writeCookieDatabase(cookieDbPath: string, encryptedValue: Buffer) {
  const sqlite = await loadSqlite();
  if (!sqlite) throw new Error('node:sqlite is unavailable in this packaged runtime.');
  const database = new sqlite.DatabaseSync(cookieDbPath);
  try {
    database.exec([
      'create table cookies (',
      'host_key text,',
      'name text,',
      'value text,',
      'encrypted_value blob,',
      'path text,',
      'expires_utc integer,',
      'is_secure integer,',
      'is_httponly integer,',
      'samesite integer',
      ');',
      `insert into cookies values ('${SAMPLE_HOST}', '${SAMPLE_COOKIE_NAME}', '', x'${encryptedValue.toString('hex')}', '/', 0, 1, 1, 1);`,
    ].join(' '));
  } finally {
    database.close();
  }
}

async function loadSqlite(): Promise<{ DatabaseSync: new (filePath: string, options?: { readOnly?: boolean }) => SqliteDatabase } | null> {
  try {
    const dynamicImport = new Function('specifier', 'return import(specifier)') as (specifier: string) => Promise<unknown>;
    return await dynamicImport('node:sqlite') as { DatabaseSync: new (filePath: string, options?: { readOnly?: boolean }) => SqliteDatabase };
  } catch {
    return null;
  }
}

interface SqliteDatabase {
  exec: (sql: string) => void;
  close: () => void;
}

async function protectWindowsDpapi(payload: Buffer): Promise<Buffer> {
  const script = [
    `$bytes = [Convert]::FromBase64String('${payload.toString('base64')}')`,
    'Add-Type -AssemblyName System.Security',
    '$protected = [Security.Cryptography.ProtectedData]::Protect($bytes, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)',
    '[Convert]::ToBase64String($protected)',
  ].join('; ');
  const output = await runPowerShell(script, 5000);
  const encoded = output.trim().split(/\s+/)[0] ?? '';
  if (!encoded) throw new Error('Windows DPAPI did not return a protected key.');
  return Buffer.from(encoded, 'base64');
}

function runPowerShell(script: string, timeoutMs: number): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], {
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error(`powershell.exe timed out after ${timeoutMs}ms: ${stderr.slice(0, 500)}`));
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
      if (status === 0) resolve(stdout);
      else reject(new Error(`powershell.exe exited with ${status}: ${stderr.slice(0, 500)}`));
    });
  });
}

function encryptChromiumCookie(key: Buffer, value: string) {
  const nonce = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  const encrypted = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
  return Buffer.concat([Buffer.from('v10'), nonce, encrypted, cipher.getAuthTag()]);
}

async function statsFor(filePaths: string[]) {
  const stats = [];
  for (const filePath of Array.from(new Set(filePaths.filter(Boolean)))) {
    try {
      const stat = await fs.stat(filePath);
      stats.push({ path: filePath, exists: stat.isFile(), sizeBytes: stat.size });
    } catch {
      stats.push({ path: filePath, exists: false, sizeBytes: 0 });
    }
  }
  return stats;
}

function parseArgs(args: string[]) {
  const flags: Record<string, string | boolean> = {};
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (!arg.startsWith('--')) continue;
    const key = arg.slice(2).replace(/-([a-z])/g, (_match, letter: string) => letter.toUpperCase());
    const next = args[index + 1];
    if (next && !next.startsWith('--')) {
      flags[key] = next;
      index += 1;
    } else {
      flags[key] = true;
    }
  }
  return flags;
}

function writeStdout(value: string) {
  return new Promise<void>((resolve, reject) => {
    process.stdout.write(value, (error) => {
      if (error) reject(error);
      else resolve();
    });
  });
}

main().catch(async (error) => {
  await writeStdout(`${JSON.stringify({
    kind: 'proxyforge-release-cookie-dpapi-smoke',
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    status: 'failed',
    error: error instanceof Error ? error.message : String(error),
  }, null, 2)}\n`);
  process.exit(1);
});
