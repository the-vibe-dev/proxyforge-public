import { spawn } from 'node:child_process';
import { createDecipheriv, pbkdf2Sync } from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import type { ManagedBrowserFamily } from './browserLauncher';

export interface BrowserCookieExtractionRequest {
  targetUrl: string;
  browser: ManagedBrowserFamily;
  profilePath: string;
}

export interface BrowserCookieEntry {
  name: string;
  value: string;
  domain: string;
  path: string;
  expiresAt?: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite?: string;
  source: 'chromium' | 'firefox';
}

export interface BrowserCookieExtractionResult {
  id: string;
  status: 'complete' | 'partial' | 'empty' | 'unsupported' | 'error';
  targetUrl: string;
  browser: ManagedBrowserFamily | 'unknown';
  profilePath: string;
  cookieHeader: string;
  cookieCount: number;
  decryptedCount: number;
  encryptedCount: number;
  skippedCount: number;
  extractedAt: string;
  cookies: BrowserCookieEntry[];
  message: string;
}

type CookieSource = 'chromium' | 'firefox';
export type BrowserCookieHostLane = 'chromium-local-state-aes-gcm' | 'chromium-windows-dpapi' | 'chromium-linux-secret-service' | 'chromium-linux-legacy' | 'firefox-sqlite';

export interface BrowserCookieReadinessCapability {
  id: BrowserCookieHostLane;
  label: string;
  source: CookieSource;
  platform: 'cross-platform' | 'linux' | 'win32';
  status: 'ready' | 'available' | 'needs-host-verification' | 'blocked';
  databasePaths: string[];
  evidence: string[];
  secretHandling: string;
  notes: string[];
}

export interface BrowserCookieReadinessReport {
  id: string;
  title: string;
  createdAt: string;
  targetUrl: string;
  browser: ManagedBrowserFamily | 'unknown';
  profilePath: string;
  sqliteAvailable: boolean;
  databaseCount: number;
  chromiumDatabaseCount: number;
  firefoxDatabaseCount: number;
  capabilityCount: number;
  readyCapabilityCount: number;
  hostVerificationRequiredCount: number;
  capabilities: BrowserCookieReadinessCapability[];
  reportReady: boolean;
  summary: string;
  content: string;
}

interface CookieDbCandidate {
  source: CookieSource;
  filePath: string;
}

interface RawCookieRow {
  host_key?: string;
  host?: string;
  name?: string;
  value?: string;
  encrypted_value?: Uint8Array;
  path?: string;
  expires_utc?: number;
  expiry?: number;
  is_secure?: number;
  isSecure?: number;
  is_httponly?: number;
  isHttpOnly?: number;
  samesite?: number;
  sameSite?: number;
}

export interface ChromiumDecryptionState {
  key?: Buffer;
  legacyKey?: Buffer;
  message?: string;
}

export async function extractBrowserCookies(request: BrowserCookieExtractionRequest): Promise<BrowserCookieExtractionResult> {
  const extractedAt = new Date().toISOString();
  const profilePath = request.profilePath.trim();
  const targetUrl = normalizeTargetUrl(request.targetUrl);
  const target = new URL(targetUrl);

  if (!profilePath) {
    return emptyResult(request, targetUrl, extractedAt, 'error', 'Cookie extraction needs a browser profile path.');
  }

  const sqlite = await loadSqlite();
  if (!sqlite) {
    return emptyResult(request, targetUrl, extractedAt, 'unsupported', 'This desktop runtime does not expose node:sqlite, so browser cookie extraction is unavailable.');
  }

  const candidates = await findCookieDatabases(profilePath, request.browser);
  if (candidates.length === 0) {
    return emptyResult(request, targetUrl, extractedAt, 'empty', `No Chromium or Firefox cookie database was found under ${profilePath}.`);
  }

  let encryptedCount = 0;
  let decryptedCount = 0;
  let skippedCount = 0;
  const cookies: BrowserCookieEntry[] = [];
  const seen = new Set<string>();
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'proxyforge-cookie-db-'));

  try {
    for (const candidate of candidates) {
      const copyPath = path.join(tempDir, `${candidate.source}-${cookies.length}-${Date.now()}.sqlite`);
      try {
        await fs.copyFile(candidate.filePath, copyPath);
        const decryption = candidate.source === 'chromium'
          ? await loadChromiumDecryptionState(candidate.filePath, profilePath)
          : {};
        const rows = readCookieRows(sqlite.DatabaseSync, copyPath, candidate.source);
        for (const row of rows) {
          const normalized = normalizeCookieRow(row, candidate.source);
          if (!normalized.name || !normalized.domain) {
            skippedCount += 1;
            continue;
          }
          if (!cookieMatchesTarget(normalized.domain, normalized.path, target)) {
            continue;
          }
          const readableValue = normalized.value || decryptCookieValue(row, candidate.source, decryption);
          if (!readableValue) {
            if (row.encrypted_value && row.encrypted_value.length > 0) {
              encryptedCount += 1;
            } else {
              skippedCount += 1;
            }
            continue;
          }
          const key = `${normalized.name}:${normalized.domain}:${normalized.path}`;
          if (seen.has(key)) continue;
          seen.add(key);
          if (!normalized.value) decryptedCount += 1;
          cookies.push({ ...normalized, value: readableValue });
        }
      } catch {
        skippedCount += 1;
      }
    }
  } finally {
    await fs.rm(tempDir, { recursive: true, force: true });
  }

  const cookieHeader = cookies.map((cookie) => `${cookie.name}=${cookie.value}`).join('; ');
  const status: BrowserCookieExtractionResult['status'] = cookies.length === 0
    ? encryptedCount > 0 ? 'partial' : 'empty'
    : encryptedCount > 0 || skippedCount > 0 ? 'partial' : 'complete';
  return {
    id: `cookie-capture-${Date.now()}`,
    status,
    targetUrl,
    browser: request.browser,
    profilePath,
    cookieHeader,
    cookieCount: cookies.length,
    decryptedCount,
    encryptedCount,
    skippedCount,
    extractedAt,
    cookies,
    message: cookies.length > 0
      ? `Extracted ${cookies.length} cookie${cookies.length === 1 ? '' : 's'} for ${target.hostname}${decryptedCount ? `; decrypted ${decryptedCount}` : ''}${encryptedCount ? `; ${encryptedCount} encrypted value${encryptedCount === 1 ? '' : 's'} could not be read` : ''}.`
      : encryptedCount > 0
        ? `Found ${encryptedCount} encrypted cookie value${encryptedCount === 1 ? '' : 's'} for ${target.hostname}, but no readable cookie values.`
        : `No readable cookies matched ${target.hostname}.`,
  };
}

export async function buildBrowserCookieReadinessReport(
  request: BrowserCookieExtractionRequest,
  createdAt = new Date().toISOString(),
): Promise<BrowserCookieReadinessReport> {
  const profilePath = request.profilePath.trim();
  const targetUrl = normalizeTargetUrl(request.targetUrl);
  const sqliteAvailable = Boolean(await loadSqlite());
  const candidates = profilePath ? await findCookieDatabases(profilePath, request.browser) : [];
  const chromiumCandidates = candidates.filter((candidate) => candidate.source === 'chromium');
  const firefoxCandidates = candidates.filter((candidate) => candidate.source === 'firefox');
  const chromiumState = chromiumCandidates[0]
    ? await loadChromiumDecryptionState(chromiumCandidates[0].filePath, profilePath)
    : undefined;
  const localStatePath = chromiumCandidates[0]
    ? await findChromiumLocalState(chromiumCandidates[0].filePath, profilePath)
    : '';
  const capabilities = buildCookieReadinessCapabilities({
    sqliteAvailable,
    chromiumCandidates,
    firefoxCandidates,
    chromiumState,
    localStatePath,
  });
  const readyCapabilityCount = capabilities.filter((capability) => capability.status === 'ready' || capability.status === 'available').length;
  const hostVerificationRequiredCount = capabilities.filter((capability) => capability.status === 'needs-host-verification').length;
  const payload = {
    kind: 'proxyforge-browser-cookie-readiness-report',
    createdAt,
    targetUrl,
    browser: request.browser,
    profilePath,
    sqliteAvailable,
    databaseCount: candidates.length,
    chromiumDatabaseCount: chromiumCandidates.length,
    firefoxDatabaseCount: firefoxCandidates.length,
    capabilities,
    reportReady: true,
  };
  const content = JSON.stringify(payload, null, 2);
  return {
    id: `cookie-readiness-${simpleDigest(content).slice(0, 12)}`,
    title: 'Browser cookie extraction and decryption readiness',
    createdAt,
    targetUrl,
    browser: request.browser,
    profilePath,
    sqliteAvailable,
    databaseCount: candidates.length,
    chromiumDatabaseCount: chromiumCandidates.length,
    firefoxDatabaseCount: firefoxCandidates.length,
    capabilityCount: capabilities.length,
    readyCapabilityCount,
    hostVerificationRequiredCount,
    capabilities,
    reportReady: true,
    summary: `Cookie readiness found ${candidates.length} browser cookie database(s), ${readyCapabilityCount} ready/available decryption lane(s), and ${hostVerificationRequiredCount} host-lane verification item(s) for ${new URL(targetUrl).hostname}.`,
    content,
  };
}

function decryptCookieValue(row: RawCookieRow, source: CookieSource, decryption: ChromiumDecryptionState) {
  if (source !== 'chromium' || !row.encrypted_value?.length) return '';
  return decryptChromiumCookieValue(Buffer.from(row.encrypted_value), decryption);
}

function buildCookieReadinessCapabilities(options: {
  sqliteAvailable: boolean;
  chromiumCandidates: CookieDbCandidate[];
  firefoxCandidates: CookieDbCandidate[];
  chromiumState?: ChromiumDecryptionState;
  localStatePath?: string;
}): BrowserCookieReadinessCapability[] {
  const chromiumPaths = options.chromiumCandidates.map((candidate) => candidate.filePath);
  const firefoxPaths = options.firefoxCandidates.map((candidate) => candidate.filePath);
  const hasChromium = chromiumPaths.length > 0;
  const hasFirefox = firefoxPaths.length > 0;
  const hasAesKey = Boolean(options.chromiumState?.key);
  const hasLegacyKey = Boolean(options.chromiumState?.legacyKey);
  const dpapiWrapped = /DPAPI/i.test(options.chromiumState?.message ?? '');
  return [
    {
      id: 'chromium-local-state-aes-gcm',
      label: 'Chromium AES-GCM profile key',
      source: 'chromium',
      platform: 'cross-platform',
      status: hasChromium && hasAesKey ? 'ready' : hasChromium && options.localStatePath ? 'needs-host-verification' : 'blocked',
      databasePaths: chromiumPaths,
      evidence: [
        options.localStatePath ? `Local State: ${options.localStatePath}` : 'Local State not found',
        hasAesKey ? `Loaded ${options.chromiumState?.key?.length ?? 0}-byte AES key without storing the key in report content.` : options.chromiumState?.message ?? 'No Chromium AES key loaded.',
      ],
      secretHandling: 'The readiness report stores only key presence, length, and source metadata; cookie values and AES key bytes are excluded.',
      notes: [
        'Supports Chrome/Chromium/Edge v10/v11 AES-GCM cookie values when Local State exposes a usable profile key.',
        'Fixture coverage decrypts AES-GCM cookie values through npm run test:browser-launcher.',
      ],
    },
    {
      id: 'chromium-windows-dpapi',
      label: 'Chromium Windows DPAPI key unwrap',
      source: 'chromium',
      platform: 'win32',
      status: hasChromium && process.platform === 'win32' && hasAesKey ? 'ready' : hasChromium || dpapiWrapped ? 'needs-host-verification' : 'blocked',
      databasePaths: chromiumPaths,
      evidence: [
        'DPAPI unwrap path uses PowerShell ProtectedData.Unprotect against the current Windows user profile.',
        dpapiWrapped ? 'A DPAPI-wrapped Local State key was detected but cannot be unwrapped on this host.' : 'No DPAPI-wrapped Local State key detected in the current profile fixture.',
      ],
      secretHandling: 'DPAPI plaintext key bytes are kept in memory only and never serialized into readiness report content.',
      notes: [
        'Requires a Windows user session with access to the browser profile owner credentials.',
        'Clean-machine Windows DPAPI sample-cookie proof remains release validation work.',
      ],
    },
    {
      id: 'chromium-linux-secret-service',
      label: 'Chromium Linux Secret Service safe-storage',
      source: 'chromium',
      platform: 'linux',
      status: hasChromium && process.platform === 'linux' ? 'available' : hasChromium ? 'needs-host-verification' : 'blocked',
      databasePaths: chromiumPaths,
      evidence: [
        process.platform === 'linux' ? 'Linux safe-storage lookup path is available in this runtime.' : 'Linux Secret Service lookup needs a Linux host lane.',
        process.env.PROXYFORGE_CHROMIUM_SAFE_STORAGE_PASSWORD ? 'Safe-storage password override is configured via environment.' : 'Falls back to secret-tool lookup and the Chromium legacy peanuts fallback.',
      ],
      secretHandling: 'Secret Service output is used transiently to derive a legacy AES-CBC key; the secret itself is not written to artifacts.',
      notes: [
        'Supports Secret Service lookup for Chrome/Chromium safe-storage labels plus deterministic legacy fallback.',
        'Fixture coverage decrypts Linux legacy cookie values through npm run test:browser-launcher.',
      ],
    },
    {
      id: 'chromium-linux-legacy',
      label: 'Chromium Linux legacy AES-CBC fallback',
      source: 'chromium',
      platform: 'linux',
      status: hasChromium && hasLegacyKey ? 'ready' : hasChromium ? 'available' : 'blocked',
      databasePaths: chromiumPaths,
      evidence: [
        hasLegacyKey ? 'Derived Linux legacy AES-CBC key for v10 cookie fallback.' : 'Legacy fallback can derive a key when a Chromium profile is present.',
      ],
      secretHandling: 'Derived legacy key is held in memory and excluded from report content.',
      notes: [
        'Covers older Chromium cookie stores and test fixtures where Local State key material is unavailable.',
      ],
    },
    {
      id: 'firefox-sqlite',
      label: 'Firefox cookies.sqlite extraction',
      source: 'firefox',
      platform: 'cross-platform',
      status: options.sqliteAvailable && hasFirefox ? 'ready' : options.sqliteAvailable ? 'available' : 'blocked',
      databasePaths: firefoxPaths,
      evidence: [
        options.sqliteAvailable ? 'node:sqlite is available for reading copied cookie databases.' : 'node:sqlite is unavailable in this runtime.',
        hasFirefox ? `${firefoxPaths.length} Firefox cookies.sqlite database(s) discovered.` : 'No Firefox cookies.sqlite database discovered in the selected profile path.',
      ],
      secretHandling: 'Firefox cookie values are copied from the profile database into redaction-aware session profiles; report content should use counts and cookie names unless explicitly authorized.',
      notes: [
        'Fixture coverage filters Firefox cookies by domain and path through npm run test:browser-launcher.',
      ],
    },
  ];
}

export function decryptChromiumCookieValue(encryptedValue: Buffer, decryption: ChromiumDecryptionState) {
  if (decryption.key) {
    const gcm = decryptChromiumGcmCookieValue(encryptedValue, decryption.key);
    if (gcm) return gcm;
  }
  if (decryption.legacyKey) {
    return decryptChromiumLegacyCookieValue(encryptedValue, decryption.legacyKey);
  }
  return '';
}

function decryptChromiumGcmCookieValue(encryptedValue: Buffer, key: Buffer) {
  if (encryptedValue.length < 3 || !['v10', 'v11'].includes(encryptedValue.subarray(0, 3).toString('utf8'))) return '';
  if (![16, 24, 32].includes(key.length) || encryptedValue.length <= 31) return '';
  const nonce = encryptedValue.subarray(3, 15);
  const ciphertext = encryptedValue.subarray(15, encryptedValue.length - 16);
  const tag = encryptedValue.subarray(encryptedValue.length - 16);
  const algorithm = key.length === 16 ? 'aes-128-gcm' : key.length === 24 ? 'aes-192-gcm' : 'aes-256-gcm';
  try {
    const decipher = createDecipheriv(algorithm, key, nonce);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
  } catch {
    return '';
  }
}

function decryptChromiumLegacyCookieValue(encryptedValue: Buffer, legacyKey: Buffer) {
  if (encryptedValue.length < 19 || !encryptedValue.subarray(0, 3).equals(Buffer.from('v10'))) return '';
  if (legacyKey.length !== 16) return '';
  try {
    const decipher = createDecipheriv('aes-128-cbc', legacyKey, Buffer.alloc(16, 0x20));
    return Buffer.concat([decipher.update(encryptedValue.subarray(3)), decipher.final()]).toString('utf8');
  } catch {
    return '';
  }
}

async function loadChromiumDecryptionState(cookieDbPath: string, profilePath: string): Promise<ChromiumDecryptionState> {
  const legacyKey = await loadLinuxChromiumLegacyKey();
  const localStatePath = await findChromiumLocalState(cookieDbPath, profilePath);
  if (!localStatePath) return { legacyKey, message: 'Chromium Local State was not found.' };
  try {
    const parsed = JSON.parse(await fs.readFile(localStatePath, 'utf8')) as { os_crypt?: { encrypted_key?: string } };
    const encodedKey = parsed.os_crypt?.encrypted_key;
    if (!encodedKey) return { legacyKey, message: 'Chromium Local State has no os_crypt encrypted_key.' };
    const wrapped = Buffer.from(encodedKey, 'base64');
    if (wrapped.subarray(0, 5).toString('utf8') === 'DPAPI') {
      if (process.platform !== 'win32') {
        return { legacyKey, message: 'Chromium key is DPAPI-wrapped and this runtime is not Windows.' };
      }
      const key = await unwrapWindowsDpapiKey(wrapped.subarray(5));
      return key ? { key, legacyKey } : { legacyKey, message: 'Windows DPAPI did not return a Chromium key.' };
    }
    if ([16, 24, 32].includes(wrapped.length)) return { key: wrapped, legacyKey };
    return { legacyKey, message: 'Chromium key format is not supported.' };
  } catch (error) {
    return { legacyKey, message: error instanceof Error ? error.message : 'Chromium key load failed.' };
  }
}

async function loadLinuxChromiumLegacyKey() {
  if (process.platform !== 'linux') return undefined;
  const password = process.env.PROXYFORGE_CHROMIUM_SAFE_STORAGE_PASSWORD
    || await lookupLinuxSafeStoragePassword()
    || 'peanuts';
  return deriveChromiumLegacyKey(password, 1);
}

export function deriveChromiumLegacyKey(password: string, iterations: number) {
  return pbkdf2Sync(password, 'saltysalt', Math.max(1, iterations), 16, 'sha1');
}

async function lookupLinuxSafeStoragePassword() {
  const lookups = [
    ['application', 'chrome'],
    ['application', 'chromium'],
    ['application', 'Chrome'],
    ['application', 'Chromium'],
  ];
  for (const args of lookups) {
    const value = await runSecretToolLookup(args);
    if (value) return value;
  }
  return '';
}

function runSecretToolLookup(args: string[]): Promise<string> {
  return new Promise((resolve) => {
    const child = spawn('secret-tool', ['lookup', ...args], {
      stdio: ['ignore', 'pipe', 'ignore'],
    });
    let output = '';
    const timer = setTimeout(() => {
      child.kill();
      resolve('');
    }, 1200);
    child.stdout.on('data', (chunk: Buffer) => {
      output += chunk.toString('utf8');
    });
    child.on('error', () => {
      clearTimeout(timer);
      resolve('');
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve(code === 0 ? output.trim() : '');
    });
  });
}

async function findChromiumLocalState(cookieDbPath: string, profilePath: string) {
  const profileRoot = path.resolve(profilePath);
  const direct = path.join(profileRoot, 'Local State');
  if (await fileExists(direct)) return direct;

  let current = path.dirname(cookieDbPath);
  for (let depth = 0; depth < 6; depth += 1) {
    const candidate = path.join(current, 'Local State');
    if (await fileExists(candidate)) return candidate;
    const parent = path.dirname(current);
    if (parent === current || !path.resolve(parent).startsWith(profileRoot)) break;
    current = parent;
  }
  return '';
}

async function fileExists(filePath: string) {
  try {
    await fs.access(filePath);
    return true;
  } catch {
    return false;
  }
}

async function unwrapWindowsDpapiKey(payload: Buffer): Promise<Buffer | null> {
  const shell = process.env.ComSpec || 'powershell.exe';
  const script = [
    `$bytes = [Convert]::FromBase64String('${payload.toString('base64')}')`,
    'Add-Type -AssemblyName System.Security',
    '$plain = [Security.Cryptography.ProtectedData]::Unprotect($bytes, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)',
    '[Convert]::ToBase64String($plain)',
  ].join('; ');

  return new Promise((resolve) => {
    const child = spawn(shell.toLowerCase().endsWith('cmd.exe') ? 'powershell.exe' : shell, ['-NoProfile', '-NonInteractive', '-Command', script], {
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'ignore'],
    });
    let output = '';
    const timer = setTimeout(() => {
      child.kill();
      resolve(null);
    }, 3500);
    child.stdout.on('data', (chunk: Buffer) => {
      output += chunk.toString('utf8');
    });
    child.on('error', () => {
      clearTimeout(timer);
      resolve(null);
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      if (code !== 0 || !output.trim()) {
        resolve(null);
        return;
      }
      try {
        resolve(Buffer.from(output.trim().split(/\s+/)[0], 'base64'));
      } catch {
        resolve(null);
      }
    });
  });
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
  prepare: (sql: string) => { all: () => RawCookieRow[] };
  close: () => void;
}

function readCookieRows(DatabaseSync: new (filePath: string, options?: { readOnly?: boolean }) => SqliteDatabase, dbPath: string, source: CookieSource) {
  const database = new DatabaseSync(dbPath, { readOnly: true });
  try {
    if (source === 'firefox') {
      return database.prepare([
        'select host, name, value, path, expiry, isSecure, isHttpOnly, sameSite',
        'from moz_cookies',
      ].join(' ')).all();
    }
    return database.prepare([
      'select host_key, name, value, encrypted_value, path, expires_utc, is_secure, is_httponly, samesite',
      'from cookies',
    ].join(' ')).all();
  } finally {
    database.close();
  }
}

function normalizeCookieRow(row: RawCookieRow, source: CookieSource): BrowserCookieEntry {
  if (source === 'firefox') {
    return {
      name: String(row.name ?? ''),
      value: String(row.value ?? ''),
      domain: String(row.host ?? ''),
      path: String(row.path ?? '/'),
      expiresAt: firefoxExpiryToIso(row.expiry),
      secure: Boolean(row.isSecure),
      httpOnly: Boolean(row.isHttpOnly),
      sameSite: sameSiteLabel(row.sameSite),
      source,
    };
  }

  return {
    name: String(row.name ?? ''),
    value: String(row.value ?? ''),
    domain: String(row.host_key ?? ''),
    path: String(row.path ?? '/'),
    expiresAt: chromiumExpiryToIso(row.expires_utc),
    secure: Boolean(row.is_secure),
    httpOnly: Boolean(row.is_httponly),
    sameSite: sameSiteLabel(row.samesite),
    source,
  };
}

async function findCookieDatabases(profilePath: string, browser: ManagedBrowserFamily): Promise<CookieDbCandidate[]> {
  const sources = browser === 'firefox'
    ? new Set<CookieSource>(['firefox'])
    : browser === 'auto'
      ? new Set<CookieSource>(['chromium', 'firefox'])
      : new Set<CookieSource>(['chromium']);
  const candidates: CookieDbCandidate[] = [];
  await walkCookieDbs(profilePath, sources, candidates, 0);
  return candidates;
}

async function walkCookieDbs(currentPath: string, sources: Set<CookieSource>, candidates: CookieDbCandidate[], depth: number): Promise<void> {
  if (depth > 5 || candidates.length >= 12) return;
  let entries: Array<{ name: string; isDirectory: () => boolean; isFile: () => boolean }>;
  try {
    entries = await fs.readdir(currentPath, { withFileTypes: true });
  } catch {
    return;
  }

  for (const entry of entries) {
    const filePath = path.join(currentPath, entry.name);
    if (entry.isFile()) {
      if (sources.has('firefox') && entry.name === 'cookies.sqlite') {
        candidates.push({ source: 'firefox', filePath });
      } else if (sources.has('chromium') && entry.name === 'Cookies') {
        candidates.push({ source: 'chromium', filePath });
      }
      continue;
    }
    if (!entry.isDirectory()) continue;
    if (/^(Cache|Code Cache|GPUCache|blob_storage|Crashpad|DawnCache|ShaderCache)$/i.test(entry.name)) continue;
    await walkCookieDbs(filePath, sources, candidates, depth + 1);
  }
}

function cookieMatchesTarget(domain: string, cookiePath: string, target: URL) {
  const normalizedDomain = domain.replace(/^\./, '').toLowerCase();
  const host = target.hostname.toLowerCase();
  const domainMatches = host === normalizedDomain || host.endsWith(`.${normalizedDomain}`);
  const normalizedPath = cookiePath || '/';
  return domainMatches && target.pathname.startsWith(normalizedPath.endsWith('/') ? normalizedPath : `${normalizedPath}`);
}

function chromiumExpiryToIso(value: number | undefined) {
  if (!value || value <= 0) return undefined;
  const epochDeltaMs = 11_644_473_600_000;
  const date = new Date(Math.floor(value / 1000) - epochDeltaMs);
  return Number.isFinite(date.getTime()) ? date.toISOString() : undefined;
}

function firefoxExpiryToIso(value: number | undefined) {
  if (!value || value <= 0) return undefined;
  const date = new Date(value * 1000);
  return Number.isFinite(date.getTime()) ? date.toISOString() : undefined;
}

function sameSiteLabel(value: number | undefined) {
  if (value === 1) return 'lax';
  if (value === 2) return 'strict';
  if (value === 3) return 'none';
  return undefined;
}

function normalizeTargetUrl(value: string) {
  const trimmed = value.trim() || 'https://app.shop.local/';
  try {
    return new URL(trimmed).toString();
  } catch {
    return new URL(`https://${trimmed.replace(/^\/+/, '')}`).toString();
  }
}

function simpleDigest(value: string) {
  let hash = 0x811c9dc5;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return `${hash.toString(16).padStart(8, '0')}${value.length.toString(16).padStart(8, '0')}`;
}

function emptyResult(
  request: BrowserCookieExtractionRequest,
  targetUrl: string,
  extractedAt: string,
  status: BrowserCookieExtractionResult['status'],
  message: string,
): BrowserCookieExtractionResult {
  return {
    id: `cookie-capture-${Date.now()}`,
    status,
    targetUrl,
    browser: request.browser,
    profilePath: request.profilePath,
    cookieHeader: '',
    cookieCount: 0,
    decryptedCount: 0,
    encryptedCount: 0,
    skippedCount: 0,
    extractedAt,
    cookies: [],
    message,
  };
}
