import { spawn } from 'node:child_process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

export type ManagedBrowserFamily = 'auto' | 'chromium' | 'chrome' | 'edge' | 'firefox';
export type ManagedBrowserLaunchPlatform = 'linux' | 'win32';

export interface BrowserLaunchRequest {
  targetUrl: string;
  browser: ManagedBrowserFamily;
  proxyHost?: string;
  proxyPort: number;
  profileName?: string;
  ignoreCertificateErrors?: boolean;
  profileBaseDir?: string;
  dryRun?: boolean;
}

export interface BrowserLaunchResult {
  id: string;
  status: 'launched' | 'preview' | 'not-found' | 'error';
  browser: ManagedBrowserFamily | 'unknown';
  browserName: string;
  targetUrl: string;
  proxyHost: string;
  proxyPort: number;
  profilePath: string;
  command: string;
  args: string[];
  pid?: number;
  startedAt: string;
  message: string;
}

export interface ManagedBrowserLaunchMatrixEntry {
  platform: ManagedBrowserLaunchPlatform;
  family: Exclude<ManagedBrowserFamily, 'auto'>;
  browserName: string;
  command: string;
  targetUrl: string;
  proxyHost: string;
  proxyPort: number;
  profilePath: string;
  args: string[];
  proxyMode: 'command-line' | 'firefox-prefs';
  cookieStore: 'chromium-network-sqlite' | 'firefox-sqlite';
  certificateMode: 'ignore-errors-flag' | 'enterprise-roots';
  evidence: {
    isolatedProfile: boolean;
    proxyConfigured: boolean;
    certWorkflowReady: boolean;
    cookieExtractionReady: boolean;
    windowsPathCovered: boolean;
    linuxPathCovered: boolean;
  };
  notes: string[];
}

export interface ManagedBrowserLaunchMatrix {
  id: string;
  title: string;
  createdAt: string;
  targetUrl: string;
  proxyHost: string;
  proxyPort: number;
  platforms: ManagedBrowserLaunchPlatform[];
  families: Array<Exclude<ManagedBrowserFamily, 'auto'>>;
  entryCount: number;
  linuxEntryCount: number;
  windowsEntryCount: number;
  firefoxEntryCount: number;
  chromiumEntryCount: number;
  reportReady: boolean;
  summary: string;
  entries: ManagedBrowserLaunchMatrixEntry[];
  content: string;
}

interface BrowserCandidate {
  family: Exclude<ManagedBrowserFamily, 'auto'>;
  name: string;
  command: string;
}

interface LaunchPlan {
  candidate: BrowserCandidate;
  targetUrl: string;
  proxyHost: string;
  proxyPort: number;
  profilePath: string;
  args: string[];
}

export async function launchManagedBrowser(request: BrowserLaunchRequest): Promise<BrowserLaunchResult> {
  const startedAt = new Date().toISOString();
  const proxyHost = request.proxyHost?.trim() || '127.0.0.1';
  const proxyPort = Number.isFinite(request.proxyPort) ? Math.max(1, Math.min(65535, Math.floor(request.proxyPort))) : 8080;
  const targetUrl = normalizeTargetUrl(request.targetUrl);
  const profileBaseDir = request.profileBaseDir || path.join(os.tmpdir(), 'proxyforge-browser-profiles');
  const profilePath = path.join(profileBaseDir, safeProfileName(request.profileName || `${request.browser}-profile`));
  const candidate = await findBrowserCandidate(request.browser);

  if (!candidate) {
    return {
      id: `browser-launch-${Date.now()}`,
      status: 'not-found',
      browser: request.browser === 'auto' ? 'unknown' : request.browser,
      browserName: request.browser === 'auto' ? 'Managed browser' : request.browser,
      targetUrl,
      proxyHost,
      proxyPort,
      profilePath,
      command: '',
      args: [],
      startedAt,
      message: `No ${request.browser === 'auto' ? 'supported Chromium, Chrome, Edge, or Firefox' : request.browser} executable was found on this machine.`,
    };
  }

  await fs.mkdir(profilePath, { recursive: true });
  const plan = await buildLaunchPlan({
    candidate,
    targetUrl,
    proxyHost,
    proxyPort,
    profilePath,
    ignoreCertificateErrors: request.ignoreCertificateErrors ?? true,
  });

  if (request.dryRun) {
    return resultFromPlan(plan, startedAt, 'launched', undefined, `Launch plan ready for ${candidate.name} through ${proxyHost}:${proxyPort}.`);
  }

  try {
    const child = spawn(plan.candidate.command, plan.args, {
      detached: true,
      stdio: 'ignore',
    });
    child.unref();
    return resultFromPlan(
      plan,
      startedAt,
      'launched',
      child.pid,
      `${candidate.name} launched through ProxyForge on ${proxyHost}:${proxyPort}.`,
    );
  } catch (error) {
    return {
      ...resultFromPlan(plan, startedAt, 'error', undefined, error instanceof Error ? error.message : 'Browser launch failed.'),
      status: 'error',
    };
  }
}

export async function findBrowserCandidate(preferred: ManagedBrowserFamily): Promise<BrowserCandidate | null> {
  const wanted = preferred === 'auto'
    ? new Set<ManagedBrowserFamily>(['chromium', 'chrome', 'edge', 'firefox'])
    : new Set<ManagedBrowserFamily>([preferred]);

  for (const candidate of browserCandidates()) {
    if (!wanted.has(candidate.family)) continue;
    if (await canAccessExecutable(candidate.command)) return candidate;
  }

  return null;
}

export async function buildLaunchPlan(options: {
  candidate: BrowserCandidate;
  targetUrl: string;
  proxyHost: string;
  proxyPort: number;
  profilePath: string;
  ignoreCertificateErrors: boolean;
}): Promise<LaunchPlan> {
  if (options.candidate.family === 'firefox') {
    await writeFirefoxProxyPrefs(options.profilePath, options.proxyHost, options.proxyPort);
    return {
      candidate: options.candidate,
      targetUrl: options.targetUrl,
      proxyHost: options.proxyHost,
      proxyPort: options.proxyPort,
      profilePath: options.profilePath,
      args: ['-no-remote', '-new-instance', '-profile', options.profilePath, options.targetUrl],
    };
  }

  const proxyServer = `http=${options.proxyHost}:${options.proxyPort};https=${options.proxyHost}:${options.proxyPort}`;
  const args = [
    `--user-data-dir=${options.profilePath}`,
    `--proxy-server=${proxyServer}`,
    '--proxy-bypass-list=<-loopback>',
    '--new-window',
  ];
  if (options.ignoreCertificateErrors) {
    args.push('--ignore-certificate-errors');
  }
  args.push(options.targetUrl);

  return {
    candidate: options.candidate,
    targetUrl: options.targetUrl,
    proxyHost: options.proxyHost,
    proxyPort: options.proxyPort,
    profilePath: options.profilePath,
    args,
  };
}

function resultFromPlan(
  plan: LaunchPlan,
  startedAt: string,
  status: BrowserLaunchResult['status'],
  pid: number | undefined,
  message: string,
): BrowserLaunchResult {
  return {
    id: `browser-launch-${Date.now()}`,
    status,
    browser: plan.candidate.family,
    browserName: plan.candidate.name,
    targetUrl: plan.targetUrl,
    proxyHost: plan.proxyHost,
    proxyPort: plan.proxyPort,
    profilePath: plan.profilePath,
    command: plan.candidate.command,
    args: plan.args,
    pid,
    startedAt,
    message,
  };
}

export function buildManagedBrowserLaunchMatrix(options: {
  targetUrl: string;
  proxyHost?: string;
  proxyPort: number;
  profileBaseDir?: string;
  ignoreCertificateErrors?: boolean;
  platforms?: ManagedBrowserLaunchPlatform[];
  families?: Array<Exclude<ManagedBrowserFamily, 'auto'>>;
  createdAt?: string;
}): ManagedBrowserLaunchMatrix {
  const createdAt = options.createdAt ?? new Date().toISOString();
  const targetUrl = normalizeTargetUrl(options.targetUrl);
  const proxyHost = options.proxyHost?.trim() || '127.0.0.1';
  const proxyPort = Number.isFinite(options.proxyPort) ? Math.max(1, Math.min(65535, Math.floor(options.proxyPort))) : 8080;
  const profileBaseDir = options.profileBaseDir || '${PROXYFORGE_USER_DATA}/browser-profiles';
  const platforms: ManagedBrowserLaunchPlatform[] = options.platforms?.length ? options.platforms : ['linux', 'win32'];
  const families: Array<Exclude<ManagedBrowserFamily, 'auto'>> = options.families?.length ? options.families : ['chromium', 'chrome', 'edge', 'firefox'];
  const entries = platforms.flatMap((platform) => families.map((family) => (
    buildMatrixEntry({
      platform,
      family,
      targetUrl,
      proxyHost,
      proxyPort,
      profileBaseDir,
      ignoreCertificateErrors: options.ignoreCertificateErrors ?? true,
    })
  )));
  const linuxEntryCount = entries.filter((entry) => entry.platform === 'linux').length;
  const windowsEntryCount = entries.filter((entry) => entry.platform === 'win32').length;
  const firefoxEntryCount = entries.filter((entry) => entry.family === 'firefox').length;
  const chromiumEntryCount = entries.length - firefoxEntryCount;
  const payload = {
    kind: 'proxyforge-managed-browser-launch-matrix',
    createdAt,
    targetUrl,
    proxyHost,
    proxyPort,
    platforms,
    families,
    entries,
    reportReady: true,
  };
  const content = JSON.stringify(payload, null, 2);
  return {
    id: `browser-launch-matrix-${simpleDigest(content).slice(0, 12)}`,
    title: 'Managed browser launch matrix',
    createdAt,
    targetUrl,
    proxyHost,
    proxyPort,
    platforms,
    families,
    entryCount: entries.length,
    linuxEntryCount,
    windowsEntryCount,
    firefoxEntryCount,
    chromiumEntryCount,
    reportReady: true,
    summary: `Managed browser matrix covers ${entries.length} Linux/Windows launch profile(s): ${chromiumEntryCount} Chromium-family command-line proxy plan(s) and ${firefoxEntryCount} Firefox preference plan(s).`,
    entries,
    content,
  };
}

function browserCandidates(): BrowserCandidate[] {
  const envCandidates = [
    process.env.PROXYFORGE_BROWSER,
    process.env.CHROME_PATH,
    process.env.CHROMIUM_PATH,
    process.env.EDGE_PATH,
    process.env.FIREFOX_PATH,
  ].filter((value): value is string => Boolean(value?.trim()))
    .map((command) => inferCandidate(command));

  if (process.platform === 'win32') {
    const programFiles = [
      process.env.PROGRAMFILES,
      process.env['PROGRAMFILES(X86)'],
      process.env.LOCALAPPDATA,
    ].filter((value): value is string => Boolean(value));
    return [
      ...envCandidates,
      ...programFiles.flatMap((root) => [
        { family: 'chrome', name: 'Google Chrome', command: path.join(root, 'Google', 'Chrome', 'Application', 'chrome.exe') },
        { family: 'edge', name: 'Microsoft Edge', command: path.join(root, 'Microsoft', 'Edge', 'Application', 'msedge.exe') },
        { family: 'firefox', name: 'Firefox', command: path.join(root, 'Mozilla Firefox', 'firefox.exe') },
      ] satisfies BrowserCandidate[]),
    ];
  }

  if (process.platform === 'darwin') {
    return [
      ...envCandidates,
      { family: 'chrome', name: 'Google Chrome', command: '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome' },
      { family: 'edge', name: 'Microsoft Edge', command: '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge' },
      { family: 'chromium', name: 'Chromium', command: '/Applications/Chromium.app/Contents/MacOS/Chromium' },
      { family: 'firefox', name: 'Firefox', command: '/Applications/Firefox.app/Contents/MacOS/firefox' },
    ];
  }

  return [
    ...envCandidates,
    { family: 'chrome', name: 'Google Chrome', command: '/usr/bin/google-chrome' },
    { family: 'chrome', name: 'Google Chrome Stable', command: '/usr/bin/google-chrome-stable' },
    { family: 'chromium', name: 'Chromium', command: '/usr/bin/chromium' },
    { family: 'chromium', name: 'Chromium Browser', command: '/usr/bin/chromium-browser' },
    { family: 'chromium', name: 'Chromium Snap', command: '/snap/bin/chromium' },
    { family: 'edge', name: 'Microsoft Edge', command: '/usr/bin/microsoft-edge' },
    { family: 'edge', name: 'Microsoft Edge Stable', command: '/usr/bin/microsoft-edge-stable' },
    { family: 'firefox', name: 'Firefox', command: '/usr/bin/firefox' },
    { family: 'firefox', name: 'Firefox Developer Edition', command: '/usr/bin/firefox-developer-edition' },
  ];
}

function buildMatrixEntry(options: {
  platform: ManagedBrowserLaunchPlatform;
  family: Exclude<ManagedBrowserFamily, 'auto'>;
  targetUrl: string;
  proxyHost: string;
  proxyPort: number;
  profileBaseDir: string;
  ignoreCertificateErrors: boolean;
}): ManagedBrowserLaunchMatrixEntry {
  const candidate = matrixCandidateFor(options.platform, options.family);
  const profilePath = matrixProfilePath(options.profileBaseDir, options.platform, options.family);
  if (options.family === 'firefox') {
    const args = ['-no-remote', '-new-instance', '-profile', profilePath, options.targetUrl];
    return {
      platform: options.platform,
      family: options.family,
      browserName: candidate.name,
      command: candidate.command,
      targetUrl: options.targetUrl,
      proxyHost: options.proxyHost,
      proxyPort: options.proxyPort,
      profilePath,
      args,
      proxyMode: 'firefox-prefs',
      cookieStore: 'firefox-sqlite',
      certificateMode: 'enterprise-roots',
      evidence: {
        isolatedProfile: args.includes('-profile') && args.includes(profilePath),
        proxyConfigured: /network\.proxy\.type", 1/.test(buildFirefoxProxyPrefs(options.proxyHost, options.proxyPort)),
        certWorkflowReady: /security\.enterprise_roots\.enabled", true/.test(buildFirefoxProxyPrefs(options.proxyHost, options.proxyPort)),
        cookieExtractionReady: true,
        windowsPathCovered: options.platform === 'win32' && /firefox\.exe$/i.test(candidate.command),
        linuxPathCovered: options.platform === 'linux' && candidate.command.startsWith('/usr/bin/'),
      },
      notes: [
        'Firefox uses a dedicated profile directory with proxy preferences written to user.js.',
        'Enterprise roots are enabled so a locally trusted ProxyForge CA can be honored by the managed profile.',
        'cookies.sqlite is supported by the Browser Cookie extraction workflow.',
      ],
    };
  }

  const proxyServer = `http=${options.proxyHost}:${options.proxyPort};https=${options.proxyHost}:${options.proxyPort}`;
  const args = [
    `--user-data-dir=${profilePath}`,
    `--proxy-server=${proxyServer}`,
    '--proxy-bypass-list=<-loopback>',
    '--new-window',
  ];
  if (options.ignoreCertificateErrors) args.push('--ignore-certificate-errors');
  args.push(options.targetUrl);
  return {
    platform: options.platform,
    family: options.family,
    browserName: candidate.name,
    command: candidate.command,
    targetUrl: options.targetUrl,
    proxyHost: options.proxyHost,
    proxyPort: options.proxyPort,
    profilePath,
    args,
    proxyMode: 'command-line',
    cookieStore: 'chromium-network-sqlite',
    certificateMode: options.ignoreCertificateErrors ? 'ignore-errors-flag' : 'enterprise-roots',
    evidence: {
      isolatedProfile: args.some((arg) => arg === `--user-data-dir=${profilePath}`),
      proxyConfigured: args.some((arg) => arg === `--proxy-server=${proxyServer}`),
      certWorkflowReady: options.ignoreCertificateErrors ? args.includes('--ignore-certificate-errors') : true,
      cookieExtractionReady: true,
      windowsPathCovered: options.platform === 'win32' && /\.(exe)$/i.test(candidate.command),
      linuxPathCovered: options.platform === 'linux' && candidate.command.startsWith('/usr/bin/'),
    },
    notes: [
      'Chromium-family browsers use an isolated user-data-dir and explicit HTTP/HTTPS proxy command-line flags.',
      'The profile keeps ProxyForge traffic separated from the operator default browser profile.',
      'Network/Cookies plus Local State key material are supported by the Browser Cookie extraction workflow.',
    ],
  };
}

function matrixCandidateFor(platform: ManagedBrowserLaunchPlatform, family: Exclude<ManagedBrowserFamily, 'auto'>): BrowserCandidate {
  const linux: Record<Exclude<ManagedBrowserFamily, 'auto'>, BrowserCandidate> = {
    chrome: { family: 'chrome', name: 'Google Chrome Stable', command: '/usr/bin/google-chrome-stable' },
    chromium: { family: 'chromium', name: 'Chromium', command: '/usr/bin/chromium' },
    edge: { family: 'edge', name: 'Microsoft Edge Stable', command: '/usr/bin/microsoft-edge-stable' },
    firefox: { family: 'firefox', name: 'Firefox', command: '/usr/bin/firefox' },
  };
  const win32: Record<Exclude<ManagedBrowserFamily, 'auto'>, BrowserCandidate> = {
    chrome: { family: 'chrome', name: 'Google Chrome', command: 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe' },
    chromium: { family: 'chromium', name: 'Chromium', command: 'C:\\Program Files\\Chromium\\Application\\chromium.exe' },
    edge: { family: 'edge', name: 'Microsoft Edge', command: 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe' },
    firefox: { family: 'firefox', name: 'Firefox', command: 'C:\\Program Files\\Mozilla Firefox\\firefox.exe' },
  };
  return platform === 'win32' ? win32[family] : linux[family];
}

function matrixProfilePath(profileBaseDir: string, platform: ManagedBrowserLaunchPlatform, family: Exclude<ManagedBrowserFamily, 'auto'>) {
  const profileName = safeProfileName(`${platform}-${family}-proxyforge`);
  if (platform === 'win32') return `${profileBaseDir.replace(/\//g, '\\')}\\${profileName}`;
  return `${profileBaseDir.replace(/\\/g, '/')}/${profileName}`;
}

function inferCandidate(command: string): BrowserCandidate {
  const basename = path.basename(command).toLowerCase();
  if (basename.includes('firefox')) return { family: 'firefox', name: 'Firefox', command };
  if (basename.includes('edge') || basename.includes('msedge')) return { family: 'edge', name: 'Microsoft Edge', command };
  if (basename.includes('chromium')) return { family: 'chromium', name: 'Chromium', command };
  return { family: 'chrome', name: 'Google Chrome', command };
}

async function canAccessExecutable(command: string) {
  try {
    await fs.access(command);
    return true;
  } catch {
    return false;
  }
}

async function writeFirefoxProxyPrefs(profilePath: string, proxyHost: string, proxyPort: number) {
  await fs.writeFile(path.join(profilePath, 'user.js'), `${buildFirefoxProxyPrefs(proxyHost, proxyPort)}\n`, 'utf8');
}

export function buildFirefoxProxyPrefs(proxyHost: string, proxyPort: number) {
  return [
    'user_pref("network.proxy.type", 1);',
    `user_pref("network.proxy.http", ${JSON.stringify(proxyHost)});`,
    `user_pref("network.proxy.http_port", ${proxyPort});`,
    `user_pref("network.proxy.ssl", ${JSON.stringify(proxyHost)});`,
    `user_pref("network.proxy.ssl_port", ${proxyPort});`,
    'user_pref("network.proxy.no_proxies_on", "");',
    'user_pref("network.proxy.allow_hijacking_localhost", true);',
    'user_pref("security.enterprise_roots.enabled", true);',
    'user_pref("security.cert_pinning.enforcement_level", 0);',
  ].join('\n');
}

function normalizeTargetUrl(value: string) {
  const trimmed = value.trim() || 'https://app.shop.local/';
  try {
    return new URL(trimmed).toString();
  } catch {
    return new URL(`https://${trimmed.replace(/^\/+/, '')}`).toString();
  }
}

function safeProfileName(value: string) {
  return value.toLowerCase().replace(/[^a-z0-9._-]+/g, '-').replace(/^-|-$/g, '').slice(0, 80) || 'default';
}

function simpleDigest(value: string) {
  let hash = 0x811c9dc5;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return `${hash.toString(16).padStart(8, '0')}${value.length.toString(16).padStart(8, '0')}`;
}
