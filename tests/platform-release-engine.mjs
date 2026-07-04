import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import path from 'node:path';
import vm from 'node:vm';

const require = createRequire(import.meta.url);
const ts = require('typescript');

const expectedExports = [
  'buildPlatformReleaseParityEvidencePackage',
];
const enginePath = path.resolve('src/platformReleaseEngine.ts');
const platformReleaseEngine = normalizeModuleExports(await loadEngine(enginePath));
const missingExports = expectedExports.filter((name) => typeof platformReleaseEngine[name] !== 'function');
assert.deepEqual(missingExports, [], `platform-release-engine: missing export(s): ${missingExports.join(', ')}`);

const context = buildPlatformReleaseContext();
const parityPackage = platformReleaseEngine.buildPlatformReleaseParityEvidencePackage(context);
const parityContent = JSON.parse(parityPackage.content);

assert.equal(parityPackage.kind, 'proxyforge-platform-release-parity-evidence-package');
assert.equal(parityPackage.secretHandling, 'execution-full-fidelity-secrets-preserved');
assert.equal(parityPackage.reportRedactionBoundary, 'redact-only-during-report-export');
assert.equal(parityPackage.reportReady, true);
assert(Object.values(parityPackage.requirements).every(Boolean), 'all Platform/Release parity requirements should be true');
assert.equal(parityPackage.artifactCount, 6);
assert.equal(parityPackage.smokeCount, 16);
assert.equal(parityPackage.gateCount, 4);
assert.equal(parityPackage.documentationCount, 3);
assert.equal(parityContent.kind, 'proxyforge-platform-release-parity-evidence-package');
assert.match(parityPackage.content, /ProxyForge-0\.1\.0-alpha\.1\.AppImage/);
assert.match(parityPackage.content, /ProxyForge Setup 0\.1\.0-alpha\.1\.exe/);
assert.match(parityPackage.content, /PROXYFORGE_RELEASE_SMOKE=1/);
assert.match(parityPackage.content, /Authorization: Bearer platform-secret-token/);
assert.match(parityPackage.content, /session=platform-session/);
assert.match(parityPackage.content, /X-API-Key: platform-api-key/);
assert.match(parityPackage.content, /platform-signing-secret/);
assert.match(parityPackage.content, /callbackToken=platform-callback-token/);
assert.match(parityPackage.content, /windows-trust-runner/);
assert.match(parityPackage.content, /ERROR_NOT_SUPPORTED/);
assert.match(parityPackage.content, /test:ci:fast/);
assert.match(parityPackage.content, /test:ci:full/);
assert.match(parityPackage.content, /redact-only-during-report-export/);

const artifactDir = path.resolve('.gitignored/test-artifacts/platform-release-engine');
await fs.mkdir(artifactDir, { recursive: true });
await fs.writeFile(path.join(artifactDir, 'platform-release-parity-evidence-package.json'), parityPackage.content);

console.log('platform-release-engine: exercised dense UI QA, Linux/Windows shell/package smokes, release gates, docs, security review, platform pins, and full-fidelity evidence');

async function loadEngine(filePath) {
  const source = await fs.readFile(filePath, 'utf8');
  const transpiled = ts.transpileModule(source, {
    compilerOptions: {
      module: ts.ModuleKind.CommonJS,
      target: ts.ScriptTarget.ES2022,
      esModuleInterop: true,
    },
    fileName: filePath,
  }).outputText;
  const module = { exports: {} };
  const sandbox = {
    module,
    exports: module.exports,
    TextDecoder,
    TextEncoder,
    URL,
    URLSearchParams,
    Buffer,
    console,
    require,
  };
  vm.runInNewContext(transpiled, sandbox, { filename: filePath });
  return module.exports;
}

function normalizeModuleExports(moduleExports) {
  const hasNamedHelper = expectedExports.some((name) => typeof moduleExports[name] === 'function');
  if (hasNamedHelper) return moduleExports;
  if (moduleExports.default && typeof moduleExports.default === 'object') return moduleExports.default;
  return moduleExports;
}

function buildPlatformReleaseContext() {
  const now = '2026-05-25T23:59:00.000Z';
  const rawRequest = [
    'GET /api/platform-release HTTP/1.1',
    'Host: app.shop.local',
    'Authorization: Bearer platform-secret-token',
    'Cookie: session=platform-session',
    'X-API-Key: platform-api-key',
    '',
    '',
  ].join('\r\n');
  const rawResponse = [
    'HTTP/1.1 200 OK',
    'Content-Type: application/json',
    'Set-Cookie: callbackToken=platform-callback-token; HttpOnly',
    '',
    '{"ok":true,"signingSecret":"platform-signing-secret"}',
  ].join('\r\n');
  const allSurfaces = [
    'Proxy',
    'Target',
    'Repeater',
    'Intruder',
    'Scanner',
    'Sequencer',
    'Decoder',
    'Comparer',
    'Logger',
    'Organizer',
    'Extensions',
    'Collaborator',
    'Reports',
    'AI',
    'Automations',
    'Exploit Lab',
  ];
  return {
    exportedAt: now,
    uiSnapshots: [
      {
        id: 'ui-desktop-dense-workbench',
        viewport: 'desktop',
        renderer: 'react-vite',
        toolSurfaces: allSurfaces,
        navigationGroups: ['Capture', 'Map', 'Attack', 'Intel', 'Evidence', 'Automation'],
        densityScore: 96,
        nonBlankPixelRatio: 0.74,
        overlapCount: 0,
        keyboardReachable: true,
        content: JSON.stringify({
          kind: 'proxyforge-ui-visual-qa',
          viewport: 'desktop',
          rawRequest,
          rawResponse,
          notes: 'Dense analyst navigation rendered with no overlapping tool labels.',
        }),
      },
      {
        id: 'ui-mobile-dense-workbench',
        viewport: 'mobile',
        renderer: 'react-vite',
        toolSurfaces: allSurfaces,
        navigationGroups: ['Capture', 'Map', 'Attack', 'Intel', 'Evidence', 'Automation'],
        densityScore: 92,
        nonBlankPixelRatio: 0.61,
        overlapCount: 0,
        keyboardReachable: true,
        content: JSON.stringify({
          kind: 'proxyforge-ui-visual-qa',
          viewport: 'mobile',
          rawRequest,
          rawResponse,
          notes: 'Mobile drawer keeps every MVP surface reachable without text collision.',
        }),
      },
    ],
    artifacts: [
      artifact('linux-appimage', 'linux', 'appimage', 'release/ProxyForge-0.1.0-alpha.1.AppImage', now, rawRequest, rawResponse),
      artifact('linux-deb', 'linux', 'deb', 'release/proxyforge_0.1.0-alpha.1_amd64.deb', now, rawRequest, rawResponse),
      artifact('linux-unpacked', 'linux', 'linux-unpacked', 'release/linux-unpacked/proxyforge', now, rawRequest, rawResponse),
      artifact('windows-nsis', 'windows', 'nsis', 'release/ProxyForge Setup 0.1.0-alpha.1.exe', now, rawRequest, rawResponse),
      artifact('windows-portable', 'windows', 'portable', 'release/ProxyForge 0.1.0-alpha.1.exe', now, rawRequest, rawResponse),
      artifact('windows-unpacked', 'windows', 'win-unpacked', 'release/win-unpacked/ProxyForge.exe', now, rawRequest, rawResponse),
    ],
    smokes: [
      smoke('linux-shell', 'linux', 'electron-shell', 'passed', 1, 0, 0, ['PROXYFORGE_RELEASE_SMOKE=1 renderer launch'], rawRequest, rawResponse),
      smoke('windows-shell', 'windows', 'electron-shell', 'passed', 1, 0, 0, ['PROXYFORGE_RELEASE_SMOKE=1 renderer launch'], rawRequest, rawResponse),
      smoke('linux-headless', 'linux', 'headless-cli', 'passed', 2, 0, 0, ['packaged headless --help', 'scan/report export'], rawRequest, rawResponse),
      smoke('windows-headless', 'windows', 'headless-cli', 'passed', 2, 0, 0, ['installed packaged headless --help', 'installed scan/report export'], rawRequest, rawResponse),
      smoke('linux-agent', 'linux', 'agent-cli', 'passed', 2, 0, 0, ['proxyforge-agent status', 'external-cwd app-root resolution'], rawRequest, rawResponse),
      smoke('windows-agent', 'windows', 'agent-cli', 'passed', 2, 0, 0, ['proxyforge-agent status', 'installed command surface'], rawRequest, rawResponse),
      smoke('linux-runtime', 'linux', 'runtime-proxy-cert-oast-report', 'passed', 5, 0, 0, ['proxy capture', 'project CA MITM', 'DNS/HTTP/SMTP OAST', 'report export'], rawRequest, rawResponse),
      smoke('windows-runtime', 'windows', 'runtime-proxy-cert-oast-report', 'passed', 5, 0, 0, ['proxy capture', 'project CA MITM', 'DNS/HTTP/SMTP OAST', 'report export'], rawRequest, rawResponse),
      smoke('linux-browser-routing', 'linux', 'browser-routing', 'passed', 2, 0, 0, ['Chromium isolated profile through packaged proxy'], rawRequest, rawResponse),
      smoke('windows-browser-routing', 'windows', 'browser-routing', 'passed', 2, 0, 0, ['Google Chrome isolated profile through packaged proxy'], rawRequest, rawResponse),
      smoke('linux-deb-install', 'linux', 'deb-install', 'passed', 3, 0, 0, ['clean-container deb install', 'installed GUI launch'], rawRequest, rawResponse),
      smoke('linux-trusted-ca', 'linux', 'trusted-ca-browser', 'passed', 3, 0, 0, ['isolated Chromium NSS trusted CA HTTPS capture'], rawRequest, rawResponse),
      smoke('linux-uninstall', 'linux', 'uninstall', 'passed', 1, 0, 0, ['clean-container deb uninstall'], rawRequest, rawResponse),
      smoke('windows-nsis', 'windows', 'nsis-install', 'passed', 4, 0, 0, ['silent NSIS install', 'installed GUI launch', 'installed runtime workflow'], rawRequest, rawResponse),
      smoke('windows-uninstall', 'windows', 'uninstall', 'passed', 1, 0, 0, ['quiet NSIS uninstall'], rawRequest, rawResponse),
      smoke('windows-dpapi', 'windows', 'dpapi-cookie', 'passed', 1, 0, 0, ['DPAPI sample-cookie extraction'], rawRequest, rawResponse),
    ],
    gates: [
      gate('build-gate', 'Build renderer and Electron runtime', 'npm run build', 'passed', 1, 1, rawRequest, rawResponse),
      gate('fast-gate', 'Curated fast regression suite', 'npm run test:ci:fast', 'passed', 50, 50, rawRequest, rawResponse),
      gate('full-gate', 'Full/nightly regression suite orchestrator', 'npm run test:ci:full -- --plan-only && node tests/ci-nightly-policy.mjs', 'passed', 2, 2, rawRequest, rawResponse),
      gate('release-security-gate', 'Release security review', 'npm run test:security-review', 'passed', 1, 1, rawRequest, rawResponse),
    ],
    installDocs: [
      {
        id: 'install-linux-windows',
        title: 'Linux and Windows install guide',
        path: 'docs/INSTALL_LINUX_WINDOWS.md',
        coveredTopics: ['Linux', 'Windows', 'certificate trust', 'browser routing', 'agentic operation', 'production signoff'],
        content: `Linux Windows certificate trust browser routing agentic operation production signoff ${rawRequest}\n${rawResponse}`,
      },
      {
        id: 'operator-guide',
        title: 'Operator guide',
        path: 'docs/OPERATOR_GUIDE.md',
        coveredTopics: ['Linux', 'Windows', 'certificate trust', 'browser routing', 'agentic operation', 'production signoff'],
        content: `Proxy CA trust, browser routing, replay, scanner, exploit, reporting, and agentic operation. ${rawRequest}\n${rawResponse}`,
      },
      {
        id: 'install-signoff',
        title: 'Install signoff guidance',
        path: 'docs/INSTALL_LINUX_WINDOWS.md',
        coveredTopics: ['Linux', 'Windows', 'certificate trust', 'browser routing', 'agentic operation', 'production signoff'],
        content: `Production signoff requires fast/full gates, release smoke, and security review. ${rawRequest}\n${rawResponse}`,
      },
    ],
    securityReviews: [
      {
        id: 'release-security-review-platform',
        status: 'passed',
        coveredAreas: ['local listeners', 'secrets', 'exploit controls', 'agent controls', 'platform pins', 'artifact hygiene'],
        criticalFindingCount: 0,
        highFindingCount: 0,
        signedBy: 'ProxyForge Release Security',
        content: JSON.stringify({
          kind: 'proxyforge-release-security-review',
          localListeners: '127.0.0.1 bindings reviewed',
          secrets: 'full fidelity until report export',
          exploitControls: 'approval-gated',
          agentControls: 'Codex Claude Vantix command surface',
          platformPins: ['windows-trust-runner trust-store lane pinned'],
          signingSecret: 'platform-signing-secret',
          rawRequest,
          rawResponse,
        }),
      },
    ],
    platformPins: [
      {
        id: 'linux-clean-container-pin',
        platform: 'linux',
        runner: 'local-clean-container',
        status: 'accepted',
        reason: 'Linux clean-container deb install/runtime/trusted-CA/uninstall lane is accepted for parity promotion.',
        content: JSON.stringify({
          runner: 'local-clean-container',
          status: 'accepted',
          rawRequest,
          rawResponse,
        }),
      },
      {
        id: 'windows-trust-store-pin',
        platform: 'windows',
        runner: 'windows-trust-runner',
        status: 'pinned-nonblocking',
        reason: 'CurrentUser Root mutation is blocked with ERROR_NOT_SUPPORTED, so Windows browser trust-store HTTPS capture stays pinned until a host lane permits temporary certificate-store mutation.',
        content: JSON.stringify({
          runner: 'windows-trust-runner',
          status: 'blocked-nonfailed',
          blockedReason: 'ERROR_NOT_SUPPORTED',
          trustStoreLane: 'pinned nonblocking',
          rawRequest,
          rawResponse,
        }),
      },
    ],
    operationalSecretSamples: [
      'Authorization: Bearer platform-secret-token',
      'session=platform-session',
      'X-API-Key: platform-api-key',
      'platform-signing-secret',
      'callbackToken=platform-callback-token',
    ],
  };
}

function artifact(id, platform, artifactType, artifactPath, builtAt, rawRequest, rawResponse) {
  return {
    id,
    platform,
    artifactType,
    path: artifactPath,
    sha256: `${id.replace(/[^a-z0-9]/gi, '')}sha256digest000000`,
    sizeBytes: 42_000_000,
    builtAt,
    evidence: ['electron-builder artifact', 'packaged app root', 'release smoke metadata'],
    content: JSON.stringify({
      kind: 'proxyforge-release-artifact',
      artifactPath,
      rawRequest,
      rawResponse,
    }),
  };
}

function smoke(id, platform, lane, status, passedChecks, blockedChecks, failedChecks, checks, rawRequest, rawResponse) {
  return {
    id,
    platform,
    lane,
    status,
    passedChecks,
    blockedChecks,
    failedChecks,
    checks,
    content: JSON.stringify({
      kind: 'proxyforge-release-smoke',
      platform,
      lane,
      status,
      env: 'PROXYFORGE_RELEASE_SMOKE=1',
      checks,
      rawRequest,
      rawResponse,
    }),
  };
}

function gate(id, name, command, status, completedSteps, totalSteps, rawRequest, rawResponse) {
  return {
    id,
    name,
    command,
    status,
    completedSteps,
    totalSteps,
    evidence: ['structured JSON summary', 'ignored artifact retention'],
    content: JSON.stringify({
      kind: 'proxyforge-release-gate',
      name,
      command,
      status,
      completedSteps,
      totalSteps,
      rawRequest,
      rawResponse,
    }),
  };
}
