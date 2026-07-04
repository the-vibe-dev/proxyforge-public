#!/usr/bin/env node
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';

const root = process.cwd();
const packageJson = JSON.parse(await fs.readFile(path.join(root, 'package.json'), 'utf8'));
const releaseVersion = packageJson.version;
const startedAt = new Date();
const requiredPackagedAgentCapabilities = [
  'anvil-package-export',
  'anvil-plan',
  'anvil-run',
  'bulk-replay',
  'bundle-sign',
  'bundle-verify',
  'callback-poll',
  'callback-provider-probe',
  'callback-relay-plan',
  'callback-relay-soak',
  'callback-replay',
  'callback-retention-prune',
  'chromium-capture',
  'content-discovery-plan',
  'content-discovery-run',
  'live-target-profile',
  'cookie-capture',
  'crawl-run',
  'evidence-list',
  'exploit-package-export',
  'exploit-preview',
  'exploit-run',
  'extension-fixtures',
  'findings-list',
  'intel',
  'insertion-points',
  'intruder-run',
  'inventory',
  'mitm-export',
  'mitm-start',
  'mitm-status',
  'mitm-stop',
  'proxy-import',
  'project-store-backup',
  'project-store-recover',
  'project-store-status',
  'repeater-desync-plan',
  'repeater-desync-probe',
  'repeater-race-run',
  'replay-matrix',
  'replay-run',
  'websocket-fuzz',
  'websocket-list',
  'websocket-replay',
  'websocket-transcript-export',
  'report-export',
  'report-preview',
  'scanner-evidence-export',
  'scanner-oast-promote',
  'scanner-plan',
  'scanner-retest',
  'scanner-run',
  'search',
  'search-index',
  'sequencer-analyze',
  'status',
  'target-access-review',
  'target-map-compare',
  'automation-ci-export',
  'automation-list',
  'automation-parity-export',
  'automation-run',
  'automation-scheduler-tick',
  'automation-service-plan',
  'automation-service-smoke',
  'vantix-intel-export',
  'vantix-report-import',
  'vantix-sync',
  'view',
];

async function main() {
  const { flags } = parseArgs(process.argv.slice(2));
  const platform = String(flags.platform ?? process.platform);
  const planOnly = Boolean(flags.plan);
  const outPath = path.resolve(String(flags.out ?? path.join('test-results', `release-smoke-${platform}.json`)));
  const result = planOnly
    ? await buildPlan(platform)
    : await runSmoke(platform, flags);
  const envelope = {
    kind: 'proxyforge-release-smoke-result',
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    durationMs: Date.now() - startedAt.getTime(),
    platform,
    planOnly,
    ...result,
  };
  await fs.mkdir(path.dirname(outPath), { recursive: true });
  await fs.writeFile(outPath, JSON.stringify(envelope, null, 2), 'utf8');
  process.stdout.write(`${JSON.stringify(envelope, null, flags.pretty === false ? 0 : 2)}\n`);
  if (envelope.status === 'failed') process.exitCode = 1;
}

async function buildPlan(platform) {
  return {
    status: 'planned',
    host: hostSummary(),
    capabilities: {
      xvfbRun: Boolean(await findCommand('xvfb-run')),
      wine: Boolean(await findCommand('wine')),
      dpkgDeb: Boolean(await findCommand('dpkg-deb')),
      unzip: Boolean(await findCommand('unzip')),
      file: Boolean(await findCommand('file')),
    },
    linux: {
      artifacts: [`release/ProxyForge-${releaseVersion}.AppImage`, `release/proxyforge_${releaseVersion}_amd64.deb`, 'release/linux-unpacked/proxyforge'],
      smoke: 'Run release/linux-unpacked/proxyforge to prove Electron Node runtime, packaged headless scan/report, packaged agent CLI, packaged external-cwd agent invocation, packaged proxy/cert/OAST/report workflow, optional packaged browser routing, and PROXYFORGE_RELEASE_SMOKE=1 GUI load under xvfb-run.',
    },
    windows: {
      artifacts: ['release/win-unpacked/ProxyForge.exe', `release/ProxyForge ${releaseVersion}.exe`, `release/ProxyForge Setup ${releaseVersion}.exe`, `release/ProxyForge-${releaseVersion}-win.zip`],
      smoke: 'Run win-unpacked/ProxyForge.exe or the NSIS setup on a Windows host to prove installed Electron Node runtime, packaged headless scan/report, packaged agent CLI, packaged external-cwd agent invocation, packaged proxy/cert/OAST/report workflow, optional packaged browser routing, optional packaged DPAPI sample-cookie extraction, PROXYFORGE_RELEASE_SMOKE GUI launch, and uninstall.',
    },
    requestedPlatform: platform,
  };
}

async function runSmoke(platform, flags) {
  if (platform === 'linux') return runLinuxSmoke(flags);
  if (platform === 'win32' || platform === 'windows') return runWindowsSmoke(flags);
  return {
    status: 'blocked',
    host: hostSummary(),
    message: `Release smoke for ${platform} is not implemented yet.`,
    checks: [],
  };
}

async function runLinuxSmoke(flags) {
  const artifact = path.resolve(String(flags.artifact ?? flags.binary ?? path.join('release', 'linux-unpacked', 'proxyforge')));
  const checks = [];
  const stat = await statArtifact(artifact);
  checks.push({
    name: 'artifact-exists',
    status: stat ? 'passed' : 'failed',
    artifact,
    sizeBytes: stat?.size ?? 0,
    sha256: stat ? await sha256File(artifact) : undefined,
  });
  if (!stat) {
    return { status: 'failed', host: hostSummary(), artifact, checks, message: `Artifact not found: ${artifact}` };
  }

  if (artifact.endsWith('.deb')) {
    const dpkgDeb = await findCommand('dpkg-deb');
    if (dpkgDeb) {
      checks.push(await runCheck('deb-metadata', dpkgDeb, ['--info', artifact], {}, 15000));
    } else {
      checks.push({ name: 'deb-metadata', status: 'blocked', message: 'dpkg-deb is not available on PATH.' });
    }
    return summarizeChecks({ host: hostSummary(), artifact, checks });
  }

  const nodeCheck = await runCheck(
    'electron-node-runtime',
    artifact,
    ['-e', 'console.log(JSON.stringify({electron:process.versions.electron,node:process.version,platform:process.platform,arch:process.arch}))'],
    { ELECTRON_RUN_AS_NODE: '1' },
    15000,
  );
  checks.push(nodeCheck);
  const headlessCheck = await runPackagedHeadlessCliCheck('packaged-headless-cli', artifact);
  if (headlessCheck) checks.push(headlessCheck);
  const agentCheck = await runPackagedAgentCliCheck('packaged-agent-cli', artifact, flags);
  if (agentCheck) checks.push(agentCheck);
  const externalAgentCheck = await runPackagedExternalAgentCliCheck('packaged-agent-cli-external-cwd', artifact, flags);
  if (externalAgentCheck) checks.push(externalAgentCheck);
  const headlessWorkflowCheck = await runPackagedHeadlessWorkflowCheck('packaged-headless-scan-report', artifact, flags);
  if (headlessWorkflowCheck) checks.push(headlessWorkflowCheck);
  const runtimeWorkflowCheck = await runPackagedRuntimeWorkflowCheck('packaged-runtime-proxy-cert-oast-report', artifact, flags);
  if (runtimeWorkflowCheck) checks.push(runtimeWorkflowCheck);
  if (wantsBrowserRouting(flags)) {
    const browserRoutingCheck = await runPackagedBrowserRoutingCheck('packaged-browser-routing', artifact, flags);
    if (browserRoutingCheck) checks.push(browserRoutingCheck);
  }

  const xvfbRun = await findCommand('xvfb-run');
  if (!xvfbRun) {
    checks.push({ name: 'packaged-gui-launch', status: 'blocked', message: 'xvfb-run is not available; run this on a Linux desktop session or install Xvfb.' });
    return summarizeChecks({ host: hostSummary(), artifact, checks });
  }

  const guiCheck = await runCheck(
    'packaged-gui-launch',
    xvfbRun,
    ['-a', artifact, '--no-sandbox'],
    { PROXYFORGE_RELEASE_SMOKE: '1' },
    Number(flags.timeout ?? 20000),
  );
  const smokeLine = guiCheck.stdout.split(/\r?\n/).find((line) => line.startsWith('PROXYFORGE_RELEASE_SMOKE '));
  const smokePayload = smokeLine ? parseJsonMaybe(smokeLine.replace(/^PROXYFORGE_RELEASE_SMOKE\s+/, '')) : null;
  checks.push({
    ...guiCheck,
    smokePayload,
    status: guiCheck.status === 'passed' && smokePayload?.status === 'passed' ? 'passed' : guiCheck.status,
  });

  return summarizeChecks({ host: hostSummary(), artifact, checks });
}

async function runWindowsSmoke(flags) {
  const artifact = path.resolve(String(flags.artifact ?? path.join('release', 'win-unpacked', 'ProxyForge.exe')));
  const checks = [];
  const stat = await statArtifact(artifact);
  checks.push({
    name: 'artifact-exists',
    status: stat ? 'passed' : 'failed',
    artifact,
    sizeBytes: stat?.size ?? 0,
    sha256: stat ? await sha256File(artifact) : undefined,
  });
  if (!stat) return { status: 'failed', host: hostSummary(), artifact, checks, message: `Artifact not found: ${artifact}` };

  const fileBin = await findCommand('file');
  const unzipBin = await findCommand('unzip');
  if (artifact.endsWith('.zip') && unzipBin) checks.push(await runCheck('windows-zip-contents', unzipBin, ['-l', artifact], {}, 15000));
  if (fileBin && artifact.toLowerCase().endsWith('.exe')) checks.push(await runCheck('windows-exe-metadata', fileBin, [artifact], {}, 15000));

  if (process.platform !== 'win32') {
    checks.push({
      name: 'windows-gui-launch',
      status: 'blocked',
      message: 'Run this command on Windows to prove GUI launch, packaged runtime proxy/cert/OAST/report workflow, optional browser routing, DPAPI cookie, headless, and report export smokes.',
    });
  } else if (isWindowsInstallerArtifact(artifact)) {
    await appendWindowsInstallerChecks(artifact, flags, checks);
  } else if (isLaunchableWindowsAppArtifact(artifact)) {
    const nodeCheck = path.basename(artifact).toLowerCase() === 'proxyforge.exe'
      ? await runCheck(
        'electron-node-runtime',
        artifact,
        ['-e', 'console.log(JSON.stringify({electron:process.versions.electron,node:process.version,platform:process.platform,arch:process.arch}))'],
        { ELECTRON_RUN_AS_NODE: '1' },
        15000,
      )
      : null;
    if (nodeCheck) checks.push(nodeCheck);
    const headlessCheck = await runPackagedHeadlessCliCheck('windows-packaged-headless-cli', artifact);
    if (headlessCheck) checks.push(headlessCheck);
    const agentCheck = await runPackagedAgentCliCheck('windows-packaged-agent-cli', artifact, flags);
    if (agentCheck) checks.push(agentCheck);
    const externalAgentCheck = await runPackagedExternalAgentCliCheck('windows-packaged-agent-cli-external-cwd', artifact, flags);
    if (externalAgentCheck) checks.push(externalAgentCheck);
    const headlessWorkflowCheck = await runPackagedHeadlessWorkflowCheck('windows-packaged-headless-scan-report', artifact, flags);
    if (headlessWorkflowCheck) checks.push(headlessWorkflowCheck);
    const runtimeWorkflowCheck = await runPackagedRuntimeWorkflowCheck('windows-packaged-runtime-proxy-cert-oast-report', artifact, flags);
    if (runtimeWorkflowCheck) checks.push(runtimeWorkflowCheck);
    if (wantsBrowserRouting(flags)) {
      const browserRoutingCheck = await runPackagedBrowserRoutingCheck('windows-packaged-browser-routing', artifact, flags);
      if (browserRoutingCheck) checks.push(browserRoutingCheck);
    }
    if (wantsDpapiCookie(flags)) {
      const dpapiCookieCheck = await runPackagedDpapiCookieCheck('windows-packaged-dpapi-cookie', artifact, flags);
      if (dpapiCookieCheck) checks.push(dpapiCookieCheck);
    }
    checks.push(await runWindowsGuiSmokeCheck('windows-gui-launch', artifact, flags));
  } else {
    checks.push({
      name: 'windows-gui-launch',
      status: 'blocked',
      message: 'Selected artifact is an installer or archive. Use release/win-unpacked/ProxyForge.exe or the portable executable for the packaged GUI launch smoke.',
    });
  }
  return summarizeChecks({ host: hostSummary(), artifact, checks });
}

async function appendWindowsInstallerChecks(artifact, flags, checks) {
  const installCheck = await runCheck(
    'windows-installer-silent-install',
    artifact,
    ['/S'],
    {},
    Number(flags.installTimeout ?? 90000),
  );
  checks.push(installCheck);
  if (installCheck.status !== 'passed') return;

  await delay(Number(flags.installWaitMs ?? 20000));
  const installed = await findWindowsInstalledExecutable(flags.installedExecutable);
  checks.push(installed
    ? {
        name: 'windows-installed-executable',
        status: 'passed',
        artifact: installed.path,
        sizeBytes: installed.size,
        sha256: await sha256File(installed.path),
      }
    : {
        name: 'windows-installed-executable',
        status: 'failed',
        message: 'Installed ProxyForge.exe was not found under the expected Windows per-user program locations.',
      });
  if (!installed) return;

  checks.push(await runCheck(
    'windows-installed-electron-node-runtime',
    installed.path,
    ['-e', 'console.log(JSON.stringify({electron:process.versions.electron,node:process.version,platform:process.platform,arch:process.arch}))'],
    { ELECTRON_RUN_AS_NODE: '1' },
    15000,
  ));
  const headlessCheck = await runPackagedHeadlessCliCheck('windows-installed-headless-cli', installed.path);
  if (headlessCheck) checks.push(headlessCheck);
  const agentCheck = await runPackagedAgentCliCheck('windows-installed-agent-cli', installed.path, flags);
  if (agentCheck) checks.push(agentCheck);
  const headlessWorkflowCheck = await runPackagedHeadlessWorkflowCheck('windows-installed-headless-scan-report', installed.path, flags);
  if (headlessWorkflowCheck) checks.push(headlessWorkflowCheck);
  const runtimeWorkflowCheck = await runPackagedRuntimeWorkflowCheck('windows-installed-runtime-proxy-cert-oast-report', installed.path, flags);
  if (runtimeWorkflowCheck) checks.push(runtimeWorkflowCheck);
  if (wantsBrowserRouting(flags)) {
    const browserRoutingCheck = await runPackagedBrowserRoutingCheck('windows-installed-browser-routing', installed.path, flags);
    if (browserRoutingCheck) checks.push(browserRoutingCheck);
  }
  if (wantsDpapiCookie(flags)) {
    const dpapiCookieCheck = await runPackagedDpapiCookieCheck('windows-installed-dpapi-cookie', installed.path, flags);
    if (dpapiCookieCheck) checks.push(dpapiCookieCheck);
  }
  checks.push(await runWindowsGuiSmokeCheck('windows-installed-gui-launch', installed.path, flags));

  if (flags.uninstall) {
    const uninstaller = await findWindowsUninstaller(installed.path);
    if (!uninstaller) {
      checks.push({
        name: 'windows-installer-silent-uninstall',
        status: 'failed',
        message: 'Uninstaller was not found beside the installed executable.',
      });
      return;
    }
    const uninstallCheck = await runCheck(
      'windows-installer-silent-uninstall',
      uninstaller,
      ['/currentuser', '/S'],
      {},
      Number(flags.uninstallTimeout ?? 90000),
    );
    checks.push(uninstallCheck);
    await delay(Number(flags.uninstallWaitMs ?? 8000));
    const installedAfterUninstall = await statArtifact(installed.path);
    checks.push({
      name: 'windows-installed-executable-removed',
      status: installedAfterUninstall ? 'failed' : 'passed',
      artifact: installed.path,
      message: installedAfterUninstall ? 'Installed executable still exists after quiet uninstall.' : 'Installed executable removed by quiet uninstall.',
    });
  }
}

async function runWindowsGuiSmokeCheck(name, artifact, flags) {
  const guiCheck = await runCheck(
    name,
    artifact,
    [],
    { PROXYFORGE_RELEASE_SMOKE: '1' },
    Number(flags.timeout ?? 20000),
  );
  const smokeLine = guiCheck.stdout.split(/\r?\n/).find((line) => line.startsWith('PROXYFORGE_RELEASE_SMOKE '));
  const smokePayload = smokeLine ? parseJsonMaybe(smokeLine.replace(/^PROXYFORGE_RELEASE_SMOKE\s+/, '')) : null;
  return {
    ...guiCheck,
    smokePayload,
    status: guiCheck.status === 'passed' && smokePayload?.status === 'passed' ? 'passed' : 'failed',
  };
}

async function runPackagedHeadlessCliCheck(name, executable) {
  const scriptPath = await packagedHeadlessScriptPath(executable);
  if (!scriptPath) return null;
  return runCheck(
    name,
    executable,
    [scriptPath, '--help'],
    { ELECTRON_RUN_AS_NODE: '1' },
    15000,
  );
}

async function runPackagedAgentCliCheck(name, executable, flags) {
  const scriptPath = await packagedAgentScriptPath(executable);
  if (!scriptPath) return null;
  const check = await runCheck(
    name,
    executable,
    [
      scriptPath,
      'status',
      '--target',
      String(flags.agentTarget ?? flags['agent-target'] ?? 'https://agent-smoke.proxyforge.local/'),
      '--json',
    ],
    { ELECTRON_RUN_AS_NODE: '1' },
    Number(flags.agentTimeout ?? flags['agent-timeout'] ?? 20000),
  );
  const summary = parseJsonMaybe(check.stdout);
  const capabilities = Array.isArray(summary?.data?.capabilities) ? summary.data.capabilities : [];
  const requiredCapabilities = requiredPackagedAgentCapabilities;
  const requiredCapabilityStatus = Object.fromEntries(requiredCapabilities.map((capability) => [
    capability.replace(/-([a-z])/g, (_match, char) => char.toUpperCase()),
    capabilities.includes(capability),
  ]));
  const passed = check.status === 'passed'
    && summary?.kind === 'proxyforge-agent-result'
    && summary?.status === 'completed'
    && summary?.safety?.redacted === false
    && summary?.safety?.secretHandling === 'execution-full-fidelity-secrets-preserved'
    && requiredCapabilities.every((capability) => capabilities.includes(capability));
  const agentSummary = summary ? {
    command: summary.command,
    status: summary.status,
    mode: summary.mode,
    capabilityCount: capabilities.length,
    requiredCapabilityCount: requiredCapabilities.length,
    requiredCapabilities: requiredCapabilityStatus,
    missingCapabilities: requiredCapabilities.filter((capability) => !capabilities.includes(capability)),
    runtime: summary.data?.runtime,
    secretHandling: summary.safety?.secretHandling,
    redacted: summary.safety?.redacted,
  } : null;
  return {
    ...check,
    stdout: agentSummary ? `${JSON.stringify(agentSummary, null, 2)}\n` : check.stdout.slice(0, 12000),
    stdoutBytes: Buffer.byteLength(check.stdout),
    status: passed ? 'passed' : 'failed',
    message: passed
      ? 'Packaged agent CLI exposed the full-fidelity Codex/Claude/Vantix command surface.'
      : 'Packaged agent CLI did not expose the expected command surface or secret-handling boundary.',
    agentSummary,
  };
}

async function runPackagedExternalAgentCliCheck(name, executable, flags) {
  const scriptPath = await packagedAgentScriptPath(executable);
  if (!scriptPath) return null;
  const externalCwd = path.resolve(String(flags.agentExternalCwd ?? flags['agent-external-cwd'] ?? path.join('test-results', 'release-smoke-agent-external-cwd', `${name}-${Date.now()}`)));
  await fs.mkdir(externalCwd, { recursive: true });
  const check = await runCheck(
    name,
    executable,
    [
      scriptPath,
      'status',
      '--target',
      String(flags.agentTarget ?? flags['agent-target'] ?? 'https://agent-smoke.proxyforge.local/'),
      '--json',
    ],
    { ELECTRON_RUN_AS_NODE: '1' },
    Number(flags.agentTimeout ?? flags['agent-timeout'] ?? 20000),
    { cwd: externalCwd },
  );
  const summary = parseJsonMaybe(check.stdout);
  const capabilities = Array.isArray(summary?.data?.capabilities) ? summary.data.capabilities : [];
  const runtime = summary?.data?.runtime ?? {};
  const requiredCapabilities = requiredPackagedAgentCapabilities;
  const requiredCapabilityStatus = Object.fromEntries(requiredCapabilities.map((capability) => [
    capability.replace(/-([a-z])/g, (_match, char) => char.toUpperCase()),
    capabilities.includes(capability),
  ]));
  const passed = check.status === 'passed'
    && summary?.kind === 'proxyforge-agent-result'
    && summary?.status === 'completed'
    && summary?.safety?.secretHandling === 'execution-full-fidelity-secrets-preserved'
    && path.resolve(String(runtime.cwd ?? '')) === externalCwd
    && String(runtime.appRoot ?? '').includes('app.asar')
    && !String(runtime.appRoot ?? '').startsWith(externalCwd)
    && requiredCapabilities.every((capability) => capabilities.includes(capability));
  const agentSummary = summary ? {
    command: summary.command,
    status: summary.status,
    mode: summary.mode,
    capabilityCount: capabilities.length,
    requiredCapabilityCount: requiredCapabilities.length,
    requiredCapabilities: requiredCapabilityStatus,
    missingCapabilities: requiredCapabilities.filter((capability) => !capabilities.includes(capability)),
    externalCwd,
    runtime,
    secretHandling: summary.safety?.secretHandling,
    redacted: summary.safety?.redacted,
  } : null;
  return {
    ...check,
    stdout: agentSummary ? `${JSON.stringify(agentSummary, null, 2)}\n` : check.stdout.slice(0, 12000),
    stdoutBytes: Buffer.byteLength(check.stdout),
    status: passed ? 'passed' : 'failed',
    message: passed
      ? 'Packaged agent CLI ran from an external cwd while resolving runtime modules from app.asar.'
      : 'Packaged agent CLI failed external-cwd runtime resolution proof.',
    agentSummary,
  };
}

async function runPackagedHeadlessWorkflowCheck(name, executable, flags) {
  const scriptPath = await packagedHeadlessScriptPath(executable);
  if (!scriptPath) return null;
  const server = http.createServer((request, response) => {
    const headers = {
      'content-type': request.headers.origin ? 'application/json' : 'text/html',
      ...(request.headers.origin ? {
        'access-control-allow-origin': request.headers.origin,
        'access-control-allow-credentials': 'true',
      } : {}),
    };
    if (request.method === 'OPTIONS') {
      response.writeHead(204, {
        allow: 'GET, POST, DELETE',
        'access-control-allow-methods': 'GET, POST, DELETE',
      });
      response.end();
      return;
    }
    const bodyParts = [`path=${request.url}`];
    if (request.headers['x-forwarded-host']) bodyParts.push(String(request.headers['x-forwarded-host']));
    if (request.headers.origin) bodyParts.push('cors-origin');
    response.writeHead(200, headers);
    response.end([
      '<html><title>ProxyForge release smoke target</title>',
      '<a href="/orders?status=open">Orders</a>',
      '<form method="post" action="/api/refunds"><input name="orderId"><input name="amount"></form>',
      `<pre>${bodyParts.join(' ')}</pre>`,
      '</html>',
    ].join(''));
  });

  const port = await listen(server);
  const outRoot = flags.headlessOutDir
    ? path.resolve(String(flags.headlessOutDir))
    : path.join(root, 'test-results', 'release-smoke-headless');
  const outDir = path.join(outRoot, `${name}-${Date.now()}`);
  try {
    const check = await runCheck(
      name,
      executable,
      [
        scriptPath,
        '--target',
        `http://127.0.0.1:${port}/`,
        '--scope',
        '127.0.0.1',
        '--out-dir',
        outDir,
        '--report',
        'json,markdown',
        '--sarif',
        '--junit',
        '--checks',
        'security-headers,cors-origin,cache-key,method-options',
        '--crawl-depth',
        '1',
        '--crawl-pages',
        '4',
        '--fail-on',
        'none',
      ],
      { ELECTRON_RUN_AS_NODE: '1' },
      Number(flags.headlessTimeout ?? 45000),
    );
    const summary = parseJsonMaybe(check.stdout);
    const artifactStats = summary ? await collectHeadlessArtifactStats(summary) : [];
    const headlessSummary = summary ? {
      summaryPath: summary.summaryPath,
      outDir: summary.outDir,
      exitCode: summary.exitCode,
      findingCount: summary.findingCount,
      reportCount: summary.reportCount,
      ciArtifactCount: summary.ciArtifactCount,
      totalRequests: summary.totalRequests,
      highestSeverity: summary.highestSeverity,
    } : null;
    const passed = check.status === 'passed'
      && summary?.exitCode === 0
      && summary?.findingCount >= 1
      && summary?.reportCount >= 2
      && summary?.ciArtifactCount >= 2
      && artifactStats.every((artifact) => artifact.exists);
    return {
      ...check,
      stdout: headlessSummary ? `${JSON.stringify(headlessSummary, null, 2)}\n` : check.stdout.slice(0, 12000),
      stdoutBytes: Buffer.byteLength(check.stdout),
      status: passed ? 'passed' : 'failed',
      message: passed
        ? `Packaged headless scan exported ${summary.reportCount} report(s) and ${summary.ciArtifactCount} CI artifact(s).`
        : 'Packaged headless scan did not produce the expected reports and CI artifacts.',
      headlessSummary,
      artifactStats,
    };
  } finally {
    await closeServer(server);
  }
}

async function runPackagedRuntimeWorkflowCheck(name, executable, flags) {
  const scriptPath = await packagedElectronScriptPath(executable, 'releaseWorkflowSmoke.js');
  if (!scriptPath) return null;
  const outRoot = flags.runtimeOutDir
    ? path.resolve(String(flags.runtimeOutDir))
    : path.join(root, 'test-results', 'release-smoke-runtime');
  const outDir = path.join(outRoot, `${name}-${Date.now()}`);
  const check = await runCheck(
    name,
    executable,
    [
      scriptPath,
      '--out-dir',
      outDir,
    ],
    { ELECTRON_RUN_AS_NODE: '1' },
    Number(flags.runtimeTimeout ?? 70000),
  );
  const summary = parseJsonMaybe(check.stdout);
  const passed = check.status === 'passed'
    && summary?.status === 'passed'
    && summary?.proxy?.httpCaptured === true
    && summary?.proxy?.httpsCaptured === true
    && summary?.certificate?.ready === true
    && summary?.oast?.interactionCount >= 3
    && summary?.oast?.tokensPreserved === true
    && summary?.reports?.count >= 5
    && summary?.reports?.operationalSecretsPreserved === true
    && summary?.reports?.reportSecretsRedacted === true
    && Array.isArray(summary?.reports?.artifactStats)
    && summary.reports.artifactStats.every((artifact) => artifact.exists === true);
  const runtimeSummary = summary ? {
    outDir: summary.outDir,
    proxy: summary.proxy,
    certificate: summary.certificate,
    oast: summary.oast,
    reports: {
      count: summary.reports?.count,
      formats: summary.reports?.formats,
      operationalCapturePath: summary.reports?.operationalCapturePath,
      operationalSecretsPreserved: summary.reports?.operationalSecretsPreserved,
      reportSecretsRedacted: summary.reports?.reportSecretsRedacted,
    },
  } : null;
  return {
    ...check,
    stdout: runtimeSummary ? `${JSON.stringify(runtimeSummary, null, 2)}\n` : check.stdout.slice(0, 12000),
    stdoutBytes: Buffer.byteLength(check.stdout),
    status: passed ? 'passed' : 'failed',
    message: passed
      ? 'Packaged runtime captured proxy and HTTPS MITM traffic, OAST callbacks, and full report exports.'
      : 'Packaged runtime workflow did not produce the expected proxy, certificate, OAST, and report evidence.',
    runtimeSummary,
    artifactStats: summary?.reports?.artifactStats ?? [],
  };
}

async function runPackagedBrowserRoutingCheck(name, executable, flags) {
  const scriptPath = await packagedElectronScriptPath(executable, 'releaseBrowserRoutingSmoke.js');
  if (!scriptPath) return null;
  const outRoot = flags.browserRoutingOutDir
    ? path.resolve(String(flags.browserRoutingOutDir))
    : flags['browser-routing-out-dir']
      ? path.resolve(String(flags['browser-routing-out-dir']))
      : path.join(root, 'test-results', 'release-smoke-browser-routing');
  const outDir = path.join(outRoot, `${name}-${Date.now()}`);
  const args = [
    scriptPath,
    '--out-dir',
    outDir,
  ];
  if (flags.browser && flags.browser !== true) {
    args.push('--browser', String(flags.browser));
  }
  if (flags.browserTrustStore ?? flags['browser-trust-store'] ?? flags.trustedCa ?? flags['trusted-ca']) {
    args.push('--trusted-ca');
  }
  const check = await runCheck(
    name,
    executable,
    args,
    { ELECTRON_RUN_AS_NODE: '1' },
    Number(flags.browserRoutingTimeout ?? flags['browser-routing-timeout'] ?? 90000),
  );
  const summary = parseJsonMaybe(check.stdout);
  const passed = check.status === 'passed'
    && summary?.status === 'passed'
    && summary?.proxy?.browserCaptured === true
    && summary?.browser?.proxyConfigured === true
    && Array.isArray(summary?.artifacts)
    && summary.artifacts.every((artifact) => artifact.exists === true);
  const blocked = summary?.status === 'blocked';
  const browserSummary = summary ? {
    outDir: summary.outDir,
    status: summary.status,
    checks: Array.isArray(summary.checks)
      ? summary.checks.map((browserCheck) => ({
          name: browserCheck.name,
          status: browserCheck.status,
          message: browserCheck.message,
        }))
      : [],
    proxy: summary.proxy,
    browser: summary.browser,
    artifacts: summary.artifacts,
  } : null;
  return {
    ...check,
    stdout: browserSummary ? `${JSON.stringify(browserSummary, null, 2)}\n` : check.stdout.slice(0, 12000),
    stdoutBytes: Buffer.byteLength(check.stdout),
    status: passed ? 'passed' : blocked ? 'blocked' : 'failed',
    message: passed
      ? 'Packaged runtime launched a managed browser and captured its routed request through ProxyForge.'
      : blocked
        ? 'Packaged browser routing smoke is blocked on this host; see browserSummary.checks for the host capability gate.'
      : 'Packaged browser routing smoke did not produce the expected proxy capture evidence.',
    browserSummary,
    artifactStats: summary?.artifacts ?? [],
  };
}

async function runPackagedDpapiCookieCheck(name, executable, flags) {
  const scriptPath = await packagedElectronScriptPath(executable, 'releaseCookieDpapiSmoke.js');
  if (!scriptPath) return null;
  const outRoot = flags.dpapiCookieOutDir
    ? path.resolve(String(flags.dpapiCookieOutDir))
    : flags['dpapi-cookie-out-dir']
      ? path.resolve(String(flags['dpapi-cookie-out-dir']))
      : path.join(root, 'test-results', 'release-smoke-dpapi-cookie');
  const outDir = path.join(outRoot, `${name}-${Date.now()}`);
  const check = await runCheck(
    name,
    executable,
    [
      scriptPath,
      '--out-dir',
      outDir,
    ],
    { ELECTRON_RUN_AS_NODE: '1' },
    Number(flags.dpapiCookieTimeout ?? flags['dpapi-cookie-timeout'] ?? 45000),
  );
  const summary = parseJsonMaybe(check.stdout);
  const passed = check.status === 'passed'
    && summary?.status === 'passed'
    && summary?.dpapi?.wrappedKeyCreated === true
    && summary?.dpapi?.readinessStatus === 'ready'
    && summary?.extraction?.cookieCount >= 1
    && summary?.extraction?.decryptedCount >= 1
    && summary?.extraction?.encryptedCount === 0
    && summary?.extraction?.operationalCookieHeaderPreserved === true
    && summary?.extraction?.summaryCookieValuesRedacted === true
    && Array.isArray(summary?.artifacts)
    && summary.artifacts.every((artifact) => artifact.exists === true);
  const dpapiSummary = summary ? {
    outDir: summary.outDir,
    platform: summary.platform,
    dpapi: summary.dpapi,
    extraction: summary.extraction,
    artifacts: summary.artifacts,
  } : null;
  return {
    ...check,
    stdout: dpapiSummary ? `${JSON.stringify(dpapiSummary, null, 2)}\n` : check.stdout.slice(0, 12000),
    stdoutBytes: Buffer.byteLength(check.stdout),
    status: passed ? 'passed' : 'failed',
    message: passed
      ? 'Packaged runtime unwrapped a DPAPI-protected Chromium profile key and decrypted a sample cookie.'
      : 'Packaged DPAPI sample-cookie smoke did not produce the expected decryption evidence.',
    dpapiSummary,
    artifactStats: summary?.artifacts ?? [],
  };
}

async function collectHeadlessArtifactStats(summary) {
  const paths = [
    summary.summaryPath,
    ...(Array.isArray(summary.reports) ? summary.reports.map((artifact) => artifact.path) : []),
    ...(Array.isArray(summary.ciArtifacts) ? summary.ciArtifacts.map((artifact) => artifact.path) : []),
  ].filter(Boolean);
  const uniquePaths = Array.from(new Set(paths));
  const stats = [];
  for (const artifactPath of uniquePaths) {
    const stat = await statArtifact(artifactPath);
    stats.push({
      path: artifactPath,
      exists: Boolean(stat),
      sizeBytes: stat?.size ?? 0,
      sha256: stat ? await sha256File(artifactPath) : undefined,
    });
  }
  return stats;
}

function wantsBrowserRouting(flags) {
  return Boolean(flags.browserRouting ?? flags['browser-routing'] ?? flags.requireBrowserRouting ?? flags['require-browser-routing']);
}

function wantsDpapiCookie(flags) {
  return Boolean(flags.dpapiCookie ?? flags['dpapi-cookie'] ?? flags.requireDpapiCookie ?? flags['require-dpapi-cookie']);
}

async function packagedHeadlessScriptPath(executable) {
  return packagedElectronScriptPath(executable, 'headlessRunner.js');
}

async function packagedAgentScriptPath(executable) {
  return packagedAppScriptPath(executable, path.join('scripts', 'proxyforge-agent.mjs'));
}

async function packagedElectronScriptPath(executable, scriptName) {
  return packagedAppScriptPath(executable, path.join('dist-electron', scriptName));
}

async function packagedAppScriptPath(executable, relativePath) {
  const resourceRoot = path.join(path.dirname(executable), 'resources');
  const appAsar = path.join(resourceRoot, 'app.asar');
  const stat = await statArtifact(appAsar);
  if (!stat?.isFile()) return '';
  return path.join(appAsar, relativePath);
}

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      if (address && typeof address === 'object') resolve(address.port);
      else reject(new Error('Release smoke target did not bind to a TCP port.'));
    });
  });
}

function closeServer(server) {
  return new Promise((resolve, reject) => {
    server.close((error) => {
      if (error) reject(error);
      else resolve();
    });
  });
}

async function findWindowsInstalledExecutable(explicitPath) {
  const candidates = [
    explicitPath,
    process.env.LOCALAPPDATA ? path.join(process.env.LOCALAPPDATA, 'Programs', 'proxyforge', 'ProxyForge.exe') : '',
    process.env.LOCALAPPDATA ? path.join(process.env.LOCALAPPDATA, 'Programs', 'ProxyForge', 'ProxyForge.exe') : '',
  ].filter(Boolean).map((candidate) => path.resolve(String(candidate)));

  for (const candidate of candidates) {
    const stat = await statArtifact(candidate);
    if (stat) return { path: candidate, size: stat.size };
  }

  if (!process.env.LOCALAPPDATA) return null;
  const found = await findNamedFile(path.join(process.env.LOCALAPPDATA, 'Programs'), 'ProxyForge.exe', 4);
  if (!found) return null;
  const stat = await statArtifact(found);
  return stat ? { path: found, size: stat.size } : null;
}

async function findWindowsUninstaller(installedExecutable) {
  const installedDir = path.dirname(installedExecutable);
  const candidates = [
    path.join(installedDir, 'Uninstall ProxyForge.exe'),
    path.join(installedDir, 'Uninstall proxyforge.exe'),
  ];
  for (const candidate of candidates) {
    if (await statArtifact(candidate)) return candidate;
  }
  return findNamedFile(installedDir, 'Uninstall ProxyForge.exe', 2);
}

async function findNamedFile(directory, fileName, maxDepth) {
  if (maxDepth < 0) return '';
  let entries;
  try {
    entries = await fs.readdir(directory, { withFileTypes: true });
  } catch {
    return '';
  }
  for (const entry of entries) {
    const fullPath = path.join(directory, entry.name);
    if (entry.isFile() && entry.name.toLowerCase() === fileName.toLowerCase()) return fullPath;
    if (entry.isDirectory()) {
      const found = await findNamedFile(fullPath, fileName, maxDepth - 1);
      if (found) return found;
    }
  }
  return '';
}

function isWindowsInstallerArtifact(artifact) {
  const fileName = path.basename(artifact).toLowerCase();
  return fileName.endsWith('.exe') && fileName.includes('setup');
}

function isLaunchableWindowsAppArtifact(artifact) {
  const fileName = path.basename(artifact).toLowerCase();
  return fileName.endsWith('.exe') && !fileName.includes('setup');
}

function delay(ms) {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

function summarizeChecks(payload) {
  const failed = payload.checks.some((check) => check.status === 'failed');
  const blocked = payload.checks.some((check) => check.status === 'blocked');
  return {
    ...payload,
    status: failed ? 'failed' : blocked ? 'blocked' : 'passed',
    passedChecks: payload.checks.filter((check) => check.status === 'passed').length,
    blockedChecks: payload.checks.filter((check) => check.status === 'blocked').length,
    failedChecks: payload.checks.filter((check) => check.status === 'failed').length,
  };
}

function runCheck(name, command, args, extraEnv, timeoutMs, options = {}) {
  return new Promise((resolve) => {
    const started = Date.now();
    const cwd = options.cwd ?? root;
    const child = spawn(command, args, {
      cwd,
      env: { ...process.env, ...extraEnv },
      windowsHide: true,
    });
    let stdout = '';
    let stderr = '';
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGTERM');
    }, timeoutMs);
    child.stdout.on('data', (chunk) => {
      stdout += chunk.toString();
    });
    child.stderr.on('data', (chunk) => {
      stderr += chunk.toString();
    });
    child.on('error', (error) => {
      clearTimeout(timer);
      resolve({
        name,
        command,
        args,
        cwd,
        status: 'failed',
        durationMs: Date.now() - started,
        stdout,
        stderr,
        message: error.message,
      });
    });
    child.on('close', (code, signal) => {
      clearTimeout(timer);
      resolve({
        name,
        command,
        args,
        cwd,
        status: code === 0 && !timedOut ? 'passed' : 'failed',
        exitCode: code,
        signal,
        timedOut,
        durationMs: Date.now() - started,
        stdout,
        stderr,
      });
    });
  });
}

async function statArtifact(filePath) {
  try {
    return await fs.stat(filePath);
  } catch {
    return null;
  }
}

async function sha256File(filePath) {
  const hash = createHash('sha256');
  const content = await fs.readFile(filePath);
  hash.update(content);
  return hash.digest('hex');
}

async function findCommand(command) {
  const paths = String(process.env.PATH ?? '').split(path.delimiter);
  const candidates = process.platform === 'win32' ? [command, `${command}.exe`, `${command}.cmd`, `${command}.bat`] : [command];
  for (const directory of paths) {
    for (const candidate of candidates) {
      const fullPath = path.join(directory, candidate);
      try {
        await fs.access(fullPath);
        return fullPath;
      } catch {
        // Keep scanning PATH.
      }
    }
  }
  return '';
}

function hostSummary() {
  return {
    platform: process.platform,
    arch: process.arch,
    release: os.release(),
    node: process.version,
    cwd: root,
  };
}

function parseJsonMaybe(value) {
  try {
    return JSON.parse(value);
  } catch {
    return null;
  }
}

function parseArgs(argv) {
  const flags = {};
  const positionals = [];
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (token.startsWith('--')) {
      const eq = token.indexOf('=');
      if (eq !== -1) {
        flags[token.slice(2, eq)] = coerceFlag(token.slice(eq + 1));
        continue;
      }
      const key = token.slice(2);
      const next = argv[index + 1];
      if (!next || next.startsWith('--')) {
        flags[key] = true;
      } else {
        flags[key] = coerceFlag(next);
        index += 1;
      }
      continue;
    }
    positionals.push(token);
  }
  return { flags, positionals };
}

function coerceFlag(value) {
  if (value === 'true') return true;
  if (value === 'false') return false;
  return value;
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.stack ?? error.message : String(error)}\n`);
  process.exitCode = 1;
});
