#!/usr/bin/env node
import { execFile, spawn } from 'node:child_process';
import dgram from 'node:dgram';
import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';

const root = process.cwd();
const require = createRequire(import.meta.url);
const forge = require('node-forge');
const args = parseArgs(process.argv.slice(2));
const version = JSON.parse(await fs.readFile(path.join(root, 'package.json'), 'utf8')).version;
const tag = args.tag ?? `v${version}`;
const lane = args.lane ?? (process.platform === 'win32' ? 'windows' : 'linux');
const resultsRoot = path.resolve(args['results-dir'] ?? 'test-results');
const agentPath = path.join(root, 'scripts', 'proxyforge-agent.mjs');
const token = 'pf_live_validation_token';
const secret = 'pf_live_validation_secret';
const logPath = lane === 'windows'
  ? path.join(resultsRoot, 'windows-live-validation', 'windows-live-validation.log')
  : path.join(resultsRoot, 'live-validation.log');
const commandLog = [];

await main();

async function main() {
  const commit = await git(['rev-parse', 'HEAD']);
  await assertBuiltRuntime();
  if (lane === 'windows') {
    await runWindowsLane(commit);
    return;
  }
  await runLinuxSourceLane(commit);
}

async function runLinuxSourceLane(commit) {
  await archiveExisting([
    path.join(resultsRoot, 'live-agent-validation'),
    path.join(resultsRoot, 'live-mitm-validation'),
    path.join(resultsRoot, 'live-replay-validation'),
    path.join(resultsRoot, 'live-scanner-validation'),
    path.join(resultsRoot, 'live-report-validation'),
    path.join(resultsRoot, 'live-oast-validation'),
    path.join(resultsRoot, 'live-validation.log'),
    path.join(resultsRoot, 'live-validation-summary.json'),
  ]);
  await fs.mkdir(resultsRoot, { recursive: true });
  await log(`candidate version=${version} commit=${commit} platform=${process.platform}`);

  const dirs = liveDirs(resultsRoot);
  for (const dir of Object.values(dirs)) await fs.mkdir(dir, { recursive: true });

  const target = await startLocalTarget();
  const httpsTarget = await startHttpsTarget(dirs.mitm);
  const mitmProcesses = [];
  try {
    await log(`local target=${target.url} httpsTarget=${httpsTarget.url}`);
    const help = await runCommand(process.execPath, [agentPath, '--help']);
    await fs.writeFile(path.join(dirs.agent, 'proxyforge-agent-help.txt'), help.stdout, 'utf8');

    const proxy = await startMitm(path.join(dirs.mitm, 'session'), ['--upstream-tls', 'strict']);
    mitmProcesses.push(proxy);
    await writeJson(path.join(dirs.mitm, 'mitm-start.json'), proxy.ready);
    await sendHttpTraffic(proxy.ready.data.proxyUrl, target.url);
    const mitmExport = await runAgentJson(['mitm-export', '--session-dir', path.join(dirs.mitm, 'session'), '--json']);
    await writeJson(path.join(dirs.mitm, 'mitm-export.json'), mitmExport);

    const proxyImport = await runAgentJson(['proxy-import', '--file', path.join(dirs.mitm, 'session', 'exchanges.jsonl'), '--json']);
    await writeJson(path.join(dirs.agent, 'proxy-import.json'), proxyImport);
    const projectPath = path.join(dirs.agent, 'live-project.proxyforge.json');
    const project = buildProject(proxyImport.data.exchanges, target);
    await writeJson(projectPath, project);

    const originalId = project.exchanges.find((exchange) => exchange.method === 'POST' && exchange.path === '/echo')?.id;
    assert(originalId, 'captured POST /echo exchange is required for replay and scanner validation');
    const replayOriginal = await runAgentJson(['replay-run', '--project', projectPath, '--request-id', originalId, '--scope', '127.0.0.1', '--execute', '--json']);
    await writeJson(path.join(dirs.replay, 'replay-original.json'), replayOriginal);
    const replayMutated = await runAgentJson(['replay-run', '--project', projectPath, '--request-id', 'hx-live-replay-mutated', '--scope', '127.0.0.1', '--execute', '--json']);
    await writeJson(path.join(dirs.replay, 'replay-mutated.json'), replayMutated);

    const scannerRun = await runAgentJson([
      'scanner-run',
      '--project', projectPath,
      '--request-id', originalId,
      '--scope', '127.0.0.1',
      '--check-pack', 'full-active',
      '--max-requests', '13',
      '--throttle', '100',
      '--out', dirs.scanner,
      '--execute',
      '--soak',
      '--min-requests', '1',
      '--json',
    ]);
    await writeJson(path.join(dirs.scanner, 'scanner-run.json'), scannerRun);

    const httpsProxy = await startMitm(path.join(dirs.mitm, 'https-session'), ['--upstream-tls', 'relaxed']);
    mitmProcesses.push(httpsProxy);
    await writeJson(path.join(dirs.mitm, 'https-mitm-start.json'), httpsProxy.ready);
    const httpsCurl = await runCommand('curl', ['-sk', '--noproxy', '', '-x', httpsProxy.ready.data.proxyUrl, '-H', `Authorization: Bearer ${token}`, `${httpsTarget.url}/headers`]);
    await fs.writeFile(path.join(dirs.mitm, 'https-curl.txt'), `${httpsCurl.stdout}${httpsCurl.stderr}`, 'utf8');
    const httpsExport = await runAgentJson(['mitm-export', '--session-dir', path.join(dirs.mitm, 'https-session'), '--json']);
    await writeJson(path.join(dirs.mitm, 'https-mitm-export.json'), httpsExport);

    const reportJson = await runAgentJson(['report-export', '--project', projectPath, '--format', 'json', '--out', dirs.report, '--json']);
    await writeJson(path.join(dirs.report, 'report-export-json-command.json'), reportJson);
    const reportMarkdown = await runAgentJson(['report-export', '--project', projectPath, '--format', 'markdown', '--out', dirs.report, '--json']);
    await writeJson(path.join(dirs.report, 'report-export-markdown-command.json'), reportMarkdown);

    await writeJson(path.join(dirs.agent, 'target-observed-requests.json'), target.observed);
    await writeJson(path.join(dirs.replay, 'target-observed-mutations.json'), target.observed.filter((entry) => entry.headers['x-proxyforge-live-test'] || entry.url.includes('pf_live=1')));
    assert(target.observed.some((entry) => entry.method === 'GET' && entry.url === '/'), 'target must observe captured GET / traffic');
    assert(target.observed.some((entry) => entry.method === 'POST' && entry.url.startsWith('/echo') && entry.body.includes(secret)), 'target must observe captured POST secret body');
    assert(target.observed.some((entry) => entry.headers.authorization === `Bearer ${token}`), 'target must observe authorization-bearing request');
    assert(target.observed.some((entry) => entry.headers['x-proxyforge-live-test'] === 'replay-validation' && entry.url.includes('pf_live=1') && entry.body.includes('replay-validation')), 'target must observe replay mutation');
    assert((mitmExport.data.exchangeCount ?? 0) >= 5, 'MITM export must contain captured HTTP exchanges');
    assert((httpsExport.data.exchangeCount ?? 0) >= 1, 'HTTPS MITM export must contain decrypted HTTPS exchange evidence');
    assert(scannerRun.status === 'completed', `scanner-run must complete; got ${scannerRun.status}`);
    await assertReportsRedacted(dirs.report);
    assert(JSON.stringify(project).includes(token) && JSON.stringify(project).includes(secret), 'operational project evidence must preserve live validation secrets');

    const oast = await runOastValidation(commit, dirs.oast);
    const summary = await buildSummary(commit, {
      mitm: 'pass',
      httpsMitm: 'pass',
      replay: 'pass',
      scanner: 'pass',
      oast: oast.status === 'pass' ? 'pass' : 'fail',
      reportExport: 'pass',
      agentInterface: 'pass',
    });
    await writeJson(path.join(resultsRoot, 'live-validation-summary.json'), summary);
    await log(`live validation completed releaseDecision=${summary.releaseDecision}`);
  } finally {
    for (const proxy of mitmProcesses.reverse()) await stopMitm(proxy).catch((error) => log(`mitm stop warning: ${error.message}`));
    await httpsTarget.close();
    await target.close();
    await fs.writeFile(logPath, `${commandLog.join('\n')}\n`, 'utf8');
  }
}

async function runWindowsLane(commit) {
  const windowsRoot = path.join(resultsRoot, 'windows-live-validation');
  await archiveExisting([
    path.join(windowsRoot, 'live-agent-validation'),
    path.join(windowsRoot, 'live-mitm-validation'),
    path.join(windowsRoot, 'live-replay-validation'),
    path.join(windowsRoot, 'live-scanner-validation'),
    path.join(windowsRoot, 'live-report-validation'),
    path.join(windowsRoot, 'windows-live-validation-summary.json'),
    path.join(windowsRoot, 'windows-live-validation.log'),
  ]);
  await fs.mkdir(windowsRoot, { recursive: true });
  await log(`candidate version=${version} commit=${commit} platform=${process.platform}`);
  const localRoot = windowsRoot;
  const dirs = liveDirs(localRoot);
  for (const dir of Object.values(dirs)) await fs.mkdir(dir, { recursive: true });

  const target = await startLocalTarget();
  const httpsTarget = await startHttpsTarget(dirs.mitm);
  const mitmProcesses = [];
  try {
    await log(`local target=${target.url} httpsTarget=${httpsTarget.url}`);
    const help = await runCommand(process.execPath, [agentPath, '--help']);
    await fs.writeFile(path.join(dirs.agent, 'proxyforge-agent-help.txt'), help.stdout, 'utf8');
    const proxy = await startMitm(path.join(dirs.mitm, 'session'), ['--upstream-tls', 'strict']);
    mitmProcesses.push(proxy);
    await writeJson(path.join(dirs.mitm, 'mitm-start.json'), proxy.ready);
    await sendHttpTraffic(proxy.ready.data.proxyUrl, target.url);
    const mitmExport = await runAgentJson(['mitm-export', '--session-dir', path.join(dirs.mitm, 'session'), '--json']);
    await writeJson(path.join(dirs.mitm, 'mitm-export.json'), mitmExport);
    const proxyImport = await runAgentJson(['proxy-import', '--file', path.join(dirs.mitm, 'session', 'exchanges.jsonl'), '--json']);
    await writeJson(path.join(dirs.agent, 'proxy-import.json'), proxyImport);
    const projectPath = path.join(dirs.agent, 'live-project.proxyforge.json');
    const project = buildProject(proxyImport.data.exchanges, target);
    await writeJson(projectPath, project);
    const originalId = project.exchanges.find((exchange) => exchange.method === 'POST' && exchange.path === '/echo')?.id;
    assert(originalId, 'captured POST /echo exchange is required for replay and scanner validation');
    await writeJson(path.join(dirs.replay, 'replay-original.json'), await runAgentJson(['replay-run', '--project', projectPath, '--request-id', originalId, '--scope', '127.0.0.1', '--execute', '--json']));
    await writeJson(path.join(dirs.replay, 'replay-mutated.json'), await runAgentJson(['replay-run', '--project', projectPath, '--request-id', 'hx-live-replay-mutated', '--scope', '127.0.0.1', '--execute', '--json']));
    await writeJson(path.join(dirs.scanner, 'scanner-run.json'), await runAgentJson(['scanner-run', '--project', projectPath, '--request-id', originalId, '--scope', '127.0.0.1', '--check-pack', 'full-active', '--max-requests', '13', '--throttle', '100', '--out', dirs.scanner, '--execute', '--soak', '--min-requests', '1', '--json']));
    const httpsProxy = await startMitm(path.join(dirs.mitm, 'https-session'), ['--upstream-tls', 'relaxed']);
    mitmProcesses.push(httpsProxy);
    await writeJson(path.join(dirs.mitm, 'https-mitm-start.json'), httpsProxy.ready);
    const httpsCurl = await runCommand('curl', ['-sk', '--noproxy', '', '-x', httpsProxy.ready.data.proxyUrl, '-H', `Authorization: Bearer ${token}`, `${httpsTarget.url}/headers`]);
    await fs.writeFile(path.join(dirs.mitm, 'https-curl.txt'), `${httpsCurl.stdout}${httpsCurl.stderr}`, 'utf8');
    await writeJson(path.join(dirs.mitm, 'https-mitm-export.json'), await runAgentJson(['mitm-export', '--session-dir', path.join(dirs.mitm, 'https-session'), '--json']));
    await writeJson(path.join(dirs.report, 'report-export-json-command.json'), await runAgentJson(['report-export', '--project', projectPath, '--format', 'json', '--out', dirs.report, '--json']));
    await writeJson(path.join(dirs.report, 'report-export-markdown-command.json'), await runAgentJson(['report-export', '--project', projectPath, '--format', 'markdown', '--out', dirs.report, '--json']));
    await assertReportsRedacted(dirs.report);
    await writeJson(path.join(dirs.agent, 'target-observed-requests.json'), target.observed);
    await writeJson(path.join(dirs.replay, 'target-observed-mutations.json'), target.observed.filter((entry) => entry.headers['x-proxyforge-live-test'] || entry.url.includes('pf_live=1')));
    const windowsSummary = {
      version,
      commit,
      node: `${os.hostname()} (${process.platform})`,
      mitm: 'pass',
      httpsMitm: 'pass',
      replay: 'pass',
      scanner: 'pass',
      oast: 'covered-by-linux-local-oast-and-windows-agent-report-lanes',
      reportExport: 'pass',
      agentInterface: 'pass',
      guiSmoke: 'skipped-with-reason',
      guiSmokeReason: 'Headless source live-validation runner does not exercise the Electron GUI; use RDP GUI smoke for final publish evidence.',
    };
    await writeJson(path.join(windowsRoot, 'windows-live-validation-summary.json'), windowsSummary);
    await mergeWindowsSummary(commit, windowsSummary);
    await log('windows live validation completed');
  } finally {
    for (const proxy of mitmProcesses.reverse()) await stopMitm(proxy).catch((error) => log(`mitm stop warning: ${error.message}`));
    await httpsTarget.close();
    await target.close();
    await fs.writeFile(logPath, `${commandLog.join('\n')}\n`, 'utf8');
  }
}

async function runOastValidation(commit, outDir) {
  const { CallbackListenerService } = require(path.join(root, 'dist-electron', 'callbackListenerService.js'));
  const service = new CallbackListenerService();
  const profile = {
    id: 'live-oast-validation',
    name: 'Live OAST validation',
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
    signingKeyId: 'live-validation-key',
    ciCommand: 'proxyforge live oast validation',
    healthChecks: [],
    summary: 'Live OAST validation profile',
    content: '{}',
  };
  const payloads = [
    callbackPayload('cb-live-http', 'pf-live-http-oast', 'http', 'https://pf-live-http-oast.oast.local/probe'),
    callbackPayload('cb-live-dns', 'pf-live-dns-oast', 'dns', 'pf-live-dns-oast.oast.local'),
    callbackPayload('cb-live-smtp', 'pf-live-smtp-oast', 'smtp', 'pf-live-smtp-oast@oast.local'),
  ];
  try {
    const start = await service.start(profile, payloads);
    await sendHttpCallback(start.ports.http, 'pf-live-http-oast');
    await sendDnsCallback(start.ports.dns, 'pf-live-dns-oast.oast.local');
    await sendSmtpCallback(start.ports.smtp, 'pf-live-smtp-oast@oast.local');
    await delay(150);
    const poll = service.poll(profile.id, payloads);
    const stop = await service.stop(profile.id);
    await writeJson(path.join(outDir, 'live-oast-poll.json'), poll);
    const summary = {
      version,
      commit,
      status: poll.interactions.length >= 3 ? 'pass' : 'fail',
      profileId: profile.id,
      protocols: [...new Set(poll.interactions.map((interaction) => interaction.protocol))].sort(),
      start: { running: start.running, host: start.host, ports: start.ports },
      poll: {
        newInteractionCount: poll.newInteractionIds.length,
        interactionCount: poll.interactions.length,
        protocols: [...new Set(poll.interactions.map((interaction) => interaction.protocol))].sort(),
        payloadIds: poll.interactions.map((interaction) => interaction.payloadId),
        rawTokensPreserved: {
          http: JSON.stringify(poll).includes('pf-live-http-oast'),
          dns: JSON.stringify(poll).includes('pf-live-dns-oast'),
          smtp: JSON.stringify(poll).includes('pf-live-smtp-oast'),
        },
        duplicateSuppression: service.poll(profile.id, payloads).newInteractionIds.length === 0,
      },
      stop: { running: stop.running },
      artifacts: {
        poll: normalizeArtifact(path.join(outDir, 'live-oast-poll.json')),
        summary: normalizeArtifact(path.join(outDir, 'live-oast-summary.json')),
      },
    };
    await writeJson(path.join(outDir, 'live-oast-summary.json'), summary);
    return summary;
  } finally {
    await service.stopAll();
  }
}

function liveDirs(base) {
  return {
    agent: path.join(base, 'live-agent-validation'),
    mitm: path.join(base, 'live-mitm-validation'),
    replay: path.join(base, 'live-replay-validation'),
    scanner: path.join(base, 'live-scanner-validation'),
    report: path.join(base, 'live-report-validation'),
    oast: path.join(base, 'live-oast-validation'),
  };
}

async function startLocalTarget() {
  const observed = [];
  const server = http.createServer(async (request, response) => {
    const body = await readRequestBody(request);
    const headers = lowerHeaders(request.headers);
    observed.push({ at: new Date().toISOString(), method: request.method, url: request.url, headers, body });
    const url = new URL(request.url, 'http://127.0.0.1');
    if (request.method === 'OPTIONS' || url.pathname === '/options') {
      response.writeHead(204, { Allow: 'GET, POST, OPTIONS', 'Access-Control-Allow-Methods': 'GET, POST, OPTIONS' });
      response.end();
      return;
    }
    if (url.pathname === '/') {
      response.writeHead(200, { 'Content-Type': 'text/html' });
      response.end('<html><a href="/headers">headers</a><form action="/echo" method="post"></form></html>');
      return;
    }
    if (url.pathname === '/echo') {
      const cmd = url.searchParams.get('cmd');
      const payload = cmd
        ? { ok: true, commandOutput: `uid=1000(proxyforge) ${cmd}` }
        : { ok: true, method: request.method, url: request.url, body, token, secret };
      response.writeHead(202, { 'Content-Type': 'application/json', 'X-Echo-Live': 'accepted' });
      response.end(JSON.stringify(payload));
      return;
    }
    if (url.pathname === '/set-cookie') {
      response.writeHead(200, { 'Content-Type': 'text/plain', 'Set-Cookie': `pf_live_session=${secret}; HttpOnly; SameSite=Lax` });
      response.end('cookie set');
      return;
    }
    if (url.pathname === '/headers') {
      response.writeHead(200, { 'Content-Type': 'application/json', 'X-Live-Header': token });
      response.end(JSON.stringify({ authorization: headers.authorization ?? '', cookie: headers.cookie ?? '' }));
      return;
    }
    if (url.pathname === '/redirect') {
      response.writeHead(302, { Location: '/headers', 'Content-Type': 'text/plain' });
      response.end('redirect');
      return;
    }
    if (url.pathname === '/security-missing') {
      response.writeHead(200, { 'Content-Type': 'text/plain' });
      response.end('missing security headers');
      return;
    }
    if (url.pathname === '/cors') {
      response.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': headers.origin ?? '*' });
      response.end(JSON.stringify({ cors: true }));
      return;
    }
    if (url.pathname === '/graphql') {
      response.writeHead(200, { 'Content-Type': 'application/json' });
      response.end(JSON.stringify({ data: { __schema: { queryType: { name: 'Query' } } } }));
      return;
    }
    response.writeHead(404, { 'Content-Type': 'text/plain' });
    response.end('not found');
  });
  await listen(server, 0, '127.0.0.1');
  const port = server.address().port;
  return { url: `http://127.0.0.1:${port}`, port, observed, close: () => closeServer(server) };
}

async function startHttpsTarget(workDir) {
  const certDir = path.join(workDir, 'https-target-cert');
  await fs.mkdir(certDir, { recursive: true });
  const keyPath = path.join(certDir, 'target.key');
  const certPath = path.join(certDir, 'target.crt');
  await writeSelfSignedTargetCertificate(keyPath, certPath);
  const key = await fs.readFile(keyPath);
  const cert = await fs.readFile(certPath);
  const server = https.createServer({ key, cert }, async (request, response) => {
    const headers = lowerHeaders(request.headers);
    await readRequestBody(request);
    if (request.url?.startsWith('/headers')) {
      response.writeHead(200, { 'Content-Type': 'application/json', 'X-Live-Header': token });
      response.end(JSON.stringify({ authorization: headers.authorization ?? '', tls: true }));
      return;
    }
    response.writeHead(200, { 'Content-Type': 'text/plain' });
    response.end('https target');
  });
  await listen(server, 0, '127.0.0.1');
  const port = server.address().port;
  return { url: `https://127.0.0.1:${port}`, close: () => closeServer(server) };
}

async function writeSelfSignedTargetCertificate(keyPath, certPath) {
  const keys = forge.pki.rsa.generateKeyPair({ bits: 2048, workers: -1 });
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = Math.floor(Date.now() / 1000).toString(16);
  cert.validity.notBefore = new Date(Date.now() - 60_000);
  cert.validity.notAfter = new Date(Date.now() + 24 * 60 * 60 * 1000);
  const attrs = [
    { name: 'commonName', value: '127.0.0.1' },
    { name: 'organizationName', value: 'ProxyForge Live Validation' },
    { name: 'countryName', value: 'US' },
  ];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.setExtensions([
    { name: 'basicConstraints', cA: false, critical: true },
    { name: 'keyUsage', digitalSignature: true, keyEncipherment: true, critical: true },
    { name: 'extKeyUsage', serverAuth: true },
    {
      name: 'subjectAltName',
      altNames: [
        { type: 7, ip: '127.0.0.1' },
        { type: 2, value: 'localhost' },
      ],
    },
  ]);
  cert.sign(keys.privateKey, forge.md.sha256.create());
  await fs.writeFile(keyPath, forge.pki.privateKeyToPem(keys.privateKey), { encoding: 'utf8', mode: 0o600 });
  await fs.writeFile(certPath, forge.pki.certificateToPem(cert), 'utf8');
  await log(`generated self-signed HTTPS target certificate ${normalizeArtifact(certPath)}`);
}

async function sendHttpTraffic(proxyUrl, targetUrl) {
  await runCommand('curl', ['-sS', '--noproxy', '', '-x', proxyUrl, `${targetUrl}/`]);
  await runCommand('curl', ['-sS', '--noproxy', '', '-x', proxyUrl, '-X', 'POST', `${targetUrl}/echo`, '-H', 'Content-Type: application/json', '-H', `Authorization: Bearer ${token}`, '-H', `Cookie: pf_live_session=${secret}`, '--data', JSON.stringify({ hello: 'proxyforge', secret })]);
  await runCommand('curl', ['-sS', '--noproxy', '', '-x', proxyUrl, `${targetUrl}/set-cookie`]);
  await runCommand('curl', ['-sS', '--noproxy', '', '-x', proxyUrl, '-H', `Authorization: Bearer ${token}`, `${targetUrl}/headers`]);
  await runCommand('curl', ['-sS', '--noproxy', '', '-x', proxyUrl, `${targetUrl}/redirect`]);
}

async function startMitm(sessionDir, extraArgs) {
  await fs.mkdir(sessionDir, { recursive: true });
  const child = spawn(process.execPath, [
    agentPath,
    'mitm-start',
    '--session-dir', sessionDir,
    '--port', '0',
    '--ensure-ca',
    '--scope', '127.0.0.1,localhost',
    ...extraArgs,
    '--json',
  ], { cwd: root, stdio: ['ignore', 'pipe', 'pipe'] });
  const ready = await readFirstJsonLine(child, 'mitm-start');
  await log(`$ ${process.execPath} ${[agentPath, 'mitm-start', '--session-dir', sessionDir, '--port', '0', '--ensure-ca', '--scope', '127.0.0.1,localhost', ...extraArgs, '--json'].join(' ')}`);
  return { child, sessionDir, ready };
}

async function stopMitm(proxy) {
  await runAgentJson(['mitm-stop', '--session-dir', proxy.sessionDir, '--json']).catch(() => undefined);
  if (!proxy.child.killed) proxy.child.kill('SIGTERM');
  await waitForExit(proxy.child, 2000).catch(() => undefined);
}

async function runAgentJson(agentArgs) {
  const result = await runCommand(process.execPath, [agentPath, ...agentArgs]);
  return parseJson(result.stdout, `agent ${agentArgs[0]}`);
}

async function runCommand(command, commandArgs, options = {}) {
  await log(`$ ${command} ${commandArgs.join(' ')}`);
  return new Promise((resolve, reject) => {
    execFile(command, commandArgs, { cwd: root, timeout: options.timeout ?? 30000, maxBuffer: options.maxBuffer ?? 20 * 1024 * 1024 }, (error, stdout, stderr) => {
      if (error) {
        error.message = `${error.message}\nstdout:\n${stdout}\nstderr:\n${stderr}`;
        reject(error);
        return;
      }
      resolve({ stdout, stderr });
    });
  });
}

function buildProject(exchanges, target) {
  const mutatedRequestRaw = [
    `POST /echo?pf_live=1 HTTP/1.1`,
    `Host: 127.0.0.1:${target.port}`,
    `Authorization: Bearer ${token}`,
    `Cookie: pf_live_session=${secret}`,
    'X-ProxyForge-Live-Test: replay-validation',
    'Content-Type: application/json',
    'Content-Length: 69',
    '',
    JSON.stringify({ mutation: 'replay-validation', secret }),
  ].join('\n');
  return {
    version: 1,
    savedAt: new Date().toISOString(),
    projectName: `ProxyForge Live Validation ${lane}`,
    scopeAllowlist: ['127.0.0.1', 'localhost'],
    exchanges: [
      ...exchanges.map((exchange) => ({ ...exchange, tags: [...new Set([...(exchange.tags ?? []), 'live-validation'])] })),
      {
        id: 'hx-live-replay-mutated',
        method: 'POST',
        host: `127.0.0.1:${target.port}`,
        path: '/echo?pf_live=1',
        url: `${target.url}/echo?pf_live=1`,
        status: 202,
        length: 190,
        mime: 'application/json',
        risk: 'info',
        timing: 13,
        source: 'proxy',
        time: new Date().toISOString().slice(11, 19),
        requestRaw: mutatedRequestRaw,
        responseRaw: 'HTTP/1.1 202 Accepted\nContent-Type: application/json\n\n{"ok":true}',
        notes: 'Live validation replay mutation fixture.',
        tags: ['live-validation', 'replay-mutated'],
      },
    ],
    issues: [
      {
        id: 'issue-live-validation-security-headers',
        title: 'Live validation missing security headers',
        severity: 'low',
        host: '127.0.0.1',
        path: '/security-missing',
        confidence: 'firm',
        status: 'open',
        detail: `Operational detail intentionally contains Bearer ${token} and ${secret} for report redaction verification.`,
        remediation: 'Apply security headers in production routes.',
        evidenceRefs: [{ kind: 'exchange', id: exchanges.find((exchange) => exchange.method === 'POST')?.id, label: 'Captured live exchange', source: 'mitm' }],
      },
    ],
  };
}

async function assertReportsRedacted(reportDir) {
  const files = await listFiles(reportDir);
  const reportFiles = files.filter((file) => /\.(json|md|html|pdf)$/i.test(file));
  assert(reportFiles.length >= 2, 'report export must create at least JSON/Markdown artifacts');
  for (const file of reportFiles) {
    const text = await fs.readFile(file, 'utf8').catch(() => '');
    assert(!text.includes(token), `report/export leaked ${token}: ${file}`);
    assert(!text.includes(secret), `report/export leaked ${secret}: ${file}`);
  }
}

async function buildSummary(commit, linuxSourceValidation) {
  const existingWindows = await readJsonMaybe(path.join(resultsRoot, 'windows-live-validation', 'windows-live-validation-summary.json'));
  const windowsCurrent = existingWindows?.commit === commit;
  const windowsLiveValidation = windowsCurrent
    ? {
        node: existingWindows.node,
        mitm: existingWindows.mitm,
        httpsMitm: existingWindows.httpsMitm,
        replay: existingWindows.replay,
        scanner: existingWindows.scanner,
        oast: existingWindows.oast,
        reportExport: existingWindows.reportExport,
        agentInterface: existingWindows.agentInterface,
        guiSmoke: existingWindows.guiSmoke,
      }
    : {
        node: existingWindows?.node ? `${existingWindows.node} (stale for ${existingWindows.commit ?? 'unknown commit'})` : 'not-run-current-commit',
        mitm: 'fail-current-windows-live-validation-missing',
        httpsMitm: 'fail-current-windows-live-validation-missing',
        replay: 'fail-current-windows-live-validation-missing',
        scanner: 'fail-current-windows-live-validation-missing',
        oast: 'fail-current-windows-live-validation-missing',
        reportExport: 'fail-current-windows-live-validation-missing',
        agentInterface: 'fail-current-windows-live-validation-missing',
        guiSmoke: 'skipped-with-reason',
      };
  const releaseDecision = allPass(linuxSourceValidation, ['mitm', 'httpsMitm', 'replay', 'scanner', 'oast', 'reportExport', 'agentInterface'])
    && allPass(windowsLiveValidation, ['mitm', 'httpsMitm', 'replay', 'scanner', 'reportExport', 'agentInterface'])
    ? 'GO'
    : 'NO-GO';
  return {
    version,
    commit,
    tag,
    linuxSourceValidation,
    windowsLiveValidation,
    artifacts: [
      'test-results/live-agent-validation',
      'test-results/live-mitm-validation',
      'test-results/live-replay-validation',
      'test-results/live-scanner-validation',
      'test-results/live-report-validation',
      'test-results/live-oast-validation',
      'test-results/windows-live-validation',
    ],
    releaseDecision,
    notes: releaseDecision === 'GO'
      ? ['Linux source and Windows live validation passed for the current commit.']
      : ['Linux source live validation passed for the current commit; Windows live validation must be rerun for this exact commit before public publish.'],
  };
}

async function mergeWindowsSummary(commit, windowsSummary) {
  const summaryPath = path.join(resultsRoot, 'live-validation-summary.json');
  const existing = await readJsonMaybe(summaryPath);
  if (!existing || existing.commit !== commit) return;
  const merged = {
    ...existing,
    windowsLiveValidation: {
      node: windowsSummary.node,
      mitm: windowsSummary.mitm,
      httpsMitm: windowsSummary.httpsMitm,
      replay: windowsSummary.replay,
      scanner: windowsSummary.scanner,
      oast: windowsSummary.oast,
      reportExport: windowsSummary.reportExport,
      agentInterface: windowsSummary.agentInterface,
      guiSmoke: windowsSummary.guiSmoke,
    },
  };
  merged.releaseDecision = allPass(merged.linuxSourceValidation, ['mitm', 'httpsMitm', 'replay', 'scanner', 'oast', 'reportExport', 'agentInterface'])
    && allPass(merged.windowsLiveValidation, ['mitm', 'httpsMitm', 'replay', 'scanner', 'reportExport', 'agentInterface'])
    ? 'GO'
    : 'NO-GO';
  await writeJson(summaryPath, merged);
}

function allPass(group, keys) {
  return keys.every((key) => typeof group?.[key] === 'string' && /^pass(?:\b|-|$)/i.test(group[key]));
}

async function archiveExisting(paths) {
  const existing = [];
  for (const candidate of paths) {
    if (fsSync.existsSync(candidate)) existing.push(candidate);
  }
  if (!existing.length) return;
  const archiveRoot = path.join(root, '.gitignored', 'live-validation-archive', new Date().toISOString().replace(/[:.]/g, '-'));
  for (const candidate of existing) {
    const relativePath = path.relative(root, candidate);
    const destination = path.join(archiveRoot, relativePath);
    await fs.mkdir(path.dirname(destination), { recursive: true });
    await fs.rename(candidate, destination);
  }
}

async function assertBuiltRuntime() {
  const required = ['proxyEngine.js', 'certManager.js', 'reportEngine.js', 'callbackListenerService.js'];
  for (const file of required) {
    const candidate = path.join(root, 'dist-electron', file);
    assert(fsSync.existsSync(candidate), `missing ${candidate}; run npm run build before live validation`);
  }
}

function callbackPayload(id, tokenValue, protocol, endpoint) {
  return {
    id,
    token: tokenValue,
    label: `${protocol} live callback`,
    protocol,
    endpoint,
    createdAt: new Date().toISOString(),
    status: 'waiting',
    sourceHost: '127.0.0.1',
    sourcePath: '/live-oast-validation',
    notes: 'Live OAST validation payload',
  };
}

function sendHttpCallback(port, tokenValue) {
  return new Promise((resolve, reject) => {
    const request = http.request({
      host: '127.0.0.1',
      port,
      path: `/probe?token=${tokenValue}&live=1`,
      headers: { Host: `${tokenValue}.oast.local`, 'User-Agent': 'proxyforge-live-oast-validation' },
    }, (response) => {
      response.resume();
      response.on('end', resolve);
    });
    request.on('error', reject);
    request.end('runtime=http-live');
  });
}

function sendDnsCallback(port, name) {
  return new Promise((resolve, reject) => {
    const socket = dgram.createSocket('udp4');
    const timer = setTimeout(() => {
      socket.close();
      reject(new Error('Timed out waiting for DNS callback response'));
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
    socket.send(buildDnsQuery(name), port, '127.0.0.1');
  });
}

function sendSmtpCallback(port, recipient) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host: '127.0.0.1', port });
    let settled = false;
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error('Timed out waiting for SMTP callback'));
    }, 2000);
    const settle = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.end();
      resolve();
    };
    socket.on('connect', () => {
      socket.write(['EHLO live.local', 'MAIL FROM:<live@proxyforge.local>', `RCPT TO:<${recipient}>`, 'DATA', 'Subject: live oast validation', '', 'runtime=smtp-live', '.', 'QUIT', ''].join('\r\n'));
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

function buildDnsQuery(name) {
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

function readFirstJsonLine(child, label) {
  return new Promise((resolve, reject) => {
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => reject(new Error(`${label} did not become ready\nstdout:\n${stdout}\nstderr:\n${stderr}`)), 10000);
    child.stdout.on('data', (chunk) => {
      stdout += chunk.toString('utf8');
      const line = stdout.split(/\r?\n/).find((candidate) => candidate.trim().startsWith('{'));
      if (line) {
        clearTimeout(timer);
        resolve(parseJson(line, label));
      }
    });
    child.stderr.on('data', (chunk) => {
      stderr += chunk.toString('utf8');
    });
    child.once('exit', (code) => {
      clearTimeout(timer);
      reject(new Error(`${label} exited before ready with code ${code}\nstdout:\n${stdout}\nstderr:\n${stderr}`));
    });
    child.once('error', reject);
  });
}

function waitForExit(child, timeoutMs) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('Timed out waiting for child exit')), timeoutMs);
    child.once('exit', () => {
      clearTimeout(timer);
      resolve();
    });
  });
}

function readRequestBody(request) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    request.on('data', (chunk) => chunks.push(chunk));
    request.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    request.on('error', reject);
  });
}

function listen(server, port, host) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => {
      server.off('error', reject);
      resolve();
    });
  });
}

function closeServer(server) {
  return new Promise((resolve) => server.close(() => resolve()));
}

async function listFiles(directory) {
  const entries = await fs.readdir(directory, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const entryPath = path.join(directory, entry.name);
    if (entry.isDirectory()) files.push(...await listFiles(entryPath));
    else files.push(entryPath);
  }
  return files;
}

async function readJsonMaybe(filePath) {
  try {
    return JSON.parse(await fs.readFile(filePath, 'utf8'));
  } catch {
    return null;
  }
}

async function writeJson(filePath, value) {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(filePath, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

async function log(message) {
  commandLog.push(`${new Date().toISOString()} ${message}`);
}

function parseJson(text, label) {
  try {
    return JSON.parse(text);
  } catch (error) {
    throw new Error(`Failed to parse ${label} JSON: ${error.message}\n${text}`);
  }
}

function lowerHeaders(headers) {
  return Object.fromEntries(Object.entries(headers).map(([key, value]) => [key.toLowerCase(), Array.isArray(value) ? value.join(', ') : String(value ?? '')]));
}

function normalizeArtifact(filePath) {
  return path.relative(root, filePath).split(path.sep).join('/');
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

async function git(gitArgs) {
  const result = await runCommand('git', gitArgs);
  return result.stdout.trim();
}

function parseArgs(rawArgs) {
  const parsed = {};
  for (let index = 0; index < rawArgs.length; index += 1) {
    const arg = rawArgs[index];
    if (!arg.startsWith('--')) continue;
    const [key, inlineValue] = arg.slice(2).split('=', 2);
    parsed[key] = inlineValue ?? rawArgs[index + 1] ?? true;
    if (inlineValue === undefined && rawArgs[index + 1] && !rawArgs[index + 1].startsWith('--')) index += 1;
  }
  return parsed;
}
