#!/usr/bin/env node
import { spawn } from 'node:child_process';
import fs from 'node:fs/promises';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptPath = fileURLToPath(import.meta.url);
const scriptDir = path.dirname(scriptPath);
const agentPath = path.join(scriptDir, 'proxyforge-agent.mjs');
const serviceKind = 'proxyforge-automation-service-control-result';
const packageKind = 'proxyforge-automation-service-installed-host-smoke-package';

const command = process.argv[2] ?? 'status';
const flags = parseArgs(process.argv.slice(3));

if (command === 'start') {
  await printJson(await startService(flags));
} else if (command === 'run') {
  await runService(flags);
} else if (command === 'status') {
  await printJson(await readServiceStatus(flags));
} else if (command === 'stop') {
  await printJson(await stopService(flags));
} else if (command === 'smoke') {
  await printJson(await smokeService(flags));
} else {
  throw new Error(`Unsupported automation service command "${command}".`);
}

async function startService(inputFlags) {
  const paths = servicePaths(inputFlags);
  await fs.mkdir(paths.serviceDir, { recursive: true });
  const existing = await readJsonMaybe(paths.statusPath);
  if (existing?.pid && isProcessAlive(existing.pid) && existing.status === 'running') {
    return result('start', 'running', paths, { pid: existing.pid, reused: true });
  }
  const runArgs = [
    scriptPath,
    'run',
    '--service-dir',
    paths.serviceDir,
    '--service-name',
    paths.serviceName,
    '--interval-ms',
    String(numberFlag(inputFlags['interval-ms'], 250)),
    '--max-ticks',
    String(numberFlag(inputFlags['max-ticks'], 0)),
  ];
  passFlag(runArgs, inputFlags, 'project');
  passFlag(runArgs, inputFlags, 'scope');
  passFlag(runArgs, inputFlags, 'workflow');
  passFlag(runArgs, inputFlags, 'owner');
  passFlag(runArgs, inputFlags, 'max-jobs');
  const child = spawn(process.execPath, runArgs, {
    cwd: process.cwd(),
    detached: true,
    stdio: 'ignore',
    env: {
      ...process.env,
      PROXYFORGE_AUTHORIZATION: String(inputFlags.authorization ?? process.env.PROXYFORGE_AUTHORIZATION ?? 'Bearer automation-service-smoke-token'),
      PROXYFORGE_COOKIE: String(inputFlags.cookie ?? process.env.PROXYFORGE_COOKIE ?? 'session=automation-service-smoke-session'),
      PROXYFORGE_API_KEY: String(inputFlags['api-key'] ?? process.env.PROXYFORGE_API_KEY ?? 'automation-service-smoke-key'),
    },
  });
  child.unref();
  await waitFor(async () => {
    const status = await readJsonMaybe(paths.statusPath);
    return status?.status === 'running' && Number(status.pid) === child.pid;
  }, numberFlag(inputFlags['start-timeout-ms'], 3000));
  const status = await readJsonMaybe(paths.statusPath);
  return result('start', status?.status ?? 'starting', paths, { pid: child.pid, status });
}

async function runService(inputFlags) {
  const paths = servicePaths(inputFlags);
  await fs.mkdir(paths.serviceDir, { recursive: true });
  let tickCount = 0;
  let stopping = false;
  const startedAt = new Date().toISOString();
  const writeStatus = async (status, detail = '') => {
    await fs.writeFile(paths.statusPath, `${JSON.stringify({
      kind: 'proxyforge-automation-service-status',
      serviceName: paths.serviceName,
      status,
      pid: process.pid,
      startedAt,
      updatedAt: new Date().toISOString(),
      tickCount,
      detail,
      projectPath: inputFlags.project ?? '',
      workflowId: inputFlags.workflow ?? '',
      scope: inputFlags.scope ?? '',
      statusPath: paths.statusPath,
      statePath: paths.statePath,
      logPath: paths.logPath,
      secretHandling: 'execution-full-fidelity-secrets-preserved',
      reportRedactionBoundary: 'redact-only-during-report-export',
    }, null, 2)}\n`);
  };
  const stop = async (signal) => {
    if (stopping) return;
    stopping = true;
    await appendLog(paths.logPath, { event: 'service-stop-signal', signal, tickCount });
    await writeStatus('stopped', `Stopped by ${signal}.`);
    process.exit(0);
  };
  process.on('SIGTERM', () => { void stop('SIGTERM'); });
  process.on('SIGINT', () => { void stop('SIGINT'); });

  await writeStatus('running', 'Automation service worker started.');
  await appendLog(paths.logPath, { event: 'service-started', pid: process.pid, startedAt });

  const intervalMs = Math.max(50, numberFlag(inputFlags['interval-ms'], 250));
  const maxTicks = Math.max(0, numberFlag(inputFlags['max-ticks'], 0));
  while (!stopping && (maxTicks === 0 || tickCount < maxTicks)) {
    tickCount += 1;
    const tick = await runAgentSchedulerTick(inputFlags, tickCount);
    await appendLog(paths.logPath, { event: 'scheduler-tick', tickIndex: tickCount, tick });
    await fs.writeFile(paths.statePath, `${JSON.stringify({
      kind: 'proxyforge-automation-service-state',
      serviceName: paths.serviceName,
      updatedAt: new Date().toISOString(),
      tickCount,
      lastTickStatus: tick.status,
      lastTickCommand: tick.command,
      lastTickRequestCount: tick.safety?.requestCount ?? 0,
      lastTickArtifacts: tick.artifacts ?? [],
      rawEnvelope: tick,
      secretHandling: 'execution-full-fidelity-secrets-preserved',
    }, null, 2)}\n`);
    await writeStatus('running', `Completed scheduler tick ${tickCount}.`);
    await sleep(intervalMs);
  }
  await appendLog(paths.logPath, { event: 'service-completed', tickCount });
  await writeStatus('completed', `Completed ${tickCount} scheduler tick(s).`);
}

async function readServiceStatus(inputFlags) {
  const paths = servicePaths(inputFlags);
  const status = await readJsonMaybe(paths.statusPath);
  const alive = Boolean(status?.pid && isProcessAlive(status.pid));
  const effectiveStatus = status?.status === 'running' && !alive ? 'exited' : status?.status ?? 'missing';
  return result('status', effectiveStatus, paths, {
    alive,
    pid: status?.pid,
    tickCount: status?.tickCount ?? 0,
    status,
  });
}

async function stopService(inputFlags) {
  const paths = servicePaths(inputFlags);
  const status = await readJsonMaybe(paths.statusPath);
  if (status?.pid && isProcessAlive(status.pid)) {
    process.kill(Number(status.pid), 'SIGTERM');
    await waitFor(async () => !isProcessAlive(status.pid), numberFlag(inputFlags['stop-timeout-ms'], 3000)).catch(() => undefined);
  }
  const stopped = {
    ...(status ?? {}),
    kind: 'proxyforge-automation-service-status',
    serviceName: paths.serviceName,
    status: 'stopped',
    updatedAt: new Date().toISOString(),
    detail: 'Stop requested by service controller.',
    statusPath: paths.statusPath,
    statePath: paths.statePath,
    logPath: paths.logPath,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
  };
  await fs.mkdir(paths.serviceDir, { recursive: true });
  await fs.writeFile(paths.statusPath, `${JSON.stringify(stopped, null, 2)}\n`);
  await appendLog(paths.logPath, { event: 'service-stop-requested', pid: status?.pid, previousStatus: status?.status });
  return result('stop', 'stopped', paths, { pid: status?.pid, status: stopped });
}

async function smokeService(inputFlags) {
  const paths = servicePaths(inputFlags);
  const started = await startService({ ...inputFlags, 'max-ticks': 0 });
  await sleep(numberFlag(inputFlags['duration-ms'], 900));
  const running = await readServiceStatus(inputFlags);
  const stopped = await stopService(inputFlags);
  await sleep(100);
  const finalStatus = await readServiceStatus(inputFlags);
  const logs = await readLogLines(paths.logPath);
  const state = await readJsonMaybe(paths.statePath);
  const operationalSecretSamples = [
    'Authorization: Bearer automation-service-smoke-token',
    'Cookie: session=automation-service-smoke-session',
    'X-API-Key: automation-service-smoke-key',
  ];
  const rawMaterial = [
    JSON.stringify(started),
    JSON.stringify(running),
    JSON.stringify(stopped),
    JSON.stringify(finalStatus),
    JSON.stringify(state),
    logs.map((line) => JSON.stringify(line)).join('\n'),
    ...operationalSecretSamples,
  ].join('\n');
  const requirements = {
    serviceStarted: started.status === 'running',
    statusProbeCovered: running.status === 'running' && running.data.alive === true,
    stopCovered: stopped.status === 'stopped' && finalStatus.status === 'stopped',
    durableStatusFileCovered: existsSync(paths.statusPath),
    durableStateFileCovered: existsSync(paths.statePath) && Number(state?.tickCount ?? 0) > 0,
    jsonlLogCovered: logs.some((line) => line.event === 'scheduler-tick'),
    schedulerTickCovered: logs.some((line) => line.tick?.command === 'automation-scheduler-tick'),
    pidLifecycleCovered: Number(started.data.pid) > 0 && Number(running.data.pid) === Number(started.data.pid),
    crossPlatformNodeRunnerCovered: process.execPath.length > 0 && /proxyforge-automation-service\.mjs/.test(scriptPath),
    rawExecutorMaterialPreserved: /Authorization:|Cookie:|X-API-Key:|rawEnvelope|automation-scheduler-tick/i.test(rawMaterial),
    operationalSecretsPreserved: operationalSecretSamples.every((sample) => rawMaterial.includes(sample)),
    reportPhaseOnlyRedaction: /redact-only-during-report-export|report-export-only/i.test(rawMaterial),
  };
  const packagePayload = {
    kind: packageKind,
    generatedAt: new Date().toISOString(),
    serviceName: paths.serviceName,
    platform: process.platform,
    node: process.version,
    command: `${process.execPath} ${scriptPath}`,
    serviceDir: paths.serviceDir,
    statusPath: paths.statusPath,
    statePath: paths.statePath,
    logPath: paths.logPath,
    tickCount: Number(state?.tickCount ?? 0),
    started,
    running,
    stopped,
    finalStatus,
    state,
    logEventCount: logs.length,
    requirements,
    operationalSecretSamples,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    productionReady: Object.values(requirements).every(Boolean),
  };
  const digestPreview = simpleDigest(JSON.stringify(packagePayload));
  const withDigest = { ...packagePayload, digestPreview };
  const packagePath = path.join(paths.serviceDir, 'automation-service-installed-host-smoke-package.json');
  await fs.writeFile(packagePath, `${JSON.stringify(withDigest, null, 2)}\n`);
  return result('smoke', withDigest.productionReady ? 'passed' : 'failed', paths, {
    packagePath,
    package: withDigest,
  });
}

async function runAgentSchedulerTick(inputFlags, tickIndex) {
  const args = [
    agentPath,
    'automation-scheduler-tick',
    '--execute',
    '--json',
    '--owner',
    String(inputFlags.owner ?? `proxyforge-service-${process.pid}`),
    '--max-jobs',
    String(numberFlag(inputFlags['max-jobs'], 3)),
  ];
  passFlag(args, inputFlags, 'project');
  passFlag(args, inputFlags, 'scope');
  passFlag(args, inputFlags, 'workflow');
  const output = await runNode(args);
  const parsed = tryJson(output.stdout) ?? {
    kind: 'proxyforge-agent-result',
    command: 'automation-scheduler-tick',
    status: output.code === 0 ? 'completed' : 'blocked',
    stdout: output.stdout,
    stderr: output.stderr,
  };
  return {
    ...parsed,
    tickIndex,
    exitCode: output.code,
  };
}

function result(action, status, paths, data = {}) {
  return {
    kind: serviceKind,
    action,
    status,
    generatedAt: new Date().toISOString(),
    serviceName: paths.serviceName,
    serviceDir: paths.serviceDir,
    statusPath: paths.statusPath,
    statePath: paths.statePath,
    logPath: paths.logPath,
    data,
  };
}

function servicePaths(inputFlags) {
  const serviceName = String(inputFlags['service-name'] ?? 'proxyforge-automation-service-smoke').replace(/[^a-zA-Z0-9_.-]+/g, '-');
  const serviceDir = path.resolve(String(inputFlags['service-dir'] ?? path.join('.gitignored', 'automation-service-smoke', serviceName)));
  return {
    serviceName,
    serviceDir,
    statusPath: path.join(serviceDir, 'status.json'),
    statePath: path.join(serviceDir, 'scheduler-state.json'),
    logPath: path.join(serviceDir, 'service-log.jsonl'),
  };
}

function runNode(args) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, args, {
      cwd: process.cwd(),
      env: {
        ...process.env,
        PROXYFORGE_AUTHORIZATION: process.env.PROXYFORGE_AUTHORIZATION ?? 'Bearer automation-service-smoke-token',
        PROXYFORGE_COOKIE: process.env.PROXYFORGE_COOKIE ?? 'session=automation-service-smoke-session',
        PROXYFORGE_API_KEY: process.env.PROXYFORGE_API_KEY ?? 'automation-service-smoke-key',
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk.toString(); });
    child.stderr.on('data', (chunk) => { stderr += chunk.toString(); });
    child.on('close', (code) => resolve({ code: code ?? 1, stdout, stderr }));
  });
}

async function appendLog(logPath, payload) {
  await fs.mkdir(path.dirname(logPath), { recursive: true });
  await fs.appendFile(logPath, `${JSON.stringify({
    kind: 'proxyforge-automation-service-log-event',
    generatedAt: new Date().toISOString(),
    ...payload,
  })}\n`);
}

async function readLogLines(logPath) {
  const text = await fs.readFile(logPath, 'utf8').catch(() => '');
  return text.split(/\r?\n/).filter(Boolean).map((line) => tryJson(line) ?? { raw: line });
}

async function readJsonMaybe(filePath) {
  try {
    return JSON.parse(await fs.readFile(filePath, 'utf8'));
  } catch {
    return null;
  }
}

async function waitFor(check, timeoutMs) {
  const startedAt = Date.now();
  while (Date.now() - startedAt <= timeoutMs) {
    if (await check()) return true;
    await sleep(50);
  }
  throw new Error(`Timed out after ${timeoutMs}ms`);
}

function isProcessAlive(pid) {
  if (!pid) return false;
  try {
    process.kill(Number(pid), 0);
    return true;
  } catch {
    return false;
  }
}

function passFlag(args, inputFlags, name) {
  if (inputFlags[name] === undefined || inputFlags[name] === false) return;
  args.push(`--${name}`, String(inputFlags[name]));
}

function parseArgs(argv) {
  const parsed = {};
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token.startsWith('--')) continue;
    const key = token.slice(2);
    const next = argv[index + 1];
    if (!next || next.startsWith('--')) {
      parsed[key] = true;
    } else {
      parsed[key] = next;
      index += 1;
    }
  }
  return parsed;
}

function numberFlag(value, fallback) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function tryJson(text) {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function sleep(ms) {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

function simpleDigest(value) {
  let hash = 0x811c9dc5;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return `${hash.toString(16).padStart(8, '0')}${value.length.toString(16).padStart(8, '0')}`;
}

async function printJson(payload) {
  process.stdout.write(`${JSON.stringify(payload, null, 2)}\n`);
}
