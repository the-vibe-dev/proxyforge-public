import { strict as assert } from 'node:assert';
import { spawn } from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';

const artifactDir = path.resolve('.gitignored/test-artifacts/automation-service-smoke');
await fs.mkdir(artifactDir, { recursive: true });

const directDir = path.join(artifactDir, 'direct-service');
const direct = await runNodeJson([
  'scripts/proxyforge-automation-service.mjs',
  'smoke',
  '--service-dir',
  directDir,
  '--duration-ms',
  '650',
  '--interval-ms',
  '100',
]);
assert.equal(direct.status, 0, direct.stderr || direct.stdout);
assert.equal(direct.json.kind, 'proxyforge-automation-service-control-result');
assert.equal(direct.json.action, 'smoke');
assert.equal(direct.json.status, 'passed');
assert.equal(direct.json.data.package.kind, 'proxyforge-automation-service-installed-host-smoke-package');
assert.equal(direct.json.data.package.productionReady, true);
assert(Object.values(direct.json.data.package.requirements).every(Boolean), 'direct installed-host service smoke requirements should pass');
assert.match(JSON.stringify(direct.json), /serviceStarted|statusProbeCovered|stopCovered|durableStateFileCovered|jsonlLogCovered|schedulerTickCovered/);
assert.match(JSON.stringify(direct.json), /Authorization: Bearer automation-service-smoke-token|session=automation-service-smoke-session|automation-service-smoke-key/);
assert.equal((await pathExists(path.join(directDir, 'status.json'))), true);
assert.equal((await pathExists(path.join(directDir, 'scheduler-state.json'))), true);
assert.equal((await pathExists(path.join(directDir, 'service-log.jsonl'))), true);

const agentDir = path.join(artifactDir, 'agent-service');
const agentOut = path.join(artifactDir, 'agent-service-smoke-package.json');
const agent = await runNodeJson([
  'scripts/proxyforge-agent.mjs',
  'automation-service-smoke',
  '--service-dir',
  agentDir,
  '--duration-ms',
  '650',
  '--interval-ms',
  '100',
  '--execute',
  '--out',
  agentOut,
  '--json',
]);
assert.equal(agent.status, 0, agent.stderr || agent.stdout);
assert.equal(agent.json.kind, 'proxyforge-agent-result');
assert.equal(agent.json.command, 'automation-service-smoke');
assert.equal(agent.json.status, 'completed');
assert.equal(agent.json.safety.secretHandling, 'execution-full-fidelity-secrets-preserved');
assert.equal(agent.json.safety.redacted, false);
assert(agent.json.safety.gates.includes('installed-host-service-smoke'));
assert.equal(agent.json.data.smokePackage.kind, 'proxyforge-automation-service-installed-host-smoke-package');
assert.equal(agent.json.data.smokePackage.productionReady, true);
assert(Object.values(agent.json.data.smokePackage.requirements).every(Boolean), 'agent service smoke package requirements should pass');
assert.match(JSON.stringify(agent.json), /automation-scheduler-tick|pid-status-stop-lifecycle|durable-state-log|redact-only-during-report-export/);
assert.match(JSON.stringify(agent.json), /Authorization: Bearer automation-service-smoke-token|session=automation-service-smoke-session|automation-service-smoke-key/);
assert.equal((await pathExists(agentOut)), true);

console.log('automation-service-smoke: verified installed-host service start/status/stop smoke, durable state/logs, agent command, and full-fidelity secret boundary');

function runNodeJson(args) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, args, {
      cwd: process.cwd(),
      env: {
        ...process.env,
        FORCE_COLOR: '0',
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk.toString(); });
    child.stderr.on('data', (chunk) => { stderr += chunk.toString(); });
    child.on('close', (status) => {
      resolve({
        status: status ?? 1,
        stdout,
        stderr,
        json: tryJson(stdout),
      });
    });
  });
}

async function pathExists(filePath) {
  try {
    await fs.access(filePath);
    return true;
  } catch {
    return false;
  }
}

function tryJson(value) {
  try {
    return JSON.parse(value);
  } catch {
    return null;
  }
}
