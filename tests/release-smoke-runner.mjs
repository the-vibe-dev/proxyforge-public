import { strict as assert } from 'node:assert';
import { spawn } from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';

const outPath = path.resolve('test-results/release-smoke-plan-test.json');
const result = await run(process.execPath, [
  'scripts/release-smoke.mjs',
  '--plan',
  '--platform',
  'linux',
  '--out',
  outPath,
]);

assert.equal(result.status, 0, result.stderr || result.stdout);
const envelope = JSON.parse(await fs.readFile(outPath, 'utf8'));
const releaseSmokeScript = await fs.readFile(path.resolve('scripts/release-smoke.mjs'), 'utf8');
assert.equal(envelope.kind, 'proxyforge-release-smoke-result');
assert.equal(envelope.schemaVersion, 1);
assert.equal(envelope.planOnly, true);
assert.equal(envelope.status, 'planned');
assert.equal(envelope.platform, 'linux');
assert(envelope.linux.artifacts.includes('release/ProxyForge-0.1.0-alpha.1.AppImage'));
assert.match(envelope.linux.smoke, /packaged agent CLI|external-cwd agent|PROXYFORGE_RELEASE_SMOKE|xvfb-run/i);
assert.match(envelope.windows.smoke, /packaged agent CLI|external-cwd agent|Windows host|PROXYFORGE_RELEASE_SMOKE/i);
assert.equal(typeof envelope.capabilities.xvfbRun, 'boolean');
assert.match(releaseSmokeScript, /'search-index'/, 'packaged agent CLI smoke should require search-index capability');
assert.match(releaseSmokeScript, /'proxy-import'/, 'packaged agent CLI smoke should require proxy-import capability');
assert.match(releaseSmokeScript, /'project-store-status'/, 'packaged agent CLI smoke should require Project Store status capability');
assert.match(releaseSmokeScript, /'project-store-recover'/, 'packaged agent CLI smoke should require Project Store recovery capability');
assert.match(releaseSmokeScript, /'project-store-backup'/, 'packaged agent CLI smoke should require Project Store backup capability');
assert.match(releaseSmokeScript, /'crawl-run'/, 'packaged agent CLI smoke should require crawl-run capability');
assert.match(releaseSmokeScript, /'content-discovery-run'/, 'packaged agent CLI smoke should require content-discovery-run capability');
assert.match(releaseSmokeScript, /'target-access-review'/, 'packaged agent CLI smoke should require target-access-review capability');
assert.match(releaseSmokeScript, /'target-map-compare'/, 'packaged agent CLI smoke should require target-map-compare capability');
assert.match(releaseSmokeScript, /'sequencer-analyze'/, 'packaged agent CLI smoke should require Sequencer capability');
assert.match(releaseSmokeScript, /'insertion-points'/, 'packaged agent CLI smoke should require insertion point capability');
assert.match(releaseSmokeScript, /'websocket-list'/, 'packaged agent CLI smoke should require WebSocket inventory capability');
assert.match(releaseSmokeScript, /'websocket-replay'/, 'packaged agent CLI smoke should require WebSocket replay capability');
assert.match(releaseSmokeScript, /'websocket-fuzz'/, 'packaged agent CLI smoke should require WebSocket fuzz capability');
assert.match(releaseSmokeScript, /'websocket-transcript-export'/, 'packaged agent CLI smoke should require WebSocket transcript capability');
assert.match(releaseSmokeScript, /'scanner-retest'/, 'packaged agent CLI smoke should require scanner retest capability');
assert.match(releaseSmokeScript, /'scanner-evidence-export'/, 'packaged agent CLI smoke should require scanner evidence export capability');
assert.match(releaseSmokeScript, /'anvil-plan'/, 'packaged agent CLI smoke should require Anvil plan capability');
assert.match(releaseSmokeScript, /'anvil-run'/, 'packaged agent CLI smoke should require Anvil run capability');
assert.match(releaseSmokeScript, /'anvil-package-export'/, 'packaged agent CLI smoke should require Anvil package export capability');
assert.match(releaseSmokeScript, /requiredCapabilityCount/, 'packaged agent CLI smoke should report required capability count');
assert.match(releaseSmokeScript, /runPackagedExternalAgentCliCheck/, 'release smoke should prove packaged external-cwd agent invocation');

console.log('release-smoke-runner: validated plan output and platform smoke metadata');

function run(command, args) {
  return new Promise((resolve) => {
    const child = spawn(command, args, { cwd: process.cwd(), windowsHide: true });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => {
      stdout += chunk.toString();
    });
    child.stderr.on('data', (chunk) => {
      stderr += chunk.toString();
    });
    child.on('close', (status) => {
      resolve({ status, stdout, stderr });
    });
  });
}
