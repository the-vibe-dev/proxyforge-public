import { strict as assert } from 'node:assert';
import { spawn } from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';

const outDir = path.join(process.cwd(), 'test-results', 'release-runtime-workflow-test');
const result = await runNode(['dist-electron/releaseWorkflowSmoke.js', '--out-dir', outDir]);

assert.equal(result.status, 0, result.stderr);
const summary = JSON.parse(result.stdout);
assert.equal(summary.kind, 'proxyforge-release-runtime-workflow-smoke');
assert.equal(summary.status, 'passed');
assert.equal(summary.proxy.httpCaptured, true);
assert.equal(summary.proxy.httpsCaptured, true);
assert.equal(summary.certificate.ready, true);
assert.match(summary.certificate.fingerprintSha256, /^([0-9A-F]{2}:){31}[0-9A-F]{2}$/);
assert.equal(summary.oast.interactionCount, 3);
assert.deepEqual(new Set(summary.oast.protocols), new Set(['http', 'dns', 'smtp']));
assert.equal(summary.oast.tokensPreserved, true);
assert.equal(summary.reports.count, 5);
assert.deepEqual(new Set(summary.reports.formats), new Set(['json', 'markdown', 'html', 'pdf', 'bundle']));
assert.equal(summary.reports.operationalSecretsPreserved, true);
assert.equal(summary.reports.reportSecretsRedacted, true);
for (const artifact of summary.reports.artifactStats) {
  assert.equal((await fs.stat(artifact.path)).isFile(), true, `${artifact.path} should exist`);
  assert(artifact.sizeBytes > 0, `${artifact.path} should not be empty`);
}

console.log('release-runtime-workflow: verified proxy, HTTPS MITM, OAST, reports, and secret boundary');

function runNode(args) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, args, {
      cwd: process.cwd(),
      env: process.env,
      windowsHide: true,
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => {
      stdout += chunk.toString();
    });
    child.stderr.on('data', (chunk) => {
      stderr += chunk.toString();
    });
    child.on('error', reject);
    child.on('close', (status) => {
      resolve({ status, stdout, stderr });
    });
  });
}
