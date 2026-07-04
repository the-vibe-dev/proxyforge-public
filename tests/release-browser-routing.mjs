import { strict as assert } from 'node:assert';
import { spawn } from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';

const outDir = path.join(process.cwd(), 'test-results', 'release-browser-routing-test');
const result = await runNode(['dist-electron/releaseBrowserRoutingSmoke.js', '--out-dir', outDir]);
const summary = JSON.parse(result.stdout);

assert.equal(summary.kind, 'proxyforge-release-browser-routing-smoke');

if (summary.status === 'blocked') {
  assert.notEqual(result.status, 0, 'blocked browser routing proof should require an explicit host with Chromium/Chrome/Edge');
  console.log('release-browser-routing: blocked because no Chromium/Chrome/Edge host browser was available');
} else {
  assert.equal(result.status, 0, result.stderr);
  assert.equal(summary.status, 'passed');
  assert.equal(summary.proxy.browserCaptured, true);
  assert.equal(summary.browser.proxyConfigured, true);
  assert.match(summary.browser.name, /chrom|edge/i);
  assert.equal(summary.browser.certificateMode, 'ignore-errors-flag');
  assert.equal(summary.browser.trustStoreConfigured, false);
  for (const artifact of summary.artifacts) {
    assert.equal((await fs.stat(artifact.path)).isFile(), true, `${artifact.path} should exist`);
    assert(artifact.sizeBytes > 0, `${artifact.path} should not be empty`);
  }
  console.log('release-browser-routing: verified managed browser traffic routed through ProxyForge');
}

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
