import { strict as assert } from 'node:assert';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';

const root = process.cwd();
const agentScript = path.join(root, 'scripts', 'proxyforge-agent.mjs');
const agentSource = await fs.readFile(agentScript, 'utf8');
const electronMain = await fs.readFile(path.join(root, 'electron', 'main.ts'), 'utf8');
const reportEngine = await fs.readFile(path.join(root, 'electron', 'reportEngine.ts'), 'utf8');

assert.match(agentSource, /ensurePrivateDir\(sessionDir,\s*\{\s*hardenExisting:\s*true\s*\}\)/, 'MITM session storage should explicitly harden app-owned existing directories');
assert.match(agentSource, /if \(createdRoot\)[\s\S]*chmodCreatedDirectoryTree/, 'agent directory helper should chmod only newly-created directory trees by default');
assert.match(electronMain, /writeAppPrivateFile[\s\S]*hardenExisting:\s*true/, 'desktop app-owned state writer should harden private state directories');
assert.match(electronMain, /writeUserExportFile[\s\S]*hardenExisting:\s*false/, 'desktop user export writer should preserve existing selected parent directories');
assert.match(electronMain, /exportProjectSnapshot[\s\S]*writeUserExportFile/, 'project export should use the user export writer');
assert.match(electronMain, /exportSignedAuditPackage[\s\S]*writeUserExportFile/, 'signed audit export should use the user export writer');
assert.match(reportEngine, /const createdRoot = await fs\.mkdir/, 'report engine should distinguish newly-created output directories');
assert.doesNotMatch(reportEngine, /await fs\.mkdir\(dirPath,[\s\S]{0,140}await chmodIfPossible\(dirPath,\s*SECURE_REPORT_DIR_MODE\)/, 'report engine must not chmod an existing report output directory unconditionally');

if (process.platform !== 'win32') {
  const tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'proxyforge-private-output-'));
  await assertAgentExportPreservesParentMode(path.join(tempRoot, 'shared-0775'), 0o775);
  await assertAgentExportPreservesParentMode(path.join(tempRoot, 'shared-0755'), 0o755);
  await assertAgentExportCreatesPrivateParents(path.join(tempRoot, 'new-parent', 'nested', 'export.json'));
}

console.log('private-output-permissions: verified export parents are preserved and created output files remain private');

async function assertAgentExportPreservesParentMode(parentDir, expectedMode) {
  await fs.mkdir(parentDir, { recursive: true });
  await fs.chmod(parentDir, expectedMode);
  const before = await unixMode(parentDir);
  const outPath = path.join(parentDir, 'automation-ci-export.json');
  execFileSync(process.execPath, [
    agentScript,
    'automation-ci-export',
    '--out',
    outPath,
    '--json',
  ], { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  const after = await unixMode(parentDir);
  const fileMode = await unixMode(outPath);
  assert.equal(before, expectedMode, `${parentDir} test setup should start at ${octal(expectedMode)}, got ${octal(before)}`);
  assert.equal(after, before, `${parentDir} parent mode should be preserved`);
  assert.equal(fileMode, 0o600, `${outPath} should be private`);
}

async function assertAgentExportCreatesPrivateParents(outPath) {
  execFileSync(process.execPath, [
    agentScript,
    'automation-ci-export',
    '--out',
    outPath,
    '--json',
  ], { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  assert.equal(await unixMode(path.dirname(outPath)), 0o700, 'new export parent should be private');
  assert.equal(await unixMode(path.dirname(path.dirname(outPath))), 0o700, 'new intermediate export parent should be private');
  assert.equal(await unixMode(outPath), 0o600, 'new export file should be private');
}

async function unixMode(filePath) {
  return (await fs.stat(filePath)).mode & 0o777;
}

function octal(mode) {
  return `0${mode.toString(8)}`;
}
