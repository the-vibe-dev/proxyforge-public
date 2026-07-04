#!/usr/bin/env node
import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const root = process.cwd();
const args = parseArgs(process.argv.slice(2));
const evidenceDir = path.resolve(root, args['evidence-dir'] ?? 'test-results');
const releaseDir = path.resolve(root, args['release-dir'] ?? 'release');
const packageJson = readJson(path.join(root, 'package.json'));
const releaseTag = args.tag ?? `v${packageJson.version}`;
const failures = [];
const checks = [];

check('package version matches release tag', () => {
  const expectedVersion = releaseTag.replace(/^v/, '');
  assert(packageJson.version === expectedVersion, `package.json version must be ${expectedVersion}; got ${packageJson.version}`);
});

const headCommit = git(['rev-parse', 'HEAD']);
const tagCommit = git(['rev-parse', `${releaseTag}^{}`]);
check('release tag peels to checked-out commit', () => {
  assert(headCommit, 'git HEAD is unavailable; publish preflight must run in a git checkout');
  assert(tagCommit, `release tag ${releaseTag} is unavailable in this checkout`);
  assert(tagCommit === headCommit, `release tag ${releaseTag} must point at checked-out commit ${headCommit}; got ${tagCommit}`);
});

const liveSummaryPath = path.join(evidenceDir, 'live-validation-summary.json');
const liveSummary = maybeReadJson(liveSummaryPath);
const requiredLiveArtifacts = [
  'test-results/live-agent-validation',
  'test-results/live-mitm-validation',
  'test-results/live-replay-validation',
  'test-results/live-scanner-validation',
  'test-results/live-report-validation',
  'test-results/windows-live-validation',
];
check('live validation summary exists and matches commit', () => {
  assert(liveSummary, `missing ${relative(liveSummaryPath)}`);
  assert(liveSummary.version === packageJson.version, `live summary version must be ${packageJson.version}; got ${liveSummary.version}`);
  assert(liveSummary.commit === headCommit, `live summary commit must be ${headCommit}; got ${liveSummary.commit}`);
  assert(liveSummary.tag === releaseTag, `live summary tag must be ${releaseTag}; got ${liveSummary.tag}`);
  assert(liveSummary.releaseDecision === 'GO', `live summary releaseDecision must be GO; got ${liveSummary.releaseDecision}`);
});

check('live validation artifact paths exist', () => {
  assert(Array.isArray(liveSummary?.artifacts), 'live summary artifacts must be an array');
  for (const requiredArtifact of requiredLiveArtifacts) {
    assert(liveSummary.artifacts.includes(requiredArtifact), `live summary artifacts must include ${requiredArtifact}`);
  }
  for (const artifact of liveSummary.artifacts) {
    assert(typeof artifact === 'string' && artifact.trim(), `live summary artifact path must be a non-empty string; got ${JSON.stringify(artifact)}`);
    const artifactPath = path.resolve(root, artifact);
    assert(pathInside(artifactPath, evidenceDir), `live summary artifact must stay under ${relative(evidenceDir)}; got ${artifact}`);
    assert(fs.existsSync(artifactPath), `live summary artifact is missing: ${artifact}`);
    const stat = fs.statSync(artifactPath);
    if (stat.isDirectory()) {
      assert(directoryHasFiles(artifactPath), `live summary artifact directory is empty: ${artifact}`);
    }
  }
});

for (const [lane, required] of Object.entries({
  linuxSourceValidation: ['mitm', 'httpsMitm', 'replay', 'scanner', 'oast', 'reportExport', 'agentInterface'],
  windowsLiveValidation: ['mitm', 'httpsMitm', 'replay', 'scanner', 'reportExport', 'agentInterface'],
})) {
  check(`${lane} required live lanes passed`, () => {
    const group = liveSummary?.[lane];
    assert(group && typeof group === 'object', `live summary missing ${lane}`);
    for (const key of required) {
      assert(isPass(group[key]), `${lane}.${key} must pass; got ${JSON.stringify(group[key])}`);
    }
  });
}

check('Windows GUI smoke is passed or explicitly skipped', () => {
  const guiSmoke = liveSummary?.windowsLiveValidation?.guiSmoke;
  assert(isPass(guiSmoke) || guiSmoke === 'skipped-with-reason', `windowsLiveValidation.guiSmoke must pass or be skipped-with-reason; got ${JSON.stringify(guiSmoke)}`);
});

check('Windows live-validation log exists', () => {
  const logPath = path.join(evidenceDir, 'windows-live-validation', 'windows-live-validation.log');
  assert(fs.existsSync(logPath), `missing ${relative(logPath)}`);
  assert(fs.statSync(logPath).size > 0, `${relative(logPath)} is empty`);
});

for (const platform of ['linux', 'windows']) {
  const fusePath = path.join(evidenceDir, `electron-fuse-${platform}.json`);
  const licensePath = path.join(evidenceDir, `release-license-${platform}.txt`);
  const smokePath = path.join(evidenceDir, `release-smoke-${platform}.json`);
  const fuseReceipt = maybeReadJson(fusePath);
  const smokeReceipt = maybeReadJson(smokePath);

  check(`${platform} Electron fuse receipt passed`, () => {
    assert(fuseReceipt, `missing ${relative(fusePath)}`);
    assert(fuseReceipt.status === 'passed', `${relative(fusePath)} status must be passed; got ${fuseReceipt.status}`);
    assert(Array.isArray(fuseReceipt.mismatches) && fuseReceipt.mismatches.length === 0, `${relative(fusePath)} must have zero mismatches`);
  });

  check(`${platform} packaged license receipt exists`, () => {
    assert(fs.existsSync(licensePath), `missing ${relative(licensePath)}`);
    const text = fs.readFileSync(licensePath, 'utf8');
    assert(/verified packaged license receipts/i.test(text), `${relative(licensePath)} must contain packaged license verification output`);
  });

  check(`${platform} native release smoke passed`, () => {
    assert(smokeReceipt, `missing ${relative(smokePath)}`);
    assert(smokeReceipt.platform === platform, `${relative(smokePath)} platform must be ${platform}; got ${smokeReceipt.platform}`);
    assert(smokeReceipt.status === 'passed', `${relative(smokePath)} status must be passed; got ${smokeReceipt.status}`);
    assert(Number(smokeReceipt.failedChecks ?? 0) === 0, `${relative(smokePath)} must have zero failed checks`);
    assert(Number(smokeReceipt.blockedChecks ?? 0) === 0, `${relative(smokePath)} must have zero blocked checks`);
  });
}

const requiredArtifacts = [
  `ProxyForge-${packageJson.version}.AppImage`,
  `proxyforge_${packageJson.version}_amd64.deb`,
  `ProxyForge Setup ${packageJson.version}.exe`,
  `ProxyForge ${packageJson.version}.exe`,
];
check('release artifacts match SHA256SUMS', () => {
  const sumsPath = path.join(releaseDir, 'SHA256SUMS.txt');
  assert(fs.existsSync(sumsPath), `missing ${relative(sumsPath)}`);
  const sums = parseSha256Sums(fs.readFileSync(sumsPath, 'utf8'));
  for (const artifact of requiredArtifacts) {
    const artifactPath = path.join(releaseDir, artifact);
    assert(fs.existsSync(artifactPath), `missing ${relative(artifactPath)}`);
    assert(sums.has(artifact), `SHA256SUMS.txt must include ${artifact}`);
    const actualHash = sha256File(artifactPath);
    const expectedHash = sums.get(artifact);
    assert(actualHash === expectedHash, `${artifact} SHA-256 mismatch: SHA256SUMS.txt has ${expectedHash}; actual file is ${actualHash}`);
  }
});

const result = {
  kind: 'proxyforge-release-publish-preflight',
  status: failures.length ? 'failed' : 'passed',
  releaseTag,
  version: packageJson.version,
  headCommit,
  tagCommit,
  evidenceDir: relative(evidenceDir),
  releaseDir: relative(releaseDir),
  passedChecks: checks.filter((entry) => entry.status === 'passed').length,
  failedChecks: failures.length,
  checks,
};

console.log(JSON.stringify(result, null, 2));
if (failures.length) {
  process.exitCode = 1;
}

function check(name, fn) {
  try {
    fn();
    checks.push({ name, status: 'passed' });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    const entry = { name, status: 'failed', message };
    checks.push(entry);
    failures.push(entry);
  }
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function isPass(value) {
  return typeof value === 'string' && /^pass(?:\\b|-|$)/i.test(value);
}

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

function parseSha256Sums(text) {
  const entries = new Map();
  for (const line of text.split(/\r?\n/)) {
    const match = line.match(/^([a-f0-9]{64})\s+\*?(.+?)\s*$/i);
    if (match) {
      entries.set(match[2], match[1].toLowerCase());
    }
  }
  return entries;
}

function sha256File(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function directoryHasFiles(directory) {
  const entries = fs.readdirSync(directory, { withFileTypes: true });
  for (const entry of entries) {
    const entryPath = path.join(directory, entry.name);
    if (entry.isFile()) {
      return true;
    }
    if (entry.isDirectory() && directoryHasFiles(entryPath)) {
      return true;
    }
  }
  return false;
}

function pathInside(candidate, parent) {
  const relativePath = path.relative(parent, candidate);
  return relativePath === '' || (!relativePath.startsWith('..') && !path.isAbsolute(relativePath));
}

function maybeReadJson(filePath) {
  try {
    return readJson(filePath);
  } catch {
    return null;
  }
}

function git(gitArgs) {
  try {
    return execFileSync('git', gitArgs, { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
  } catch {
    return '';
  }
}

function parseArgs(rawArgs) {
  const parsed = {};
  for (let index = 0; index < rawArgs.length; index += 1) {
    const arg = rawArgs[index];
    if (!arg.startsWith('--')) {
      continue;
    }
    const [key, inlineValue] = arg.slice(2).split('=', 2);
    parsed[key] = inlineValue ?? rawArgs[index + 1] ?? '';
    if (inlineValue === undefined) {
      index += 1;
    }
  }
  return parsed;
}

function relative(filePath) {
  return path.relative(root, filePath) || '.';
}
