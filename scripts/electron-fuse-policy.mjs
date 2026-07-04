#!/usr/bin/env node
import { access, readdir } from 'node:fs/promises';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { flipFuses, getCurrentFuseWire, FuseVersion, FuseV1Options } from '@electron/fuses';

export const proxyforgeFusePolicy = Object.freeze({
  version: FuseVersion.V1,
  strictlyRequireAllFuses: true,
  policyVersion: 1,
  notes: [
    'RunAsNode remains enabled until packaged CLI/release-smoke execution no longer depends on Electron as a Node host.',
    'NODE_OPTIONS and inspect CLI arguments are disabled to reduce packaged-runtime injection and debugging surfaces.',
    'Cookie encryption and app.asar loading are enabled for packaged desktop artifacts.',
  ],
  expected: Object.freeze({
    [FuseV1Options.RunAsNode]: true,
    [FuseV1Options.EnableCookieEncryption]: true,
    [FuseV1Options.EnableNodeOptionsEnvironmentVariable]: false,
    [FuseV1Options.EnableNodeCliInspectArguments]: false,
    [FuseV1Options.EnableEmbeddedAsarIntegrityValidation]: true,
    [FuseV1Options.OnlyLoadAppFromAsar]: true,
    [FuseV1Options.LoadBrowserProcessSpecificV8Snapshot]: false,
    [FuseV1Options.GrantFileProtocolExtraPrivileges]: false,
    [FuseV1Options.WasmTrapHandlers]: true,
  }),
});

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

export default async function afterPack(context) {
  const executable = await resolvePackagedElectronExecutable(context);
  if (!executable) {
    throw new Error(`Unable to locate packaged Electron executable in ${context?.appOutDir ?? 'unknown appOutDir'}`);
  }
  await applyFusePolicy(executable);
}

export async function applyFusePolicy(executablePath) {
  await flipFuses(executablePath, {
    version: proxyforgeFusePolicy.version,
    strictlyRequireAllFuses: proxyforgeFusePolicy.strictlyRequireAllFuses,
    ...proxyforgeFusePolicy.expected,
  });
  return verifyFusePolicy(executablePath);
}

export async function verifyFusePolicy(executablePath) {
  const current = await getCurrentFuseWire(executablePath);
  const mismatches = [];
  for (const [option, expected] of Object.entries(proxyforgeFusePolicy.expected)) {
    const optionId = Number(option);
    const actual = normalizeFuseState(current[optionId]);
    if (actual !== expected) {
      mismatches.push({
        option: FuseV1Options[optionId],
        expected,
        actual,
      });
    }
  }
  return {
    kind: 'proxyforge-electron-fuse-verification',
    status: mismatches.length ? 'failed' : 'passed',
    executablePath,
    policyVersion: proxyforgeFusePolicy.policyVersion,
    current: fuseWireToObject(current),
    expected: fusePolicyToObject(proxyforgeFusePolicy.expected),
    compatibilityExceptions: [
      {
        fuse: 'RunAsNode',
        state: true,
        reason: 'Packaged CLI and release-smoke checks currently execute bundled runtime modules through Electron-as-Node.',
        removalCondition: 'Disable after packaged CLI entrypoints are available without ELECTRON_RUN_AS_NODE.',
      },
    ],
    mismatches,
  };
}

export async function checkSourceConfiguration(rootDir = root) {
  const packageJson = JSON.parse(fs.readFileSync(path.join(rootDir, 'package.json'), 'utf8'));
  const checklist = fs.readFileSync(path.join(rootDir, 'docs/RELEASE_CHECKLIST.md'), 'utf8');
  const security = fs.readFileSync(path.join(rootDir, 'SECURITY.md'), 'utf8');
  const workflow = fs.readFileSync(path.join(rootDir, '.github/workflows/nightly-full-suite.yml'), 'utf8');
  const failures = [];

  if (packageJson.devDependencies?.['@electron/fuses'] !== '^2.1.2') failures.push('package.json must explicitly own Electron 42-compatible @electron/fuses');
  if (packageJson.build?.afterPack !== 'scripts/electron-fuse-policy.mjs') failures.push('electron-builder afterPack must apply the fuse policy');
  if (!/release:fuses/.test(JSON.stringify(packageJson.scripts ?? {}))) failures.push('package scripts must expose release:fuses');
  if (!/Electron fuse/i.test(checklist) || !/RunAsNode/i.test(checklist)) failures.push('release checklist must document Electron fuse verification and RunAsNode exception');
  if (!/GitHub Security Advisory/i.test(security)) failures.push('SECURITY.md must prefer private GitHub Security Advisories');
  if (!/pull_request:/.test(workflow) || !/push:/.test(workflow)) failures.push('CI workflow must run on pull_request and push');

  return {
    kind: 'proxyforge-electron-fuse-source-configuration',
    status: failures.length ? 'failed' : 'passed',
    policyVersion: proxyforgeFusePolicy.policyVersion,
    expected: fusePolicyToObject(proxyforgeFusePolicy.expected),
    failures,
  };
}

async function resolvePackagedElectronExecutable(context) {
  const appOutDir = context?.appOutDir;
  if (!appOutDir) return '';
  const productFilename = context?.packager?.appInfo?.productFilename;
  const executableName = context?.packager?.executableName;
  const platformName = String(context?.electronPlatformName ?? context?.packager?.platform?.name ?? process.platform);
  const candidates = [];

  if (platformName === 'win32') {
    for (const name of [productFilename, executableName, 'ProxyForge']) {
      if (name) candidates.push(path.join(appOutDir, `${name}.exe`));
    }
  } else if (platformName === 'linux') {
    for (const name of [executableName, productFilename, 'proxyforge', 'ProxyForge']) {
      if (name) candidates.push(path.join(appOutDir, name));
    }
  } else if (platformName === 'darwin') {
    for (const name of [productFilename, executableName, 'ProxyForge']) {
      if (name) candidates.push(path.join(appOutDir, `${name}.app`, 'Contents', 'MacOS', name));
    }
  }

  for (const candidate of candidates) {
    if (await exists(candidate)) return candidate;
  }

  const fallback = await findLikelyExecutable(appOutDir, platformName);
  return fallback ?? '';
}

async function findLikelyExecutable(directory, platformName) {
  const entries = await readdir(directory, { withFileTypes: true }).catch(() => []);
  for (const entry of entries) {
    const candidate = path.join(directory, entry.name);
    if (entry.isFile()) {
      if (platformName === 'win32' && entry.name.toLowerCase().endsWith('.exe')) return candidate;
      if (platformName === 'linux') {
        try {
          await access(candidate, fs.constants.X_OK);
          return candidate;
        } catch {
          continue;
        }
      }
    }
  }
  return null;
}

function normalizeFuseState(value) {
  if (value === true || value === '1' || value === 49) return true;
  if (value === false || value === '0' || value === 48) return false;
  return value;
}

function fuseWireToObject(current) {
  const result = {};
  for (const option of Object.values(FuseV1Options).filter((value) => typeof value === 'number')) {
    result[FuseV1Options[option]] = normalizeFuseState(current[option]);
  }
  return result;
}

function fusePolicyToObject(policy) {
  const result = {};
  for (const [option, expected] of Object.entries(policy)) {
    result[FuseV1Options[Number(option)]] = expected;
  }
  return result;
}

async function exists(candidate) {
  try {
    await access(candidate);
    return true;
  } catch {
    return false;
  }
}

function parseArgs(argv) {
  const args = { mode: 'check-config' };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--verify') {
      args.mode = 'verify';
    } else if (arg === '--apply') {
      args.mode = 'apply';
    } else if (arg === '--check-config') {
      args.mode = 'check-config';
    } else if (arg === '--policy-json') {
      args.mode = 'policy-json';
    } else if (arg === '--app') {
      args.app = argv[index + 1];
      index += 1;
    }
  }
  return args;
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const args = parseArgs(process.argv.slice(2));
  let result;
  if (args.mode === 'policy-json') {
    result = {
      kind: 'proxyforge-electron-fuse-policy',
      policyVersion: proxyforgeFusePolicy.policyVersion,
      expected: fusePolicyToObject(proxyforgeFusePolicy.expected),
      compatibilityExceptions: ['RunAsNode'],
      notes: proxyforgeFusePolicy.notes,
    };
  } else if (args.mode === 'verify') {
    if (!args.app) throw new Error('--verify requires --app');
    result = await verifyFusePolicy(path.resolve(args.app));
  } else if (args.mode === 'apply') {
    if (!args.app) throw new Error('--apply requires --app');
    result = await applyFusePolicy(path.resolve(args.app));
  } else {
    result = await checkSourceConfiguration();
  }
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  if (result.status === 'failed') process.exitCode = 1;
}
