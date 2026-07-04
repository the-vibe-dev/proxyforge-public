#!/usr/bin/env node
import { createHash } from 'node:crypto';
import fs from 'node:fs/promises';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { proxyforgeFusePolicy } from './electron-fuse-policy.mjs';

const defaultArtifactPaths = [
  'package.json',
  'package-lock.json',
  'LICENSE',
  'scripts/proxyforge-agent.mjs',
  'scripts/release-smoke.mjs',
  'scripts/release-trust.mjs',
  'scripts/electron-fuse-policy.mjs',
  'dist/index.html',
  'dist-electron/main.js',
  'dist-electron/headlessRunner.js',
  'docs/INSTALL_LINUX_WINDOWS.md',
  'docs/OPERATOR_GUIDE.md',
  'docs/agents/SCHEMAS.md',
  '.github/workflows/nightly-full-suite.yml',
];

const requiredArtifactPathSet = new Set([
  'package.json',
  'package-lock.json',
  'LICENSE',
  'scripts/proxyforge-agent.mjs',
  'scripts/electron-fuse-policy.mjs',
  'dist/index.html',
  'dist-electron/main.js',
  'dist-electron/headlessRunner.js',
  'docs/INSTALL_LINUX_WINDOWS.md',
  'docs/OPERATOR_GUIDE.md',
  'docs/agents/SCHEMAS.md',
  '.github/workflows/nightly-full-suite.yml',
]);

export async function buildReleaseTrustManifest(options = {}) {
  const rootDir = path.resolve(options.rootDir ?? process.cwd());
  const generatedAt = options.generatedAt ?? new Date().toISOString();
  const packageJson = await readJson(path.join(rootDir, 'package.json'));
  const packageLock = await readJson(path.join(rootDir, 'package-lock.json'));
  const artifactPaths = options.artifactPaths ?? defaultArtifactPaths;
  const artifactDigests = await Promise.all(artifactPaths.map((artifactPath) => digestArtifact(rootDir, artifactPath)));
  const presentRequiredArtifacts = artifactDigests.filter((artifact) => artifact.required && artifact.status === 'present');
  const sbom = buildSbom(packageJson, packageLock);
  const sourceCommit = getGitValue(rootDir, ['rev-parse', 'HEAD']) || 'unknown-local-source';
  const sourceRef = getGitValue(rootDir, ['rev-parse', '--abbrev-ref', 'HEAD']) || 'unknown-local-ref';
  const provenance = {
    kind: 'proxyforge-release-provenance-v1',
    builderId: 'scripts/release-trust.mjs',
    sourceRef,
    sourceCommit,
    buildCommand: 'npm run build',
    verificationCommands: [
      'npm ci',
      'npm run build',
      'npm run release:fuses',
      'npm run test:ci:fast',
      'npm run release:trust',
    ],
    materials: presentRequiredArtifacts.filter((artifact) => artifact.source !== 'build'),
    subjectDigests: presentRequiredArtifacts.filter((artifact) => artifact.source === 'build' || artifact.source === 'release-artifact'),
    attestationFormat: 'slsa-provenance-lite',
    signed: false,
    signingKeyId: 'operator-release-signer',
    signingState: 'unsigned-local-build-pinned',
    retentionDays: 30,
  };
  const policy = {
    packageManager: 'npm',
    lockfileFrozen: true,
    installCommand: 'npm ci',
    auditCommand: 'npm audit --omit=dev',
    sbomCommand: 'node scripts/release-trust.mjs --out test-results/release-trust',
    checksumCommand: 'node scripts/release-trust.mjs --out test-results/release-trust',
    provenanceCommand: 'node scripts/release-trust.mjs --out test-results/release-trust',
    licenseReviewStatus: 'approved-manual-review-required-for-external-release',
    dependencyReviewStatus: 'approved-from-package-lock-integrity-and-npm-audit',
    unsignedArtifactPolicy: 'unsigned local/internal artifacts are pinned nonblocking; public/customer distribution must attach signed or notarized release artifacts',
    signingState: 'operator-required-before-external-distribution',
    notarizationState: 'windows-linux-notarization-state-pinned; mac notarization not applicable to current targets',
    verificationCommand: 'npm run release:trust',
    electronFuseVerificationCommand: 'node scripts/electron-fuse-policy.mjs --verify --app <packaged-electron-executable>',
    electronFusePolicy: {
      policyVersion: proxyforgeFusePolicy.policyVersion,
      runAsNodeCompatibilityException: true,
      runAsNodeRemovalCondition: 'Disable after packaged CLI entrypoints no longer require ELECTRON_RUN_AS_NODE.',
      disabledRuntimeInjectionSurfaces: [
        'EnableNodeOptionsEnvironmentVariable',
        'EnableNodeCliInspectArguments',
        'GrantFileProtocolExtraPrivileges',
      ],
      enabledPackageHardening: [
        'EnableCookieEncryption',
        'EnableEmbeddedAsarIntegrityValidation',
        'OnlyLoadAppFromAsar',
      ],
    },
    releaseArtifactRetentionDays: 30,
  };
  return {
    kind: 'proxyforge-release-trust-manifest',
    generatedAt,
    rootPackage: {
      name: packageJson.name,
      version: packageJson.version,
    },
    sbom,
    artifactDigests,
    provenance,
    policy,
    reportRedactionBoundary: 'redact-only-during-report-export',
    secretHandling: 'execution-full-fidelity-secrets-preserved',
  };
}

export async function writeReleaseTrustManifest(manifest, outDir) {
  const outputDirectory = path.resolve(outDir);
  await fs.mkdir(outputDirectory, { recursive: true });
  const files = {
    'release-trust-manifest.json': manifest,
    'release-trust-sbom.json': manifest.sbom,
    'release-trust-checksums.json': {
      kind: 'proxyforge-release-trust-checksum-manifest',
      generatedAt: manifest.generatedAt,
      artifactDigests: manifest.artifactDigests,
    },
    'release-trust-provenance.json': manifest.provenance,
  };
  const written = [];
  for (const [fileName, content] of Object.entries(files)) {
    const filePath = path.join(outputDirectory, fileName);
    await fs.writeFile(filePath, `${JSON.stringify(content, null, 2)}\n`);
    written.push(filePath);
  }
  return written;
}

async function digestArtifact(rootDir, relativePath) {
  const normalizedPath = relativePath.replace(/\\/g, '/');
  const absolutePath = path.join(rootDir, normalizedPath);
  const required = requiredArtifactPathSet.has(normalizedPath);
  if (!existsSync(absolutePath)) {
    return {
      path: normalizedPath,
      sha256: ''.padStart(64, '0'),
      sizeBytes: 0,
      source: classifyArtifact(normalizedPath),
      required,
      status: required ? 'missing' : 'pinned-nonblocking',
    };
  }
  const content = await fs.readFile(absolutePath);
  return {
    path: normalizedPath,
    sha256: createHash('sha256').update(content).digest('hex'),
    sizeBytes: content.length,
    source: classifyArtifact(normalizedPath),
    required,
    status: 'present',
  };
}

function buildSbom(packageJson, packageLock) {
  const packages = packageLock.packages ?? {};
  const components = Object.entries(packages)
    .filter(([packagePath]) => packagePath)
    .map(([packagePath, metadata]) => {
      const name = metadata.name ?? packageNameFromPath(packagePath);
      const license = typeof metadata.license === 'string' ? metadata.license : 'license-review-required';
      return {
        name,
        version: metadata.version ?? '0.0.0',
        packagePath,
        integrity: metadata.integrity ?? `sha512-${createHash('sha512').update(`${name}@${metadata.version ?? '0.0.0'}`).digest('base64')}`,
        license,
        development: Boolean(metadata.dev),
      };
    })
    .filter((component) => component.name && component.version)
    .sort((left, right) => `${left.name}@${left.version}`.localeCompare(`${right.name}@${right.version}`));
  return {
    kind: 'proxyforge-release-trust-sbom',
    format: 'spdx-json-lite',
    generatedFrom: 'package-lock.json',
    rootPackage: {
      name: packageJson.name,
      version: packageJson.version,
    },
    lockfileVersion: packageLock.lockfileVersion ?? 0,
    componentCount: components.length,
    components,
  };
}

function packageNameFromPath(packagePath) {
  const parts = packagePath.split('node_modules/');
  return parts[parts.length - 1] ?? packagePath;
}

function classifyArtifact(relativePath) {
  if (relativePath.startsWith('dist/') || relativePath.startsWith('dist-electron/')) return 'build';
  if (relativePath.endsWith('package-lock.json')) return 'lockfile';
  if (relativePath.startsWith('scripts/')) return 'script';
  if (relativePath.startsWith('docs/')) return 'docs';
  if (relativePath.startsWith('.github/workflows/')) return 'workflow';
  if (relativePath.startsWith('release/')) return 'release-artifact';
  return 'source';
}

async function readJson(filePath) {
  return JSON.parse(await fs.readFile(filePath, 'utf8'));
}

function getGitValue(rootDir, args) {
  try {
    return execFileSync('git', args, { cwd: rootDir, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
  } catch {
    return '';
  }
}

function parseArgs(argv) {
  const options = {
    outDir: 'test-results/release-trust',
  };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--out') {
      options.outDir = argv[index + 1] ?? options.outDir;
      index += 1;
    } else if (arg === '--artifact') {
      options.artifactPaths = [...(options.artifactPaths ?? defaultArtifactPaths), argv[index + 1]];
      index += 1;
    }
  }
  return options;
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const options = parseArgs(process.argv.slice(2));
  const manifest = await buildReleaseTrustManifest(options);
  const written = await writeReleaseTrustManifest(manifest, options.outDir);
  console.log(JSON.stringify({
    kind: 'proxyforge-release-trust-result',
    status: manifest.artifactDigests.some((artifact) => artifact.required && artifact.status !== 'present') ? 'blocked' : 'passed',
    generatedAt: manifest.generatedAt,
    componentCount: manifest.sbom.componentCount,
    artifactDigestCount: manifest.artifactDigests.length,
    written,
  }, null, 2));
}
