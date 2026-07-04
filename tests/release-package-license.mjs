import { strict as assert } from 'node:assert';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import fs from 'node:fs';
import path from 'node:path';

const root = process.cwd();
const require = createRequire(import.meta.url);
const packageJson = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
const licensePath = path.join(root, 'LICENSE');
const licenseText = fs.readFileSync(licensePath, 'utf8');
const licenseSha256 = sha256(licenseText);
const buildFiles = packageJson.build?.files ?? [];
const verifyArtifacts = process.argv.includes('--verify-artifacts') || process.env.VERIFY_PACKAGED_LICENSE === '1';

assert.ok(buildFiles.includes('LICENSE'), 'Electron Builder build.files must include the project LICENSE notice');
assert.match(licenseText, /MIT License/);
assert.match(licenseText, /Permission is hereby granted, free of charge/);

const appAsarCandidates = verifyArtifacts ? [
  path.join(root, 'release', 'linux-unpacked', 'resources', 'app.asar'),
  path.join(root, 'release', 'win-unpacked', 'resources', 'app.asar'),
].filter((candidate) => fs.existsSync(candidate)) : [];

const receipts = [];
const asar = verifyArtifacts ? require('@electron/asar') : null;
for (const appAsar of appAsarCandidates) {
  const entries = asar.listPackage(appAsar);
  const resourceLicensePath = path.join(path.dirname(appAsar), 'LICENSE');
  const packagedLicense = entries.includes('/LICENSE')
    ? asar.extractFile(appAsar, 'LICENSE').toString('utf8')
    : fs.existsSync(resourceLicensePath)
      ? fs.readFileSync(resourceLicensePath, 'utf8')
      : null;
  assert.ok(packagedLicense, `${appAsar} should contain /LICENSE or be accompanied by resources/LICENSE`);
  assert.equal(sha256(packagedLicense), licenseSha256, `${appAsar} should contain the exact project license text`);
  receipts.push({
    appAsar,
    licensePath: entries.includes('/LICENSE') ? '/LICENSE' : resourceLicensePath,
    licenseSha256,
  });
}

if (verifyArtifacts) {
  assert.ok(receipts.length > 0, 'packaged license verification requires at least one release/*/resources/app.asar artifact');
}

if (!receipts.length) {
  console.log(`release-package-license: verified source package allowlist; packaged app.asar not present in this source-only run; licenseSha256=${licenseSha256}`);
} else {
  console.log(`release-package-license: verified packaged license receipts ${JSON.stringify(receipts)}`);
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}
