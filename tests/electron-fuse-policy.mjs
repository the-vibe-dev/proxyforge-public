import { strict as assert } from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';
import { FuseV1Options } from '@electron/fuses';
import { checkSourceConfiguration, proxyforgeFusePolicy } from '../scripts/electron-fuse-policy.mjs';

const root = process.cwd();
const packageJson = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
const mainSource = fs.readFileSync(path.join(root, 'electron/main.ts'), 'utf8');
const releaseTrust = fs.readFileSync(path.join(root, 'scripts/release-trust.mjs'), 'utf8');
const checklist = fs.readFileSync(path.join(root, 'docs/RELEASE_CHECKLIST.md'), 'utf8');
const workflow = fs.readFileSync(path.join(root, '.github/workflows/nightly-full-suite.yml'), 'utf8');

assert.equal(packageJson.devDependencies?.['@electron/fuses'], '^2.1.2');
assert.equal(packageJson.build?.afterPack, 'scripts/electron-fuse-policy.mjs');
assert.match(packageJson.scripts?.['release:fuses'] ?? '', /electron-fuse-policy\.mjs --check-config/);
assert.match(packageJson.scripts?.['test:release:fuses'] ?? '', /tests\/electron-fuse-policy\.mjs/);

assert.equal(proxyforgeFusePolicy.expected[FuseV1Options.RunAsNode], true, 'RunAsNode compatibility exception must be explicit');
assert.equal(proxyforgeFusePolicy.expected[FuseV1Options.EnableNodeOptionsEnvironmentVariable], false);
assert.equal(proxyforgeFusePolicy.expected[FuseV1Options.EnableNodeCliInspectArguments], false);
assert.equal(proxyforgeFusePolicy.expected[FuseV1Options.EnableCookieEncryption], true);
assert.equal(proxyforgeFusePolicy.expected[FuseV1Options.OnlyLoadAppFromAsar], true);
assert.equal(proxyforgeFusePolicy.expected[FuseV1Options.GrantFileProtocolExtraPrivileges], false);
assert.equal(proxyforgeFusePolicy.expected[FuseV1Options.WasmTrapHandlers], true);
assert.equal(proxyforgeFusePolicy.strictlyRequireAllFuses, true);
assert.match(mainSource, /PACKAGED_RENDERER_PROTOCOL\s*=\s*'proxyforge'/, 'packaged renderer should use the custom app protocol');
assert.match(mainSource, /registerFileProtocol\(PACKAGED_RENDERER_PROTOCOL/, 'packaged renderer protocol should serve the asar renderer allowlist');

const sourceConfig = await checkSourceConfiguration(root);
assert.equal(sourceConfig.status, 'passed', sourceConfig.failures.join('; '));

assert.match(releaseTrust, /scripts\/electron-fuse-policy\.mjs/);
assert.match(releaseTrust, /electronFusePolicy/);
assert.match(checklist, /Electron fuse/i);
assert.match(checklist, /RunAsNode/i);
assert.match(checklist, /NODE_OPTIONS/i);
assert.match(workflow, /test:release:fuses/);
assert.match(workflow, /runs-on:\s*\$\{\{\s*matrix\.os\s*\}\}/);

console.log('electron-fuse-policy: verified source configuration, package hook, release docs, CI coverage, and explicit RunAsNode exception');
