import { strict as assert } from 'node:assert';
import fs from 'node:fs/promises';
import path from 'node:path';

const workflowPath = path.resolve('.github/workflows/nightly-full-suite.yml');
const fullSuitePath = path.resolve('tests/ci-full-suite.mjs');
const playwrightConfigPath = path.resolve('playwright.config.ts');
const workflow = await fs.readFile(workflowPath, 'utf8');
const fullSuite = await fs.readFile(fullSuitePath, 'utf8');
const playwrightConfig = await fs.readFile(playwrightConfigPath, 'utf8');

assert.match(workflow, /name:\s*ProxyForge Nightly Full Suite/, 'nightly workflow should have a stable release-facing name');
assert.match(workflow, /pull_request:/, 'release workflow should run a change-time PR source gate');
assert.match(workflow, /push:[\s\S]*branches:[\s\S]*main/, 'release workflow should run on protected branch pushes');
assert.match(workflow, /push:[\s\S]*tags:[\s\S]*'v\*'/, 'release workflow should run native artifact gates for version tags');
assert.match(workflow, /schedule:[\s\S]*cron:\s*'17 8 \* \* \*'/, 'nightly workflow should run on a scheduled cadence');
assert.match(workflow, /workflow_dispatch:[\s\S]*plan_only:[\s\S]*skip_browser:/, 'nightly workflow should keep manual plan-only and browser-skip controls');
assert.match(workflow, /actions\/checkout@v5/, 'nightly workflow should pin a modern checkout action');
assert.match(workflow, /actions\/setup-node@v5[\s\S]*node-version:\s*'24'/, 'nightly workflow should use the Node major exercised by packaged Electron');
assert.match(workflow, /FORCE_JAVASCRIPT_ACTIONS_TO_NODE24:\s*'true'/, 'nightly workflow should opt JavaScript actions into Node 24 before GitHub removes Node 20');
assert.match(workflow, /npm ci/, 'nightly workflow should use clean dependency installation');
assert.match(workflow, /npx playwright install --with-deps chromium/, 'nightly workflow should provision browser dependencies before the full browser suite');
assert.match(workflow, /actions\/cache\/restore@v4/, 'nightly workflow should restore retained full-suite history before executing');
assert.match(workflow, /actions\/cache\/save@v4/, 'nightly workflow should save retained full-suite history after execution');
assert.match(workflow, /key:\s*proxyforge-full-suite-history-\$\{\{\s*github\.ref_name\s*\}\}-\$\{\{\s*github\.run_id\s*\}\}-\$\{\{\s*github\.run_attempt\s*\}\}/, 'retained-history cache key should be unique per branch run and attempt');
assert.match(workflow, /restore-keys:\s*\|[\s\S]*proxyforge-full-suite-history-\$\{\{\s*github\.ref_name\s*\}\}-/, 'retained-history cache should restore the latest branch-local history');
assert.match(workflow, /if:\s*always\(\)\s*&&\s*github\.event\.inputs\.plan_only\s*!=\s*'true'/, 'retained-history cache save should skip plan-only metadata runs');
assert.match(workflow, /npm run test:ci:full -- "\$\{args\[@\]\}"/, 'nightly workflow should run the full suite with dispatch arguments');
assert.match(workflow, /actions\/upload-artifact@v4/, 'nightly workflow should upload artifacts even when the suite fails');
assert.match(workflow, /if:\s*always\(\)/, 'artifact upload should run for failed nightly runs');
assert.match(workflow, /retention-days:\s*30/, 'nightly failure artifacts should keep the documented 30-day retention');

const fullNightlyWorkflow = workflow.slice(workflow.indexOf('full-nightly:'));
const sourceGateWorkflow = workflow.slice(workflow.indexOf('source-gate:'), workflow.indexOf('native-artifact-gate:'));
const restoreIndex = fullNightlyWorkflow.indexOf('actions/cache/restore@v4');
const runIndex = fullNightlyWorkflow.indexOf('npm run test:ci:full');
const saveIndex = fullNightlyWorkflow.indexOf('actions/cache/save@v4');
const uploadIndex = fullNightlyWorkflow.indexOf('actions/upload-artifact@v4');
const sourceInstallIndex = sourceGateWorkflow.indexOf('npm ci');
const sourceChromiumIndex = sourceGateWorkflow.indexOf('npx playwright install --with-deps chromium');
const sourceBuildIndex = sourceGateWorkflow.indexOf('npm run build');
const sourceFastIndex = sourceGateWorkflow.indexOf('npm run test:ci:fast');
assert.ok(restoreIndex > -1 && restoreIndex < runIndex, 'retained history must be restored before the full suite runs');
assert.ok(saveIndex > runIndex && saveIndex < uploadIndex, 'retained history must be saved before artifact upload finalizes the run');
assert.ok(sourceInstallIndex > -1, 'source gate must install dependencies');
assert.ok(sourceChromiumIndex > sourceInstallIndex, 'source gate must install Chromium after npm ci');
assert.ok(sourceBuildIndex > sourceChromiumIndex, 'source gate must install Chromium before build/source tests');
assert.ok(sourceFastIndex > sourceBuildIndex, 'source gate must run the curated fast gate after build/source guards');

for (const requiredPath of [
  'test-results/ci-full-suite-summary.json',
  'test-results/ci-full-suite-plan.json',
  'test-results/.last-run.json',
  'test-results/ci-full-suite-history/',
  'test-results/ci-full-suite-history/dashboard.json',
  'test-results/playwright-artifacts/',
  'playwright-report/',
]) {
  assert.ok(workflow.includes(requiredPath), `nightly workflow should upload ${requiredPath}`);
  assert.ok(fullSuite.includes(requiredPath), `full-suite upload policy should document ${requiredPath}`);
}

assert.match(fullSuite, /maxFlakySteps:\s*0/, 'full suite should default to zero tolerated flaky steps');
assert.match(fullSuite, /ownerRequired:\s*true/, 'full suite should require coverage ownership metadata');
assert.match(fullSuite, /coverageOwnership/, 'full suite should emit coverage ownership metadata');
assert.match(playwrightConfig, /outputDir:\s*['"]test-results\/playwright-artifacts['"]/, 'Playwright output must stay in a subdirectory so retained full-suite history is not cleaned');
assert.match(workflow, /name:\s*Change-time source gate/, 'workflow should include a required source gate for PRs and protected branches');
assert.match(workflow, /npm run release:fuses/, 'source gate should verify Electron fuse policy configuration');
assert.match(workflow, /npm run test:release:fuses/, 'source gate should run the fuse policy test');
assert.match(workflow, /name:\s*Run curated fast gate[\s\S]*npm run test:ci:fast/, 'source gate should run the curated fast gate on PRs, main pushes, and tags');
assert.match(workflow, /npm audit --omit=dev/, 'source gate should run a production dependency audit');
assert.ok(workflow.indexOf('npm run test:ci:fast') < workflow.indexOf('npm audit --omit=dev'), 'fast gate should run before the final production audit step');
assert.match(workflow, /name:\s*Native artifact gate/, 'workflow should include native Linux/Windows artifact gates');
assert.match(workflow, /matrix:[\s\S]*os:[\s\S]*ubuntu-latest[\s\S]*windows-latest/, 'native artifact gate should run on Linux and Windows hosts');
assert.match(workflow, /libasound2t64/, 'Linux native gate should install the Ubuntu 24.04 ALSA runtime dependency');
assert.match(workflow, /npm run dist:\$\{\{\s*matrix\.dist\s*\}\}/, 'native artifact gate should build the platform artifact from package scripts');
assert.match(workflow, /name:\s*Verify packaged license[\s\S]*npm run release:license -- --verify-artifacts/, 'native artifact gate should verify the packaged project license notice');
assert.match(workflow, /test-results\/electron-fuse-\$\{\{\s*matrix\.smoke_platform\s*\}\}\.json/, 'native artifact gate should retain Electron fuse verification receipts');
assert.match(workflow, /test-results\/release-license-\$\{\{\s*matrix\.smoke_platform\s*\}\}\.txt/, 'native artifact gate should retain packaged-license verification receipts');
assert.match(workflow, /node scripts\/release-smoke\.mjs --platform \$\{\{\s*matrix\.smoke_platform\s*\}\}/, 'native artifact gate should smoke the built artifact');
assert.match(workflow, /test-results\/release-smoke-\$\{\{\s*matrix\.smoke_platform\s*\}\}\.json/, 'native artifact gate should retain release smoke receipts');
assert.match(workflow, /name:\s*Generate artifact checksums[\s\S]*SHA256SUMS\.txt/, 'native artifact gate should generate checksums from the actual built artifacts');
assert.match(workflow, /test-results\/\*\*\/\*\.txt/, 'native artifact upload should include text receipts');

for (const requiredStep of [
  'tests/platform-release-engine.mjs',
  'tests/ui-scale-production-engine.mjs',
  'tests/platform-shell-production-engine.mjs',
  'tests/agent-control-production-engine.mjs',
  'tests/ai-provider-production-engine.mjs',
  'tests/release-security-production-engine.mjs',
  'tests/fast-regression-production-engine.mjs',
  'tests/full-nightly-production-engine.mjs',
  'tests/full-nightly-history-engine.mjs',
  'tests/install-docs-production-engine.mjs',
  'tests/windows-package-production-engine.mjs',
  'tests/linux-package-production-engine.mjs',
  'tests/safety-enterprise-engine.mjs',
  'tests/project-parity-engine.mjs',
  'tests/project-import-compatibility-engine.mjs',
  'tests/customer-scale-interop-engine.mjs',
  'tests/extension-third-party-compatibility-engine.mjs',
  'tests/project-store-v2.mjs',
  'tests/project-store-settings-workflow.mjs',
  'tests/project-store-cookie-jar-workflow.mjs',
  'tests/proxy-project-store-workflow.mjs',
  'tests/project-store-oast-workflow.mjs',
  'tests/project-store-oast-signed-evidence.mjs',
  'tests/scanner-oast-ssrf.mjs',
  'tests/vulnerable-fixture-app.mjs',
  'tests/session-cookie-jar.mjs',
  'tests/session-macro-engine.mjs',
  'tests/session-replay-engine.mjs',
  'tests/proxy-listener-engine.mjs',
  'tests/scanner-passive-engine.mjs',
  'tests/intruder-oast-correlation.mjs',
  'tests/repeater-workspace-engine.mjs',
  'tests/repeater-oast-workflow.mjs',
  'tests/repeater-desync-race-engine.mjs',
  'tests/logger-evidence-engine.mjs',
  'tests/organizer-evidence-engine.mjs',
  'tests/viewer-engine.mjs',
  'tests/exploit-engine.mjs',
  'tests/ai-action-engine.mjs',
  'tests/agent-cli.mjs',
]) {
  assert.ok(fullSuite.includes(requiredStep), `full-suite coverage should include ${requiredStep}`);
}

console.log('ci-nightly-policy: verified scheduled full-suite workflow, artifact upload policy, ownership metadata, and flake budget');
