import { strict as assert } from 'node:assert';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

const root = process.cwd();
const packageJson = readJson('package.json');
const gitignore = fs.readFileSync(path.join(root, '.gitignore'), 'utf8');
const matrix = fs.readFileSync(path.join(root, 'docs/FEATURE_MATRIX.md'), 'utf8');
const releaseNotes = fs.readFileSync(path.join(root, 'docs/RELEASE_NOTES_v0.1.0-alpha.1.md'), 'utf8');
const readme = fs.readFileSync(path.join(root, 'README.md'), 'utf8');
const securityPolicy = fs.readFileSync(path.join(root, 'SECURITY.md'), 'utf8');
const installGuide = fs.readFileSync(path.join(root, 'docs/INSTALL_LINUX_WINDOWS.md'), 'utf8');
const operatorGuide = fs.readFileSync(path.join(root, 'docs/OPERATOR_GUIDE.md'), 'utf8');
const agenticInterface = fs.readFileSync(path.join(root, 'docs/AGENTIC_INTERFACE.md'), 'utf8');
const codexAgentDocs = fs.readFileSync(path.join(root, 'docs/agents/CODEX.md'), 'utf8');
const claudeAgentDocs = fs.readFileSync(path.join(root, 'docs/agents/CLAUDE.md'), 'utf8');
const vantixAgentDocs = fs.readFileSync(path.join(root, 'docs/agents/VANTIX.md'), 'utf8');
const agentSchemas = fs.readFileSync(path.join(root, 'docs/agents/SCHEMAS.md'), 'utf8');
const agentOptionAudit = fs.readFileSync(path.join(root, 'docs/agents/MVP_OPTION_AUDIT.md'), 'utf8');
const viteConfig = fs.readFileSync(path.join(root, 'vite.config.ts'), 'utf8');
const electronMain = fs.readFileSync(path.join(root, 'electron/main.ts'), 'utf8');
const pagesWorkflow = fs.readFileSync(path.join(root, '.github/workflows/pages.yml'), 'utf8');
const pagesBuilder = fs.readFileSync(path.join(root, 'scripts/build-github-pages.mjs'), 'utf8');
const countsJson = readJson('docs/counts.json');
const brandManifest = readJson('assets/brand-manifest.json');
const versionBadge = fs.readFileSync(path.join(root, 'assets/badges/version.svg'), 'utf8');
const licenseBadge = fs.readFileSync(path.join(root, 'assets/badges/license.svg'), 'utf8');
const workbenchesBadge = fs.readFileSync(path.join(root, 'assets/badges/workbenches.svg'), 'utf8');

assert.equal(packageJson.version, '0.1.0-alpha.1', 'package metadata should identify the alpha release candidate version');
assert.equal(packageJson.main, 'dist-electron/main.js', 'desktop main should point at compiled Electron main');
assert.equal(packageJson.bin?.proxyforge, 'dist-electron/headlessRunner.js', 'packaged CLI should expose the headless runner');
assert.equal(packageJson.bin?.['proxyforge-agent'], 'scripts/proxyforge-agent.mjs', 'packaged CLI should expose the agentic control wrapper');
assert.equal(packageJson.license, 'MIT', 'open-source alpha should declare the repository license');
assert.equal(packageJson.private, true, 'desktop alpha package metadata should be private to prevent accidental npm publication');
assert.equal(packageJson.repository?.url, 'git+https://github.com/the-vibe-dev/proxyforge-public.git', 'package metadata should identify the source repository');
assert.equal(packageJson.homepage, 'https://github.com/the-vibe-dev/proxyforge-public#readme', 'package metadata should expose the project homepage');
assert.equal(packageJson.bugs?.url, 'https://github.com/the-vibe-dev/proxyforge-public/issues', 'package metadata should expose the issue tracker');
assert.equal(packageJson.scripts?.['docs:pages'], 'node scripts/build-github-pages.mjs', 'package scripts should build the GitHub Pages docs');
assert.match(packageJson.author?.email ?? '', /users\.noreply\.github\.com$/, 'package metadata should not use a local placeholder maintainer email');
assert.match(packageJson.engines?.node ?? '', />=22\.12\.0/, 'package metadata should declare supported Node versions');
assert.match(packageJson.packageManager ?? '', /^npm@/, 'package metadata should pin the package manager family');
assert.equal(packageJson.devDependencies?.['@electron/fuses'], '^2.1.2', 'Electron fuse tooling should be an explicit Electron 42-compatible dev dependency');
assert.equal(packageJson.build?.afterPack, 'scripts/electron-fuse-policy.mjs', 'packaged builds should apply the Electron fuse policy');
assertFile('LICENSE', 'open-source alpha should include a top-level license');
assertFile('SECURITY.md', 'open-source alpha should include a responsible security policy');
assertFile('scripts/build-github-pages.mjs', 'open-source alpha should include the GitHub Pages docs builder');
assertFile('.github/workflows/pages.yml', 'open-source alpha should include the GitHub Pages deployment workflow');
assert.match(readme, /Open-Source Alpha Candidate Status/i, 'README should state alpha candidate readiness');
assert.match(readme, /Source alpha candidate/i, 'README should distinguish source-alpha candidate status');
assert.match(readme, /GitHub source gate records `npm run test:ci:fast` passing/i, 'README should require a green GitHub fast source gate before tagging');
assert.match(readme, /Unsigned binaries can be built for validation, but they are not release-certified public installers until native artifact receipts and `npm run release:preflight` pass/i, 'README should distinguish buildable unsigned binaries from release-certified installers');
assert.match(readme, /npm run docs:pages/i, 'README should document the GitHub Pages docs build');
assert.match(readme, /npm run test:ci:fast/i, 'README should identify the fast CI gate');
assert.match(readme, /Known Alpha Limits/i, 'README should document known alpha limits');
assert.match(readme, /report\/export flows/i, 'README should document the redaction boundary');
assert.match(readme, /npx playwright install --with-deps chromium/i, 'README should document the local Playwright browser install prerequisite');
assert.match(readme, /missing Playwright browser or blocked Playwright CDN are environment-blocked/i, 'README should document local Playwright environment blockers');
assert.match(releaseNotes, /GitHub CI records a clean run for the exact release commit with Chromium installed/i, 'release notes should require CI Chromium before source alpha tagging');
assert.match(releaseNotes, /Unsigned binaries can be built for validation, but publish release-certified installers only after native artifact receipts and `npm run release:preflight` pass/i, 'release notes should distinguish validation binaries from release-certified installers');
assert.match(releaseNotes, /expected to fail in extracted source archives without a git tag, live-validation evidence, native receipts, and `SHA256SUMS\.txt`/i, 'release notes should explain source archive preflight failures');
assert.ok(!fs.existsSync(path.join(root, 'docs/RELEASE_CHECKLIST.md')), 'public source should not include internal release checklist receipts');
assert.ok(!fs.existsSync(path.join(root, 'docs/RELEASE_EVIDENCE.md')), 'public source should not include internal release evidence logs');
assert.match(pagesWorkflow, /actions\/upload-pages-artifact@v4[\s\S]*path:\s*\.gitignored\/github-pages/i, 'GitHub Pages workflow should upload the generated static docs artifact');
assert.match(pagesWorkflow, /actions\/deploy-pages@v5/i, 'GitHub Pages workflow should deploy with the official Pages action');
assert.match(pagesWorkflow, /workflow_dispatch:/i, 'GitHub Pages workflow should be manually runnable for release docs publishing');
assert.doesNotMatch(pagesWorkflow, /^\s*push:/m, 'GitHub Pages workflow should not make source-alpha pushes red when GitHub artifact quota is recalculating');
assert.match(pagesBuilder, /proxyforge-github-hero\.png/i, 'GitHub Pages builder should publish the branded ProxyForge hero asset');
assert.match(pagesBuilder, /copySiteAssets/i, 'GitHub Pages builder should copy local brand assets into the Pages artifact');
assert.match(pagesBuilder, /stripReadmeChrome/i, 'GitHub Pages builder should prevent GitHub-only README HTML from rendering as plaintext');
assert.match(pagesBuilder, /code-block/i, 'GitHub Pages builder should render fenced code as styled code blocks');
assert.doesNotMatch(pagesBuilder, /RELEASE_CHECKLIST|RELEASE_EVIDENCE|release-checklist|release-evidence/i, 'GitHub Pages builder should not publish internal release checklist/evidence docs');
assert.match(securityPolicy, /authorized|Alpha Scope|Reporting Vulnerabilities|Secret Handling|Responsible Use|GitHub Security Advisory/i, 'SECURITY.md should document authorized use, private reporting, secret handling, and responsible-use boundaries');
assert.match(securityPolicy, /proxyforge-public\/security\/advisories\/new/i, 'SECURITY.md should point private security reports at the public repository');
assert.equal(countsJson.version, packageJson.version, 'docs/counts.json should match package version');
assert.equal(countsJson.workbench_surfaces_from_readme, 20, 'docs/counts.json should match the README workbench count');
assert.equal(brandManifest.version, packageJson.version, 'brand manifest should match package version');
assert.match(versionBadge, /version: 0\.1\.0-alpha\.1|0\.1\.0-ALPHA\.1/, 'version badge should match the alpha version');
assert.match(licenseBadge, /license: MIT|>MIT</, 'license badge should match package MIT license');
assert.match(workbenchesBadge, /workbenches: 20|>20</, 'workbench badge should match README and counts JSON');
assert.doesNotMatch(`${readme}\n${securityPolicy}\n${installGuide}\n${versionBadge}\n${licenseBadge}\n${workbenchesBadge}\n${JSON.stringify(brandManifest)}`, /0\.1\.0-beta\.1|TBD \/ Authorized Use|workbenches: 15|the-vibe-dev\/pffix/i, 'public release metadata should not contain stale beta/license/count/repo values');
assert.match(viteConfig, /\*\*\/\.gitignored\/\*\*|\*\*\/test-results\/\*\*|\*\*\/release\/\*\*/i, 'Vite dev server should ignore generated artifact directories during browser smokes');
assert.match(electronMain, /const devServerUrl = app\.isPackaged \? undefined : process\.env\.VITE_DEV_SERVER_URL;/, 'packaged Electron builds should ignore VITE_DEV_SERVER_URL');
assert.match(electronMain, /if \(!app\.isPackaged && process\.env\.VITE_DEV_SERVER_URL\)/, 'renderer URL authorization should only allow dev origins outside packaged builds');

assertScript('build', /tsc --noEmit -p tsconfig\.app\.json && vite build && tsc -p electron\/tsconfig\.json/);
assertScript('dist:linux', /electron-builder --linux AppImage deb/);
assertScript('dist:win', /electron-builder --win nsis portable/);
assertScript('dist:win:zip', /electron-builder --win zip --config\.win\.signAndEditExecutable=false/);
assertScript('dist:linux', /--publish never/);
assertScript('dist:win', /--publish never/);
assertScript('dist:win:zip', /--publish never/);
assertScript('release:smoke', /node scripts\/release-smoke\.mjs/);
assertScript('release:smoke:linux', /scripts\/release-smoke\.mjs --platform linux/);
assertScript('release:smoke:windows', /scripts\/release-smoke\.mjs --platform windows/);
assertScript('release:live:source', /scripts\/live-validation\.mjs --lane linux/);
assertScript('release:live:windows', /scripts\/live-validation\.mjs --lane windows/);
assertScript('release:trust', /node scripts\/release-trust\.mjs --out test-results\/release-trust/);
assertScript('release:fuses', /node scripts\/electron-fuse-policy\.mjs --check-config/);
assertScript('release:license', /node tests\/release-package-license\.mjs/);
assertScript('release:preflight', /node scripts\/release-publish-preflight\.mjs/);
assertScript('test:automation-service-smoke', /npm run build && node tests\/automation-service-smoke\.mjs/);
assertScript('test:release', /node tests\/release-readiness\.mjs && node tests\/release-runtime-workflow\.mjs/);
assertScript('test:release:fuses', /node tests\/electron-fuse-policy\.mjs/);
assertScript('test:private-output', /node tests\/private-output-permissions\.mjs/);
assertScript('test:roadmap', /node tests\/roadmap-completion\.mjs/);
assertScript('test:release:browser-routing', /node tests\/release-browser-routing\.mjs/);
assertScript('test:scanner', /node tests\/scanner-passive-engine\.mjs && node tests\/active-scanner\.mjs && node tests\/scanner-live-calibration\.mjs/);
assertScript('test:ci:fast', /node tests\/ci-fast-suite\.mjs/);
assertScript('test:ci:full', /node tests\/ci-full-suite\.mjs/);
assertScript('test:ci:nightly-policy', /node tests\/ci-nightly-policy\.mjs/);
assertScript('test:vulnerable-fixture', /node tests\/vulnerable-fixture-app\.mjs/);
assertScript('test:security-review', /node tests\/security-review-engine\.mjs/);
assertScript('test:browser-launcher', /node tests\/browser-launcher\.mjs/);
assertScript('test:session-cookie-jar', /node tests\/session-cookie-jar\.mjs/);
assertScript('test:session-macro', /node tests\/session-macro-engine\.mjs/);
assertScript('test:session-replay', /node tests\/session-replay-engine\.mjs/);
assertScript('test:intruder-oast-correlation', /node tests\/intruder-oast-correlation\.mjs/);
assertScript('test:repeater-oast-workflow', /node tests\/repeater-oast-workflow\.mjs/);
assertScript('test:proxy-listener', /node tests\/proxy-listener-engine\.mjs/);
assertScript('test:intercept', /node tests\/intercept-engine\.mjs/);
assertScript('test:proxy-history', /node tests\/proxy-history-engine\.mjs/);
assertScript('test:websocket', /node tests\/websocket-engine\.mjs/);
assertScript('test:enterprise-policy', /node tests\/enterprise-policy-transport\.mjs/);
assertScript('test:organizer', /node tests\/organizer-evidence-engine\.mjs/);
assertScript('test:platform-release', /node tests\/platform-release-engine\.mjs/);
assertScript('test:ui-scale-production', /node tests\/ui-scale-production-engine\.mjs/);
assertScript('test:platform-shell-production', /node tests\/platform-shell-production-engine\.mjs/);
assertScript('test:agent-control-production', /node tests\/agent-control-production-engine\.mjs/);
assertScript('test:ai-provider-production', /node tests\/ai-provider-production-engine\.mjs/);
assertScript('test:release-security-production', /node tests\/release-security-production-engine\.mjs/);
assertScript('test:release-trust-production', /node tests\/release-trust-production-engine\.mjs/);
assertScript('test:fast-regression-production', /node tests\/fast-regression-production-engine\.mjs/);
assertScript('test:full-nightly-production', /node tests\/full-nightly-production-engine\.mjs/);
assertScript('test:full-nightly-history', /node tests\/full-nightly-history-engine\.mjs/);
assertScript('test:install-docs-production', /node tests\/install-docs-production-engine\.mjs/);
assertScript('test:windows-package-production', /node tests\/windows-package-production-engine\.mjs/);
assertScript('test:linux-package-production', /node tests\/linux-package-production-engine\.mjs/);
assertScript('test:report', /node tests\/report-engine\.mjs && node tests\/report-pdf-visual-qa\.mjs/);
assertScript('test:agent', /node tests\/agent-cli\.mjs && node tests\/agent-option-audit\.mjs/);
assertScript('test:project-store-v2', /node tests\/project-store-v2\.mjs/);
assertScript('test:project-lifecycle', /node tests\/project-lifecycle-ipc-contract\.mjs/);
assertScript('test:project-import-compatibility', /node tests\/project-import-compatibility-engine\.mjs/);
assertScript('test:extension-third-party-compatibility', /node tests\/extension-third-party-compatibility-engine\.mjs/);
assertScript('test:project-settings', /node tests\/project-store-settings-workflow\.mjs/);
assertScript('test:project-cookie-jar', /node tests\/project-store-cookie-jar-workflow\.mjs/);
assertScript('test:project-repeater', /node tests\/project-store-repeater-workflow\.mjs/);
assertScript('test:project-intruder', /node tests\/project-store-intruder-workflow\.mjs/);
assertScript('test:project-scanner', /node tests\/project-store-scanner-workflow\.mjs/);
assertScript('test:project-issue-report', /node tests\/project-store-issue-report-workflow\.mjs/);
assertScript('test:project-websocket', /node tests\/project-store-websocket-workflow\.mjs/);
assertScript('test:proxy-store-workflow', /node tests\/proxy-project-store-workflow\.mjs/);
assertScript('test:oast-store-workflow', /node tests\/project-store-oast-workflow\.mjs/);
assertScript('test:oast-signed-evidence', /node tests\/project-store-oast-signed-evidence\.mjs/);
assertScript('test:scanner-oast-ssrf', /node tests\/scanner-oast-ssrf\.mjs/);

assert.equal(packageJson.build?.appId, 'dev.proxyforge.desktop', 'release app id should be stable');
assert.equal(packageJson.build?.productName, 'ProxyForge', 'release product name should be user-facing');
assert.equal(packageJson.author?.name, 'ProxyForge Maintainers', 'Linux deb metadata should include a maintainer name');
assert.match(packageJson.author?.email ?? '', /@/, 'Linux deb metadata should include a maintainer email');
assert.equal(packageJson.build?.directories?.output, 'release', 'release artifacts should land in the ignored release directory');
assertIncludes(packageJson.build?.files ?? [], 'dist/**/*', 'renderer build should be packaged');
assertIncludes(packageJson.build?.files ?? [], 'dist-electron/**/*', 'Electron build should be packaged');
assertIncludes(packageJson.build?.files ?? [], 'scripts/proxyforge-agent.mjs', 'agentic CLI wrapper should be packaged');
assertIncludes(packageJson.build?.files ?? [], 'scripts/proxyforge-automation-service.mjs', 'automation service runner should be packaged');
assertIncludes(packageJson.build?.files ?? [], 'scripts/release-smoke.mjs', 'release smoke runner should be packaged');
assertIncludes(packageJson.build?.files ?? [], 'scripts/release-trust.mjs', 'release trust generator should be packaged');
assertIncludes(packageJson.build?.files ?? [], 'docs/INSTALL_LINUX_WINDOWS.md', 'end-user install guide should be packaged');
assertIncludes(packageJson.build?.files ?? [], 'docs/OPERATOR_GUIDE.md', 'operator guide should be packaged');
assertDoesNotInclude(packageJson.build?.files ?? [], 'docs/RELEASE_CHECKLIST.md', 'internal release checklist should not be packaged');
assertDoesNotInclude(packageJson.build?.files ?? [], 'docs/RELEASE_EVIDENCE.md', 'internal release evidence should not be packaged');
assertIncludes(packageJson.build?.files ?? [], 'docs/agents/**/*', 'agent docs should be packaged');
assertIncludes(packageJson.build?.files ?? [], 'LICENSE', 'project license notice should be packaged');
assertIncludes(packageJson.build?.files ?? [], 'package.json', 'package metadata should be packaged');
assert.ok(JSON.stringify(packageJson.build?.extraResources ?? []).includes('"from":"LICENSE"'), 'project license notice should also be copied beside packaged resources');
assertIncludes(packageJson.build?.linux?.target ?? [], 'AppImage', 'Linux release should build AppImage');
assertIncludes(packageJson.build?.linux?.target ?? [], 'deb', 'Linux release should build deb');
assertIncludes(packageJson.build?.deb?.depends ?? [], 'libgbm1', 'Linux deb should declare Electron libgbm runtime dependency');
assertIncludes(packageJson.build?.deb?.depends ?? [], 'libasound2', 'Linux deb should declare Electron ALSA runtime dependency');
assertIncludes(packageJson.build?.win?.target ?? [], 'nsis', 'Windows release should build NSIS installer');
assertIncludes(packageJson.build?.win?.target ?? [], 'portable', 'Windows release should build portable exe');

assertFile('dist/index.html', 'renderer output should exist after npm run build');
assertFile('dist-electron/main.js', 'Electron main output should exist after npm run build');
assertFile('dist-electron/preload.js', 'Electron preload output should exist after npm run build');
assertFile('dist-electron/headlessRunner.js', 'headless CLI output should exist after npm run build');
assertFile('dist-electron/releaseWorkflowSmoke.js', 'packaged runtime workflow smoke should exist after npm run build');
assertFile('dist-electron/releaseBrowserRoutingSmoke.js', 'packaged browser routing smoke should exist after npm run build');
assertFile('dist-electron/releaseCookieDpapiSmoke.js', 'packaged Windows DPAPI cookie smoke should exist after npm run build');
assertFile('dist-electron/proxyEngine.js', 'proxy engine should be packaged for desktop runtime');
assertFile('dist-electron/sessionEngine.js', 'session replay engine should be packaged for desktop runtime');
assertFile('dist-electron/certManager.js', 'certificate manager should be packaged for desktop runtime');
assertFile('dist-electron/callbackListenerService.js', 'callback listener service should be packaged for desktop runtime');
assertFile('dist-electron/services/projectLifecycleService.js', 'project lifecycle service should be packaged for desktop runtime');
assertFile('dist-electron/reportEngine.js', 'report engine should be packaged for desktop runtime');
assertFile('dist-electron/repeaterDesyncRaceEngine.js', 'Repeater desync/race engine should be packaged for desktop runtime');
assertFile('dist-electron/enterprisePolicyTransport.js', 'enterprise policy transport should be packaged for desktop runtime');
assertFile('dist-electron/projectStore.js', 'Project Store v2 should be packaged for desktop runtime');
assertFile('dist-electron/callbackListenerService.js', 'callback listener should be packaged for durable OAST runtime');
assertFile('scripts/release-smoke.mjs', 'release smoke runner should exist');
assertFile('scripts/release-trust.mjs', 'release trust generator should exist');
assertFile('scripts/electron-fuse-policy.mjs', 'Electron fuse policy helper should exist');
assertFile('scripts/release-publish-preflight.mjs', 'release publish preflight should exist');
assertFile('scripts/proxyforge-automation-service.mjs', 'automation service smoke runner should exist');
assertFile('scripts/release-deb-container-smoke.sh', 'Linux deb clean-container smoke helper should exist');
assertFile('.github/workflows/nightly-full-suite.yml', 'nightly full-suite workflow should exist');
assertFile('tests/release-runtime-workflow.mjs', 'release runtime workflow smoke should exist');
assertFile('tests/electron-fuse-policy.mjs', 'Electron fuse policy smoke should exist');
assertFile('tests/release-package-license.mjs', 'packaged license verifier should exist');
assertFile('tests/private-output-permissions.mjs', 'private output permission regression should exist');
assertFile('tests/roadmap-completion.mjs', 'roadmap completion smoke should exist');
assertFile('tests/release-browser-routing.mjs', 'release browser routing smoke should exist');
assertFile('tests/ci-nightly-policy.mjs', 'nightly CI policy gate should exist');
assertFile('tests/fixtures/vulnerable-app/server.mjs', 'live vulnerable fixture app should exist');
assertFile('tests/vulnerable-fixture-app.mjs', 'live vulnerable fixture regression should exist');
assertFile('tests/report-pdf-visual-qa.mjs', 'PDF visual QA smoke should exist');
assertFile('tests/organizer-evidence-engine.mjs', 'Organizer parity evidence smoke should exist');
assertFile('tests/scanner-passive-engine.mjs', 'Scanner passive/dedupe parity smoke should exist');
assertFile('tests/scanner-live-calibration.mjs', 'Scanner live calibration smoke should exist');
assertFile('tests/platform-release-engine.mjs', 'Platform/Release parity evidence smoke should exist');
assertFile('tests/ui-scale-production-engine.mjs', 'UI Scale production evidence smoke should exist');
assertFile('tests/project-import-compatibility-engine.mjs', 'Project import compatibility smoke should exist');
assertFile('tests/customer-scale-interop-engine.mjs', 'customer-scale interop profiling smoke should exist');
assertFile('tests/extension-third-party-compatibility-engine.mjs', 'third-party Extension SDK compatibility smoke should exist');
assertFile('tests/project-store-v2.mjs', 'Project Store v2 persistence smoke should exist');
assertFile('tests/ipc-contract-security.mjs', 'Typed IPC capability and audit contract smoke should exist');
assertFile('tests/project-store-target-inventory-workflow.mjs', 'Project Store target inventory workflow smoke should exist');
assertFile('tests/project-store-run-state-workflow.mjs', 'Project Store automation AI extension run-state workflow smoke should exist');
assertFile('tests/project-store-live-run-state-wiring.mjs', 'Project Store live run-state wiring smoke should exist');
assertFile('tests/platform-shell-production-engine.mjs', 'Platform Shell production evidence smoke should exist');
assertFile('tests/agent-control-production-engine.mjs', 'Agent Control production evidence smoke should exist');
assertFile('tests/ai-provider-production-engine.mjs', 'AI Provider production evidence smoke should exist');
assertFile('tests/release-security-production-engine.mjs', 'Release Security production evidence smoke should exist');
assertFile('tests/release-trust-production-engine.mjs', 'Release Trust production evidence smoke should exist');
assertFile('tests/fast-regression-production-engine.mjs', 'Fast Regression production evidence smoke should exist');
assertFile('tests/full-nightly-production-engine.mjs', 'Full/Nightly production evidence smoke should exist');
assertFile('tests/full-nightly-history-engine.mjs', 'Full/Nightly retained history evidence smoke should exist');
assertFile('tests/install-docs-production-engine.mjs', 'Install Docs production evidence smoke should exist');
assertFile('tests/windows-package-production-engine.mjs', 'Windows Package production evidence smoke should exist');
assertFile('tests/linux-package-production-engine.mjs', 'Linux Package production evidence smoke should exist');
assertFile('tests/automation-service-smoke.mjs', 'Automation installed-host service smoke should exist');
assertFile('docs/INSTALL_LINUX_WINDOWS.md', 'Linux/Windows install guide should exist');
assertFile('docs/OPERATOR_GUIDE.md', 'operator guide should exist');
assertFile('docs/RELEASE_NOTES_v0.1.0-alpha.1.md', 'alpha release notes should exist');
assertFile('docs/HOTFIX_PROCESS.md', 'alpha hotfix process should exist');
assertFile('docs/agents/MVP_OPTION_AUDIT.md', 'MVP agent option audit should exist');

assert.match(gitignore, /^release\/$/m, 'release artifacts should stay out of git');
assert.match(gitignore, /^\.gitignored\/$/m, 'local quarantine folder should stay out of git');

assert.match(installGuide, /Linux And Windows Install Guide|release:smoke:linux|release:smoke:windows|ProxyForge-0\.1\.0-alpha\.1\.AppImage|ProxyForge-0\.1\.0-alpha\.1-win\.zip|PROXYFORGE_RELEASE_SMOKE|release-deb-container-smoke|browser-trust-store|dpapi-cookie/i, 'install guide should cover Linux/Windows artifacts and smoke commands');
assert.match(installGuide, /OPERATOR_GUIDE|day-to-day proxy|OAST|scanner|replay|exploit|troubleshooting/i, 'install guide should hand off to the operator guide');
assert.match(operatorGuide, /Operating Boundaries|First-Run Checklist|Proxy And Certificate Workflow|Browser And Session Operations|Traffic Search And Viewing|Replay, Desync, Race, And Intruder|Scanner And Crawl Workflow|Extensions|Collaborator And OAST|Exploit Lab Safety|Reporting And Submission|Agentic Operation|Recovery And Troubleshooting|Production Signoff/i, 'operator guide should cover production operator workflows');
assert.match(operatorGuide, /full tokens, cookies, keys, headers, callbacks, raw requests, and raw responses|full fidelity|report export/i, 'operator guide should preserve full-fidelity executor artifacts until report export');
assert.match(operatorGuide, /windows-trust-runner|ERROR_NOT_SUPPORTED|trust-store lane pinned/i, 'operator guide should document the nonblocking Windows trust-store pin');
assert.match(operatorGuide, /CONNECT tunnels|client-to-server bytes|server-to-client bytes|total tunnel bytes|close reason/i, 'operator guide should document CONNECT tunnel byte-accounting evidence');
assert.match(operatorGuide, /proxyforge-proxy-http-listener-capture-package|raw request and response|operational secret/i, 'operator guide should document HTTP listener capture evidence packages');
assert.match(operatorGuide, /proxyforge-proxy-history-filter-set-package|saved predicates|annotation lane counts|operational secret signals/i, 'operator guide should document advanced Proxy history filter-set packages');
assert.match(operatorGuide, /proxyforge-proxy-http2-multiplexing-report|stream-id coverage|multiplexed authority buckets|ALPN or h2c/i, 'operator guide should document HTTP/2 multiplexing evidence packages');
assert.match(operatorGuide, /proxyforge-websocket-capture-evidence-package|bidirectional client\/server frame counts|text and binary payload byte accounting|operational secret signals/i, 'operator guide should document WebSocket capture evidence packages');
assert.match(operatorGuide, /proxyforge-websocket-intercept-rewrite-replay-evidence-package|client and server intercept decisions|edited-forward frames|saved replay payloads|rewritten replay proof/i, 'operator guide should document WebSocket intercept/rewrite/replay evidence packages');
assert.match(operatorGuide, /proxyforge-websocket-state-transcript-evidence-package|state graph\/filter\/export metadata|truncation counts|JSON\/Markdown transcript exports|large-transcript import counts/i, 'operator guide should document WebSocket state/transcript evidence packages');
assert.match(operatorGuide, /proxyforge-search-parity-evidence-package|full-text metadata\/body\/raw search|semantic ranking|persistent local index restore\/reuse|search-index\/view handoff/i, 'operator guide should document Search parity evidence packages');
assert.match(operatorGuide, /proxyforge-viewer-parity-evidence-package|Pretty JSON|GraphQL|binary\/hex views|replay comparison exports|report attachment handoff/i, 'operator guide should document Viewer parity evidence packages');
assert.match(operatorGuide, /proxyforge-sequencer-parity-evidence-package|cookie\/form\/custom location extraction|5,000-sample reliability gates|20,000-sample FIPS-ready cap behavior/i, 'operator guide should document Sequencer parity evidence packages');
assert.match(operatorGuide, /proxyforge-logger-parity-evidence-package|tool-generated traffic capture|archive imports|conflict\/dedupe review|signed provenance/i, 'operator guide should document Logger parity evidence packages');
assert.match(operatorGuide, /proxyforge-organizer-parity-evidence-package|multi-tool collections|reviewer SLA|passphrase-sealed packages|conflict audit/i, 'operator guide should document Organizer parity evidence packages');
assert.match(operatorGuide, /proxyforge-extension-parity-evidence-package|catalog and local manifest|signed updates|runtime diagnostics/i, 'operator guide should document Extension parity evidence packages');
assert.match(operatorGuide, /proxyforge-extension-third-party-sdk-compatibility-package|third-party extension SDK|multi-message|session token refresh|package refresh/i, 'operator guide should document third-party Extension SDK compatibility packages');
assert.match(operatorGuide, /proxyforge-project-parity-evidence-package|local save\/restore|schema migration|browser cookie extraction/i, 'operator guide should document Project parity evidence packages');
assert.match(operatorGuide, /proxyforge-project-import-compatibility-evidence-package|legacy proxy XML, HAR, raw HTTP, JSONL, and ProxyForge v1|duplicate and conflict diagnostics|package refresh/i, 'operator guide should document Project import compatibility evidence packages');
assert.match(operatorGuide, /proxyforge-project-customer-scale-interop-evidence-package|3,000-plus imported exchanges|Search\/Viewer\/Logger\/Target scale|Project Store backup\/reopen/i, 'operator guide should document customer-scale Project interop packages');
assert.match(operatorGuide, /proxyforge-project-customer-workspace-restore-interop-package|four imported workspace profiles|Project Store backup\/reopen proof|restored-exchange integrity/i, 'operator guide should document customer workspace restore interop packages');
assert.match(operatorGuide, /proxyforge-safety-enterprise-parity-evidence-package|scope gates, throttles, request caps|SSO mapping\/federation fixtures/i, 'operator guide should document Safety/Enterprise parity evidence packages');
assert.match(operatorGuide, /proxyforge-platform-release-parity-evidence-package|dense React\/Vite navigation|Linux and Windows Electron shell launch|Windows trust-store pinning/i, 'operator guide should document Platform/Release parity evidence packages');
assert.match(operatorGuide, /proxyforge-ui-scale-production-evidence-package|large-project UI scale|responsive overflow proof|bounded row windows|report-export-only/i, 'operator guide should document UI Scale production evidence packages');
assert.match(operatorGuide, /proxyforge-platform-shell-production-evidence-package|Linux and Windows packaged Electron shell launch|external-cwd app\.asar agent execution|known host-limit pins/i, 'operator guide should document Platform Shell production evidence packages');
assert.match(operatorGuide, /proxyforge-agent-control-production-evidence-package|70-command Codex\/Claude\/Vantix surface|persistent MITM|long-running soak/i, 'operator guide should document Agent Control production evidence packages');
assert.match(operatorGuide, /proxyforge-ai-provider-production-evidence-package|Codex CLI provider|Claude CLI provider|OpenAI-compatible HTTP provider|no direct action traffic/i, 'operator guide should document AI Provider production evidence packages');
assert.match(operatorGuide, /proxyforge-release-security-production-evidence-package|formal zero-finding release security review|local listeners|platform pins|full-fidelity executor material/i, 'operator guide should document Release Security production evidence packages');
assert.match(operatorGuide, /proxyforge-release-trust-production-evidence-package|SBOM|SHA-256 checksums|provenance|signing\/notarization state/i, 'operator guide should document Release Trust production evidence packages');
assert.match(operatorGuide, /proxyforge-fast-regression-production-evidence-package|completed every required step|release\/platform\/security\/project\/agent\/browser\/proxy\/scanner\/repeater\/intruder\/report lanes/i, 'operator guide should document Fast Regression production evidence packages');
assert.match(operatorGuide, /proxyforge-full-nightly-production-evidence-package|trend dashboard|historical full-run pass|plan-only summary validates metadata/i, 'operator guide should document Full/Nightly production evidence packages');
assert.match(operatorGuide, /proxyforge-full-nightly-retained-history-evidence-package|retained runtime summaries|ci-full-suite-history\/dashboard\.json|plan-only summaries are excluded/i, 'operator guide should document Full/Nightly retained history packages');
assert.match(operatorGuide, /proxyforge-install-docs-production-evidence-package|Linux\/Windows install guide|operator guide|agent docs|replay\/desync\/race\/scanner\/exploit\/OAST/i, 'operator guide should document Install Docs production evidence packages');
assert.match(operatorGuide, /proxyforge-windows-package-production-evidence-package|NSIS|portable|win-unpacked|DPAPI|trust-store pin|portable-wrapper stdout/i, 'operator guide should document Windows Package production evidence packages');
assert.match(operatorGuide, /proxyforge-linux-package-production-evidence-package|AppImage|deb|linux-unpacked|clean-container|trusted-CA|known warning/i, 'operator guide should document Linux Package production evidence packages');
assert.match(operatorGuide, /proxyforge-collaborator-parity-evidence-package|DNS\/HTTP\/SMTP payload generation|signed poll batches|callback replay execution|report-package persistence/i, 'operator guide should document Collaborator/OAST parity evidence packages');
assert.match(operatorGuide, /proxyforge-automation-parity-evidence-package|automation-scheduler-tick|automation-ci-export|durable scheduler queues|CI\/headless provider presets/i, 'operator guide should document Automation parity evidence packages and agent commands');
assert.match(operatorGuide, /proxyforge-ai-parity-evidence-package|Codex provider coverage|Claude provider coverage|OpenAI-compatible local provider coverage|controlled actions|report-export-only redaction/i, 'operator guide should document AI parity evidence packages and provider coverage');
assert.match(operatorGuide, /proxyforge-scanner-passive-dedupe-parity-package|security headers, cookie flags, CORS, cache controls, mixed content, information disclosure, authz metadata, server errors|route-variant dedupe/i, 'operator guide should document Scanner passive/dedupe parity packages');
assert.match(operatorGuide, /proxyforge-active-scan-check-pack-evidence-package|supported and unsupported check accounting|operational secret signals/i, 'operator guide should document Active Scanner check-pack evidence packages');
assert.match(operatorGuide, /proxyforge-target-parity-evidence-package|crawl-path lineage|authenticated session profile reuse|query\/form\/path\/header\/cookie\/body insertion points/i, 'operator guide should document Target parity evidence packages');
assert.match(operatorGuide, /proxyforge-crawl-audit-insertion-evidence-package|query\/form\/path insertion coverage|out-of-scope skips/i, 'operator guide should document Crawl audit insertion evidence packages');
assert.match(operatorGuide, /proxyforge-scanner-retest-evidence-delta-package|baseline proof|retest proof|outcome history/i, 'operator guide should document Scanner retest evidence delta packages');
assert.match(operatorGuide, /proxyforge-anvil-custom-check-parity-package|plain-text `?\.anvil`? definition|custom-only headless run/i, 'operator guide should document Anvil custom scan-check parity packages');
assert.match(operatorGuide, /proxyforge-proxy-cross-tool-handoff-package|Repeater raw requests|Scanner candidates|Reports attachment fingerprints/i, 'operator guide should document Proxy cross-tool handoff packages');
assert.match(operatorGuide, /proxyforge-proxy-intercept-evidence-package|edited message|synthetic drop response/i, 'operator guide should document request/response intercept evidence packages');
assert.match(operatorGuide, /proxyforge-proxy-match-replace-rule-library|large-rule-set warnings|sample before\/after rewrites/i, 'operator guide should document match/replace rule-library packages');
assert.match(operatorGuide, /proxyforge-proxy-browser-proxy-chain-diversity-package|Chromium, Chrome, Edge, and Firefox|upstream-auth, CONNECT chain, PAC, and direct|report-export-only redaction/i, 'operator guide should document Proxy browser/proxy-chain diversity packages');
assert.match(operatorGuide, /search-index --soak|automation-run|automation-scheduler-tick|automation-parity-export|automation-service-plan|automation-service-smoke|live-target-profile|scanner-run --soak|bulk-replay --soak|intruder-run|repeater-desync-probe|repeater-race-run|--max-release-skew-ms|extension-fixtures|callback-provider-probe|callback-relay-soak|callback-retention-prune|bundle-verify/i, 'operator guide should cover agent-accessible high-risk workflows');
assert.match(operatorGuide, /proxyforge-repeater-parity-evidence-package|manual request editing\/send|tab groups\/workspaces|session profile injection/i, 'operator guide should document Repeater parity evidence packages');
assert.match(operatorGuide, /proxyforge-repeater-race-desync-production-package|parser-differential framing|single-packet soak proof|release-skew\/race-window budgets/i, 'operator guide should document Repeater race/desync production packages');
assert.match(operatorGuide, /proxyforge-exploit-parity-evidence-package|non-destructive previews|approval\/scope\/stop-on-proof gates|Repeater backend execution|full-fidelity operational raw material/i, 'operator guide should document Exploit Lab parity evidence packages');
assert.match(operatorGuide, /proxyforge-intruder-checkpoint-resume-package|checkpoint offsets|resource-pool state|payload-rule state/i, 'operator guide should document Intruder checkpoint/resume packages');
assert.match(operatorGuide, /proxyforge-intruder-grep-extract-comparison-package|baseline\/candidate deltas|clustered response signatures|statistical rankings/i, 'operator guide should document Intruder grep/extract comparison packages');
assert.match(operatorGuide, /proxyforge-intruder-live-target-profile-package|live-target diversity|high-volume streaming|package refresh|resource-pool concurrency/i, 'operator guide should document Intruder live-target profile packages');
assert.match(operatorGuide, /proxyforge-decoder-parity-evidence-package|JWT\/JWS signing preview|JWE decrypt\/edit\/re-encrypt|binary\/hex inspection/i, 'operator guide should document Decoder parity evidence packages');
assert.match(operatorGuide, /proxyforge-comparer-parity-evidence-package|line\/unified diff|structured HTTP diff|replay\/baseline delta review/i, 'operator guide should document Comparer parity evidence packages');
assert.match(operatorGuide, /proxyforge-report-parity-evidence-package|Markdown\/HTML\/JSON\/PDF\/bundle rendering|tamper rejection|cross-tool evidence attachment/i, 'operator guide should document Report parity evidence packages');
assert.match(operatorGuide, /proxyforge-report-external-bundle-diversity-package|four external recipient\/channel\/key\/template profiles|canonical JSON round trips|cross-tool attachment diversity/i, 'operator guide should document Report external bundle diversity packages');
assert.match(operatorGuide, /proxyforge-report-template-library-interop-package|template library export|duplicate conflict review|variable resolution/i, 'operator guide should document Report template library interop packages');
assert.match(agenticInterface, /mitm-start|--ensure-ca|--upstream-tls strict\|relaxed|chromium-capture|sequencer-analyze|automation-run|automation-scheduler-tick|automation-parity-export|automation-service-plan|automation-service-smoke|replay-run|bulk-replay|live-target-profile|intruder-run|repeater-desync-probe|repeater-race-run|scanner-plan|scanner-run --soak|scanner-retest|scanner-evidence-export|anvil-plan|anvil-run|anvil-package-export|extension-fixtures|callback-poll|callback-provider-probe|callback-relay-soak|exploit-run|vantix/i, 'agentic interface plan should cover MITM project-CA/TLS controls, browser, Sequencer, automations, replay, bulk replay, live target profiling, Intruder, Repeater desync/race, scanner, Anvil, extensions, callback, exploit, and Vantix commands');
assert.match(agenticInterface, /proxyforge-ai-provider-production-evidence-package|Codex CLI|Claude CLI|OpenAI-compatible HTTP|controlled actions|no direct action traffic/i, 'agentic interface should document AI provider production evidence and action boundary');
assert.match(operatorGuide, /--redirect follow|--connection keep-alive|--timeout/i, 'operator guide should document agent replay transport controls');
assert.match(agenticInterface, /MVP option audit|MVP_OPTION_AUDIT/i, 'agentic interface should require the post-MVP agent option audit gate');
assertFile('scripts/proxyforge-agent.mjs', 'agentic CLI wrapper should exist');
assert.match(codexAgentDocs, /sequencer-analyze|automation-run|automation-scheduler-tick|automation-parity-export|automation-service-plan|automation-service-smoke|replay-run|bulk-replay|live-target-profile|intruder-run|repeater-desync-probe|repeater-race-run|scanner-plan|scanner-run --soak|scanner-retest|scanner-evidence-export|anvil-plan|anvil-run|anvil-package-export|extension-fixtures|report-export/i, 'Codex agent docs should describe Sequencer, automations, replay, bulk replay, live target profiling, Intruder, desync/race, scanner, Anvil, extension, and report commands');
assert.match(claudeAgentDocs, /sequencer-analyze|automation-run|automation-scheduler-tick|automation-ci-export|automation-service-smoke|replay-matrix|bulk-replay|live-target-profile|intruder-run|repeater-desync-plan|scanner-run|scanner-retest|scanner-evidence-export|anvil-plan|anvil-run|anvil-package-export|extension-fixtures|callback-poll|exploit-preview/i, 'Claude agent docs should describe Sequencer, automations, replay, bulk replay, live target profiling, Intruder, desync planning, scanner, Anvil, extension, callback, and exploit preview commands');
assert.match(vantixAgentDocs, /vantix-sync|vantix-intel-export|sequencer-analyze|automation-run|automation-scheduler-tick|automation-parity-export|automation-service-plan|automation-service-smoke|bulk-replay|live-target-profile|intruder-run|scanner-run|scanner-retest|scanner-evidence-export|anvil-plan|anvil-run|anvil-package-export|extension-fixtures|repeater-race-run|report-export/i, 'Vantix agent docs should describe Vantix handoff, Sequencer, automations, bulk replay, live target profiling, Intruder, scanner, Anvil, extensions, and Repeater race commands');
assert.match(agentSchemas, /proxyforge-agent-result|schemaVersion|status|httpsInspection|upstreamTlsMode|project-ca-status|scanner-live-calibration-soak|sequencer-large-sample-soak|redirectHistory|finalUrl|bulk-replay-high-volume-soak|attackModeMatrix|payloadTransformations|intruder-high-volume-soak|parserDifferential|queued-followup|repeater-race-high-concurrency-soak|rawTranscript|releaseSkewMs/i, 'agent schema docs should describe the JSON envelope and MITM/Scanner/Sequencer/replay transport/bulk replay/Intruder/desync/race output');
assert.match(agentSchemas, /proxyforge-repeater-parity-evidence-package|manualRequestEditorCovered|tabsAndGroupedWorkspacesCovered|sessionProfileInjectionCovered/i, 'agent schema docs should describe Repeater parity evidence packages');
assert.match(agentSchemas, /proxyforge-repeater-race-desync-production-package|parserDifferentialCovered|singlePacketRaceSoakCovered|timingBudgetCovered|packageRefreshCovered/i, 'agent schema docs should describe Repeater race/desync production packages');
assert.match(agentSchemas, /proxyforge-agent-automation-parity-evidence-package|macroRecordingCovered|durableSchedulerQueueCovered|ciProviderPresetsCovered|operationalSecretsPreserved/i, 'agent schema docs should describe Automation parity evidence packages');
assert.match(agentSchemas, /proxyforge-automation-service-installed-host-smoke-package|serviceStarted|statusProbeCovered|schedulerTickCovered|reportPhaseOnlyRedaction/i, 'agent schema docs should describe Automation installed-host service smoke packages');
assert.match(agentSchemas, /proxyforge-ai-parity-evidence-package|codexProviderCovered|claudeProviderCovered|openAiCompatibleProviderCovered|benchmarkReplayCovered|controlledActionsCovered/i, 'agent schema docs should describe AI parity evidence packages');
assert.match(agentSchemas, /proxyforge-extension-parity-evidence-package|catalogInstallCovered|sandboxApiCovered|signedUpdatePolicyCovered|runtimeDiagnosticsCovered/i, 'agent schema docs should describe Extension parity evidence packages');
assert.match(agentSchemas, /proxyforge-extension-third-party-sdk-compatibility-package|contextMenuMultiSelectionCovered|sessionHandlingTokenRefreshCovered|unsupportedApisFailClosedCovered|packageRefreshCovered/i, 'agent schema docs should describe third-party Extension SDK compatibility packages');
assert.match(agentSchemas, /proxyforge-project-parity-evidence-package|localPersistenceRestoreCovered|proxyforgeJsonRoundTripCovered|schemaVersionMigrationCovered|cookieDecryptionReadinessCovered/i, 'agent schema docs should describe Project parity evidence packages');
assert.match(agentSchemas, /proxyforge-project-import-compatibility-evidence-package|legacyProxyXmlCorpusCovered|duplicateDetectionCovered|conflictPreservationCovered|packageRefreshCovered/i, 'agent schema docs should describe Project import compatibility evidence packages');
assert.match(agentSchemas, /proxyforge-project-customer-scale-interop-evidence-package|customerScaleCorpusCovered|searchViewerScaleCovered|repeaterScannerIntruderHandoffCovered|reportAttachmentScaleCovered/i, 'agent schema docs should describe customer-scale Project interop evidence packages');
assert.match(agentSchemas, /proxyforge-project-customer-workspace-restore-interop-package|multipleCustomerWorkspacesCovered|projectStoreBackupRestoreCovered|crossToolRestoreProfileCovered/i, 'agent schema docs should describe customer workspace restore interop evidence packages');
assert.match(agentSchemas, /proxyforge-proxy-browser-proxy-chain-diversity-package|multiBrowserFamilyCovered|linuxWindowsProfileCoverage|upstreamCredentialPreservationCovered|reportPhaseOnlyRedaction/i, 'agent schema docs should describe Proxy browser/proxy-chain diversity packages');
assert.match(agentSchemas, /proxyforge-safety-enterprise-parity-evidence-package|scopeGateCovered|approvalGateCovered|ssoFederationFixtureCovered|enterpriseBackendSoakCovered/i, 'agent schema docs should describe Safety/Enterprise parity evidence packages');
assert.match(agentSchemas, /proxyforge-platform-release-parity-evidence-package|denseNavigationCovered|linuxElectronShellCovered|windowsArtifactsCovered|windowsTrustStorePinCovered|fullNightlySuiteCovered/i, 'agent schema docs should describe Platform/Release parity evidence packages');
assert.match(agentSchemas, /proxyforge-ui-scale-production-evidence-package|desktopTabletMobileCovered|noViewportOverlapOrOverflow|largeProjectDataDensityCovered|latencyBudgetsCovered|productionReady/i, 'agent schema docs should describe UI Scale production evidence packages');
assert.match(agentSchemas, /proxyforge-platform-shell-production-evidence-package|linuxShellLaunchCovered|windowsShellLaunchCovered|externalCwdAgentCovered|knownHostLimitsPinned/i, 'agent schema docs should describe Platform Shell production evidence packages');
assert.match(agentSchemas, /proxyforge-agent-control-production-evidence-package|sourceCommandSurfaceCovered|packagedLinuxCommandSurfaceCovered|longRunningSoakCovered|policyAuditCovered/i, 'agent schema docs should describe Agent Control production evidence packages');
assert.match(agentSchemas, /proxyforge-ai-provider-production-evidence-package|codexCliProviderCovered|claudeCliProviderCovered|openAiCompatibleProviderCovered|noDirectActionTrafficCovered|productionReady/i, 'agent schema docs should describe AI Provider production evidence packages');
assert.match(agentSchemas, /proxyforge-release-security-production-evidence-package|formalSecurityReviewPassed|allSecurityCategoriesCovered|platformPinsCovered|reportPhaseOnlyRedaction|productionReady/i, 'agent schema docs should describe Release Security production evidence packages');
assert.match(agentSchemas, /proxyforge-release-trust-production-evidence-package|sbomGeneratedFromLockfile|sourceChecksumsCovered|provenanceStatementCovered|signingStatePinned|productionReady/i, 'agent schema docs should describe Release Trust production evidence packages');
assert.match(agentSchemas, /proxyforge-fast-regression-production-evidence-package|currentSummaryPassed|completedEveryStep|proxyScannerRepeaterIntruderCovered|reportAndSecurityCovered|productionReady/i, 'agent schema docs should describe Fast Regression production evidence packages');
assert.match(agentSchemas, /proxyforge-full-nightly-production-evidence-package|fullSuitePlanValid|trendDashboardCovered|historicalRuntimePassCovered|planOnlyBoundaryCovered|productionReady/i, 'agent schema docs should describe Full/Nightly production evidence packages');
assert.match(agentSchemas, /proxyforge-full-nightly-retained-history-evidence-package|minimumRuntimeHistoryCovered|currentRuntimeSummaryRetained|planOnlyRunsExcludedFromRuntimeHistory|digestIntegrityCovered/i, 'agent schema docs should describe Full/Nightly retained history evidence packages');
assert.match(agentSchemas, /proxyforge-full-nightly-hosted-retained-history-evidence-package|scheduledRunReceiptsCovered|retainedHistoryRestoreSaveCovered|hostedArtifactUploadCovered|retainedDashboardLinksHostedRuns/i, 'agent schema docs should describe Full/Nightly hosted retained history evidence packages');
assert.match(agentSchemas, /proxyforge-install-docs-production-evidence-package|installGuidePackaged|operatorGuidePackaged|packagedDocsSynchronized|agenticOperationCovered|highRiskWorkflowsCovered|reportPhaseOnlyRedaction/i, 'agent schema docs should describe Install Docs production evidence packages');
assert.match(agentSchemas, /proxyforge-windows-package-production-evidence-package|nativeArtifactsCovered|nsisInstallUninstallCovered|trustStorePinAccepted|portableWrapperPinned|reportPhaseOnlyRedaction/i, 'agent schema docs should describe Windows Package production evidence packages');
assert.match(agentSchemas, /proxyforge-linux-package-production-evidence-package|appImageDebUnpackedArtifactsCovered|cleanContainerTrustedCaCovered|knownWarningsPinned|reportPhaseOnlyRedaction/i, 'agent schema docs should describe Linux Package production evidence packages');
assert.match(agentSchemas, /proxyforge-search-parity-evidence-package|fullTextSearchCovered|structuredPredicatesCovered|providerScoreMergeCovered|persistentIndexCovered|largeProjectSoakCovered|reportPhaseOnlyRedaction/i, 'agent schema docs should describe Search parity evidence packages');
assert.match(agentSchemas, /proxyforge-viewer-parity-evidence-package|rawViewCovered|prettyJsonViewCovered|graphqlViewCovered|replayComparisonExportsCovered|reportAttachmentCovered|reportPhaseOnlyRedaction/i, 'agent schema docs should describe Viewer parity evidence packages');
assert.match(agentSchemas, /proxyforge-sequencer-parity-evidence-package|tokenLocationExtractionCovered|largeSampleReliabilityCovered|fipsCapCovered|fullFidelityTokenSamplesPreserved/i, 'agent schema docs should describe Sequencer parity evidence packages');
assert.match(agentSchemas, /proxyforge-logger-parity-evidence-package|toolGeneratedTrafficCovered|archiveImportExportCovered|archiveConflictDedupeCovered|fullFidelityRawMaterialPreserved/i, 'agent schema docs should describe Logger parity evidence packages');
assert.match(agentSchemas, /proxyforge-organizer-parity-evidence-package|collectionsCovered|passphraseSealedPackageCovered|conflictAuditCovered/i, 'agent schema docs should describe Organizer parity evidence packages');
assert.match(agentSchemas, /proxyforge-collaborator-parity-evidence-package|payloadGenerationCovered|dnsHttpSmtpProtocolsCovered|automatedReplayExecutionCovered|callbackSecretsPreserved/i, 'agent schema docs should describe Collaborator/OAST parity evidence packages');
assert.match(agentSchemas, /proxyforge-collaborator-package-refresh-evidence-package|providerHostProofRefreshCovered|externalProviderDiversityRefreshCovered|reportRoundTripRefreshCovered|stalePackageIds/i, 'agent schema docs should describe Collaborator/OAST package-refresh evidence packages');
assert.match(agentSchemas, /proxyforge-exploit-parity-evidence-package|pocTemplatesCovered|approvalGatesCovered|savedExploitChainsCovered|repeaterBackendCovered|destructiveClassExcluded|rawExecutorMaterialPreserved/i, 'agent schema docs should describe Exploit Lab parity evidence packages');
assert.match(agentSchemas, /proxyforge-exploit-package-refresh-evidence-package|backendExecutionRefreshCovered|callbackValidationRefreshCovered|destructiveClassStillExcluded|stalePackageIds/i, 'agent schema docs should describe Exploit Lab package-refresh evidence packages');
assert.match(agentSchemas, /proxyforge-target-parity-evidence-package|siteMapUrlTreeCovered|authenticatedSessionReuseCovered|parameterInsertionInventoryCovered/i, 'agent schema docs should describe Target parity evidence packages');
assert.match(agentSchemas, /proxyforge-scanner-passive-dedupe-parity-package|passiveChecksCovered|routeVariantDedupeCovered|rawRequestResponsePreserved/i, 'agent schema docs should describe Scanner passive/dedupe parity packages');
assert.match(agentSchemas, /proxyforge-active-scan-check-pack-evidence-package|checkPackMatrix|checkCoverage|rawProbeSamples/i, 'agent schema docs should describe Active Scanner check-pack evidence packages');
assert.match(agentSchemas, /proxyforge-crawl-audit-insertion-evidence-package|query\/form\/path coverage|duplicate merges|raw probe samples/i, 'agent schema docs should describe Crawl audit insertion evidence packages');
assert.match(agentSchemas, /proxyforge-scanner-retest-evidence-delta-package|outcomeCoverage|rawExchangeSamples/i, 'agent schema docs should describe Scanner retest evidence delta packages');
assert.match(agentSchemas, /proxyforge-anvil-custom-check-parity-package|positiveNegativeFixturesCovered|operationalSecretSignals/i, 'agent schema docs should describe Anvil custom scan-check parity packages');
assert.match(agentSchemas, /proxyforge-intruder-checkpoint-resume-package|resumeLinks|queueStateCovered/i, 'agent schema docs should describe Intruder checkpoint/resume packages');
assert.match(agentSchemas, /proxyforge-intruder-grep-extract-comparison-package|grepMatchCovered|statisticalRankingCovered/i, 'agent schema docs should describe Intruder grep/extract comparison packages');
assert.match(agentSchemas, /proxyforge-intruder-live-target-profile-package|liveTargetDiversityCovered|highVolumeStreamingCovered|resourcePoolConcurrencyCovered|packageRefreshCovered/i, 'agent schema docs should describe Intruder live-target profile packages');
assert.match(agentSchemas, /proxyforge-decoder-parity-evidence-package|jweDecryptEditReencryptCovered|encodeDecodeHashFormatCovered/i, 'agent schema docs should describe Decoder parity evidence packages');
assert.match(agentSchemas, /proxyforge-comparer-parity-evidence-package|structuredHttpDiffCovered|normalizationPresetsCovered/i, 'agent schema docs should describe Comparer parity evidence packages');
assert.match(agentSchemas, /proxyforge-analysis-tool-refresh-evidence-package|searchRefreshCovered|loggerRefreshCovered|viewerRefreshCovered|packageRefreshCovered|stalePackageIds/i, 'agent schema docs should describe Analysis tool refresh evidence packages');
assert.match(agentSchemas, /proxyforge-report-parity-evidence-package|allSubmissionFormatsCovered|signedBundleVerificationCovered|reportExportsRedacted/i, 'agent schema docs should describe Report parity evidence packages');
assert.match(agentSchemas, /proxyforge-report-external-bundle-diversity-package|externalSharedBundleDiversityCovered|digestOnlyNoSecretReviewCovered|canonicalRoundTripCovered|crossToolAttachmentDiversityCovered/i, 'agent schema docs should describe Report external bundle diversity evidence packages');
assert.match(agentSchemas, /proxyforge-report-template-library-interop-package|templateLibraryExportCovered|duplicateConflictReviewCovered|templateVariablesResolved|bundleRenderCovered/i, 'agent schema docs should describe Report template library interop evidence packages');
assert.match(operatorGuide, /proxyforge-proxy-browser-proxy-chain-diversity-package|browser\/proxy-chain diversity package|proxy-history/i, 'operator guide should include Proxy browser/proxy-chain diversity evidence');
assert.match(matrix, /Proxy browser\/proxy-chain diversity checkpoint|proxyforge-proxy-browser-proxy-chain-diversity-package|external live-host diversity/i, 'feature matrix should track Proxy browser/proxy-chain diversity as closed for this parity pass');
assert.match(matrix, /\| G6 — Alpha cut \| Complete \|/i, 'feature matrix should mark the alpha cut gate complete');
assert.deepEqual(forbiddenBrandTermHits(), [], 'tracked alpha candidate files should not contain legacy product brand terms');
assert.match(agentOptionAudit, /mitm-start|chromium-capture|sequencer-analyze|automation-run|automation-scheduler-tick|automation-parity-export|automation-service-plan|automation-service-smoke|replay-run|intruder-run|repeater-desync-probe|repeater-race-run|scanner-run|scanner-retest|scanner-evidence-export|anvil-plan|anvil-run|anvil-package-export|exploit-run|report-export|vantix-sync/i, 'MVP option audit should enumerate required agent command coverage');
assert.match(agentOptionAudit, /tokens, keys, cookies, headers, callbacks, raw requests, raw responses/i, 'MVP option audit should preserve full-fidelity executor handling until reporting');

const releaseArtifacts = fs.existsSync(path.join(root, 'release'))
  ? fs.readdirSync(path.join(root, 'release'), { recursive: true }).map(String)
  : [];
if (releaseArtifacts.length) {
  const artifactText = releaseArtifacts.join('\n');
  const hasLinuxArtifact = /AppImage|\.deb$/i.test(artifactText);
  const hasWindowsArtifact = /\.exe$|portable|Setup|-win\.zip$/i.test(artifactText);
  assert.ok(hasLinuxArtifact || hasWindowsArtifact, 'release directory should contain recognizable desktop artifacts when present');
}

console.log('release-readiness: verified package scripts, builder targets, build outputs, public docs, and ignored artifacts');

function assertScript(name, pattern) {
  assert.match(packageJson.scripts?.[name] ?? '', pattern, `package script ${name} should match release expectation`);
}

function assertFile(relativePath, message) {
  assert.ok(fs.existsSync(path.join(root, relativePath)), message);
}

function assertIncludes(values, expected, message) {
  assert.ok(Array.isArray(values) && values.includes(expected), message);
}

function assertDoesNotInclude(values, forbidden, message) {
  assert.ok(Array.isArray(values) && !values.includes(forbidden), message);
}

function forbiddenBrandTermHits() {
  const excludedDirs = new Set(['.git', '.gitignored', 'dist', 'dist-electron', 'node_modules', 'release', 'test-results']);
  const textExtensions = new Set(['.css', '.html', '.json', '.md', '.mjs', '.ts', '.tsx', '.txt', '.xml', '.yaml', '.yml']);
  const hits = [];
  const scanFilesystem = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (entry.isDirectory()) {
        if (!excludedDirs.has(entry.name)) scanFilesystem(path.join(dir, entry.name));
        continue;
      }
      if (!entry.isFile()) continue;
      const filePath = path.join(dir, entry.name);
      const relativePath = path.relative(root, filePath);
      const ext = path.extname(entry.name);
      if (!textExtensions.has(ext) && entry.name !== 'LICENSE') continue;
      const content = fs.readFileSync(filePath, 'utf8');
      const forbidden = new RegExp([
        'bu' + 'rpsuite',
        'bu' + 'rp suite',
        'bu' + 'rp',
        'ports' + 'wigger',
        '\\bB' + 'App\\b'
      ].join('|'), 'i');
      if (forbidden.test(content)) hits.push(relativePath);
    }
  };
  const trackedFiles = fs.existsSync(path.join(root, '.git'))
    ? execFileSync('git', ['ls-files'], { cwd: root, encoding: 'utf8' })
      .split('\n')
      .filter(Boolean)
    : [];
  if (!trackedFiles.length) {
    scanFilesystem(root);
    return hits.sort();
  }
  for (const relativePath of trackedFiles) {
    const filePath = path.join(root, relativePath);
    if (!fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) continue;
    const ext = path.extname(relativePath);
    if (!textExtensions.has(ext) && path.basename(relativePath) !== 'LICENSE') continue;
    const content = fs.readFileSync(filePath, 'utf8');
    const forbidden = new RegExp([
      'bu' + 'rpsuite',
      'bu' + 'rp suite',
      'bu' + 'rp',
      'ports' + 'wigger',
      '\\bB' + 'App\\b'
    ].join('|'), 'i');
    if (forbidden.test(content)) hits.push(relativePath);
  }
  return hits.sort();
}

function readJson(relativePath) {
  return JSON.parse(fs.readFileSync(path.join(root, relativePath), 'utf8'));
}
