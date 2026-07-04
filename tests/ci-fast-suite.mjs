// run-all: skip  (CI orchestrator — runs npm build and full test pipeline; invoke directly)
import { strict as assert } from 'node:assert';
import { spawn } from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';

const startedAt = new Date();
const npmBin = process.platform === 'win32' ? 'npm.cmd' : 'npm';
const npxBin = process.platform === 'win32' ? 'npx.cmd' : 'npx';

const steps = [
  {
    name: 'Build renderer and Electron runtime',
    command: npmBin,
    args: ['run', 'build'],
    kind: 'build',
  },
  {
    name: 'Live vulnerable fixture app',
    command: process.execPath,
    args: ['tests/vulnerable-fixture-app.mjs'],
    kind: 'runtime',
  },
  {
    name: 'Release readiness verifier',
    command: process.execPath,
    args: ['tests/release-readiness.mjs'],
    kind: 'release',
  },
  {
    name: 'Electron fuse policy verifier',
    command: process.execPath,
    args: ['tests/electron-fuse-policy.mjs'],
    kind: 'release',
  },
  {
    name: 'Package license verifier',
    command: process.execPath,
    args: ['tests/release-package-license.mjs'],
    kind: 'release',
  },
  {
    name: 'Private output permission verifier',
    command: process.execPath,
    args: ['tests/private-output-permissions.mjs'],
    kind: 'release',
  },
  {
    name: 'Roadmap completion verifier',
    command: process.execPath,
    args: ['tests/roadmap-completion.mjs'],
    kind: 'release',
  },
  {
    name: 'Release smoke runner plan',
    command: process.execPath,
    args: ['tests/release-smoke-runner.mjs'],
    kind: 'release',
  },
  {
    name: 'CI nightly policy gate',
    command: process.execPath,
    args: ['tests/ci-nightly-policy.mjs'],
    kind: 'release',
  },
  {
    name: 'Release runtime workflow smoke',
    command: process.execPath,
    args: ['tests/release-runtime-workflow.mjs'],
    kind: 'release',
  },
  {
    name: 'Platform Release parity evidence engine',
    command: process.execPath,
    args: ['tests/platform-release-engine.mjs'],
    kind: 'release',
  },
  {
    name: 'UI Scale production evidence engine',
    command: process.execPath,
    args: ['tests/ui-scale-production-engine.mjs'],
    kind: 'release',
  },
  {
    name: 'Platform Shell production evidence engine',
    command: process.execPath,
    args: ['tests/platform-shell-production-engine.mjs'],
    kind: 'release',
  },
  {
    name: 'Agent Control production evidence engine',
    command: process.execPath,
    args: ['tests/agent-control-production-engine.mjs'],
    kind: 'runtime',
  },
  {
    name: 'AI Provider production evidence engine',
    command: process.execPath,
    args: ['tests/ai-provider-production-engine.mjs'],
    kind: 'engine',
  },
  {
    name: 'Release Security production evidence engine',
    command: process.execPath,
    args: ['tests/release-security-production-engine.mjs'],
    kind: 'release',
  },
  {
    name: 'Release Trust production evidence engine',
    command: process.execPath,
    args: ['tests/release-trust-production-engine.mjs'],
    kind: 'release',
  },
  {
    name: 'Fast regression production evidence engine',
    command: process.execPath,
    args: ['tests/fast-regression-production-engine.mjs'],
    kind: 'release',
  },
  {
    name: 'Full/Nightly production evidence engine',
    command: process.execPath,
    args: ['tests/full-nightly-production-engine.mjs'],
    kind: 'release',
  },
  {
    name: 'Full/Nightly retained history engine',
    command: process.execPath,
    args: ['tests/full-nightly-history-engine.mjs'],
    kind: 'release',
  },
  {
    name: 'Install docs production evidence engine',
    command: process.execPath,
    args: ['tests/install-docs-production-engine.mjs'],
    kind: 'release',
  },
  {
    name: 'Windows package production evidence engine',
    command: process.execPath,
    args: ['tests/windows-package-production-engine.mjs'],
    kind: 'release',
  },
  {
    name: 'Linux package production evidence engine',
    command: process.execPath,
    args: ['tests/linux-package-production-engine.mjs'],
    kind: 'release',
  },
  {
    name: 'Enterprise policy transport engine',
    command: process.execPath,
    args: ['tests/enterprise-policy-transport.mjs'],
    kind: 'engine',
  },
  {
    name: 'Safety and enterprise parity evidence engine',
    command: process.execPath,
    args: ['tests/safety-enterprise-engine.mjs'],
    kind: 'engine',
  },
  {
    name: 'Project parity evidence engine',
    command: process.execPath,
    args: ['tests/project-parity-engine.mjs'],
    kind: 'engine',
  },
  {
    name: 'Project import compatibility engine',
    command: process.execPath,
    args: ['tests/project-import-compatibility-engine.mjs'],
    kind: 'engine',
  },
  {
    name: 'Customer-scale interop profiling engine',
    command: process.execPath,
    args: ['tests/customer-scale-interop-engine.mjs'],
    kind: 'engine',
  },
  {
    name: 'Project Store v2 persistence engine',
    command: process.execPath,
    args: ['tests/project-store-v2.mjs'],
    kind: 'engine',
  },
  {
    name: 'Project Store crash recovery engine',
    command: process.execPath,
    args: ['tests/project-store-crash-recovery.mjs'],
    kind: 'engine',
  },
  {
    name: 'Project lifecycle IPC contract engine',
    command: process.execPath,
    args: ['tests/project-lifecycle-ipc-contract.mjs'],
    kind: 'runtime',
  },
  {
    name: 'Typed IPC capability and audit contract engine',
    command: process.execPath,
    args: ['tests/ipc-contract-security.mjs'],
    kind: 'runtime',
  },
  {
    name: 'Project Store settings workflow engine',
    command: process.execPath,
    args: ['tests/project-store-settings-workflow.mjs'],
    kind: 'engine',
  },
  {
    name: 'Project Store cookie jar workflow engine',
    command: process.execPath,
    args: ['tests/project-store-cookie-jar-workflow.mjs'],
    kind: 'engine',
  },
  {
    name: 'Project Store target inventory workflow engine',
    command: process.execPath,
    args: ['tests/project-store-target-inventory-workflow.mjs'],
    kind: 'engine',
  },
  {
    name: 'Project Store automation AI extension run-state workflow engine',
    command: process.execPath,
    args: ['tests/project-store-run-state-workflow.mjs'],
    kind: 'engine',
  },
  {
    name: 'Project Store live automation AI extension run-state wiring engine',
    command: process.execPath,
    args: ['tests/project-store-live-run-state-wiring.mjs'],
    kind: 'engine',
  },
  {
    name: 'Project Store Repeater workflow engine',
    command: process.execPath,
    args: ['tests/project-store-repeater-workflow.mjs'],
    kind: 'engine',
  },
  {
    name: 'Project Store Intruder workflow engine',
    command: process.execPath,
    args: ['tests/project-store-intruder-workflow.mjs'],
    kind: 'engine',
  },
  {
    name: 'Project Store Scanner workflow engine',
    command: process.execPath,
    args: ['tests/project-store-scanner-workflow.mjs'],
    kind: 'engine',
  },
  {
    name: 'Project Store issue/report workflow engine',
    command: process.execPath,
    args: ['tests/project-store-issue-report-workflow.mjs'],
    kind: 'engine',
  },
  {
    name: 'Project Store WebSocket workflow engine',
    command: process.execPath,
    args: ['tests/project-store-websocket-workflow.mjs'],
    kind: 'engine',
  },
  {
    name: 'Proxy Project Store workflow engine',
    command: process.execPath,
    args: ['tests/proxy-project-store-workflow.mjs'],
    kind: 'engine',
  },
  {
    name: 'Project Store OAST workflow engine',
    command: process.execPath,
    args: ['tests/project-store-oast-workflow.mjs'],
    kind: 'engine',
  },
  {
    name: 'Project Store signed OAST evidence engine',
    command: process.execPath,
    args: ['tests/project-store-oast-signed-evidence.mjs'],
    kind: 'engine',
  },
  {
    name: 'Scanner OAST SSRF workflow engine',
    command: process.execPath,
    args: ['tests/scanner-oast-ssrf.mjs'],
    kind: 'engine',
  },
  {
    name: 'Scanner insertion point inventory engine',
    command: process.execPath,
    args: ['tests/insertion-point-engine.mjs'],
    kind: 'engine',
  },
  {
    name: 'Agent option audit gate',
    command: process.execPath,
    args: ['tests/agent-option-audit.mjs'],
    kind: 'runtime',
  },
  {
    name: 'Search semantic ranking engine',
    command: process.execPath,
    args: ['tests/search-engine.mjs'],
    kind: 'engine',
  },
  {
    name: 'Viewer parity engine',
    command: process.execPath,
    args: ['tests/viewer-engine.mjs'],
    kind: 'engine',
  },
  {
    name: 'Logger custom column compatibility engine',
    command: process.execPath,
    args: ['tests/logger-column-engine.mjs'],
    kind: 'engine',
  },
  {
    name: 'Logger parity evidence engine',
    command: process.execPath,
    args: ['tests/logger-evidence-engine.mjs'],
    kind: 'engine',
  },
  {
    name: 'Organizer parity evidence engine',
    command: process.execPath,
    args: ['tests/organizer-evidence-engine.mjs'],
    kind: 'engine',
  },
  {
    name: 'Sequencer large-sample reliability engine',
    command: process.execPath,
    args: ['tests/sequencer-engine.mjs'],
    kind: 'engine',
  },
  {
    name: 'Decoder token workflow engine',
    command: process.execPath,
    args: ['tests/decoder-engine.mjs'],
    kind: 'engine',
  },
  {
    name: 'Decoder transform chain golden corpus',
    command: process.execPath,
    args: ['tests/decoder-golden.mjs'],
    kind: 'engine',
  },
  {
    name: 'Comparer parity engine',
    command: process.execPath,
    args: ['tests/compare-engine.mjs'],
    kind: 'engine',
  },
  {
    name: 'Analysis tool refresh evidence engine',
    command: process.execPath,
    args: ['tests/analysis-tool-refresh-engine.mjs'],
    kind: 'engine',
  },
  {
    name: 'Automation scheduler engine',
    command: process.execPath,
    args: ['tests/automation-engine.mjs'],
    kind: 'engine',
  },
  {
    name: 'Automation installed-host service smoke',
    command: process.execPath,
    args: ['tests/automation-service-smoke.mjs'],
    kind: 'runtime',
  },
  {
    name: 'Sandboxed extension runtime engine',
    command: process.execPath,
    args: ['tests/extension-engine.mjs'],
    kind: 'engine',
  },
  {
    name: 'Extension third-party compatibility engine',
    command: process.execPath,
    args: ['tests/extension-third-party-compatibility-engine.mjs'],
    kind: 'engine',
  },
  {
    name: 'Callback live backend engine',
    command: process.execPath,
    args: ['tests/callback-live-backend-engine.mjs'],
    kind: 'engine',
  },
  {
    name: 'OAST relay integration engine',
    command: process.execPath,
    args: ['tests/oast-relay-integration.mjs'],
    kind: 'engine',
  },
  {
    name: 'OAST provider diversity engine',
    command: process.execPath,
    args: ['tests/oast-provider-diversity.mjs'],
    kind: 'engine',
  },
  {
    name: 'Exploit backend execution engine',
    command: process.execPath,
    args: ['tests/exploit-engine.mjs'],
    kind: 'engine',
  },
  {
    name: 'AI controlled action execution engine',
    command: process.execPath,
    args: ['tests/ai-action-engine.mjs'],
    kind: 'engine',
  },
  {
    name: 'Repeater transport engine',
    command: process.execPath,
    args: ['tests/repeater-transport.mjs'],
    kind: 'engine',
  },
  {
    name: 'Repeater workspace parity engine',
    command: process.execPath,
    args: ['tests/repeater-workspace-engine.mjs'],
    kind: 'engine',
  },
  {
    name: 'Repeater OAST workflow engine',
    command: process.execPath,
    args: ['tests/repeater-oast-workflow.mjs'],
    kind: 'engine',
  },
  {
    name: 'Session profile live refresh engine',
    command: process.execPath,
    args: ['tests/session-profile-refresh.mjs'],
    kind: 'engine',
  },
  {
    name: 'Shared session cookie jar engine',
    command: process.execPath,
    args: ['tests/session-cookie-jar.mjs'],
    kind: 'engine',
  },
  {
    name: 'Session macro token refresh engine',
    command: process.execPath,
    args: ['tests/session-macro-engine.mjs'],
    kind: 'engine',
  },
  {
    name: 'Session replay runtime engine',
    command: process.execPath,
    args: ['tests/session-replay-engine.mjs'],
    kind: 'engine',
  },
  {
    name: 'Crawler runtime engine',
    command: process.execPath,
    args: ['tests/crawl-engine.mjs'],
    kind: 'engine',
  },
  {
    name: 'Target access-control and comparison map engine',
    command: process.execPath,
    args: ['tests/target-map-engine.mjs'],
    kind: 'engine',
  },
  {
    name: 'Browser launch and cookie matrix engine',
    command: process.execPath,
    args: ['tests/browser-launcher.mjs'],
    kind: 'platform',
  },
  {
    name: 'Proxy HTTP listener capture engine',
    command: process.execPath,
    args: ['tests/proxy-listener-engine.mjs'],
    kind: 'engine',
  },
  {
    name: 'CONNECT tunnel byte-accounting engine',
    command: process.execPath,
    args: ['tests/connect-tunnel.mjs'],
    kind: 'engine',
  },
  {
    name: 'HTTPS MITM project CA engine',
    command: process.execPath,
    args: ['tests/https-mitm.mjs'],
    kind: 'engine',
  },
  {
    name: 'Proxy intercept request-response engine',
    command: process.execPath,
    args: ['tests/intercept-engine.mjs'],
    kind: 'engine',
  },
  {
    name: 'Repeater desync race socket engine',
    command: process.execPath,
    args: ['tests/repeater-desync-race-engine.mjs'],
    kind: 'engine',
  },
  {
    name: 'Intruder attack mode matrix engine',
    command: process.execPath,
    args: ['tests/intruder-engine.mjs'],
    kind: 'engine',
  },
  {
    name: 'Intruder OAST row correlation engine',
    command: process.execPath,
    args: ['tests/intruder-oast-correlation.mjs'],
    kind: 'engine',
  },
  {
    name: 'Proxy HTTP/2 fidelity engine',
    command: process.execPath,
    args: ['tests/proxy-history-engine.mjs'],
    kind: 'engine',
  },
  {
    name: 'Proxy WebSocket capture engine',
    command: process.execPath,
    args: ['tests/websocket-engine.mjs'],
    kind: 'engine',
  },
  {
    name: 'Scanner passive dedupe engine',
    command: process.execPath,
    args: ['tests/scanner-passive-engine.mjs'],
    kind: 'engine',
  },
  {
    name: 'Active scanner check-pack engine',
    command: process.execPath,
    args: ['tests/active-scanner.mjs'],
    kind: 'engine',
  },
  {
    name: 'Crawl insertion audit engine',
    command: process.execPath,
    args: ['tests/crawl-audit.mjs'],
    kind: 'engine',
  },
  {
    name: 'Scanner active evidence engine',
    command: process.execPath,
    args: ['tests/scanner-active-scan-engine.mjs'],
    kind: 'engine',
  },
  {
    name: 'Scanner retest evidence delta engine',
    command: process.execPath,
    args: ['tests/scanner-retest-engine.mjs'],
    kind: 'engine',
  },
  {
    name: 'Anvil custom scan-check engine',
    command: process.execPath,
    args: ['tests/anvil-engine.mjs'],
    kind: 'engine',
  },
  {
    name: 'Scanner live calibration engine',
    command: process.execPath,
    args: ['tests/scanner-live-calibration.mjs'],
    kind: 'engine',
  },
  {
    name: 'Release security review engine',
    command: process.execPath,
    args: ['tests/security-review-engine.mjs'],
    kind: 'release',
  },
  {
    name: 'Report export parity engine',
    command: process.execPath,
    args: ['tests/report-engine.mjs'],
    kind: 'engine',
  },
  {
    name: 'Report PDF visual QA smoke',
    command: process.execPath,
    args: ['tests/report-pdf-visual-qa.mjs'],
    kind: 'engine',
  },
  {
    name: 'Headless CLI runtime smoke',
    command: process.execPath,
    args: ['tests/headless-runner.mjs'],
    kind: 'runtime',
  },
  {
    name: 'Agentic control CLI smoke',
    command: process.execPath,
    args: ['tests/agent-cli.mjs'],
    kind: 'runtime',
  },
  {
    name: 'Browser workflow source audit',
    command: process.execPath,
    args: ['tests/browser-suite-audit.mjs'],
    kind: 'e2e',
  },
  {
    name: 'Focused browser workflow smoke',
    command: npxBin,
    args: ['playwright', 'test', 'tests/proxyforge.spec.ts', '-g', 'search|automation|extension|project lifecycle'],
    kind: 'e2e',
  },
];

const results = [];

for (const step of steps) {
  const result = await runStep(step);
  results.push(result);
  if (result.status !== 'passed') break;
}

const completedAt = new Date();
const summary = {
  kind: 'proxyforge-ci-fast-suite-summary',
  startedAt: startedAt.toISOString(),
  completedAt: completedAt.toISOString(),
  durationMs: completedAt.getTime() - startedAt.getTime(),
  passed: results.every((result) => result.status === 'passed') && results.length === steps.length,
  totalSteps: steps.length,
  completedSteps: results.length,
  results,
};

await fs.mkdir(path.resolve('test-results'), { recursive: true });
await fs.writeFile(path.resolve('test-results/ci-fast-suite-summary.json'), JSON.stringify(summary, null, 2));

assert.equal(summary.passed, true, `ci-fast-suite failed at ${results.find((result) => result.status !== 'passed')?.name ?? 'unknown step'}`);
console.log(`ci-fast-suite: ${summary.completedSteps}/${summary.totalSteps} steps passed in ${summary.durationMs}ms`);

function runStep(step) {
  const start = new Date();
  console.log(`ci-fast-suite: starting ${step.name}`);
  return new Promise((resolve) => {
    const child = spawn(step.command, step.args, {
      cwd: process.cwd(),
      env: {
        ...process.env,
        CI: process.env.CI ?? '1',
        FORCE_COLOR: process.env.FORCE_COLOR ?? '0',
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => {
      const text = chunk.toString();
      stdout += text;
      process.stdout.write(text);
    });
    child.stderr.on('data', (chunk) => {
      const text = chunk.toString();
      stderr += text;
      process.stderr.write(text);
    });
    child.on('close', (code) => {
      const end = new Date();
      const status = code === 0 ? 'passed' : 'failed';
      console.log(`ci-fast-suite: ${status} ${step.name}`);
      resolve({
        name: step.name,
        kind: step.kind,
        command: [step.command, ...step.args].join(' '),
        status,
        exitCode: code,
        startedAt: start.toISOString(),
        completedAt: end.toISOString(),
        durationMs: end.getTime() - start.getTime(),
        stdoutTail: tail(stdout),
        stderrTail: tail(stderr),
      });
    });
  });
}

function tail(value) {
  return value.split(/\r?\n/).filter(Boolean).slice(-12).join('\n');
}
