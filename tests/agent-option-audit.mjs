import { strict as assert } from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';

const root = process.cwd();
const cli = fs.readFileSync(path.join(root, 'scripts/proxyforge-agent.mjs'), 'utf8');
const auditDoc = fs.readFileSync(path.join(root, 'docs/agents/MVP_OPTION_AUDIT.md'), 'utf8');
const agenticInterface = fs.readFileSync(path.join(root, 'docs/AGENTIC_INTERFACE.md'), 'utf8');
const codex = fs.readFileSync(path.join(root, 'docs/agents/CODEX.md'), 'utf8');
const claude = fs.readFileSync(path.join(root, 'docs/agents/CLAUDE.md'), 'utf8');
const vantix = fs.readFileSync(path.join(root, 'docs/agents/VANTIX.md'), 'utf8');
const schemas = fs.readFileSync(path.join(root, 'docs/agents/SCHEMAS.md'), 'utf8');
const matrix = fs.readFileSync(path.join(root, 'docs/FEATURE_MATRIX.md'), 'utf8');

const requiredCommands = [
  'status',
  'inventory',
  'evidence-list',
  'findings-list',
  'mitm-start',
  'mitm-status',
  'mitm-export',
  'mitm-stop',
  'search',
  'search-index',
  'view',
  'chromium-capture',
  'cookie-capture',
  'proxy-import',
  'project-store-status',
  'project-store-recover',
  'project-store-backup',
  'crawl-run',
  'content-discovery-plan',
  'content-discovery-run',
  'live-target-profile',
  'target-access-review',
  'target-map-compare',
  'automation-list',
  'automation-run',
  'automation-ci-export',
  'automation-scheduler-tick',
  'automation-parity-export',
  'automation-service-plan',
  'automation-service-smoke',
  'intel',
  'sequencer-analyze',
  'decoder-chain',
  'replay-run',
  'bulk-replay',
  'replay-matrix',
  'websocket-list',
  'websocket-replay',
  'websocket-fuzz',
  'websocket-transcript-export',
  'intruder-run',
  'repeater-desync-plan',
  'repeater-desync-probe',
  'repeater-race-run',
  'insertion-points',
  'scanner-plan',
  'scanner-run',
  'scanner-retest',
  'scanner-evidence-export',
  'scanner-oast-promote',
  'anvil-plan',
  'anvil-run',
  'anvil-package-export',
  'extension-fixtures',
  'callback-poll',
  'callback-provider-probe',
  'callback-replay',
  'callback-relay-plan',
  'callback-relay-soak',
  'callback-retention-prune',
  'exploit-preview',
  'exploit-run',
  'exploit-package-export',
  'report-preview',
  'report-export',
  'bundle-sign',
  'bundle-verify',
  'vantix-sync',
  'vantix-intel-export',
  'vantix-report-import',
];

const commandBlock = cli.match(/const commands = new Set\(\[\n(?<body>[\s\S]*?)\n\]\);/)?.groups?.body ?? '';
const implementedCommands = new Set(Array.from(commandBlock.matchAll(/'([^']+)'/g), (match) => match[1]));

const approvedPrivateOutputFunctions = new Set([
  'ensurePrivateDir',
  'writePrivateFile',
  'appendPrivateFile',
]);
for (const match of cli.matchAll(/fs\.(writeFile|appendFile|mkdir)\s*\(/g)) {
  const call = match[0];
  const functionName = enclosingFunctionName(cli, match.index ?? 0);
  assert(
    approvedPrivateOutputFunctions.has(functionName),
    `proxyforge-agent should route operational output through private helpers before ${call} in ${functionName || 'module scope'}`,
  );
}
assert.match(cli, /assertNoSymlinkComponents/, 'private agent output helper should reject symlink parents');
assert.match(cli, /mode: secureAgentFileMode/, 'private agent output helper should create files with secure mode');
assert.match(cli, /mode: secureAgentDirMode/, 'private agent output helper should create directories with secure mode');

for (const command of requiredCommands) {
  assert(implementedCommands.has(command), `proxyforge-agent should implement ${command}`);
  assert(auditDoc.includes(`\`${command}\``), `MVP option audit doc should mention ${command}`);
}

for (const doc of [agenticInterface, codex, claude, vantix, schemas, auditDoc]) {
  assert.match(doc, /sequencer-analyze/i, 'agent docs should mention sequencer-analyze');
  assert.match(doc, /decoder-chain/i, 'agent docs should mention decoder-chain');
  assert.match(doc, /target-map-compare/i, 'agent docs should mention target-map-compare');
  assert.match(doc, /live-target-profile/i, 'agent docs should mention live-target-profile');
  assert.match(doc, /automation-run/i, 'agent docs should mention automation-run');
  assert.match(doc, /automation-scheduler-tick/i, 'agent docs should mention automation-scheduler-tick');
  assert.match(doc, /automation-service-plan/i, 'agent docs should mention automation-service-plan');
  assert.match(doc, /automation-service-smoke/i, 'agent docs should mention automation-service-smoke');
  assert.match(doc, /intruder-run/i, 'agent docs should mention intruder-run');
  assert.match(doc, /repeater-desync-probe/i, 'agent docs should mention repeater-desync-probe');
  assert.match(doc, /repeater-race-run/i, 'agent docs should mention repeater-race-run');
  assert.match(doc, /insertion-points/i, 'agent docs should mention insertion-points');
  assert.match(doc, /websocket-list|websocket-replay|websocket-fuzz|websocket-transcript-export/i, 'agent docs should mention WebSocket agent commands');
  assert.match(doc, /project-store-status|project-store-recover|project-store-backup/i, 'agent docs should mention Project Store recovery commands');
}

assert.match(auditDoc, /rawTranscript/i, 'audit doc should preserve desync raw transcript guidance');
assert.match(auditDoc, /parser-differential|queued-followup|leftover-preview/i, 'audit doc should preserve desync parser differential guidance');
assert.match(auditDoc, /--ensure-ca|--upstream-tls strict\|relaxed|project-CA readiness/i, 'audit doc should preserve persistent MITM project-CA and upstream TLS controls');
assert.match(auditDoc, /releaseSkewMs/i, 'audit doc should preserve race timing guidance');
assert.match(auditDoc, /repeater-race-run --soak|data\.soakPackage/i, 'audit doc should preserve race soak package guidance');
assert.match(auditDoc, /attack-mode matrices|Sniper\/Battering Ram\/Pitchfork\/Cluster Bomb/i, 'audit doc should preserve Intruder attack-mode matrix guidance');
assert.match(auditDoc, /payload transformation matrices|processors\/recursive rules/i, 'audit doc should preserve Intruder payload transformation guidance');
assert.match(auditDoc, /scanner-run --soak|false-positive controls|suppressed findings/i, 'audit doc should preserve scanner calibration soak guidance');
assert.match(auditDoc, /live-target-profile|live target profiling|Scanner\/Intruder handoff/i, 'audit doc should preserve live target profiling guidance');
assert.match(auditDoc, /status\.data\.scannerCatalog|--check-pack baseline\\\|input-attacks\\\|api-graphql\\\|auth-state\\\|full-active/i, 'audit doc should preserve scanner catalog and check-pack guidance');
for (const doc of [agenticInterface, codex, claude, vantix, schemas]) {
  assert.match(doc, /scannerCatalog|--check-pack full-active|input-attacks|reflected XSS|command injection/i, 'agent docs should mention scanner catalog/check-pack execution');
}
assert.match(auditDoc, /scanner-retest|scanner-evidence-export|retest evidence delta/i, 'audit doc should preserve scanner retest/evidence export guidance');
assert.match(auditDoc, /scanner-oast-promote|OAST issue promotion/i, 'audit doc should preserve Scanner OAST issue promotion guidance');
assert.match(auditDoc, /anvil-run|anvil-package-export|Anvil custom scan-check/i, 'audit doc should preserve Anvil agent guidance');
assert.match(auditDoc, /callback-provider-probe|provider host proof|OAST provider/i, 'audit doc should preserve OAST provider host proof guidance');
assert.match(agenticInterface, /submission\/reporting commands redact|submission\/reporting exports/i, 'agentic interface should preserve report-phase redaction boundary');
assert.match(agenticInterface, /tokens, keys, cookies, headers, and raw traffic/i, 'agentic interface should preserve full-fidelity executor secret handling');
assert.match(agenticInterface, /External-cwd execution|app root/i, 'agentic interface should document external-cwd agent execution');
assert.match(vantix, /cd ~\/vantix|agentRuntime\.commandPrefix/i, 'Vantix docs should show external runner invocation and command prefix handoff');
assert.match(matrix, /MVP option audit|Agent option audit|MVP Agent Option Audit/i, 'feature matrix should track the post-MVP agent option audit gate');

console.log(`agent-option-audit: verified ${requiredCommands.length} agent commands, private output inventory, desync/race docs, secret boundary, and matrix gate`);

function enclosingFunctionName(source, index) {
  const before = source.slice(0, index);
  const matches = Array.from(before.matchAll(/(?:async\s+)?function\s+([A-Za-z0-9_]+)\s*\(/g));
  return matches.at(-1)?.[1] ?? '';
}
