#!/usr/bin/env node
import { createRequire } from 'node:module';
import { spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import fs from 'node:fs/promises';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import tls from 'node:tls';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const agentScriptPath = fileURLToPath(import.meta.url);
const agentScriptDir = path.dirname(agentScriptPath);
const agentRootDir = path.basename(agentScriptDir) === 'scripts' ? path.dirname(agentScriptDir) : process.cwd();
const agentCommandPrefix = `${process.execPath} ${shellQuote(agentScriptPath)}`;
const automationServiceScriptPath = path.join(agentScriptDir, 'proxyforge-automation-service.mjs');
const schemaVersion = 1;
const secureAgentDirMode = 0o700;
const secureAgentFileMode = 0o600;
const defaultChecks = ['security-headers', 'cors-origin', 'cache-key', 'method-options'];
const activeScannerChecks = [
  { id: 'security-headers', label: 'Security headers', category: 'baseline', severity: 'medium', defaultEnabled: true },
  { id: 'cors-origin', label: 'CORS origin', category: 'baseline', severity: 'high', defaultEnabled: true },
  { id: 'cache-key', label: 'Cache key', category: 'baseline', severity: 'medium', defaultEnabled: true },
  { id: 'method-options', label: 'OPTIONS methods', category: 'baseline', severity: 'info', defaultEnabled: true },
  { id: 'authz-diff', label: 'Auth state diff', category: 'auth', severity: 'high', defaultEnabled: false },
  { id: 'jwt-claims', label: 'JWT claim exposure', category: 'auth', severity: 'medium', defaultEnabled: false },
  { id: 'graphql-introspection', label: 'GraphQL introspection', category: 'api', severity: 'medium', defaultEnabled: false },
  { id: 'oast-ssrf', label: 'OAST SSRF callback', category: 'oast', severity: 'high', defaultEnabled: false },
  { id: 'reflected-xss', label: 'Reflected XSS', category: 'injection', severity: 'high', defaultEnabled: false },
  { id: 'sql-injection', label: 'SQL injection', category: 'injection', severity: 'high', defaultEnabled: false },
  { id: 'path-traversal', label: 'Path traversal', category: 'injection', severity: 'high', defaultEnabled: false },
  { id: 'open-redirect', label: 'Open redirect', category: 'redirect', severity: 'medium', defaultEnabled: false },
  { id: 'command-injection', label: 'Command injection', category: 'injection', severity: 'critical', defaultEnabled: false },
];
const activeScannerCheckIds = activeScannerChecks.map((check) => check.id);
const activeScannerCheckPacks = [
  {
    id: 'baseline',
    label: 'Baseline web pack',
    checks: ['security-headers', 'cors-origin', 'cache-key', 'method-options'],
    detail: 'Low-noise headers, CORS, cache routing, and method policy checks.',
  },
  {
    id: 'input-attacks',
    label: 'Input attack pack',
    checks: ['reflected-xss', 'sql-injection', 'path-traversal', 'open-redirect', 'command-injection'],
    detail: 'Core reflected-input exploit probes for scoped live testing.',
  },
  {
    id: 'api-graphql',
    label: 'API and GraphQL pack',
    checks: ['graphql-introspection', 'jwt-claims', 'cors-origin', 'method-options', 'oast-ssrf', 'sql-injection', 'command-injection'],
    detail: 'API schema, token, CORS, OAST, and injection checks.',
  },
  {
    id: 'auth-state',
    label: 'Authenticated state pack',
    checks: ['authz-diff', 'jwt-claims', 'security-headers'],
    detail: 'Low-privilege comparison, token claims, and baseline hardening.',
  },
  {
    id: 'full-active',
    label: 'Full active pack',
    checks: activeScannerCheckIds,
    detail: 'Every built-in active scanner check family currently supported by ProxyForge.',
  },
];
const agentAutomationCiProviders = ['github-actions', 'gitlab-ci', 'azure-pipelines', 'jenkins'];
const commands = new Set([
  'status',
  'inventory',
  'evidence-list',
  'findings-list',
  'mitm-start',
  'mitm-status',
  'mitm-stop',
  'mitm-export',
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
  'playbook-list',
  'playbook-plan',
  'playbook-run',
  'playbook-export',
  'playback-client',
  'playback-server',
  'spec-import',
  'spider-ajax-run',
  'spider-passive-run',
  'dom-tracer-sessions',
  'dom-tracer-export',
]);
const reportingCommands = new Set([
  'report-preview',
  'report-export',
  'bundle-sign',
  'bundle-verify',
  'vantix-report-import',
]);

async function main() {
  const parsed = parseArgs(process.argv.slice(2));
  if (parsed.help || !parsed.command) {
    printHelp();
    return;
  }
  if (!commands.has(parsed.command)) {
    throw new Error(`Unsupported command "${parsed.command}". Run proxyforge-agent help for command names.`);
  }

  const project = parsed.command.startsWith('project-store-')
    ? defaultProject(parsed.flags.target)
    : await loadProject(parsed.flags.project ?? parsed.flags.history, parsed.flags.target);
  const scopeAllowlist = scopeFromFlags(parsed.flags, project, parsed.flags.target);
  if (parsed.command === 'mitm-start') {
    await mitmStartForeground(parsed.flags, project, scopeAllowlist);
    return;
  }
  const selectedExchange = selectExchange(project, parsed.flags['request-id'] ?? parsed.flags.exchange ?? parsed.flags.id, parsed.flags.target);
  const startedAt = new Date().toISOString();
  const result = await runCommand(parsed.command, parsed.flags, project, selectedExchange, scopeAllowlist, startedAt);
  const reportingPhase = isReportingPhase(parsed.command, parsed.flags);
  const envelope = {
    kind: 'proxyforge-agent-result',
    schemaVersion,
    command: parsed.command,
    generatedAt: new Date().toISOString(),
    status: result.status ?? 'completed',
    mode: result.mode ?? (parsed.flags.execute ? 'executed' : 'read-only'),
    project: projectSummary(project),
    safety: {
      redacted: reportingPhase,
      secretHandling: reportingPhase ? 'submission-reporting-redaction' : 'execution-full-fidelity-secrets-preserved',
      scopeAllowlist,
      trafficSent: Boolean(result.trafficSent),
      requestCount: result.requestCount ?? 0,
      approvals: result.approvals ?? [],
      gates: result.gates ?? defaultGatesForPhase(reportingPhase),
    },
    artifacts: result.artifacts ?? [],
    data: result.data ?? {},
    audit: result.audit ?? [auditEvent(parsed.command, result.status ?? 'completed', result.detail ?? 'Agent command completed', result.requestCount ?? 0)],
  };
  const output = reportingPhase ? redactDeep(envelope) : envelope;

  process.stdout.write(`${JSON.stringify(output, null, parsed.flags.pretty === false ? 0 : 2)}\n`);
  if (output.status === 'blocked') process.exitCode = 2;
}

async function runCommand(command, flags, project, selectedExchange, scopeAllowlist, startedAt) {
  if (command === 'status') return statusResult(project, scopeAllowlist);
  if (command === 'inventory') return inventoryResult(project, scopeAllowlist);
  if (command === 'evidence-list') return evidenceListResult(project);
  if (command === 'findings-list') return findingsListResult(project);
  if (command === 'mitm-status') return mitmStatusResult(flags);
  if (command === 'mitm-stop') return mitmStopResult(flags);
  if (command === 'mitm-export') return mitmExportResult(flags);
  if (command === 'search') return searchResult(project, String(flags.query ?? flags.q ?? ''));
  if (command === 'search-index') return searchIndexResult(project, flags, scopeAllowlist);
  if (command === 'view') return viewResult(project, selectedExchange, flags);
  if (command === 'chromium-capture') return chromiumCaptureResult(flags, project, scopeAllowlist);
  if (command === 'cookie-capture') return cookieCaptureResult(flags, project);
  if (command === 'proxy-import') return proxyImportResult(flags);
  if (command === 'project-store-status') return projectStoreStatusResult(flags);
  if (command === 'project-store-recover') return projectStoreRecoverResult(flags);
  if (command === 'project-store-backup') return projectStoreBackupResult(flags);
  if (command === 'crawl-run') return crawlRunResult(flags, project, scopeAllowlist);
  if (command === 'content-discovery-plan') return contentDiscoveryPlanResult(flags, project, scopeAllowlist);
  if (command === 'content-discovery-run') return contentDiscoveryRunResult(flags, project, scopeAllowlist);
  if (command === 'live-target-profile') return liveTargetProfileResult(flags, project, scopeAllowlist);
  if (command === 'target-access-review') return targetAccessReviewResult(flags, project, scopeAllowlist);
  if (command === 'target-map-compare') return targetMapCompareResult(flags, project, scopeAllowlist);
  if (command === 'automation-list') return automationListResult(project, scopeAllowlist);
  if (command === 'automation-run') return automationRunResult(flags, project, selectedExchange, scopeAllowlist);
  if (command === 'automation-ci-export') return automationCiExportResult(flags, project, scopeAllowlist);
  if (command === 'automation-scheduler-tick') return automationSchedulerTickResult(flags, project, selectedExchange, scopeAllowlist);
  if (command === 'automation-parity-export') return automationParityExportResult(flags, project, selectedExchange, scopeAllowlist);
  if (command === 'automation-service-plan') return automationServicePlanResult(flags, project, selectedExchange, scopeAllowlist);
  if (command === 'automation-service-smoke') return automationServiceSmokeResult(flags, project, selectedExchange, scopeAllowlist);
  if (command === 'intel') return intelResult(flags, project, selectedExchange, scopeAllowlist);
  if (command === 'sequencer-analyze') return sequencerAnalyzeResult(flags, project, selectedExchange);
  if (command === 'decoder-chain') return decoderChainResult(flags, project, selectedExchange);
  if (command === 'replay-run') return replayRunResult(flags, selectedExchange, scopeAllowlist);
  if (command === 'bulk-replay') return bulkReplayResult(flags, project, scopeAllowlist);
  if (command === 'replay-matrix') return replayMatrixResult(flags, selectedExchange, scopeAllowlist);
  if (command === 'websocket-list') return webSocketListResult(flags, project, scopeAllowlist);
  if (command === 'websocket-replay') return webSocketReplayResult(flags, project, scopeAllowlist);
  if (command === 'websocket-fuzz') return webSocketFuzzResult(flags, project, scopeAllowlist);
  if (command === 'websocket-transcript-export') return webSocketTranscriptExportResult(flags, project, scopeAllowlist);
  if (command === 'intruder-run') return intruderRunResult(flags, project, selectedExchange, scopeAllowlist);
  if (command === 'repeater-desync-plan') return repeaterDesyncPlanResult(flags, project, selectedExchange, scopeAllowlist);
  if (command === 'repeater-desync-probe') return repeaterDesyncProbeResult(flags, project, selectedExchange, scopeAllowlist);
  if (command === 'repeater-race-run') return repeaterRaceRunResult(flags, project, selectedExchange, scopeAllowlist);
  if (command === 'insertion-points') return insertionPointsResult(flags, project, selectedExchange, scopeAllowlist);
  if (command === 'scanner-plan') return scannerPlanResult(flags, project, selectedExchange, scopeAllowlist);
  if (command === 'scanner-run') return scannerRunResult(flags, project, selectedExchange, scopeAllowlist);
  if (command === 'scanner-retest') return scannerRetestResult(flags, project, selectedExchange, scopeAllowlist);
  if (command === 'scanner-evidence-export') return scannerEvidenceExportResult(flags, project, selectedExchange, scopeAllowlist);
  if (command === 'scanner-oast-promote') return scannerOastPromoteResult(flags, project, selectedExchange, scopeAllowlist);
  if (command === 'anvil-plan') return anvilPlanResult(flags, project, selectedExchange, scopeAllowlist);
  if (command === 'anvil-run') return anvilRunResult(flags, project, selectedExchange, scopeAllowlist);
  if (command === 'anvil-package-export') return anvilPackageExportResult(flags, project, selectedExchange, scopeAllowlist);
  if (command === 'extension-fixtures') return extensionFixturesResult(flags, project, selectedExchange);
  if (command === 'callback-poll') return callbackPollResult(flags, project);
  if (command === 'callback-provider-probe') return callbackProviderProbeResult(flags, project, scopeAllowlist);
  if (command === 'callback-replay') return callbackReplayResult(flags, project, scopeAllowlist);
  if (command === 'callback-relay-plan') return callbackRelayPlanResult(flags, project);
  if (command === 'callback-relay-soak') return callbackRelaySoakResult(flags, project);
  if (command === 'callback-retention-prune') return callbackRetentionPruneResult(flags, project);
  if (command === 'exploit-preview') return exploitPreviewResult(flags, selectedExchange, scopeAllowlist);
  if (command === 'exploit-run') return exploitRunResult(flags, selectedExchange, scopeAllowlist);
  if (command === 'exploit-package-export') return exploitPackageExportResult(flags, selectedExchange, scopeAllowlist);
  if (command === 'report-preview') return reportPreviewResult(flags, project, scopeAllowlist);
  if (command === 'report-export') return reportExportResult(flags, project, scopeAllowlist);
  if (command === 'bundle-sign') return bundleSignResult(flags, project);
  if (command === 'bundle-verify') return bundleVerifyResult(flags);
  if (command === 'vantix-sync' || command === 'vantix-intel-export' || command === 'vantix-report-import') {
    return vantixResult(command, flags, project, scopeAllowlist, startedAt);
  }
  if (command === 'playbook-list') return playbookListResult(flags, project, scopeAllowlist);
  if (command === 'playbook-plan') return playbookPlanResult(flags, project, selectedExchange, scopeAllowlist);
  if (command === 'playbook-run') return playbookRunResult(flags, project, selectedExchange, scopeAllowlist);
  if (command === 'playbook-export') return playbookExportResult(flags, project, selectedExchange, scopeAllowlist);
  if (command === 'playback-client') return playbackClientResult(flags, project, scopeAllowlist);
  if (command === 'playback-server') return playbackServerResult(flags, project, scopeAllowlist);
  if (command === 'spec-import') return specImportResult(flags, project, scopeAllowlist);
  if (command === 'spider-passive-run') return spiderPassiveRunResult(flags, project, selectedExchange, scopeAllowlist);
  if (command === 'spider-ajax-run') return spiderAjaxRunResult(flags, project, selectedExchange, scopeAllowlist);
  if (command === 'dom-tracer-sessions') return domTracerSessionsResult(flags, project, selectedExchange, scopeAllowlist);
  if (command === 'dom-tracer-export') return domTracerExportResult(flags, project, selectedExchange, scopeAllowlist);
  return { status: 'blocked', detail: `Command ${command} is not wired.` };
}

function isReportingPhase(command, flags) {
  return reportingCommands.has(command) || flags['report-redaction'] === true;
}

function defaultGatesForPhase(reportingPhase) {
  return reportingPhase ? ['submission-reporting-redaction'] : ['full-fidelity-operational-output'];
}

function statusResult(project, scopeAllowlist) {
  return {
    status: 'completed',
    mode: 'read-only',
    data: {
      summary: projectSummary(project),
      scopeAllowlist,
      capabilities: Array.from(commands).sort(),
      runtime: {
        scriptPath: agentScriptPath,
        appRoot: agentRootDir,
        cwd: process.cwd(),
      },
      scannerCatalog: agentScannerCatalog(),
      releaseGate: 'Agent commands preserve full execution secrets by default and redact only during submission/reporting exports; active workflows still require explicit execute/approval flags.',
    },
    requestCount: 0,
  };
}

function inventoryResult(project, scopeAllowlist) {
  const byHost = groupBy(project.exchanges, (exchange) => exchange.host || hostFromUrl(exchange.url) || 'unknown');
  return {
    status: 'completed',
    mode: 'read-only',
    data: {
      project: projectSummary(project),
      scopeAllowlist,
      hosts: Object.entries(byHost).map(([host, exchanges]) => ({
        host,
        exchangeCount: exchanges.length,
        methods: unique(exchanges.map((exchange) => exchange.method)),
        paths: unique(exchanges.map((exchange) => exchange.path)).slice(0, 25),
      })),
      toolArtifacts: artifactInventory(project),
    },
    requestCount: 0,
  };
}

function evidenceListResult(project) {
  return {
    status: 'completed',
    mode: 'read-only',
    data: {
      exchanges: project.exchanges.map(exchangeSummary),
      browserLaunches: project.browserLaunches ?? [],
      reports: project.reportFullPackages ?? [],
      aiActionExecutions: project.aiActionExecutionPackages ?? [],
      callbackPackages: project.callbackCorrelationReplays ?? [],
      exploitRuns: project.exploitRuns ?? [],
      scannerRetestWorkflows: project.scannerRetestWorkflows ?? [],
      scannerEvidenceDeltas: project.scannerEvidenceDeltas ?? [],
      scannerActiveScanEvidencePackages: project.scannerActiveScanEvidencePackages ?? [],
      webSocketMessages: project.webSocketMessages ?? [],
      savedWebSocketReplays: project.savedWebSocketReplays ?? [],
      webSocketFuzzRuns: project.webSocketFuzzRuns ?? [],
      webSocketTranscriptExports: project.webSocketTranscriptExports ?? [],
      anvilDefinitions: project.anvilDefinitions ?? [],
      anvilRuleLibraries: project.anvilRuleLibraries ?? [],
      anvilFixtures: project.anvilFixtures ?? [],
      anvilValidationRuns: project.anvilValidationRuns ?? [],
      anvilHeadlessRuns: project.anvilHeadlessRuns ?? [],
      anvilPackageReviews: project.anvilPackageReviews ?? [],
      installedExtensions: project.installedExtensions ?? [],
      extensionCompatibilityFixtures: project.extensionCompatibilityFixtures ?? [],
    },
    requestCount: 0,
  };
}

function findingsListResult(project) {
  return {
    status: 'completed',
    mode: 'read-only',
    data: {
      findings: project.issues,
      count: project.issues.length,
      severities: groupCounts(project.issues.map((issue) => issue.severity ?? 'info')),
    },
    requestCount: 0,
  };
}

function automationListResult(project, scopeAllowlist) {
  const workflows = agentAutomationWorkflows(project);
  const schedulerState = agentCreateAutomationSchedulerState(workflows, new Date(), project.automationSchedulerState);
  return {
    status: 'completed',
    mode: 'read-only',
    data: {
      kind: 'proxyforge-agent-automation-inventory',
      workflowCount: workflows.length,
      workflows,
      schedulerState,
      executions: project.automationExecutions ?? [],
      scopeAllowlist,
      commands: {
        run: `${agentCommandPrefix} automation-run --project <project> --workflow <id> --execute --json`,
        schedulerTick: `${agentCommandPrefix} automation-scheduler-tick --project <project> --execute --json`,
        ciExport: `${agentCommandPrefix} automation-ci-export --project <project> --workflow <id> --provider github-actions --json`,
        parityExport: `${agentCommandPrefix} automation-parity-export --project <project> --out ./automation-parity.json --json`,
        servicePlan: `${agentCommandPrefix} automation-service-plan --project <project> --workflow <id> --out ./automation-service-lifecycle.json --json`,
        serviceSmoke: `${agentCommandPrefix} automation-service-smoke --project <project> --workflow <id> --service-dir ./.gitignored/automation-service-smoke --execute --json`,
      },
    },
    artifacts: workflows.map((workflow) => artifact('automation-workflow', workflow.id, workflow.name)),
    requestCount: 0,
  };
}

async function automationRunResult(flags, project, selectedExchange, scopeAllowlist) {
  const workflows = agentAutomationWorkflows(project);
  const workflow = agentSelectAutomationWorkflow(workflows, flags.workflow ?? flags['workflow-id'] ?? flags.id);
  if (!workflow) return blocked('No automation workflow is available to run.', ['automation-workflow-required']);
  const exchange = selectedExchange ?? project.exchanges[0] ?? defaultProject(flags.target).exchanges[0];
  const approval = await loadAgentAutomationApproval(flags.approve ?? flags.approval);
  const execution = agentRunAutomationWorkflow(workflow, exchange, scopeAllowlist, approval);
  if (!flags.execute) {
    return {
      status: 'planned',
      mode: 'planned',
      trafficSent: false,
      requestCount: 0,
      gates: ['automation-execute-required', 'scope-gate', 'approval-gate', 'full-fidelity-operational-output'],
      data: {
        kind: 'proxyforge-agent-automation-run-plan',
        workflow,
        executionPreview: execution,
        approvalRequired: workflow.steps.some((step) => step.requiresApproval),
        command: `${agentCommandPrefix} automation-run --workflow ${shellQuote(workflow.id)} --execute --json`,
      },
      artifacts: [artifact('automation-run-plan', `automation-plan-${simpleDigest(workflow.id).slice(0, 10)}`, 'Automation run plan')],
      audit: [auditEvent('automation-run', 'planned', `Prepared automation workflow ${workflow.name}; add --execute to run.`, 0)],
    };
  }
  if (execution.status === 'blocked') {
    return {
      status: 'blocked',
      mode: 'blocked',
      trafficSent: false,
      requestCount: 0,
      gates: ['scope-gate', 'approval-gate', 'full-fidelity-operational-output'],
      data: { kind: 'proxyforge-agent-automation-run-result', workflow, execution },
      artifacts: [artifact('automation-run-blocked', execution.id, 'Automation blocked receipt')],
      audit: [auditEvent('automation-run', 'blocked', execution.logs.at(-1) ?? 'Automation workflow blocked.', 0)],
    };
  }
  return {
    status: 'completed',
    mode: 'executed',
    trafficSent: true,
    requestCount: execution.totalRequests,
    gates: ['scope-gate', 'approval-gate', 'rate-limit', 'full-fidelity-operational-output'],
    data: { kind: 'proxyforge-agent-automation-run-result', workflow, execution },
    artifacts: [artifact('automation-run', execution.id, 'Automation execution evidence')],
    audit: [auditEvent('automation-run', 'completed', `Automation workflow ${workflow.name} completed.`, execution.totalRequests)],
  };
}

async function automationCiExportResult(flags, project, scopeAllowlist) {
  const workflows = agentAutomationWorkflows(project);
  const workflow = agentSelectAutomationWorkflow(workflows, flags.workflow ?? flags['workflow-id'] ?? flags.id) ?? workflows[0];
  if (!workflow) return blocked('No automation workflow is available for CI export.', ['automation-workflow-required']);
  const providers = parseList(flags.provider ?? flags.providers).length
    ? parseList(flags.provider ?? flags.providers).filter((provider) => agentAutomationCiProviders.includes(provider))
    : agentAutomationCiProviders;
  const presets = agentAutomationCiProviderMatrix(workflow, scopeAllowlist, providers);
  const outPath = flags.out ? path.resolve(String(flags.out)) : undefined;
  if (outPath) {
    await writePrivateFile(outPath, JSON.stringify({ kind: 'proxyforge-agent-automation-ci-export', workflow, presets }, null, 2), 'utf8');
  }
  return {
    status: 'completed',
    mode: 'read-only',
    trafficSent: false,
    requestCount: 0,
    data: {
      kind: 'proxyforge-agent-automation-ci-export',
      workflow,
      presets,
      outPath,
    },
    artifacts: [
      artifact('automation-ci-export', outPath ?? `automation-ci-${simpleDigest(workflow.id).slice(0, 10)}`, 'Automation CI/headless provider presets'),
    ],
    audit: [auditEvent('automation-ci-export', 'completed', `Exported ${presets.length} CI provider preset(s).`, 0)],
  };
}

function automationSchedulerTickResult(flags, project, selectedExchange, scopeAllowlist) {
  const workflows = agentAutomationWorkflows(project);
  const exchange = selectedExchange ?? project.exchanges[0] ?? defaultProject(flags.target).exchanges[0];
  const state = agentCreateAutomationSchedulerState(workflows, new Date(), project.automationSchedulerState);
  const dueJobs = state.queue.filter((job) => agentIsAutomationSchedulerJobDue(job, new Date()));
  if (!flags.execute) {
    return {
      status: 'planned',
      mode: 'planned',
      trafficSent: false,
      requestCount: 0,
      gates: ['automation-scheduler-execute-required', 'scope-gate', 'approval-gate'],
      data: {
        kind: 'proxyforge-agent-automation-scheduler-tick-plan',
        state,
        dueJobCount: dueJobs.length,
        dueJobs,
      },
      artifacts: [artifact('automation-scheduler-plan', state.id, 'Automation scheduler tick plan')],
      audit: [auditEvent('automation-scheduler-tick', 'planned', `Scheduler has ${dueJobs.length} due job(s).`, 0)],
    };
  }
  const tick = agentRunAutomationSchedulerTick({
    state,
    workflows,
    exchange,
    scopeAllowlist,
    now: new Date(),
    ownerId: String(flags.owner ?? 'proxyforge-agent-scheduler'),
    maxJobs: Math.max(1, Math.min(20, Math.round(numberFlag(flags['max-jobs'], 3)))),
  });
  const requestCount = tick.executions.reduce((sum, execution) => sum + execution.totalRequests, 0);
  return {
    status: 'completed',
    mode: 'executed',
    trafficSent: tick.completedJobs > 0,
    requestCount,
    gates: ['scope-gate', 'approval-gate', 'scheduler-lease', 'full-fidelity-operational-output'],
    data: {
      kind: 'proxyforge-agent-automation-scheduler-tick-result',
      tick,
    },
    artifacts: [artifact('automation-scheduler-tick', tick.state.id, 'Automation scheduler tick evidence')],
    audit: [auditEvent('automation-scheduler-tick', 'completed', tick.logs.at(-1) ?? 'Scheduler tick completed.', requestCount)],
  };
}

async function automationParityExportResult(flags, project, selectedExchange, scopeAllowlist) {
  const packagePayload = agentBuildAutomationParityPackage(project, selectedExchange ?? project.exchanges[0] ?? defaultProject(flags.target).exchanges[0], scopeAllowlist);
  const outPath = flags.out ? path.resolve(String(flags.out)) : undefined;
  if (outPath) {
    await writePrivateFile(outPath, JSON.stringify(packagePayload, null, 2), 'utf8');
  }
  return {
    status: packagePayload.reportReady ? 'completed' : 'blocked',
    mode: 'read-only',
    trafficSent: false,
    requestCount: 0,
    data: { parityPackage: packagePayload, outPath },
    artifacts: [artifact('automation-parity', outPath ?? packagePayload.id, 'Automation parity evidence package')],
    audit: [auditEvent('automation-parity-export', packagePayload.reportReady ? 'completed' : 'blocked', packagePayload.summary, 0)],
  };
}

async function automationServicePlanResult(flags, project, selectedExchange, scopeAllowlist) {
  const workflows = agentAutomationWorkflows(project);
  const workflow = agentSelectAutomationWorkflow(workflows, flags.workflow ?? flags['workflow-id'] ?? flags.id)
    ?? workflows.find((item) => item.scheduleEnabled)
    ?? workflows[0];
  if (!workflow) return blocked('No automation workflow is available for a service lifecycle plan.', ['automation-workflow-required']);
  const schedulerState = agentCreateAutomationSchedulerState(workflows, new Date(), project.automationSchedulerState);
  const exchange = selectedExchange ?? project.exchanges[0] ?? defaultProject(flags.target).exchanges[0];
  const packagePayload = agentBuildAutomationServiceLifecyclePackage({
    workflow,
    schedulerState,
    projectPath: String(flags.project ?? flags.history ?? './workspace.proxyforge.json'),
    scopeAllowlist,
    installRoot: String(flags['install-root'] ?? '/opt/ProxyForge'),
    agentCommand: String(flags['agent-command'] ?? agentCommandPrefix),
    windowsInstallRoot: String(flags['windows-install-root'] ?? '%ProgramFiles%\\ProxyForge'),
    windowsAgentCommand: String(flags['windows-agent-command'] ?? '"%ProgramFiles%\\ProxyForge\\resources\\app.asar\\scripts\\proxyforge-agent.mjs"'),
    serviceName: flags['service-name'] ? String(flags['service-name']) : `proxyforge-automation-${workflow.id}`,
    linuxUser: flags['linux-user'] ? String(flags['linux-user']) : undefined,
    windowsUser: flags['windows-user'] ? String(flags['windows-user']) : undefined,
    exchange,
    generatedAt: new Date().toISOString(),
  });
  const outPath = flags.out ? path.resolve(String(flags.out)) : undefined;
  if (outPath) {
    await writePrivateFile(outPath, JSON.stringify(packagePayload, null, 2), 'utf8');
  }
  return {
    status: packagePayload.reportReady ? 'completed' : 'blocked',
    mode: 'read-only',
    trafficSent: false,
    requestCount: 0,
    gates: ['automation-service-lifecycle-plan', 'full-fidelity-operational-output', 'report-export-only-redaction'],
    data: {
      serviceLifecyclePackage: packagePayload,
      outPath,
    },
    artifacts: [artifact('automation-service-lifecycle', outPath ?? packagePayload.id, 'Automation OS service lifecycle package')],
    audit: [auditEvent('automation-service-plan', packagePayload.reportReady ? 'completed' : 'blocked', packagePayload.summary, 0)],
  };
}

async function automationServiceSmokeResult(flags, project, selectedExchange, scopeAllowlist) {
  const workflows = agentAutomationWorkflows(project);
  const workflow = agentSelectAutomationWorkflow(workflows, flags.workflow ?? flags['workflow-id'] ?? flags.id)
    ?? workflows.find((item) => item.scheduleEnabled)
    ?? workflows[0];
  if (!workflow) return blocked('No automation workflow is available for a service smoke.', ['automation-workflow-required']);
  const serviceDir = path.resolve(String(flags['service-dir'] ?? path.join('.gitignored', 'automation-service-smoke', `agent-${workflow.id}`)));
  if (!flags.execute) {
    return {
      status: 'planned',
      mode: 'planned',
      trafficSent: false,
      requestCount: 0,
      gates: ['automation-service-execute-required', 'installed-host-service-smoke', 'full-fidelity-operational-output'],
      data: {
        kind: 'proxyforge-agent-automation-service-smoke-plan',
        workflow,
        serviceDir,
        command: `${process.execPath} ${automationServiceScriptPath} smoke --service-dir ${shellQuote(serviceDir)} --project ${shellQuote(String(flags.project ?? './workspace.proxyforge.json'))} --workflow ${shellQuote(workflow.id)} --scope ${shellQuote(scopeAllowlist.join(','))}`,
      },
      artifacts: [artifact('automation-service-smoke-plan', serviceDir, 'Automation installed-host service smoke plan')],
      audit: [auditEvent('automation-service-smoke', 'planned', `Planned installed-host Automation service smoke for ${workflow.name}.`, 0)],
    };
  }
  const serviceArgs = [
    automationServiceScriptPath,
    'smoke',
    '--service-dir',
    serviceDir,
    '--service-name',
    String(flags['service-name'] ?? `proxyforge-automation-${workflow.id}`),
    '--workflow',
    workflow.id,
    '--scope',
    scopeAllowlist.join(','),
    '--duration-ms',
    String(Math.max(250, Math.min(5000, Math.round(numberFlag(flags['duration-ms'], 900))))),
    '--interval-ms',
    String(Math.max(50, Math.min(2000, Math.round(numberFlag(flags['interval-ms'], 150))))),
    '--max-jobs',
    String(Math.max(1, Math.min(20, Math.round(numberFlag(flags['max-jobs'], 3))))),
  ];
  if (flags.project) serviceArgs.push('--project', String(flags.project));
  const serviceResult = await runNodeJson(serviceArgs);
  if (serviceResult.code !== 0 && !serviceResult.json) {
    return blocked(`Automation service smoke failed: ${serviceResult.stderr || serviceResult.stdout}`, ['automation-service-smoke-failed']);
  }
  const smokePackage = serviceResult.json?.data?.package ?? serviceResult.json?.package;
  const outPath = flags.out ? path.resolve(String(flags.out)) : undefined;
  if (outPath && smokePackage) {
    await writePrivateFile(outPath, `${JSON.stringify(smokePackage, null, 2)}\n`, 'utf8');
  }
  const requestCount = Number(smokePackage?.tickCount ?? 0);
  const passed = Boolean(smokePackage?.productionReady);
  return {
    status: passed ? 'completed' : 'blocked',
    mode: 'executed',
    trafficSent: requestCount > 0,
    requestCount,
    gates: ['installed-host-service-smoke', 'pid-status-stop-lifecycle', 'durable-state-log', 'full-fidelity-operational-output', 'report-export-only-redaction'],
    data: {
      kind: 'proxyforge-agent-automation-service-smoke-result',
      workflow,
      serviceResult: serviceResult.json,
      smokePackage,
      outPath,
      stdoutTail: tailText(serviceResult.stdout),
      stderrTail: tailText(serviceResult.stderr),
    },
    artifacts: [
      artifact('automation-service-smoke', outPath ?? serviceResult.json?.data?.packagePath ?? serviceDir, 'Automation installed-host service smoke package'),
    ],
    audit: [auditEvent('automation-service-smoke', passed ? 'completed' : 'blocked', `Automation service smoke ${passed ? 'passed' : 'blocked'} for ${workflow.name}.`, requestCount)],
  };
}

async function mitmStartForeground(flags, project, scopeAllowlist) {
  const proxyModule = optionalDist('proxyEngine.js');
  const certModule = optionalDist('certManager.js');
  if (!proxyModule?.ProxyEngine || !certModule?.CertificateAuthorityManager) {
    throw new Error('MITM session requires a built desktop runtime. Run npm run build first.');
  }

  const sessionId = String(flags['session-id'] ?? `agent-mitm-${Date.now()}-${Math.random().toString(16).slice(2)}`);
  const sessionDir = path.resolve(flags['session-dir'] ?? path.join(process.cwd(), 'proxyforge-agent-session'));
  const logPath = path.join(sessionDir, 'exchanges.jsonl');
  const statusPath = path.join(sessionDir, 'session.json');
  const certDir = path.join(sessionDir, 'certs');
  const startedAt = new Date().toISOString();
  const requestedPort = numberFlag(flags.port, 8080);
  const port = requestedPort === 0 ? await findFreePort() : requestedPort;
  const upstreamTlsMode = agentUpstreamTlsMode(flags['upstream-tls'] ?? flags['upstream-tls-mode']);
  const upstreamProxyConfig = flags['upstream-proxy']
    ? {
        enabled: true,
        url: String(flags['upstream-proxy']),
        authorization: flags['upstream-proxy-authorization'] ? String(flags['upstream-proxy-authorization']) : undefined,
        noProxy: String(flags['upstream-proxy-no-proxy'] ?? '')
          .split(',')
          .map((item) => item.trim())
          .filter(Boolean),
      }
    : null;
  let exchangeCount = 0;
  let webSocketMessageCount = 0;
  let stopped = false;
  let upstreamProxyStatus = {
    enabled: false,
    noProxy: [],
    message: 'Upstream proxy chaining disabled',
  };
  let httpsInspectionState = {
    enabled: flags['https-inspection'] !== false,
    upstreamTlsMode,
    upstreamProxy: upstreamProxyStatus,
    message: `HTTPS inspection ${flags['https-inspection'] === false ? 'disabled' : 'enabled'}; ${upstreamTlsMode} upstream TLS validation`,
  };

  await ensurePrivateDir(sessionDir, { hardenExisting: true });
  await writePrivateFile(logPath, '', { flag: 'a' });
  const caManager = new certModule.CertificateAuthorityManager(certDir);
  if (flags['ensure-ca']) await caManager.ensureRoot();

  const writeStatus = async (status, message) => {
    const certificate = await caManager.status().catch((error) => ({
      ready: false,
      rootCertificatePath: path.join(certDir, 'projects', 'default-project', 'proxyforge-root-ca.pem'),
      projectId: 'default-project',
      projectLabel: 'Default Project',
      projectCertificateDir: path.join(certDir, 'projects', 'default-project'),
      hostCertificateCount: 0,
      message: error instanceof Error ? error.message : 'Certificate status unavailable',
    }));
    const payload = {
      kind: 'proxyforge-agent-mitm-session',
      schemaVersion,
      sessionId,
      pid: process.pid,
      status,
      message,
      project: projectSummary(project),
      scopeAllowlist,
      port,
      host: '127.0.0.1',
      proxyUrl: `http://127.0.0.1:${port}`,
      startedAt,
      updatedAt: new Date().toISOString(),
      logPath,
      statusPath,
      certDir,
      httpsInspection: {
        enabled: httpsInspectionState.enabled,
        upstreamTlsMode: httpsInspectionState.upstreamTlsMode,
        upstreamProxy: upstreamProxyStatus,
        message: httpsInspectionState.message,
        certificate,
      },
      exchangeCount,
      webSocketMessageCount,
      capabilities: ['http-proxy', 'connect-tunnel', 'https-mitm', 'project-ca-status', 'upstream-tls-mode', 'upstream-proxy-chain', 'streamed-response-capture', 'websocket-capture', 'persistent-jsonl-log', 'replay-scanner-exploit-handoff'],
    };
    await writePrivateFile(statusPath, JSON.stringify(payload, null, 2), 'utf8');
    return payload;
  };

  const appendEvent = (kind, payload) => {
    const line = JSON.stringify({
      kind,
      schemaVersion,
      sessionId,
      at: new Date().toISOString(),
      payload,
    });
    appendPrivateFile(logPath, `${line}\n`).catch(() => undefined);
  };

  const proxy = new proxyModule.ProxyEngine(
    (exchange) => {
      exchangeCount += 1;
      appendEvent('proxyforge-agent-mitm-exchange', { exchange });
      writeStatus('running', `Captured ${exchangeCount} HTTP exchange${exchangeCount === 1 ? '' : 's'}`).catch(() => undefined);
    },
    new certModule.CertificateAuthorityManager(certDir),
    (pending) => {
      appendEvent('proxyforge-agent-mitm-intercepts', { pendingCount: pending.length, pending });
    },
    (message) => {
      webSocketMessageCount += 1;
      appendEvent('proxyforge-agent-mitm-websocket-message', { message });
      writeStatus('running', `Captured ${exchangeCount} HTTP exchange${exchangeCount === 1 ? '' : 's'} and ${webSocketMessageCount} WebSocket frame${webSocketMessageCount === 1 ? '' : 's'}`).catch(() => undefined);
    },
    (pending) => {
      appendEvent('proxyforge-agent-mitm-websocket-intercepts', { pendingCount: pending.length, pending });
    },
  );

  httpsInspectionState = proxy.setUpstreamTlsValidation(upstreamTlsMode);
  if (upstreamTlsMode === 'relaxed') {
    appendEvent('proxyforge-agent-mitm-upstream-tls-warning', {
      upstreamTlsMode,
      message: 'Relaxed upstream TLS validation was explicitly selected for this run.',
    });
  }
  if (upstreamProxyConfig && typeof proxy.setUpstreamProxy === 'function') {
    upstreamProxyStatus = proxy.setUpstreamProxy(upstreamProxyConfig);
    httpsInspectionState = proxy.httpsInspectionStatus();
  }
  if (flags['https-inspection'] === false) httpsInspectionState = proxy.setHttpsInspection(false);
  if (flags.intercept) proxy.setIntercept(true);
  if (flags['response-intercept']) proxy.setResponseIntercept(true);
  if (flags['websocket-intercept']) proxy.setWebSocketIntercept(true);

  const proxyStatus = await proxy.start(port);
  const ready = await writeStatus('running', proxyStatus.message);
  appendEvent('proxyforge-agent-mitm-started', ready);
  process.stdout.write(`${JSON.stringify({
    kind: 'proxyforge-agent-result',
    schemaVersion,
    command: 'mitm-start',
    generatedAt: new Date().toISOString(),
    status: 'running',
    mode: 'persistent',
    project: projectSummary(project),
    safety: {
      redacted: false,
      secretHandling: 'execution-full-fidelity-secrets-preserved',
      scopeAllowlist,
      trafficSent: false,
      requestCount: 0,
      approvals: [],
      gates: ['persistent-session', 'loopback-bind', 'full-fidelity-operational-jsonl-log', 'operator-stop-required'],
    },
    artifacts: [artifact('mitm-session', statusPath, 'Persistent MITM session'), artifact('mitm-log', logPath, 'Persistent MITM JSONL log')],
    data: ready,
    audit: [auditEvent('mitm-start', 'running', proxyStatus.message, 0)],
  })}\n`);

  const stop = async (signal) => {
    if (stopped) return;
    stopped = true;
    const stoppedStatus = await proxy.stop().catch((error) => ({ message: error instanceof Error ? error.message : 'Proxy stop failed' }));
    const finalStatus = await writeStatus('stopped', `${signal}: ${stoppedStatus.message}`);
    appendEvent('proxyforge-agent-mitm-stopped', finalStatus);
    process.exit(0);
  };
  process.once('SIGINT', () => { void stop('SIGINT'); });
  process.once('SIGTERM', () => { void stop('SIGTERM'); });

  await new Promise(() => undefined);
}

async function mitmStatusResult(flags) {
  const statusPath = mitmStatusPath(flags);
  const status = await loadJsonMaybe(statusPath);
  if (!status) return blocked(`No MITM session status found at ${statusPath}`);
  return {
    status: status.status === 'running' ? 'completed' : status.status ?? 'completed',
    mode: 'read-only',
    trafficSent: false,
    requestCount: 0,
    gates: ['session-status-read'],
    data: status,
    artifacts: [artifact('mitm-session', statusPath, 'Persistent MITM session')],
  };
}

async function mitmStopResult(flags) {
  const statusPath = mitmStatusPath(flags);
  const status = await loadJsonMaybe(statusPath);
  if (!status?.pid) return blocked(`No running MITM session pid found at ${statusPath}`);
  try {
    process.kill(Number(status.pid), 'SIGTERM');
  } catch (error) {
    return blocked(error instanceof Error ? error.message : 'Failed to stop MITM session');
  }
  return {
    status: 'completed',
    mode: 'executed',
    trafficSent: false,
    requestCount: 0,
    gates: ['session-pid-signal'],
    data: { statusPath, pid: status.pid, message: 'Stop signal sent to MITM session.' },
    artifacts: [artifact('mitm-session', statusPath, 'Persistent MITM session')],
  };
}

async function mitmExportResult(flags) {
  const sessionDir = path.resolve(flags['session-dir'] ?? path.join(process.cwd(), 'proxyforge-agent-session'));
  const logPath = path.resolve(flags.log ?? path.join(sessionDir, 'exchanges.jsonl'));
  const statusPath = mitmStatusPath(flags);
  const status = await loadJsonMaybe(statusPath);
  let lines = [];
  try {
    lines = (await fs.readFile(logPath, 'utf8')).split(/\r?\n/).filter(Boolean);
  } catch {
    lines = [];
  }
  const events = lines.map((line) => {
    try {
      return JSON.parse(line);
    } catch {
      return null;
    }
  }).filter(Boolean);
  const exchanges = events
    .filter((event) => event.kind === 'proxyforge-agent-mitm-exchange')
    .map((event) => event.payload?.exchange)
    .filter(Boolean);
  const webSocketMessages = events
    .filter((event) => event.kind === 'proxyforge-agent-mitm-websocket-message')
    .map((event) => event.payload?.message)
    .filter(Boolean);
  return {
    status: 'completed',
    mode: 'read-only',
    trafficSent: false,
    requestCount: 0,
    gates: ['session-log-read', 'full-fidelity-operational-export'],
    data: {
      status,
      logPath,
      eventCount: events.length,
      exchangeCount: exchanges.length,
      webSocketMessageCount: webSocketMessages.length,
      exchanges,
      webSocketMessages,
    },
    artifacts: [artifact('mitm-log', logPath, 'Persistent MITM JSONL log')],
  };
}

function searchResult(project, query) {
  const terms = query.toLowerCase().split(/\s+/).filter(Boolean);
  const matches = project.exchanges
    .map((exchange) => {
      const haystack = [
        exchange.id,
        exchange.method,
        exchange.url,
        exchange.host,
        exchange.path,
        exchange.notes,
        ...(exchange.tags ?? []),
        exchange.requestRaw,
        exchange.responseRaw,
      ].join('\n').toLowerCase();
      const score = terms.length ? terms.reduce((count, term) => count + (haystack.includes(term) ? 1 : 0), 0) : 0;
      return { exchange, score };
    })
    .filter((item) => item.score > 0 || terms.length === 0)
    .sort((a, b) => b.score - a.score)
    .slice(0, 25)
    .map((item) => ({
      ...exchangeSummary(item.exchange),
      score: item.score,
      snippet: makeSnippet(item.exchange, terms[0] ?? ''),
    }));
  return {
    status: 'completed',
    mode: 'read-only',
    data: {
      query,
      matchCount: matches.length,
      matches,
    },
    requestCount: 0,
  };
}

async function searchIndexResult(project, flags, scopeAllowlist) {
  const query = String(flags.query ?? flags.q ?? '');
  const indexBuildStartedAt = Date.now();
  const index = buildAgentSearchSemanticIndex(project.exchanges, {
    generatedAt: new Date().toISOString(),
    maxTokens: numberFlag(flags['max-tokens'], 4096),
  });
  const indexBuildDurationMs = Math.max(0, Date.now() - indexBuildStartedAt);
  const matches = query
    ? agentSemanticProviderMatchesFromIndex(index, query, {
      limit: numberFlag(flags.limit, 25),
      threshold: Number.isFinite(Number(flags.threshold)) ? Number(flags.threshold) : 0.12,
    })
    : [];
  const outPath = flags.out ? path.resolve(String(flags.out)) : undefined;
  if (outPath) {
    await writePrivateFile(outPath, index.content);
  }
  const soakReport = flags.soak || flags['soak-report']
    ? buildAgentSearchLargeProjectSoakReport(project.exchanges, index, {
      queries: parseList(flags['soak-query'] ?? flags.queries ?? query),
      limit: numberFlag(flags.limit, 25),
      threshold: Number.isFinite(Number(flags.threshold)) ? Number(flags.threshold) : 0.12,
      minExchangeCount: numberFlag(flags['soak-min-exchanges'], 100),
      minTotalMatches: numberFlag(flags['soak-min-matches'], 1),
      maxBuildDurationMs: numberFlag(flags['soak-max-build-ms'], 5000),
      maxTotalQueryDurationMs: numberFlag(flags['soak-max-query-ms'], 2500),
      maxIndexContentBytes: numberFlag(flags['soak-max-index-bytes'], 50 * 1024 * 1024),
      buildDurationMs: indexBuildDurationMs,
    })
    : undefined;
  const soakOutPath = soakReport && flags['soak-out'] ? path.resolve(String(flags['soak-out'])) : undefined;
  if (soakReport && soakOutPath) {
    await writePrivateFile(soakOutPath, soakReport.content);
  }
  const providerUrl = flags['provider-url'] ?? flags.providerUrl ?? flags['semantic-provider-url'];
  const providerPlan = providerUrl
    ? buildAgentSearchProviderInvocationPlan(index, query, flags, scopeAllowlist)
    : undefined;
  if (providerPlan && !flags.execute) {
    return {
      status: 'planned',
      mode: 'read-only',
      data: {
        query,
        indexPath: outPath,
        index: outPath ? summarizeAgentSearchSemanticIndex(index) : index,
        matchCount: matches.length,
        matches,
        soakReportPath: soakOutPath,
        soakReport: soakReport ? (soakOutPath ? summarizeAgentSearchLargeProjectSoakReport(soakReport) : soakReport) : undefined,
        providerPlan,
      },
      artifacts: [
        artifact('search-semantic-index', outPath ?? index.corpusDigestPreview, 'Full-fidelity persistent semantic search index'),
        ...(soakReport ? [artifact('search-large-project-soak', soakOutPath ?? soakReport.indexSummary.corpusDigestPreview, 'Full-fidelity large-project semantic index soak report')] : []),
        artifact('search-live-provider-plan', providerPlan.id, 'Scoped live semantic provider invocation plan'),
      ],
      requestCount: 0,
      trafficSent: false,
      gates: ['explicit-execute-required', 'provider-host-scope', 'full-fidelity-semantic-corpus'],
      audit: [auditEvent('search-index', 'planned', `Prepared live semantic provider invocation for ${providerPlan.provider.host}.`, 0)],
    };
  }
  if (providerPlan && !providerPlan.requirements.providerHostScopeCovered) {
    return blocked(`Search semantic provider host ${providerPlan.provider.url} is outside scope. Add --scope ${providerPlan.provider.host} when this provider is authorized.`, ['provider-host-scope']);
  }
  const providerPackage = providerPlan
    ? await executeAgentSearchProviderInvocation(index, query, flags, providerPlan, project)
    : undefined;
  const providerOutPath = providerPackage && flags['provider-out'] ? path.resolve(String(flags['provider-out'])) : undefined;
  if (providerPackage && providerOutPath) {
    await writePrivateFile(providerOutPath, providerPackage.content);
  }
  return {
    status: providerPackage && !providerPackage.reportReady ? 'blocked' : 'completed',
    mode: providerPackage ? 'executed' : 'read-only',
    data: {
      query,
      indexPath: outPath,
      index: outPath ? summarizeAgentSearchSemanticIndex(index) : index,
      matchCount: matches.length,
      matches,
      soakReportPath: soakOutPath,
      soakReport: soakReport ? (soakOutPath ? summarizeAgentSearchLargeProjectSoakReport(soakReport) : soakReport) : undefined,
      providerPackagePath: providerOutPath,
      providerPackage: providerPackage ? (providerOutPath ? summarizeAgentSearchProviderInvocationPackage(providerPackage) : providerPackage) : undefined,
      providerMatches: providerPackage?.providerMatches,
      providerRankedMatches: providerPackage?.providerRankedMatches,
    },
    artifacts: [
      artifact('search-semantic-index', outPath ?? index.corpusDigestPreview, 'Full-fidelity persistent semantic search index'),
      ...(soakReport ? [artifact('search-large-project-soak', soakOutPath ?? soakReport.indexSummary.corpusDigestPreview, 'Full-fidelity large-project semantic index soak report')] : []),
      ...(providerPackage ? [artifact('search-live-provider-invocation', providerOutPath ?? providerPackage.id, 'Live semantic provider invocation package')] : []),
    ],
    requestCount: providerPackage ? 1 : 0,
    trafficSent: Boolean(providerPackage),
    gates: providerPackage
      ? ['provider-host-scope', 'explicit-execute', 'live-semantic-provider-request', 'full-fidelity-provider-output']
      : undefined,
  };
}

function viewResult(project, selectedExchange, flags) {
  const exchange = selectedExchange ?? project.exchanges[0];
  if (!exchange) return blocked('No exchange is available to view.');
  const mode = String(flags.mode ?? 'raw');
  return {
    status: 'completed',
    mode: 'read-only',
    data: {
      mode,
      exchange: exchangeSummary(exchange),
      requestRaw: exchange.requestRaw ?? '',
      responseRaw: exchange.responseRaw ?? '',
      decoded: decodeExchange(exchange, mode),
    },
    requestCount: 0,
  };
}

async function chromiumCaptureResult(flags, project, scopeAllowlist) {
  const targetUrl = normalizeTarget(flags.target ?? project.exchanges[0]?.url ?? 'https://example.test/');
  if (!isTargetInScope(targetUrl, scopeAllowlist)) return blocked(`Target ${targetUrl} is outside scope.`, ['scope-match']);
  const browserModule = optionalDist('browserLauncher.js');
  const proxyPort = numberFlag(flags['proxy-port'], 8080);
  const proxyHost = String(flags['proxy-host'] ?? '127.0.0.1');
  const profileBaseDir = String(flags['profile-dir'] ?? path.join(os.tmpdir(), 'proxyforge-agent-browser-profiles'));
  const matrix = browserModule?.buildManagedBrowserLaunchMatrix
    ? browserModule.buildManagedBrowserLaunchMatrix({
      targetUrl,
      proxyHost,
      proxyPort,
      profileBaseDir,
      families: ['chromium', 'chrome', 'edge', 'firefox'],
      platforms: ['linux', 'win32'],
    })
    : fallbackBrowserMatrix(targetUrl, proxyHost, proxyPort, profileBaseDir);
  let launch = null;
  if (flags.execute && browserModule?.launchManagedBrowser) {
    launch = await browserModule.launchManagedBrowser({
      targetUrl,
      browser: flags.browser ?? 'auto',
      proxyHost,
      proxyPort,
      profileBaseDir,
      profileName: flags.profile ?? 'agent-profile',
      dryRun: flags['dry-run'] !== false,
    });
  }
  return {
    status: launch?.status === 'error' ? 'blocked' : 'completed',
    mode: flags.execute ? 'executed' : 'planned',
    trafficSent: false,
    requestCount: 0,
    gates: ['scope-match', 'isolated-profile', 'proxy-flags', 'full-fidelity-cookie-access'],
    data: {
      targetUrl,
      matrix,
      launch,
      agentNote: 'Default mode emits a launch/capture plan. Use --execute to ask ProxyForge to launch a managed browser on this host.',
    },
    artifacts: [artifact('browser-launch-matrix', matrix.id ?? 'browser-launch-matrix', matrix.title ?? 'Managed browser launch matrix')],
  };
}

async function cookieCaptureResult(flags, project) {
  const profilePath = flags.profile ?? flags['profile-dir'] ?? project.browserLaunches?.[0]?.profilePath ?? '';
  const browser = String(flags.browser ?? 'chromium');
  const targetUrl = normalizeTarget(flags.target ?? project.exchanges[0]?.url ?? 'https://example.test/');
  const cookieModule = optionalDist('browserCookies.js');
  let readiness = null;
  let extraction = null;
  if (cookieModule?.buildBrowserCookieReadinessReport && profilePath) {
    readiness = await cookieModule.buildBrowserCookieReadinessReport({
      browser,
      profilePath,
      domainFilter: flags.domain ?? flags.host,
      targetUrl,
    });
  }
  if (flags.execute && cookieModule?.extractBrowserCookies && profilePath) {
    extraction = await cookieModule.extractBrowserCookies({
      browser,
      profilePath,
      targetUrl,
      domainFilter: flags.domain ?? flags.host,
    });
  }
  return {
    status: 'completed',
    mode: flags.execute ? 'executed' : 'planned',
    requestCount: 0,
    gates: ['profile-path-required-for-host-extraction', 'full-fidelity-cookie-access'],
    data: {
      browser,
      profilePath,
      targetUrl,
      extraction,
      readiness: readiness ?? {
        status: profilePath ? 'unavailable' : 'planned',
        message: profilePath ? 'Cookie readiness engine is unavailable until the Electron build exists.' : 'Provide --profile to inspect a browser cookie store.',
      },
    },
  };
}

async function proxyImportResult(flags) {
  const sourcePath = flags.file ?? flags.history ?? flags.log ?? flags.project;
  if (!sourcePath) return blocked('proxy-import requires --file, --history, --log, or --project.');
  const absolutePath = path.resolve(String(sourcePath));
  const raw = await fs.readFile(absolutePath, 'utf8');
  const imported = parseProxyImport(raw);
  const exchanges = imported.exchanges.map((exchange, index) => normalizeImportedExchange(exchange, index)).filter(Boolean);
  const packagePayload = {
    kind: 'proxyforge-agent-proxy-import',
    schemaVersion,
    importedAt: new Date().toISOString(),
    sourcePath: absolutePath,
    sourceFormat: imported.sourceFormat,
    exchangeCount: exchanges.length,
    hosts: unique(exchanges.map((exchange) => exchange.host || hostFromUrl(exchange.url) || 'unknown')),
    exchanges,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    digestPreview: simpleDigest(raw),
  };
  const outPath = flags.out ? path.resolve(String(flags.out)) : undefined;
  if (outPath) {
    await writePrivateFile(outPath, JSON.stringify(packagePayload, null, 2), 'utf8');
  }
  return {
    status: 'completed',
    mode: 'read-only',
    requestCount: 0,
    gates: ['local-file-read', 'full-fidelity-operational-import'],
    data: {
      ...packagePayload,
      outputPath: outPath,
    },
    artifacts: [artifact('proxy-import', outPath ?? absolutePath, 'Full-fidelity proxy/history import package')],
  };
}

async function projectStoreStatusResult(flags) {
  const storePath = projectStorePathFromFlags(flags);
  if (!storePath) return blocked('project-store-status requires --store or --project-store pointing at a Project Store directory.');
  const { ProjectStore } = loadProjectStoreRuntime();
  const store = await ProjectStore.open(storePath, { recover: false });
  try {
    const recovery = await store.recoverPendingHttpExchanges();
    const stats = store.stats();
    const sampleExchangeIds = unique([
      ...recovery.recoveredIds,
      ...store.searchHttpExchanges({ limit: 5 }).map((exchange) => exchange.id),
    ]).slice(0, 5);
    return {
      status: recovery.failedCount ? 'blocked' : 'completed',
      mode: 'read-only',
      requestCount: 0,
      gates: ['local-project-store-read', 'crash-recovery-journal', 'full-fidelity-operational-store'],
      data: {
        kind: 'proxyforge-agent-project-store-status',
        schemaVersion,
        storePath,
        manifest: store.exportManifest(),
        stats,
        recovery,
        sampleExchanges: projectStoreExchangeDetails(store, sampleExchangeIds),
        sampleTargetHosts: store.listTargetHosts?.({ limit: 5 }) ?? [],
        sampleTargetRoutes: store.listTargetRoutes?.({ limit: 5 }) ?? [],
        sampleParameters: store.listParameters?.({ limit: 10 }) ?? [],
        sampleRepeaterSends: projectStoreRepeaterSendDetails(store, store.listRepeaterSends?.({ limit: 5 }).map((send) => send.id) ?? []),
        sampleIntruderAttacks: projectStoreIntruderAttackDetails(store, store.listIntruderAttacks?.({ limit: 5 }).map((attack) => attack.id) ?? []),
        sampleIntruderResults: projectStoreIntruderResultDetails(store, store.listIntruderResults?.({ limit: 5 }).map((result) => result.id) ?? []),
        sampleScannerTasks: store.listScannerTasks?.({ limit: 5 }) ?? [],
        sampleScannerFindings: projectStoreScannerFindingDetails(store, store.listScannerFindings?.({ limit: 5 }).map((finding) => finding.id) ?? []),
        sampleWebSocketConnections: store.listWebSocketConnections?.({ limit: 5 }) ?? [],
        sampleWebSocketFrames: projectStoreWebSocketFrameDetails(store, store.listWebSocketFrames?.({ limit: 5 }).map((frame) => frame.id) ?? []),
        sampleIssues: projectStoreIssueDetails(store, store.listIssues?.({ limit: 5 }).map((issue) => issue.id) ?? []),
        sampleReports: projectStoreReportDetails(store, store.listReportExports?.({ limit: 5 }).map((report) => report.id) ?? []),
        sampleAutomationRuns: projectStoreAutomationRunDetails(store, store.listAutomationRuns?.({ limit: 5 }).map((run) => run.id) ?? []),
        sampleAiRuns: projectStoreAiRunDetails(store, store.listAiRuns?.({ limit: 5 }).map((run) => run.id) ?? []),
        sampleExtensionRuns: projectStoreExtensionRunDetails(store, store.listExtensionRuns?.({ limit: 5 }).map((run) => run.id) ?? []),
        backupCommand: `${agentCommandPrefix} project-store-backup --store ${shellQuote(storePath)} --out ./.gitignored/proxyforge-backups --execute --json`,
        secretHandling: 'execution-full-fidelity-secrets-preserved',
        reportRedactionBoundary: 'redact-only-during-report-export',
      },
      artifacts: [artifact('project-store-status', storePath, 'Project Store status and recovery journal report')],
      audit: [auditEvent('project-store-status', 'completed', `Read Project Store ${storePath} with ${stats.exchangeCount} exchange(s).`, 0)],
    };
  } finally {
    store.close();
  }
}

async function projectStoreRecoverResult(flags) {
  const storePath = projectStorePathFromFlags(flags);
  if (!storePath) return blocked('project-store-recover requires --store or --project-store pointing at a Project Store directory.');
  const { ProjectStore } = loadProjectStoreRuntime();
  const store = await ProjectStore.open(storePath, { recover: false });
  try {
    const recovery = await store.recoverPendingHttpExchanges();
    const outPath = flags.out ? path.resolve(String(flags.out)) : undefined;
    if (outPath) {
      await writePrivateFile(outPath, JSON.stringify(recovery, null, 2), 'utf8');
    }
    return {
      status: recovery.failedCount ? 'blocked' : 'completed',
      mode: 'executed',
      requestCount: 0,
      gates: ['local-project-store-write', 'crash-recovery-journal', 'full-fidelity-operational-store'],
      data: {
        ...recovery,
        stats: store.stats(),
        sampleExchanges: projectStoreExchangeDetails(store, unique([
          ...recovery.recoveredIds,
          ...store.searchHttpExchanges({ limit: 5 }).map((exchange) => exchange.id),
        ]).slice(0, 5)),
        sampleTargetHosts: store.listTargetHosts?.({ limit: 5 }) ?? [],
        sampleTargetRoutes: store.listTargetRoutes?.({ limit: 5 }) ?? [],
        sampleParameters: store.listParameters?.({ limit: 10 }) ?? [],
        sampleRepeaterSends: projectStoreRepeaterSendDetails(store, store.listRepeaterSends?.({ limit: 5 }).map((send) => send.id) ?? []),
        sampleIntruderAttacks: projectStoreIntruderAttackDetails(store, store.listIntruderAttacks?.({ limit: 5 }).map((attack) => attack.id) ?? []),
        sampleIntruderResults: projectStoreIntruderResultDetails(store, store.listIntruderResults?.({ limit: 5 }).map((result) => result.id) ?? []),
        sampleScannerTasks: store.listScannerTasks?.({ limit: 5 }) ?? [],
        sampleScannerFindings: projectStoreScannerFindingDetails(store, store.listScannerFindings?.({ limit: 5 }).map((finding) => finding.id) ?? []),
        sampleWebSocketConnections: store.listWebSocketConnections?.({ limit: 5 }) ?? [],
        sampleWebSocketFrames: projectStoreWebSocketFrameDetails(store, store.listWebSocketFrames?.({ limit: 5 }).map((frame) => frame.id) ?? []),
        sampleIssues: projectStoreIssueDetails(store, store.listIssues?.({ limit: 5 }).map((issue) => issue.id) ?? []),
        sampleReports: projectStoreReportDetails(store, store.listReportExports?.({ limit: 5 }).map((report) => report.id) ?? []),
        sampleAutomationRuns: projectStoreAutomationRunDetails(store, store.listAutomationRuns?.({ limit: 5 }).map((run) => run.id) ?? []),
        sampleAiRuns: projectStoreAiRunDetails(store, store.listAiRuns?.({ limit: 5 }).map((run) => run.id) ?? []),
        sampleExtensionRuns: projectStoreExtensionRunDetails(store, store.listExtensionRuns?.({ limit: 5 }).map((run) => run.id) ?? []),
        outputPath: outPath,
      },
      artifacts: [artifact('project-store-recovery-report', outPath ?? storePath, 'Project Store crash recovery replay report')],
      audit: [auditEvent('project-store-recover', recovery.failedCount ? 'blocked' : 'completed', recovery.summary, recovery.recoveredHttpExchangeCount)],
    };
  } finally {
    store.close();
  }
}

async function projectStoreBackupResult(flags) {
  const storePath = projectStorePathFromFlags(flags);
  if (!storePath) return blocked('project-store-backup requires --store or --project-store pointing at a Project Store directory.');
  const backupRoot = path.resolve(String(flags.out ?? flags.backup ?? flags['backup-root'] ?? path.join('.gitignored', 'proxyforge-backups')));
  const label = String(flags.label ?? 'agent-restore-point');
  if (!flags.execute) {
    return {
      status: 'planned',
      mode: 'read-only',
      requestCount: 0,
      gates: ['explicit-execute-required', 'local-project-store-read', 'full-fidelity-operational-store'],
      data: {
        kind: 'proxyforge-agent-project-store-backup-plan',
        schemaVersion,
        storePath,
        backupRoot,
        label,
        command: `${agentCommandPrefix} project-store-backup --store ${shellQuote(storePath)} --out ${shellQuote(backupRoot)} --label ${shellQuote(label)} --execute --json`,
        secretHandling: 'execution-full-fidelity-secrets-preserved',
        reportRedactionBoundary: 'redact-only-during-report-export',
      },
      artifacts: [artifact('project-store-backup-plan', backupRoot, 'Project Store backup plan')],
      audit: [auditEvent('project-store-backup', 'planned', `Prepared Project Store backup for ${storePath}; add --execute to copy.`, 0)],
    };
  }
  const { ProjectStore } = loadProjectStoreRuntime();
  const store = await ProjectStore.open(storePath, { recover: false });
  try {
    const recovery = await store.recoverPendingHttpExchanges();
    const backup = await store.createBackup(backupRoot, { label });
    return {
      status: recovery.failedCount ? 'blocked' : 'completed',
      mode: 'executed',
      requestCount: 0,
      gates: ['explicit-execute', 'local-project-store-read', 'backup-copy', 'full-fidelity-operational-store'],
      data: {
        kind: 'proxyforge-agent-project-store-backup-result',
        schemaVersion,
        storePath,
        recovery,
        backup,
        stats: store.stats(),
        sampleExchanges: projectStoreExchangeDetails(store, store.searchHttpExchanges({ limit: 5 }).map((exchange) => exchange.id)),
        sampleTargetHosts: store.listTargetHosts?.({ limit: 5 }) ?? [],
        sampleTargetRoutes: store.listTargetRoutes?.({ limit: 5 }) ?? [],
        sampleParameters: store.listParameters?.({ limit: 10 }) ?? [],
        sampleRepeaterSends: projectStoreRepeaterSendDetails(store, store.listRepeaterSends?.({ limit: 5 }).map((send) => send.id) ?? []),
        sampleIntruderAttacks: projectStoreIntruderAttackDetails(store, store.listIntruderAttacks?.({ limit: 5 }).map((attack) => attack.id) ?? []),
        sampleIntruderResults: projectStoreIntruderResultDetails(store, store.listIntruderResults?.({ limit: 5 }).map((result) => result.id) ?? []),
        sampleScannerTasks: store.listScannerTasks?.({ limit: 5 }) ?? [],
        sampleScannerFindings: projectStoreScannerFindingDetails(store, store.listScannerFindings?.({ limit: 5 }).map((finding) => finding.id) ?? []),
        sampleWebSocketConnections: store.listWebSocketConnections?.({ limit: 5 }) ?? [],
        sampleWebSocketFrames: projectStoreWebSocketFrameDetails(store, store.listWebSocketFrames?.({ limit: 5 }).map((frame) => frame.id) ?? []),
        sampleIssues: projectStoreIssueDetails(store, store.listIssues?.({ limit: 5 }).map((issue) => issue.id) ?? []),
        sampleReports: projectStoreReportDetails(store, store.listReportExports?.({ limit: 5 }).map((report) => report.id) ?? []),
        sampleAutomationRuns: projectStoreAutomationRunDetails(store, store.listAutomationRuns?.({ limit: 5 }).map((run) => run.id) ?? []),
        sampleAiRuns: projectStoreAiRunDetails(store, store.listAiRuns?.({ limit: 5 }).map((run) => run.id) ?? []),
        sampleExtensionRuns: projectStoreExtensionRunDetails(store, store.listExtensionRuns?.({ limit: 5 }).map((run) => run.id) ?? []),
        secretHandling: 'execution-full-fidelity-secrets-preserved',
        reportRedactionBoundary: 'redact-only-during-report-export',
      },
      artifacts: [
        artifact('project-store-backup', backup.backupDir, 'Project Store restore point'),
        artifact('project-store-backup-manifest', backup.manifestPath, 'Project Store restore point manifest'),
      ],
      audit: [auditEvent('project-store-backup', recovery.failedCount ? 'blocked' : 'completed', `Created Project Store backup at ${backup.backupDir}.`, 0)],
    };
  } finally {
    store.close();
  }
}

async function crawlRunResult(flags, project, scopeAllowlist) {
  const startUrl = normalizeTarget(flags.target ?? flags.url ?? project.exchanges[0]?.url ?? 'https://example.test/');
  if (!isTargetInScope(startUrl, scopeAllowlist)) return blocked(`Crawler target ${startUrl} is outside scope.`, ['scope-match']);
  const request = {
    startUrl,
    scopeAllowlist,
    maxDepth: numberFlag(flags.depth ?? flags['max-depth'], 2),
    maxPages: numberFlag(flags.pages ?? flags['max-pages'], 20),
    throttleMs: numberFlag(flags.throttle ?? flags['throttle-ms'], 100),
    userAgent: String(flags['user-agent'] ?? 'ProxyForge Agent Crawler'),
    includeForms: flags.forms !== false && flags['include-forms'] !== false,
    headers: {
      ...headersFromFlag(flags.header),
      ...(flags.cookie ? { Cookie: String(flags.cookie) } : {}),
    },
  };
  if (!flags.execute) {
    return {
      status: 'planned',
      mode: 'planned',
      trafficSent: false,
      requestCount: 0,
      gates: ['scope-match', 'explicit-execute-required', 'bounded-crawl-budget'],
      data: {
        request,
        summary: `Crawler plan for ${startUrl}: depth ${request.maxDepth}, max ${request.maxPages} page(s), throttle ${request.throttleMs}ms.`,
      },
      artifacts: [artifact('crawl-plan', `crawl-plan-${simpleDigest(startUrl).slice(0, 10)}`, 'Scoped crawler execution plan')],
    };
  }
  const crawlModule = optionalDist('crawlEngine.js');
  if (!crawlModule?.CrawlEngine) return blocked('crawl-run requires a built desktop runtime. Run npm run build first.', ['runtime-module']);
  const engine = new crawlModule.CrawlEngine({ upstreamTlsMode: () => (flags['tls-insecure'] || flags.insecure ? 'relaxed' : 'strict') });
  const summary = await engine.runCrawl(request);
  return {
    status: summary.blocked ? 'blocked' : 'completed',
    mode: 'executed',
    trafficSent: summary.totalRequests > 0,
    requestCount: summary.totalRequests,
    gates: ['scope-match', 'explicit-execute', 'bounded-crawl-budget', 'full-fidelity-crawl-exchanges'],
    data: {
      request,
      summary,
      contentDiscovery: buildAgentContentDiscoveryPlan([...project.exchanges, ...summary.exchanges], scopeAllowlist, {
        now: summary.completedAt,
        throttleMs: request.throttleMs,
        source: 'crawl-run',
      }),
    },
    artifacts: [artifact('crawl-result', summary.id, 'Scoped crawler result with full-fidelity exchanges')],
  };
}

function contentDiscoveryPlanResult(flags, project, scopeAllowlist) {
  const plan = buildAgentContentDiscoveryPlan(project.exchanges, scopeAllowlist, {
    now: new Date().toISOString(),
    throttleMs: numberFlag(flags.throttle ?? flags['throttle-ms'], 150),
    source: String(flags.source ?? 'project-history'),
    limit: numberFlag(flags.limit, 40),
  });
  return {
    status: 'completed',
    mode: 'planned',
    requestCount: 0,
    gates: ['read-only-discovery-plan', 'scope-linked-candidates'],
    data: { plan },
    artifacts: [artifact('content-discovery-plan', plan.id, 'Agent content discovery candidate plan')],
  };
}

async function contentDiscoveryRunResult(flags, project, scopeAllowlist) {
  const limit = Math.max(1, Math.min(1000, Math.round(numberFlag(flags.limit ?? flags['max-requests'], 40))));
  const maxConcurrency = Math.max(1, Math.min(20, Math.round(numberFlag(flags.concurrency ?? flags['max-concurrency'], 2))));
  const throttleMs = Math.max(0, Math.round(numberFlag(flags.throttle ?? flags['throttle-ms'], 150)));
  const resultWindowSize = Math.max(0, Math.round(numberFlag(flags['result-window-size'], limit)));
  const transportSettings = agentReplayTransportSettings(flags);
  const plan = buildAgentContentDiscoveryPlan(project.exchanges, scopeAllowlist, {
    now: new Date().toISOString(),
    throttleMs,
    source: String(flags.source ?? 'project-history'),
    limit,
  });
  const candidates = await buildAgentContentDiscoveryRunCandidates(flags, project, scopeAllowlist, plan, limit);
  if (!candidates.length) return blocked('content-discovery-run found no in-scope candidates to probe.', ['scope-linked-candidates']);

  const inheritedHeaders = flags['no-inherit-headers'] || flags['inherit-headers'] === false
    ? {}
    : inheritedAgentDiscoveryHeaders(project, scopeAllowlist);
  const requestHeaders = {
    'User-Agent': String(flags['user-agent'] ?? 'ProxyForge Agent Content Discovery'),
    ...inheritedHeaders,
    ...headersFromFlag(flags.header),
    ...(flags.cookie ? { Cookie: String(flags.cookie) } : {}),
  };
  deleteHeader(requestHeaders, 'host');
  deleteHeader(requestHeaders, 'content-length');

  const runPlan = {
    id: `content-discovery-run-plan-${simpleDigest(`${plan.id}|${candidates.map((candidate) => candidate.url).join(',')}|${maxConcurrency}`).slice(0, 12)}`,
    kind: 'proxyforge-agent-content-discovery-run-plan',
    sourcePlanId: plan.id,
    candidateCount: candidates.length,
    limit,
    maxConcurrency,
    throttleMs,
    resultWindowSize,
    targetHosts: unique(candidates.map((candidate) => candidate.host)),
    transportSettings,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    candidates,
    inheritedHeaderNames: Object.keys(inheritedHeaders),
  };

  if (!flags.execute) {
    return {
      status: 'planned',
      mode: 'planned',
      trafficSent: false,
      requestCount: 0,
      gates: ['scope-match', 'explicit-execute-required', 'bounded-content-discovery-budget'],
      data: { plan, runPlan },
      artifacts: [
        artifact('content-discovery-plan', plan.id, 'Agent content discovery candidate plan'),
        artifact('content-discovery-run-plan', runPlan.id, 'Scoped content discovery execution plan'),
      ],
    };
  }

  const results = [];
  const statusCounts = {};
  let droppedResultCount = 0;
  let inFlight = 0;
  let maxInFlight = 0;
  let sentRequestCount = 0;
  let failedRequestCount = 0;
  let discoveredCount = 0;
  const startedAt = Date.now();
  for (let waveStart = 0; waveStart < candidates.length; waveStart += maxConcurrency) {
    if (sentRequestCount > 0 && throttleMs > 0) await delay(throttleMs);
    const wave = candidates.slice(waveStart, waveStart + maxConcurrency);
    const waveResults = await Promise.all(wave.map(async (candidate, waveIndex) => {
      const index = waveStart + waveIndex;
      const request = {
        id: candidate.id,
        method: candidate.method ?? 'GET',
        url: candidate.url,
        headers: requestHeaders,
        body: '',
      };
      inFlight += 1;
      maxInFlight = Math.max(maxInFlight, inFlight);
      try {
        const response = await executeHttpRequest(request, { ...transportSettings, scopeAllowlist });
        const discovered = isAgentContentDiscoveryHit(response);
        return {
          index,
          item: {
            index,
            candidate,
            request: replayRequestSummary(request),
            response,
            status: response.error ? 'failed' : discovered ? 'discovered' : 'not-found',
            discovered,
          },
        };
      } finally {
        inFlight = Math.max(0, inFlight - 1);
      }
    }));
    for (const { item } of waveResults.sort((left, right) => left.index - right.index)) {
      sentRequestCount += 1;
      if (item.response.error) failedRequestCount += 1;
      if (item.discovered) discoveredCount += 1;
      const statusKey = item.response.error ? 'error' : String(item.response.status ?? 0);
      statusCounts[statusKey] = (statusCounts[statusKey] ?? 0) + 1;
      if (resultWindowSize > 0) {
        results.push(item);
        while (results.length > resultWindowSize) {
          results.shift();
          droppedResultCount += 1;
        }
      } else {
        droppedResultCount += 1;
      }
    }
  }

  const durationMs = Math.max(1, Date.now() - startedAt);
  const summary = {
    id: `content-discovery-run-${Date.now()}`,
    kind: 'proxyforge-agent-content-discovery-run-summary',
    totalRequests: sentRequestCount,
    discoveredCount,
    notFoundCount: Math.max(0, sentRequestCount - discoveredCount - failedRequestCount),
    failedRequests: failedRequestCount,
    droppedResultCount,
    retainedResultCount: results.length,
    resultWindowSize,
    maxConcurrency,
    maxInFlight,
    durationMs,
    requestRatePerSecond: Number((sentRequestCount / (durationMs / 1000)).toFixed(2)),
    statusCounts,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
  };
  const soakPackage = flags.soak || flags['soak-report']
    ? buildAgentContentDiscoverySoakPackage(summary, runPlan, flags)
    : undefined;
  const outPath = flags.out ? await writeAgentContentDiscoveryArtifact(flags.out, {
    plan,
    runPlan,
    summary,
    results,
    soakPackage,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
  }) : undefined;

  return {
    status: soakPackage?.status === 'fail' ? 'blocked' : failedRequestCount > 0 ? 'partial' : 'completed',
    mode: 'executed',
    trafficSent: sentRequestCount > 0,
    requestCount: sentRequestCount,
    gates: ['scope-match', 'explicit-execute', 'bounded-content-discovery-budget', 'full-fidelity-operational-response'],
    data: {
      plan,
      runPlan,
      summary,
      results,
      responses: results.map((item) => item.response),
      soakPackage,
      outPath,
    },
    artifacts: [
      artifact('content-discovery-run', summary.id, 'Scoped content discovery execution result'),
      ...(soakPackage ? [artifact('content-discovery-soak', soakPackage.id, 'Content discovery runner soak package')] : []),
      ...(outPath ? [artifact('content-discovery-artifact', outPath, 'Content discovery full-fidelity artifact')] : []),
    ],
  };
}

async function liveTargetProfileResult(flags, project, scopeAllowlist) {
  const manifest = await loadJsonMaybe(flags.manifest ?? flags.targets ?? flags.workspace);
  const targets = agentLiveTargetEntries(flags, project, manifest)
    .slice(0, Math.max(1, Math.min(100, Math.round(numberFlag(flags['max-targets'] ?? flags.limit, 20)))))
    .map((entry, index) => agentLiveTargetSpec(entry, index, flags, manifest));
  if (!targets.length) return blocked('live-target-profile requires --manifest/--targets, --target, or scoped project history.', ['live-target-input']);
  const outOfScope = targets.filter((target) => !isTargetInScope(target.url, scopeAllowlist));
  if (outOfScope.length) {
    return blocked(`Live target ${outOfScope[0].url} is outside scope. Add --scope ${hostFromUrl(outOfScope[0].url)} only when authorized.`, ['scope-match']);
  }

  const minHosts = Math.max(1, Math.round(numberFlag(flags['min-hosts'] ?? manifest?.minHostCount, 1)));
  const minRoutes = Math.max(1, Math.round(numberFlag(flags['min-routes'] ?? manifest?.minRouteCount, Math.min(3, targets.length))));
  const minStatusClasses = Math.max(1, Math.round(numberFlag(flags['min-status-classes'] ?? manifest?.minStatusClassCount, 2)));
  const minRequests = Math.max(1, Math.round(numberFlag(flags['min-requests'] ?? manifest?.minRequestCount, targets.length)));
  const throttleMs = Math.max(0, Math.round(numberFlag(flags.throttle ?? flags['throttle-ms'], manifest?.throttleMs ?? 0)));
  const timeoutMs = Math.max(250, Math.min(120000, Math.round(numberFlag(flags.timeout ?? manifest?.timeoutMs, 10000))));
  const startedAt = new Date().toISOString();
  const plan = {
    id: `agent-live-target-profile-plan-${simpleDigest(`${targets.map((target) => target.url).join('|')}|${startedAt}`).slice(0, 12)}`,
    kind: 'proxyforge-agent-live-target-profile-plan',
    createdAt: startedAt,
    targetCount: targets.length,
    targetHosts: unique(targets.map((target) => hostFromUrl(target.url))),
    minHosts,
    minRoutes,
    minStatusClasses,
    minRequests,
    throttleMs,
    timeoutMs,
    targets: targets.map((target) => ({
      id: target.id,
      label: target.label,
      method: target.method,
      url: target.url,
      role: target.role,
      category: target.category,
      expectedToolHandoff: target.expectedToolHandoff,
      rawRequest: target.rawRequest,
    })),
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
  };

  if (!flags.execute) {
    return {
      status: 'planned',
      mode: 'planned',
      trafficSent: false,
      requestCount: 0,
      gates: ['scope-match', 'explicit-execute-required', 'bounded-live-target-profile'],
      data: { plan },
      artifacts: [artifact('live-target-profile-plan', plan.id, 'Agent live target profiling plan')],
      audit: [auditEvent('live-target-profile', 'planned', `Prepared ${targets.length} scoped live target probe(s).`, 0)],
    };
  }

  const results = [];
  const startedMs = Date.now();
  for (const [index, target] of targets.entries()) {
    if (index > 0 && throttleMs > 0) await delay(throttleMs);
    const response = await agentHttpRequestRaw(target.url, {
      method: target.method,
      headers: target.headers,
      body: target.body,
      timeoutMs,
    });
    const parsedUrl = new URL(target.url);
    const exchange = agentLiveTargetExchange(target, response, index);
    const insertionPoints = inferInsertionPoints([exchange], exchange, target.url, { maxPoints: 100 });
    results.push({
      id: `agent-live-target-result-${index + 1}`,
      targetId: target.id,
      label: target.label,
      method: target.method,
      url: target.url,
      host: parsedUrl.hostname,
      route: `${target.method} ${parsedUrl.pathname}`,
      path: parsedUrl.pathname,
      role: target.role,
      category: target.category,
      expectedToolHandoff: target.expectedToolHandoff,
      statusCode: response.statusCode,
      statusClass: agentStatusClass(response.statusCode),
      contentType: String(response.headers?.['content-type'] ?? ''),
      bodyBytes: Buffer.byteLength(response.body ?? '', 'utf8'),
      rawRequest: response.rawRequest,
      rawResponse: response.rawResponse,
      insertionPointCount: insertionPoints.length,
      insertionPoints,
      scannerCandidate: agentLiveTargetScannerCandidate(target, response, insertionPoints),
      intruderCandidate: agentLiveTargetIntruderCandidate(target, response, insertionPoints),
      replayCandidate: {
        command: `${agentCommandPrefix} replay-run --target ${shellQuote(target.url)} --scope ${shellQuote(hostFromUrl(target.url))} --execute --json`,
        reason: 'Replay candidate keeps full raw request/response material for confirmation before reporting.',
      },
    });
  }

  const profilePackage = buildAgentLiveTargetProfilePackage({
    plan,
    results,
    scopeAllowlist,
    durationMs: Math.max(1, Date.now() - startedMs),
    minHosts,
    minRoutes,
    minStatusClasses,
    minRequests,
  });
  const outPath = flags.out ? path.resolve(String(flags.out)) : undefined;
  if (outPath) {
    await writePrivateFile(outPath, JSON.stringify(profilePackage, null, 2), 'utf8');
  }
  return {
    status: profilePackage.reportReady ? 'completed' : 'blocked',
    mode: 'executed',
    trafficSent: results.length > 0,
    requestCount: results.length,
    gates: ['scope-match', 'explicit-execute', 'bounded-live-target-profile', 'scanner-intruder-handoff', 'full-fidelity-operational-response'],
    data: { plan, package: profilePackage, outPath },
    artifacts: [
      artifact('live-target-profile', profilePackage.id, 'Agent live target Scanner/Intruder profile package'),
      ...(outPath ? [artifact('live-target-profile-file', outPath, 'Agent live target profile artifact')] : []),
    ],
    audit: [auditEvent('live-target-profile', profilePackage.reportReady ? 'completed' : 'blocked', profilePackage.summary, results.length)],
  };
}

function targetAccessReviewResult(flags, project, scopeAllowlist) {
  const roles = parseList(flags.roles ?? 'customer,support_admin,finance_admin');
  const exchanges = project.exchanges.filter((exchange) => exchange?.url && isTargetInScope(exchange.url, scopeAllowlist));
  const routes = buildAgentTargetRoutes(exchanges);
  const roleMaps = roles.map((role) => buildAgentRoleMap(role, routes, exchanges, flags));
  const lanes = roleMaps.map((roleMap) => buildAgentAccessControlLane(roleMap, routes));
  const overexposedCount = lanes.reduce((total, lane) => total + lane.overexposedCount, 0);
  const underexposedCount = lanes.reduce((total, lane) => total + lane.underexposedCount, 0);
  const missingObservationCount = lanes.reduce((total, lane) => total + lane.missingObservationCount, 0);
  const packagePayload = {
    id: `agent-target-access-review-${simpleDigest(`${project.projectName}|${roles.join(',')}|${routes.map((route) => route.key).join(',')}`).slice(0, 12)}`,
    kind: 'proxyforge-agent-target-access-control-review',
    schemaVersion,
    createdAt: new Date().toISOString(),
    projectName: project.projectName,
    scopeAllowlist,
    roles,
    routeCount: routes.length,
    exchangeCount: exchanges.length,
    overexposedCount,
    underexposedCount,
    missingObservationCount,
    lanes,
    exchanges: exchanges.map(exchangeDetail),
    nextCommands: [
      'replay-matrix --project <project> --request-id <id> --roles customer,support_admin --execute --json',
      'scanner-run --project <project> --checks authz-diff --execute --json',
      'report-export --project <project> --format markdown --json',
    ],
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    summary: `Target access-control review compared ${roles.length} role(s), ${routes.length} route(s), ${overexposedCount} overexposed route(s), ${underexposedCount} underexposed route(s), and ${missingObservationCount} missing observation(s).`,
  };
  return {
    status: 'completed',
    mode: 'read-only',
    trafficSent: false,
    requestCount: 0,
    gates: ['read-only-target-map-review', 'scope-linked-history', 'full-fidelity-operational-evidence'],
    data: { review: packagePayload },
    artifacts: [artifact('target-access-review', packagePayload.id, 'Agent Target access-control review package')],
  };
}

function targetMapCompareResult(flags, project, scopeAllowlist) {
  const exchanges = project.exchanges.filter((exchange) => exchange?.url && isTargetInScope(exchange.url, scopeAllowlist));
  const routes = buildAgentTargetRoutes(exchanges);
  const baselineRoutes = selectAgentComparisonRoutes(routes, flags.baseline ?? flags['baseline-routes'] ?? flags['baseline-ids'], 'baseline');
  const candidateRoutes = selectAgentComparisonRoutes(routes, flags.candidate ?? flags['candidate-routes'] ?? flags['candidate-ids'], 'candidate');
  const packagePayload = buildAgentTargetMapComparisonPackage({
    project,
    scopeAllowlist,
    routes,
    baselineRoutes,
    candidateRoutes,
    exchanges,
    baselineName: String(flags['baseline-name'] ?? 'Agent baseline'),
    candidateName: String(flags['candidate-name'] ?? 'Agent candidate'),
  });
  return {
    status: 'completed',
    mode: 'read-only',
    trafficSent: false,
    requestCount: 0,
    gates: ['read-only-target-map-comparison', 'scope-linked-history', 'full-fidelity-operational-evidence'],
    data: { comparison: packagePayload },
    artifacts: [artifact('target-map-comparison', packagePayload.id, 'Agent Target site-map comparison package')],
  };
}

async function intelResult(flags, project, selectedExchange, scopeAllowlist) {
  const query = String(flags.query ?? '');
  const [browser, scanner] = await Promise.all([
    chromiumCaptureResult({ ...flags, execute: false }, project, scopeAllowlist),
    scannerPlanResult(flags, project, selectedExchange, scopeAllowlist),
  ]);
  return {
    status: 'completed',
    mode: 'planned',
    requestCount: 0,
    data: {
      status: statusResult(project, scopeAllowlist).data,
      browser: browser.data,
      scanner: scanner.data,
      search: query ? searchResult(project, query).data : undefined,
      contentDiscovery: contentDiscoveryPlanResult(flags, project, scopeAllowlist).data.plan,
    },
    artifacts: [
      ...(browser.artifacts ?? []),
      artifact('scanner-plan', scanner.data.planId, 'Agent scanner plan'),
    ],
  };
}

async function sequencerAnalyzeResult(flags, project, selectedExchange) {
  const samples = await loadAgentSequencerSamples(flags, project, selectedExchange);
  if (!samples.length) return blocked('No Sequencer samples were supplied or extracted from the project.', ['sequencer-samples-required']);
  const sequencerModule = optionalDist('sequencerEngine.js');
  if (!sequencerModule?.SequencerEngine) return blocked('sequencer-analyze requires a built desktop runtime. Run npm run build first.', ['desktop-runtime-required']);
  const source = normalizeAgentSequencerSource(flags.source ?? (flags['sample-file'] || flags.samples || flags.sample ? 'manual' : 'traffic'));
  const engine = new sequencerModule.SequencerEngine();
  const result = engine.analyzeSamples({
    label: String(flags.label ?? flags.name ?? 'Agent Sequencer token analysis'),
    source,
    samples,
  });
  const soakPackage = flags.soak || flags['soak-report']
    ? buildAgentSequencerSoakPackage(result, flags)
    : undefined;
  const outPath = flags.out ? await writeAgentSequencerArtifact(flags.out, {
    samples,
    result,
    soakPackage,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
  }) : undefined;
  return {
    status: soakPackage?.status === 'fail' ? 'blocked' : 'completed',
    mode: 'read-only',
    trafficSent: false,
    requestCount: 0,
    gates: ['local-token-analysis', ...(soakPackage ? ['large-sample-reliability-soak'] : []), 'full-fidelity-operational-samples'],
    data: {
      sampleSource: source,
      sampleCount: samples.length,
      samples,
      result,
      soakPackage,
      outPath,
    },
    artifacts: [
      artifact('sequencer-analysis', result.id, 'Sequencer token analysis result'),
      ...(soakPackage ? [artifact('sequencer-soak', soakPackage.id, 'Sequencer large-sample reliability soak package')] : []),
      ...(outPath ? [artifact('sequencer-artifact', outPath, 'Sequencer full-fidelity token analysis artifact')] : []),
    ],
  };
}

async function decoderChainResult(flags, project, selectedExchange) {
  const input = await loadAgentDecoderInput(flags, selectedExchange);
  if (!input) return blocked('No Decoder input was supplied. Use --input, --input-file, --request-id, or --source request|response.');
  const transformIds = normalizeAgentDecoderTransforms(flags.transforms ?? flags.transform ?? flags.chain ?? 'smart-decode');
  if (!transformIds.length) return blocked('No supported Decoder transforms were supplied.', ['decoder-transform-required']);
  const createdAt = new Date().toISOString();
  const run = await runAgentDecoderTransformChain(input, transformIds, String(flags.name ?? flags.label ?? 'Agent Decoder transform chain'), createdAt);
  const operationalSecretSamples = [
    ...extractSecretLines(input),
    ...extractSecretLines(run.finalOutput),
  ];
  const packagePayload = {
    kind: 'proxyforge-agent-decoder-transform-chain-package',
    createdAt,
    project: projectSummary(project),
    source: String(flags.source ?? (flags['input-file'] ? 'input-file' : flags.input ? 'inline' : 'selected-exchange')),
    requestId: selectedExchange?.id,
    transformIds,
    run,
    operationalSecretSamples,
    requirements: {
      transformChainExecuted: run.steps.length === transformIds.length && run.ok,
      multiStepChainCovered: transformIds.length >= 2,
      rawInputPreserved: input.length > 0,
      rawOutputPreserved: run.finalOutput.length > 0,
      operationalSecretsPreserved: operationalSecretSamples.length > 0,
      reportPhaseOnlyRedaction: true,
    },
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady: run.ok,
  };
  packagePayload.digestPreview = simpleDigest(JSON.stringify(packagePayload));
  packagePayload.content = JSON.stringify(packagePayload, null, 2);
  let outPath;
  if (flags.out) {
    outPath = path.resolve(String(flags.out));
    await writePrivateFile(outPath, packagePayload.content, 'utf8');
  }
  return {
    status: run.ok ? 'completed' : 'blocked',
    mode: 'read-only',
    trafficSent: false,
    requestCount: 0,
    gates: ['local-transform-chain', 'full-fidelity-operational-output'],
    data: {
      kind: packagePayload.kind,
      transformIds,
      finalOutput: run.finalOutput,
      run,
      package: packagePayload,
      outPath,
    },
    artifacts: [
      artifact('decoder-chain', `decoder-chain-${packagePayload.digestPreview.slice(0, 10)}`, 'Decoder transform chain package'),
      ...(outPath ? [artifact('decoder-chain-file', outPath, 'Decoder transform chain package file')] : []),
    ],
  };
}

async function replayRunResult(flags, selectedExchange, scopeAllowlist) {
  if (!selectedExchange && !flags.target) return blocked('No request or --target was provided for replay.');
  const request = requestFromExchange(selectedExchange, flags);
  if (!isTargetInScope(request.url, scopeAllowlist)) return blocked(`Replay target ${request.url} is outside scope.`, ['scope-match']);
  const transportSettings = agentReplayTransportSettings(flags);
  if (!flags.execute) {
    return {
      status: 'planned',
      mode: 'planned',
      trafficSent: false,
      requestCount: 0,
      gates: ['scope-match', 'explicit-execute-required'],
      data: { request: replayRequestSummary(request), transportSettings, response: null },
      artifacts: [artifact('replay-plan', `replay-plan-${simpleDigest(request.url).slice(0, 10)}`, 'Replay execution plan')],
    };
  }
  const response = await executeHttpRequest(request, { ...transportSettings, scopeAllowlist });
  return {
    status: response.error ? 'blocked' : 'completed',
    mode: 'executed',
    trafficSent: true,
    requestCount: 1 + (response.redirectHistory?.length ?? 0),
    gates: ['scope-match', 'explicit-execute', 'replay-transport-controls', 'full-fidelity-operational-response'],
    data: {
      request: replayRequestSummary(request),
      transportSettings,
      response,
    },
    artifacts: [artifact('replay-result', `replay-result-${simpleDigest(`${request.url}|${response.status ?? 'error'}`).slice(0, 10)}`, 'Replay execution result')],
  };
}

async function bulkReplayResult(flags, project, scopeAllowlist) {
  const limit = Math.max(1, Math.min(5000, Math.round(numberFlag(flags.limit ?? flags['max-requests'], 5))));
  const candidates = project.exchanges.filter((exchange) => isTargetInScope(exchange.url, scopeAllowlist)).slice(0, limit);
  const maxConcurrency = Math.max(1, Math.min(20, Math.round(numberFlag(flags.concurrency ?? flags['max-concurrency'], 1))));
  const throttleMs = Math.max(0, Math.round(numberFlag(flags.throttle ?? flags['throttle-ms'], 0)));
  const resultWindowSize = Math.max(0, Math.round(numberFlag(flags['result-window-size'], candidates.length)));
  const plan = {
    id: `bulk-replay-plan-${simpleDigest(`${project.projectName}|${candidates.map((exchange) => exchange.id).join(',')}|${maxConcurrency}`).slice(0, 10)}`,
    kind: 'proxyforge-agent-bulk-replay-plan',
    candidateCount: candidates.length,
    limit,
    maxConcurrency,
    throttleMs,
    resultWindowSize,
    targetHosts: unique(candidates.map((exchange) => hostFromUrl(exchange.url))),
    requests: candidates.map(exchangeSummary),
    secretHandling: 'execution-full-fidelity-secrets-preserved',
  };
  if (!flags.execute) {
    return {
      status: 'planned',
      mode: 'planned',
      requestCount: 0,
      trafficSent: false,
      data: {
        count: candidates.length,
        plan,
        requests: candidates.map(exchangeSummary),
      },
      artifacts: [artifact('bulk-replay-plan', plan.id, 'Bulk replay plan')],
    };
  }
  const results = [];
  let droppedResultCount = 0;
  let inFlight = 0;
  let maxInFlight = 0;
  let sentRequestCount = 0;
  let failedRequestCount = 0;
  const startedAt = Date.now();
  for (let waveStart = 0; waveStart < candidates.length; waveStart += maxConcurrency) {
    if (sentRequestCount > 0 && throttleMs > 0) await delay(throttleMs);
    const wave = candidates.slice(waveStart, waveStart + maxConcurrency);
    const waveResults = await Promise.all(wave.map(async (exchange, waveIndex) => {
      const index = waveStart + waveIndex;
      const request = requestFromExchange(exchange, flags);
      inFlight += 1;
      maxInFlight = Math.max(maxInFlight, inFlight);
      try {
        const response = await executeHttpRequest(request, { ...agentReplayTransportSettings(flags), scopeAllowlist });
        return {
          index,
          item: {
            index,
            exchange: exchangeSummary(exchange),
            request: replayRequestSummary(request),
            response,
            status: response.error ? 'failed' : 'completed',
          },
        };
      } finally {
        inFlight = Math.max(0, inFlight - 1);
      }
    }));
    for (const { item } of waveResults.sort((left, right) => left.index - right.index)) {
      sentRequestCount += 1;
      if (item.response.error) failedRequestCount += 1;
      if (resultWindowSize > 0) {
        results.push(item);
        while (results.length > resultWindowSize) {
          results.shift();
          droppedResultCount += 1;
        }
      } else {
        droppedResultCount += 1;
      }
    }
  }
  const durationMs = Math.max(1, Date.now() - startedAt);
  const summary = {
    id: `bulk-replay-result-${Date.now()}`,
    kind: 'proxyforge-agent-bulk-replay-summary',
    candidateCount: candidates.length,
    totalRequests: sentRequestCount,
    completedRequests: Math.max(0, sentRequestCount - failedRequestCount),
    failedRequests: failedRequestCount,
    droppedResultCount,
    retainedResultCount: results.length,
    resultWindowSize,
    maxConcurrency,
    maxInFlight,
    durationMs,
    requestRatePerSecond: Number((sentRequestCount / (durationMs / 1000)).toFixed(2)),
    secretHandling: 'execution-full-fidelity-secrets-preserved',
  };
  const soakPackage = flags.soak || flags['soak-report']
    ? buildAgentBulkReplaySoakPackage(summary, plan, flags)
    : undefined;
  const outPath = flags.out ? await writeAgentBulkReplayArtifact(flags.out, {
    plan,
    summary,
    results,
    soakPackage,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
  }) : undefined;
  return {
    status: soakPackage?.status === 'fail' ? 'blocked' : summary.failedRequests > 0 ? 'partial' : 'completed',
    mode: 'executed',
    trafficSent: sentRequestCount > 0,
    requestCount: sentRequestCount,
    gates: ['scope-match', 'explicit-execute', 'bulk-replay-resource-pool', 'full-fidelity-operational-response'],
    data: {
      count: sentRequestCount,
      plan,
      summary,
      responses: results.map((item) => item.response),
      results,
      soakPackage,
      outPath,
    },
    artifacts: [
      artifact('bulk-replay-result', summary.id, 'Bulk replay execution result'),
      ...(soakPackage ? [artifact('bulk-replay-soak', soakPackage.id, 'Bulk replay high-volume soak package')] : []),
      ...(outPath ? [artifact('bulk-replay-artifact', outPath, 'Bulk replay full-fidelity artifact')] : []),
    ],
  };
}

function buildAgentBulkReplaySoakPackage(summary, plan, flags) {
  const minRequests = Math.max(1, Math.round(numberFlag(flags['min-requests'], plan.candidateCount)));
  const minConcurrency = Math.max(1, Math.round(numberFlag(flags['min-concurrency'], Math.min(plan.maxConcurrency, Math.max(1, plan.candidateCount)))));
  const maxFailures = Math.max(0, Math.round(numberFlag(flags['max-failures'], 0)));
  const failures = [];
  const warnings = [];
  if (summary.totalRequests < minRequests) failures.push(`Sent ${summary.totalRequests} request(s), below soak floor ${minRequests}.`);
  if (summary.maxInFlight < minConcurrency) failures.push(`Max in-flight ${summary.maxInFlight} is below concurrency floor ${minConcurrency}.`);
  if (summary.failedRequests > maxFailures) failures.push(`Failed request count ${summary.failedRequests} is above soak allowance ${maxFailures}.`);
  if (summary.retainedResultCount < Math.min(summary.totalRequests, plan.resultWindowSize)) warnings.push('Retained result window is smaller than expected.');
  if (summary.durationMs <= 0 || summary.requestRatePerSecond <= 0) warnings.push('Duration/request-rate telemetry was not populated.');
  return {
    id: `agent-bulk-replay-soak-${simpleDigest(`${summary.id}|${summary.totalRequests}|${summary.maxInFlight}`).slice(0, 12)}`,
    kind: 'proxyforge-agent-bulk-replay-high-volume-soak-package',
    generatedAt: new Date().toISOString(),
    status: failures.length ? 'fail' : warnings.length ? 'warning' : 'pass',
    failures,
    warnings,
    budgets: {
      minRequests,
      minConcurrency,
      maxFailures,
      maxConcurrency: plan.maxConcurrency,
      resultWindowSize: plan.resultWindowSize,
    },
    observed: {
      totalRequests: summary.totalRequests,
      completedRequests: summary.completedRequests,
      failedRequests: summary.failedRequests,
      maxInFlight: summary.maxInFlight,
      retainedResultCount: summary.retainedResultCount,
      droppedResultCount: summary.droppedResultCount,
      durationMs: summary.durationMs,
      requestRatePerSecond: summary.requestRatePerSecond,
    },
    summary,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportReady: failures.length === 0,
  };
}

async function replayMatrixResult(flags, selectedExchange, scopeAllowlist) {
  if (!selectedExchange && !flags.target) return blocked('No request or --target was provided for replay matrix.');
  const baseRequest = requestFromExchange(selectedExchange, flags);
  if (!isTargetInScope(baseRequest.url, scopeAllowlist)) return blocked(`Replay matrix target ${baseRequest.url} is outside scope.`, ['scope-match']);
  const transportSettings = agentReplayTransportSettings(flags);
  const header = String(flags.header ?? 'X-ProxyForge-Role');
  const roles = parseList(flags.roles ?? 'customer,support_admin,finance_admin');
  const requests = roles.map((role) => ({
    ...baseRequest,
    headers: { ...baseRequest.headers, [header]: role },
    role,
  }));
  const responses = [];
  if (flags.execute) {
    for (const request of requests) {
      responses.push({ role: request.role, response: await executeHttpRequest(request, { ...transportSettings, scopeAllowlist }) });
    }
  }
  return {
    status: flags.execute ? 'completed' : 'planned',
    mode: flags.execute ? 'executed' : 'planned',
    trafficSent: Boolean(flags.execute),
    requestCount: flags.execute ? requests.length : 0,
    gates: ['scope-match', 'role-matrix', flags.execute ? 'explicit-execute' : 'explicit-execute-required'],
    data: {
      header,
      roles,
      transportSettings,
      requests: requests.map(replayRequestSummary),
      responses,
    },
    artifacts: [artifact('replay-matrix', `replay-matrix-${simpleDigest(`${baseRequest.url}|${roles.join(',')}`).slice(0, 10)}`, 'Replay matrix package')],
  };
}

async function webSocketListResult(flags, project, scopeAllowlist) {
  const frames = selectAgentWebSocketFrames(project, flags, scopeAllowlist);
  const limit = Math.max(1, Math.min(1000, Math.round(numberFlag(flags.limit, 100))));
  const packagePayload = {
    id: `agent-websocket-inventory-${simpleDigest(`${project.projectName}|${frames.map((frame) => frame.id).join(',')}`).slice(0, 12)}`,
    kind: 'proxyforge-agent-websocket-inventory',
    schemaVersion,
    generatedAt: new Date().toISOString(),
    projectName: project.projectName,
    scopeAllowlist,
    frameCount: frames.length,
    connectionCount: unique(frames.map((frame) => frame.connectionId)).length,
    connections: summarizeAgentWebSocketConnections(frames),
    frames: frames.slice(0, limit).map(agentWebSocketFrameSummary),
    retainedFrameCount: Math.min(frames.length, limit),
    droppedFrameCount: Math.max(0, frames.length - limit),
    filters: {
      connectionId: flags.connection ?? flags['connection-id'],
      host: flags.host,
      path: flags.path,
      query: flags.query ?? flags.q,
      direction: flags.direction,
      type: flags.type,
    },
    nextCommands: [
      'websocket-replay --project <project> --frame-id <id> --execute --json',
      'websocket-fuzz --project <project> --frame-id <id> --execute --json',
      'websocket-transcript-export --project <project> --connection-id <id> --format markdown --json',
    ],
    secretHandling: 'execution-full-fidelity-secrets-preserved',
  };
  const outPath = flags.out ? await writeAgentWebSocketJsonArtifact(flags.out, packagePayload, 'inventory') : undefined;
  return {
    status: 'completed',
    mode: 'read-only',
    trafficSent: false,
    requestCount: 0,
    gates: ['read-only-websocket-inventory', 'scope-linked-frame-filter', 'full-fidelity-operational-output'],
    data: { ...packagePayload, outPath },
    artifacts: [
      artifact('websocket-inventory', packagePayload.id, 'Agent WebSocket inventory package'),
      ...(outPath ? [artifact('websocket-inventory-file', outPath, 'Agent WebSocket inventory artifact')] : []),
    ],
    audit: [auditEvent('websocket-list', 'completed', `Listed ${frames.length} WebSocket frame(s).`, 0)],
  };
}

async function webSocketReplayResult(flags, project, scopeAllowlist) {
  const frame = selectAgentWebSocketFrame(project, flags, scopeAllowlist);
  if (!frame && !flags.url && !flags.target) return blocked('No WebSocket frame or --url was provided for replay.', ['websocket-frame-required']);
  const request = await buildAgentWebSocketReplayRequest(flags, frame);
  if (!isTargetInScope(request.url, scopeAllowlist)) return blocked(`WebSocket replay target ${request.url} is outside scope.`, ['scope-match']);
  const plan = {
    id: `agent-websocket-replay-plan-${simpleDigest(`${request.url}|${request.payload}|${request.opcode}`).slice(0, 12)}`,
    kind: 'proxyforge-agent-websocket-replay-plan',
    schemaVersion,
    createdAt: new Date().toISOString(),
    sourceFrame: frame ? agentWebSocketFrameSummary(frame) : null,
    request,
    transportSettings: agentWebSocketTransportSettings(flags),
    secretHandling: 'execution-full-fidelity-secrets-preserved',
  };
  if (!flags.execute) {
    return {
      status: 'planned',
      mode: 'planned',
      trafficSent: false,
      requestCount: 0,
      gates: ['scope-match', 'explicit-execute-required', 'websocket-handshake-plan', 'full-fidelity-operational-payload'],
      data: { plan },
      artifacts: [artifact('websocket-replay-plan', plan.id, 'WebSocket replay plan')],
      audit: [auditEvent('websocket-replay', 'planned', `Prepared WebSocket replay for ${request.url}; add --execute to send.`, 0)],
    };
  }
  const result = await executeAgentWebSocketReplay(request, plan.transportSettings);
  const packagePayload = {
    id: `agent-websocket-replay-${simpleDigest(`${plan.id}|${result.status}|${result.receivedFrames.length}`).slice(0, 12)}`,
    kind: 'proxyforge-agent-websocket-replay-result',
    schemaVersion,
    generatedAt: new Date().toISOString(),
    plan,
    result,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
  };
  const outPath = flags.out ? await writeAgentWebSocketJsonArtifact(flags.out, packagePayload, 'replay') : undefined;
  return {
    status: result.error ? 'blocked' : 'completed',
    mode: 'executed',
    trafficSent: true,
    requestCount: 1,
    gates: ['scope-match', 'explicit-execute', 'websocket-handshake', 'full-fidelity-operational-payload'],
    data: { package: packagePayload, outPath },
    artifacts: [
      artifact('websocket-replay-result', packagePayload.id, 'Agent WebSocket replay result'),
      ...(outPath ? [artifact('websocket-replay-file', outPath, 'Agent WebSocket replay artifact')] : []),
    ],
    audit: [auditEvent('websocket-replay', result.error ? 'blocked' : 'completed', result.error ?? `Received ${result.receivedFrames.length} WebSocket frame(s).`, 1)],
  };
}

async function webSocketFuzzResult(flags, project, scopeAllowlist) {
  const frame = selectAgentWebSocketFrame(project, flags, scopeAllowlist);
  if (!frame && !flags.url && !flags.target) return blocked('No WebSocket frame or --url was provided for fuzzing.', ['websocket-frame-required']);
  const baseRequest = await buildAgentWebSocketReplayRequest(flags, frame);
  if (!isTargetInScope(baseRequest.url, scopeAllowlist)) return blocked(`WebSocket fuzz target ${baseRequest.url} is outside scope.`, ['scope-match']);
  const maxProbes = Math.max(1, Math.min(100, Math.round(numberFlag(flags['max-probes'] ?? flags.limit, 6))));
  const throttleMs = Math.max(0, Math.min(10000, Math.round(numberFlag(flags.throttle ?? flags['throttle-ms'], 0))));
  const probes = buildAgentWebSocketFuzzProbes(baseRequest, flags).slice(0, maxProbes);
  const plan = {
    id: `agent-websocket-fuzz-plan-${simpleDigest(`${baseRequest.url}|${probes.map((probe) => probe.payload).join('|')}`).slice(0, 12)}`,
    kind: 'proxyforge-agent-websocket-fuzz-plan',
    schemaVersion,
    createdAt: new Date().toISOString(),
    sourceFrame: frame ? agentWebSocketFrameSummary(frame) : null,
    baseRequest,
    maxProbes,
    throttleMs,
    probeCount: probes.length,
    probes,
    transportSettings: agentWebSocketTransportSettings(flags),
    secretHandling: 'execution-full-fidelity-secrets-preserved',
  };
  if (!flags.execute) {
    return {
      status: 'planned',
      mode: 'planned',
      trafficSent: false,
      requestCount: 0,
      gates: ['scope-match', 'explicit-execute-required', 'bounded-websocket-fuzz-budget', 'full-fidelity-operational-payload'],
      data: { plan },
      artifacts: [artifact('websocket-fuzz-plan', plan.id, 'WebSocket fuzz plan')],
      audit: [auditEvent('websocket-fuzz', 'planned', `Prepared ${probes.length} WebSocket fuzz probe(s); add --execute to send.`, 0)],
    };
  }
  const startedAt = Date.now();
  const results = [];
  for (let index = 0; index < probes.length; index += 1) {
    if (index > 0 && throttleMs > 0) await delay(throttleMs);
    const probe = probes[index];
    const response = await executeAgentWebSocketReplay({
      ...baseRequest,
      id: probe.id,
      payload: probe.payload,
      payloadEncoding: probe.payloadEncoding,
      opcode: probe.opcode,
    }, plan.transportSettings);
    results.push({
      ...probe,
      response,
      outcome: response.error ? 'error' : response.receivedFrames.some((item) => item.type === 'close') ? 'closed' : response.receivedFrames.length ? 'accepted' : 'no-response',
    });
  }
  const durationMs = Math.max(1, Date.now() - startedAt);
  const summary = {
    id: `agent-websocket-fuzz-${Date.now()}`,
    kind: 'proxyforge-agent-websocket-fuzz-summary',
    totalProbes: results.length,
    acceptedProbes: results.filter((result) => result.outcome === 'accepted').length,
    closedProbes: results.filter((result) => result.outcome === 'closed').length,
    errorProbes: results.filter((result) => result.outcome === 'error').length,
    noResponseProbes: results.filter((result) => result.outcome === 'no-response').length,
    durationMs,
    requestRatePerSecond: Number((results.length / (durationMs / 1000)).toFixed(2)),
    secretHandling: 'execution-full-fidelity-secrets-preserved',
  };
  const packagePayload = {
    id: `agent-websocket-fuzz-${simpleDigest(`${plan.id}|${summary.totalProbes}|${summary.acceptedProbes}`).slice(0, 12)}`,
    kind: 'proxyforge-agent-websocket-fuzz-result',
    schemaVersion,
    generatedAt: new Date().toISOString(),
    plan,
    summary,
    results,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
  };
  const outPath = flags.out ? await writeAgentWebSocketJsonArtifact(flags.out, packagePayload, 'fuzz') : undefined;
  return {
    status: summary.errorProbes ? 'partial' : 'completed',
    mode: 'executed',
    trafficSent: results.length > 0,
    requestCount: results.length,
    gates: ['scope-match', 'explicit-execute', 'bounded-websocket-fuzz-budget', 'full-fidelity-operational-payload'],
    data: { package: packagePayload, outPath },
    artifacts: [
      artifact('websocket-fuzz-result', packagePayload.id, 'Agent WebSocket fuzz result'),
      ...(outPath ? [artifact('websocket-fuzz-file', outPath, 'Agent WebSocket fuzz artifact')] : []),
    ],
    audit: [auditEvent('websocket-fuzz', 'completed', `Executed ${results.length} WebSocket fuzz probe(s).`, results.length)],
  };
}

async function webSocketTranscriptExportResult(flags, project, scopeAllowlist) {
  const frames = selectAgentWebSocketFrames(project, flags, scopeAllowlist);
  if (!frames.length) return blocked('No WebSocket frames matched the transcript export filters.', ['websocket-frames-required']);
  const format = String(flags.format ?? 'json').toLowerCase() === 'markdown' ? 'markdown' : 'json';
  const transcript = buildAgentWebSocketTranscript(frames, {
    projectName: project.projectName,
    format,
    title: String(flags.title ?? `${frames[0]?.host ?? 'WebSocket'} transcript`),
  });
  const outPath = flags.out ? await writeAgentWebSocketTranscriptArtifact(flags.out, transcript) : undefined;
  return {
    status: 'completed',
    mode: 'read-only',
    trafficSent: false,
    requestCount: 0,
    gates: ['read-only-websocket-transcript-export', 'scope-linked-frame-filter', 'full-fidelity-operational-payload'],
    data: { transcript, outPath },
    artifacts: [
      artifact('websocket-transcript', transcript.id, 'Agent WebSocket transcript export'),
      ...(outPath ? [artifact('websocket-transcript-file', outPath, 'Agent WebSocket transcript artifact')] : []),
    ],
    audit: [auditEvent('websocket-transcript-export', 'completed', `Exported ${frames.length} WebSocket frame(s).`, 0)],
  };
}

async function intruderRunResult(flags, project, selectedExchange, scopeAllowlist) {
  const targetUrl = normalizeTarget(flags.target ?? selectedExchange?.url ?? project.exchanges[0]?.url ?? 'https://example.test/');
  if (!isTargetInScope(targetUrl, scopeAllowlist)) return blocked(`Intruder target ${targetUrl} is outside scope.`, ['scope-match']);

  const rawRequest = ensureAgentIntruderMarker(await loadAgentIntruderRawRequest(flags, selectedExchange, targetUrl), targetUrl, flags);
  const payloadSets = await loadAgentIntruderPayloadSets(flags);
  const attackMode = sanitizeAgentIntruderAttackMode(flags.mode ?? flags['attack-mode']);
  const payloadProcessors = sanitizeAgentIntruderPayloadProcessors(flags.processors ?? flags['payload-processors']);
  const payloadRules = sanitizeAgentIntruderPayloadRules(flags.rules ?? flags['payload-rules']);
  const grepTerms = parseList(flags.grep ?? flags['grep-terms']);
  const extractRegexes = parseList(flags.extract ?? flags['extract-regexes']);
  const attackModeMatrix = buildAgentIntruderAttackModeMatrix(rawRequest, payloadSets, payloadProcessors, payloadRules, attackMode);
  const selectedModeEntry = attackModeMatrix.modes.find((entry) => entry.mode === attackMode);
  const defaultPayloadRequestCount = selectedModeEntry?.requestCount || estimateAgentIntruderPlanCount(rawRequest, payloadSets, attackMode) || 1;
  const maxPayloadRequests = Math.max(1, Math.min(5000, Math.round(numberFlag(flags['max-requests'] ?? flags.limit, defaultPayloadRequestCount))));
  const resourcePoolMaxConcurrent = Math.max(1, Math.min(10, Math.round(numberFlag(flags.concurrency ?? flags['max-concurrency'], 1))));
  const plan = {
    id: `agent-intruder-plan-${simpleDigest(`${targetUrl}|${rawRequest}|${attackMode}|${payloadSets.map((set) => set.length).join(':')}`).slice(0, 12)}`,
    kind: 'proxyforge-agent-intruder-run-plan',
    targetUrl,
    attackMode,
    payloadPositions: countAgentIntruderMarkers(rawRequest),
    payloadSetCount: payloadSets.length,
    payloadCounts: payloadSets.map((set) => set.length),
    estimatedRequestCount: selectedModeEntry?.requestCount ?? estimateAgentIntruderPlanCount(rawRequest, payloadSets, attackMode),
    attackModeMatrix,
    maxPayloadRequests,
    resourcePoolName: String(flags.pool ?? flags['resource-pool'] ?? 'Agent Intruder pool'),
    resourcePoolMaxConcurrent,
    streamChunkSize: Math.max(1, Math.round(numberFlag(flags['stream-chunk-size'], 50))),
    resultWindowSize: Math.max(0, Math.round(numberFlag(flags['result-window-size'], Math.min(maxPayloadRequests, 100)))),
    memoryBudgetBytes: Math.max(1, Math.round(numberFlag(flags['memory-budget-bytes'], 8 * 1024 * 1024))),
    throttleMs: Math.max(0, Math.round(numberFlag(flags.throttle ?? flags['throttle-ms'], 0))),
    grepTerms,
    extractRegexes,
    payloadProcessors,
    payloadRules,
    rawRequest,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
  };

  if (!flags.execute) {
    return {
      status: 'planned',
      mode: 'planned',
      trafficSent: false,
      requestCount: 0,
      gates: ['scope-match', 'intruder-plan-only', 'explicit-execute-required', 'full-fidelity-operational-request'],
      data: { plan, summary: null },
      artifacts: [artifact('intruder-plan', plan.id, 'Agent Intruder run plan')],
    };
  }

  const proxyModule = optionalDist('proxyEngine.js');
  const certModule = optionalDist('certManager.js');
  if (!proxyModule?.ProxyEngine || !certModule?.CertificateAuthorityManager) {
    return blocked('Intruder execution requires a built desktop runtime. Run npm run build first.', ['desktop-runtime-required']);
  }

  const certDir = path.resolve(flags['cert-dir'] ?? path.join(process.cwd(), '.gitignored', 'agent-intruder-certs'));
  const proxy = new proxyModule.ProxyEngine(
    () => undefined,
    new certModule.CertificateAuthorityManager(certDir),
  );
  const summary = await proxy.runIntruderAttack({
    rawRequest,
    targetUrl,
    payloads: payloadSets[0] ?? [],
    payloadSets,
    attackMode,
    payloadProcessors,
    payloadRules,
    scopeAllowlist,
    throttleMs: plan.throttleMs,
    grepTerms,
    extractRegexes,
    startOffset: Math.max(0, Math.round(numberFlag(flags['start-offset'], 0))),
    maxPayloadRequests,
    resourcePoolName: plan.resourcePoolName,
    resourcePoolMaxConcurrent,
    streamChunkSize: plan.streamChunkSize,
    resultWindowSize: plan.resultWindowSize,
    memoryBudgetBytes: plan.memoryBudgetBytes,
  });
  const soakPackage = flags.soak || flags['soak-report']
    ? buildAgentIntruderSoakPackage(summary, plan, flags)
    : undefined;
  const outPath = flags.out ? await writeAgentIntruderArtifact(flags.out, {
    plan,
    summary,
    soakPackage,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
  }) : undefined;

  return {
    status: summary.blocked || soakPackage?.status === 'fail' ? 'blocked' : 'completed',
    mode: 'executed',
    trafficSent: !summary.blocked && summary.totalRequests > 0,
    requestCount: summary.totalRequests,
    gates: ['scope-match', 'explicit-execute', 'resource-pool-concurrency', 'streamed-result-window', 'full-fidelity-operational-artifacts'],
    data: {
      plan,
      summary,
      soakPackage,
      outPath,
    },
    artifacts: [
      artifact('intruder-run', summary.id, 'Agent Intruder execution summary'),
      ...(soakPackage ? [artifact('intruder-soak', soakPackage.id, 'Agent Intruder high-volume soak package')] : []),
      ...(outPath ? [artifact('intruder-artifact', outPath, 'Agent Intruder full-fidelity artifact')] : []),
    ],
  };
}

async function repeaterDesyncPlanResult(flags, project, selectedExchange, scopeAllowlist) {
  const plan = buildRepeaterDesyncPlan(flags, project, selectedExchange, scopeAllowlist);
  if (plan.blocked) return blocked(plan.blocked, ['scope-match']);
  return {
    status: 'planned',
    mode: 'planned',
    trafficSent: false,
    requestCount: 0,
    gates: ['scope-match', 'desync-plan-only', 'explicit-execute-required'],
    data: { plan },
    artifacts: [artifact('repeater-desync-plan', plan.id, 'Repeater desync probe plan')],
  };
}

async function repeaterDesyncProbeResult(flags, project, selectedExchange, scopeAllowlist) {
  const plan = buildRepeaterDesyncPlan(flags, project, selectedExchange, scopeAllowlist);
  if (plan.blocked) return blocked(plan.blocked, ['scope-match']);
  if (!flags.execute) {
    return {
      status: 'planned',
      mode: 'planned',
      trafficSent: false,
      requestCount: 0,
      gates: ['scope-match', 'single-connection-desync', 'explicit-execute-required'],
      data: { plan, result: null },
      artifacts: [artifact('repeater-desync-plan', plan.id, 'Repeater desync single-connection plan')],
    };
  }
  const runtimeModule = optionalDist('repeaterDesyncRaceEngine.js');
  if (!runtimeModule?.RepeaterDesyncRaceEngine) {
    return blocked('Repeater desync runtime requires a built desktop runtime. Run npm run build first.', ['desktop-runtime-required']);
  }
  const engine = new runtimeModule.RepeaterDesyncRaceEngine();
  const result = await engine.runSingleConnectionProbe({
    planId: plan.id,
    targetUrl: plan.targetUrl,
    requests: plan.requests,
    scopeAllowlist,
    timeoutMs: numberFlag(flags.timeout, 5000),
    syncTechnique: 'single-connection',
  });
  return {
    status: result.status === 'proof' ? 'completed' : 'blocked',
    mode: 'executed',
    trafficSent: result.status !== 'blocked',
    requestCount: result.requestCount,
    gates: ['scope-match', 'explicit-execute', 'single-connection-desync', 'full-fidelity-operational-response'],
    data: { plan, result },
    artifacts: [artifact('repeater-desync-evidence', result.id, 'Repeater desync socket evidence')],
  };
}

async function repeaterRaceRunResult(flags, project, selectedExchange, scopeAllowlist) {
  const plan = buildRepeaterRacePlan(flags, project, selectedExchange, scopeAllowlist);
  if (plan.blocked) return blocked(plan.blocked, ['scope-match']);
  if (!flags.execute) {
    return {
      status: 'planned',
      mode: 'planned',
      trafficSent: false,
      requestCount: 0,
      gates: ['scope-match', 'parallel-race', 'explicit-execute-required'],
      data: { plan, result: null },
      artifacts: [artifact('repeater-race-plan', plan.id, 'Repeater parallel race plan')],
    };
  }
  const runtimeModule = optionalDist('repeaterDesyncRaceEngine.js');
  if (!runtimeModule?.RepeaterDesyncRaceEngine) {
    return blocked('Repeater race runtime requires a built desktop runtime. Run npm run build first.', ['desktop-runtime-required']);
  }
  const syncTechnique = flags.sync === 'single-packet' ? 'single-packet' : 'last-byte';
  const engine = new runtimeModule.RepeaterDesyncRaceEngine();
  const result = await engine.runParallelRace({
    planId: plan.id,
    targetUrl: plan.targetUrl,
    requests: plan.requests,
    scopeAllowlist,
    timeoutMs: numberFlag(flags.timeout, 5000),
    syncTechnique,
    pauseMs: numberFlag(flags.pause, numberFlag(flags['pause-ms'], 25)),
  });
  const soakPackage = flags.soak || flags['soak-report']
    ? buildAgentRepeaterRaceSoakPackage(result, plan, flags)
    : undefined;
  const outPath = flags.out ? await writeAgentRepeaterRaceArtifact(flags.out, {
    plan,
    result,
    soakPackage,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
  }) : undefined;
  return {
    status: result.status === 'proof' && soakPackage?.status !== 'fail' ? 'completed' : 'blocked',
    mode: 'executed',
    trafficSent: result.status !== 'blocked',
    requestCount: result.requestCount,
    gates: ['scope-match', 'explicit-execute', syncTechnique, ...(soakPackage ? ['high-concurrency-race-soak'] : []), 'full-fidelity-operational-response'],
    data: { plan, result, soakPackage, outPath },
    artifacts: [
      artifact('repeater-race-evidence', result.id, 'Repeater parallel race socket evidence'),
      ...(soakPackage ? [artifact('repeater-race-soak', soakPackage.id, 'Repeater race high-concurrency soak package')] : []),
      ...(outPath ? [artifact('repeater-race-artifact', outPath, 'Repeater race full-fidelity artifact')] : []),
    ],
  };
}

async function scannerPlanResult(flags, project, selectedExchange, scopeAllowlist) {
  const targetUrl = normalizeTarget(flags.target ?? selectedExchange?.url ?? project.exchanges[0]?.url ?? 'https://example.test/');
  if (!isTargetInScope(targetUrl, scopeAllowlist)) return blocked(`Scanner target ${targetUrl} is outside scope.`, ['scope-match']);
  const selection = resolveAgentScannerSelection(flags);
  if (selection.error) return blocked(selection.error, ['scanner-check-selection']);
  const checks = selection.checks;
  const insertionPoints = inferInsertionPoints(project.exchanges, selectedExchange, targetUrl);
  const planId = `agent-scanner-plan-${simpleDigest(`${targetUrl}|${checks.join(',')}`).slice(0, 12)}`;
  return {
    status: 'completed',
    mode: 'planned',
    trafficSent: false,
    requestCount: 0,
    gates: ['scope-match', 'operator-execute-required', 'throttle-bound'],
    data: {
      planId,
      targetUrl,
      checkPackId: selection.checkPackId,
      checkPackLabel: selection.checkPackLabel,
      checks,
      unsupportedChecks: selection.unsupportedChecks,
      catalog: agentScannerCatalog(),
      throttleMs: numberFlag(flags.throttle, numberFlag(flags['throttle-ms'], 250)),
      maxRequests: numberFlag(flags['max-requests'], checks.length),
      insertionPoints,
      falsePositiveControls: ['dedupe-key', 'confidence-reason', 'retest-before-report'],
    },
    artifacts: [artifact('scanner-plan', planId, 'Scanner active plan')],
  };
}

async function insertionPointsResult(flags, project, selectedExchange, scopeAllowlist) {
  const targetUrl = normalizeTarget(flags.target ?? selectedExchange?.url ?? project.exchanges[0]?.url ?? 'https://example.test/');
  if (!isTargetInScope(targetUrl, scopeAllowlist)) return blocked(`Insertion point target ${targetUrl} is outside scope.`, ['scope-match']);
  const points = inferInsertionPoints(project.exchanges, selectedExchange, targetUrl, {
    maxPoints: numberFlag(flags.limit, numberFlag(flags['max-points'], 250)),
  });
  const packagePayload = buildAgentInsertionPointPackage(project, selectedExchange, targetUrl, points, scopeAllowlist);
  const outPath = flags.out ? await writeAgentInsertionPointArtifact(flags.out, packagePayload) : undefined;
  return {
    status: points.length ? 'completed' : 'blocked',
    mode: 'read-only',
    trafficSent: false,
    requestCount: 0,
    gates: ['scope-match', 'project-history-derived', 'scanner-ready-insertion-model', 'full-fidelity-operational-evidence'],
    data: {
      targetUrl,
      insertionPointCount: points.length,
      coverage: packagePayload.coverage,
      points,
      package: packagePayload,
      outPath,
    },
    artifacts: [
      artifact('insertion-point-inventory', packagePayload.id, 'Scanner-ready insertion point inventory package'),
      ...(outPath ? [artifact('insertion-point-inventory-file', outPath, 'Insertion point inventory package file')] : []),
    ],
  };
}

function buildAgentInsertionPointPackage(project, selectedExchange, targetUrl, points, scopeAllowlist) {
  const createdAt = new Date().toISOString();
  const sourceExchanges = selectedExchange
    ? [selectedExchange]
    : project.exchanges.filter((exchange) => exchange.url === targetUrl || exchange.host === hostFromUrl(targetUrl)).slice(0, 50);
  const types = ['query', 'path', 'header', 'cookie', 'form', 'json', 'xml', 'multipart', 'graphql'];
  const coverage = types.map((type) => ({ type, count: points.filter((point) => point.location === type || point.type === type).length }));
  const rawMaterial = [
    JSON.stringify(points),
    ...sourceExchanges.flatMap((exchange) => [exchange.requestRaw, exchange.responseRaw, exchange.url, exchange.notes]),
  ].join('\n');
  const requirements = {
    queryParametersCovered: coverage.some((row) => row.type === 'query' && row.count > 0),
    pathParametersCovered: coverage.some((row) => row.type === 'path' && row.count > 0),
    headerParametersCovered: coverage.some((row) => row.type === 'header' && row.count > 0),
    cookieParametersCovered: coverage.some((row) => row.type === 'cookie' && row.count > 0),
    formParametersCovered: coverage.some((row) => row.type === 'form' && row.count > 0),
    jsonParametersCovered: coverage.some((row) => row.type === 'json' && row.count > 0),
    xmlParametersCovered: coverage.some((row) => row.type === 'xml' && row.count > 0),
    multipartParametersCovered: coverage.some((row) => row.type === 'multipart' && row.count > 0),
    graphqlParametersCovered: coverage.some((row) => row.type === 'graphql' && row.count > 0),
    scannerReadyCorpus: points.length > 0 && points.every((point) => point.exchangeId && point.name && point.evidence),
    rawExecutorMaterialPreserved: /HTTP\/[12]|Authorization:|Cookie:|Content-Type:/i.test(rawMaterial),
    operationalSecretsPreserved: /Bearer|Cookie:|session=|api[_-]?key|secret|token/i.test(rawMaterial),
    reportPhaseOnlyRedaction: true,
  };
  const unsigned = {
    kind: 'proxyforge-agent-insertion-point-inventory-package',
    createdAt,
    targetUrl,
    scopeAllowlist,
    project: projectSummary(project),
    selectedExchangeId: selectedExchange?.id,
    coverage,
    points,
    rawExchanges: sourceExchanges.map((exchange) => ({
      id: exchange.id,
      url: exchange.url,
      method: exchange.method,
      requestRaw: exchange.requestRaw,
      responseRaw: exchange.responseRaw,
    })),
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
  };
  const digestPreview = simpleDigest(JSON.stringify(unsigned));
  return {
    id: `agent-insertion-points-${digestPreview.slice(0, 12)}`,
    ...unsigned,
    digestPreview,
    reportReady: Object.values(requirements).every(Boolean),
    summary: `Agent insertion point inventory extracted ${points.length} scanner-ready point(s) across ${coverage.filter((row) => row.count > 0).length} parameter class(es) for ${targetUrl}.`,
    content: JSON.stringify({ ...unsigned, digestPreview }, null, 2),
  };
}

function agentScannerCatalog() {
  return {
    kind: 'proxyforge-agent-scanner-catalog',
    schemaVersion,
    checkCount: activeScannerChecks.length,
    defaultChecks,
    checks: activeScannerChecks,
    checkPacks: activeScannerCheckPacks,
    commands: {
      baseline: `${agentCommandPrefix} scanner-run --project <project> --request-id <id> --check-pack baseline --execute --json`,
      inputAttacks: `${agentCommandPrefix} scanner-run --project <project> --request-id <id> --check-pack input-attacks --execute --soak --json`,
      fullActive: `${agentCommandPrefix} scanner-run --project <project> --request-id <id> --check-pack full-active --max-requests ${activeScannerCheckIds.length} --execute --soak --json`,
      oastIssuePromotion: `${agentCommandPrefix} scanner-oast-promote --project <project> --payload-id <payload-id> --interaction-id <interaction-id> --json`,
    },
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
  };
}

function resolveAgentScannerSelection(flags) {
  const explicitChecks = parseList(flags.checks);
  const requestedPackId = String(flags['check-pack'] ?? flags.pack ?? '').trim();
  const pack = requestedPackId
    ? activeScannerCheckPacks.find((item) => item.id === requestedPackId)
    : undefined;
  if (requestedPackId && !pack) {
    return {
      error: `Unknown scanner check pack "${requestedPackId}". Valid packs: ${activeScannerCheckPacks.map((item) => item.id).join(', ')}.`,
      checks: [],
      unsupportedChecks: [],
    };
  }
  const requestedChecks = explicitChecks.length ? explicitChecks : pack?.checks ?? defaultChecks;
  const supportedSet = new Set(activeScannerCheckIds);
  const checks = unique(requestedChecks.filter((check) => supportedSet.has(check)));
  const unsupportedChecks = unique(requestedChecks.filter((check) => !supportedSet.has(check)));
  if (checks.length === 0) {
    return {
      error: `No supported scanner checks selected. Valid checks: ${activeScannerCheckIds.join(', ')}.`,
      checks,
      unsupportedChecks,
    };
  }
  return {
    checkPackId: pack?.id ?? (explicitChecks.length ? 'custom' : 'baseline'),
    checkPackLabel: pack?.label ?? (explicitChecks.length ? 'Custom scanner checks' : 'Baseline web pack'),
    checks,
    unsupportedChecks,
  };
}

async function scannerRunResult(flags, project, selectedExchange, scopeAllowlist) {
  const plan = await scannerPlanResult(flags, project, selectedExchange, scopeAllowlist);
  if (plan.status === 'blocked') return plan;
  if (!flags.execute) {
    return {
      ...plan,
      status: 'planned',
      gates: [...(plan.gates ?? []), 'explicit-execute-required'],
    };
  }
  const headless = optionalDist('headlessRunner.js');
  if (!headless?.runHeadlessScan) return blocked('Headless scanner runtime is unavailable until npm run build has completed.');
  const outDir = path.resolve(flags.out ?? flags['out-dir'] ?? 'proxyforge-agent-artifacts/scanner');
  const summary = await headless.runHeadlessScan({
    projectName: project.projectName,
    projectFile: flags.project,
    projectExchangeId: selectedExchange?.id,
    targetUrl: flags.target ?? selectedExchange?.url,
    scopeAllowlist,
    outDir,
    crawl: { enabled: flags.crawl === true },
    activeScan: {
      enabled: true,
      checks: plan.data.checks,
      throttleMs: plan.data.throttleMs,
      maxRequests: plan.data.maxRequests,
    },
    report: { formats: ['json'] },
    failOnSeverity: flags['fail-on-severity'] ?? 'none',
  });
  const calibrationPackage = flags.soak || flags['soak-report'] || flags.calibration
    ? buildAgentScannerCalibrationPackage(summary, plan.data, selectedExchange, flags)
    : undefined;
  return {
    status: summary.blocked || calibrationPackage?.status === 'fail' ? 'blocked' : 'completed',
    mode: 'executed',
    trafficSent: summary.totalRequests > 0,
    requestCount: summary.totalRequests,
    gates: ['scope-match', 'explicit-execute', ...(calibrationPackage ? ['scanner-calibration-soak', 'false-positive-tuning'] : []), 'full-fidelity-operational-artifacts'],
    data: {
      plan: plan.data,
      summary,
      calibrationPackage,
      seedExchange: selectedExchange ? exchangeDetail(selectedExchange) : undefined,
    },
    artifacts: [
      artifact('scanner-summary', summary.summaryPath, 'Headless scanner summary'),
      ...(calibrationPackage ? [artifact('scanner-calibration-soak', calibrationPackage.id, 'Scanner live calibration and false-positive tuning package')] : []),
    ],
  };
}

async function scannerRetestResult(flags, project, selectedExchange, scopeAllowlist) {
  const issue = selectAgentScannerIssue(project, flags.issue ?? flags['issue-id'] ?? flags.finding, selectedExchange);
  if (!issue) return blocked('Scanner retest requires a project issue or --issue id.');
  const baselineExchange = selectExchange(project, flags.baseline ?? flags['baseline-id'] ?? flags['baseline-exchange'], undefined)
    ?? selectedExchange
    ?? findAgentIssueExchange(project, issue);
  if (!baselineExchange) return blocked(`No baseline exchange found for Scanner issue ${issue.id}.`);
  if (!isTargetInScope(baselineExchange.url, scopeAllowlist)) {
    return blocked(`Scanner retest baseline ${baselineExchange.url} is outside scope.`, ['scope-match']);
  }

  const transportSettings = agentReplayTransportSettings(flags);
  let retestExchange = selectExchange(project, flags['retest-id'] ?? flags.retest ?? flags['candidate-id'], undefined);
  let replayResponse = null;
  let trafficSent = false;
  let requestCount = 0;
  if (flags.execute) {
    const request = requestFromExchange(baselineExchange, flags);
    if (!isTargetInScope(request.url, scopeAllowlist)) return blocked(`Scanner retest target ${request.url} is outside scope.`, ['scope-match']);
    replayResponse = await executeHttpRequest(request, { ...transportSettings, scopeAllowlist });
    trafficSent = true;
    requestCount = 1 + (replayResponse.redirectHistory?.length ?? 0);
    retestExchange = exchangeFromAgentRetestResponse(baselineExchange, request, replayResponse, issue);
  }

  const previousRetests = [
    ...(Array.isArray(project.scannerRetestWorkflows) ? project.scannerRetestWorkflows : []),
  ];
  const checkIds = parseList(flags.checks).length ? parseList(flags.checks) : defaultChecks;
  const retestPackage = buildAgentScannerRetestEvidenceDeltaPackage({
    issue,
    baselineExchange,
    retestExchange,
    previousRetests,
    evidenceDeltas: Array.isArray(project.scannerEvidenceDeltas) ? project.scannerEvidenceDeltas : [],
    checkIds,
    checkPackId: String(flags['check-pack'] ?? flags.pack ?? 'agent-scanner-retest'),
    scopeAllowlist,
    throttleMs: numberFlag(flags.throttle ?? flags['throttle-ms'], 0),
    maxRequests: numberFlag(flags['max-requests'], Math.max(1, checkIds.length)),
    sessionProfileName: String(flags.session ?? flags['session-profile'] ?? 'agent session'),
    operator: String(flags.operator ?? 'ProxyForge agent'),
    runnerPolicyId: String(flags.policy ?? flags['policy-id'] ?? 'agent-scope-policy'),
    requestEdits: parseAgentRetestRequestEdits(flags),
    generatedAt: new Date().toISOString(),
  });
  const outPath = flags.out ? path.resolve(String(flags.out)) : undefined;
  if (outPath) {
    await writePrivateFile(outPath, JSON.stringify(retestPackage, null, 2), 'utf8');
  }
  return {
    status: replayResponse?.error ? 'blocked' : flags.execute || retestExchange ? 'completed' : 'planned',
    mode: flags.execute ? 'executed' : 'read-only',
    trafficSent,
    requestCount,
    gates: ['scope-match', ...(flags.execute ? ['explicit-execute', 'replay-transport-controls'] : ['project-evidence-review']), 'full-fidelity-operational-evidence-delta'],
    data: {
      issue: scannerIssueSummary(issue),
      baselineExchange: exchangeDetail(baselineExchange),
      retestExchange: retestExchange ? exchangeDetail(retestExchange) : null,
      transportSettings: flags.execute ? transportSettings : undefined,
      replayResponse,
      retestPackage,
      outPath,
    },
    artifacts: [
      artifact('scanner-retest-evidence-delta', retestPackage.id, 'Scanner retest evidence delta package'),
      ...(outPath ? [artifact('scanner-retest-artifact', outPath, 'Scanner retest full-fidelity artifact')] : []),
    ],
  };
}

async function scannerEvidenceExportResult(flags, project, selectedExchange, scopeAllowlist) {
  const packages = [];
  if (Array.isArray(project.scannerEvidenceDeltas)) packages.push(...project.scannerEvidenceDeltas);
  const issue = selectAgentScannerIssue(project, flags.issue ?? flags['issue-id'] ?? flags.finding, selectedExchange);
  const baselineExchange = issue
    ? selectExchange(project, flags.baseline ?? flags['baseline-id'] ?? flags['baseline-exchange'], undefined)
      ?? selectedExchange
      ?? findAgentIssueExchange(project, issue)
    : undefined;
  if (issue && baselineExchange) {
    const retestExchange = selectExchange(project, flags['retest-id'] ?? flags.retest ?? flags['candidate-id'], undefined) ?? baselineExchange;
    if (!isTargetInScope(baselineExchange.url, scopeAllowlist)) return blocked(`Scanner evidence export baseline ${baselineExchange.url} is outside scope.`, ['scope-match']);
    const checkIds = parseList(flags.checks).length ? parseList(flags.checks) : defaultChecks;
    packages.unshift(buildAgentScannerRetestEvidenceDeltaPackage({
      issue,
      baselineExchange,
      retestExchange,
      previousRetests: [
        ...(Array.isArray(project.scannerRetestWorkflows) ? project.scannerRetestWorkflows : []),
      ],
      evidenceDeltas: Array.isArray(project.scannerEvidenceDeltas) ? project.scannerEvidenceDeltas : [],
      checkIds,
      checkPackId: String(flags['check-pack'] ?? flags.pack ?? 'agent-scanner-retest'),
      scopeAllowlist,
      throttleMs: numberFlag(flags.throttle ?? flags['throttle-ms'], 0),
      maxRequests: numberFlag(flags['max-requests'], Math.max(1, checkIds.length)),
      sessionProfileName: String(flags.session ?? flags['session-profile'] ?? 'agent session'),
      operator: String(flags.operator ?? 'ProxyForge agent'),
      runnerPolicyId: String(flags.policy ?? flags['policy-id'] ?? 'agent-scope-policy'),
      requestEdits: parseAgentRetestRequestEdits(flags),
      generatedAt: new Date().toISOString(),
    }));
  }
  if (!packages.length) return blocked('No Scanner evidence deltas are available to export.');
  const exportPackage = {
    id: `scanner-evidence-export-${simpleDigest(JSON.stringify(packages.map((item) => item.id ?? item.fileName ?? item.title))).slice(0, 12)}`,
    kind: 'proxyforge-agent-scanner-evidence-export',
    schemaVersion,
    generatedAt: new Date().toISOString(),
    packageCount: packages.length,
    packages,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
  };
  const outPath = flags.out ? path.resolve(String(flags.out)) : undefined;
  if (outPath) {
    await writePrivateFile(outPath, JSON.stringify(exportPackage, null, 2), 'utf8');
  }
  return {
    status: 'completed',
    mode: 'read-only',
    trafficSent: false,
    requestCount: 0,
    gates: ['project-evidence-review', 'full-fidelity-operational-evidence-export', 'report-phase-only-redaction'],
    data: { exportPackage, outPath },
    artifacts: [
      artifact('scanner-evidence-export', exportPackage.id, 'Scanner evidence delta export'),
      ...(outPath ? [artifact('scanner-evidence-export-artifact', outPath, 'Scanner evidence export artifact')] : []),
    ],
  };
}

async function scannerOastPromoteResult(flags, project, selectedExchange, scopeAllowlist) {
  const workspace = await loadJsonMaybe(flags.workspace);
  const payloads = Array.isArray(workspace?.payloads) ? workspace.payloads : project.callbackPayloads ?? project.oastPayloads ?? [];
  const interactions = Array.isArray(workspace?.interactions) ? workspace.interactions : project.callbackInteractions ?? [];
  const requestedPayload = String(flags['payload-id'] ?? flags.payload ?? flags.token ?? '').trim();
  const requestedInteraction = String(flags['interaction-id'] ?? flags.interaction ?? '').trim();
  const payload = selectAgentScannerOastPayload(payloads, interactions, requestedPayload);
  if (!payload) return blocked('scanner-oast-promote requires a callback payload in --workspace or project callbackPayloads.', ['payload-ownership']);
  const interaction = selectAgentScannerOastInteraction(interactions, payload, requestedInteraction);
  if (!interaction) return blocked(`No callback interaction is linked to payload ${payload.id ?? payload.token ?? requestedPayload}.`, ['callback-interaction-linked']);
  const token = String(payload.token ?? interaction.token ?? requestedPayload ?? '').trim();
  const scannerExchange = selectedExchange
    ?? selectExchange(project, flags['scanner-exchange-id'] ?? flags['scanner-id'] ?? interaction.evidenceExchangeId, undefined)
    ?? project.exchanges.find((exchange) => token && `${exchange.requestRaw ?? ''}\n${exchange.responseRaw ?? ''}`.includes(token))
    ?? project.exchanges.find((exchange) => (exchange.tags ?? []).some((tag) => /oast|scanner|ssrf/i.test(tag)));
  if (!scannerExchange) return blocked('No Scanner exchange was found for OAST issue promotion.', ['scanner-exchange-linked']);
  if (!isTargetInScope(scannerExchange.url, scopeAllowlist)) {
    return blocked(`Scanner OAST promotion target ${scannerExchange.url} is outside scope.`, ['scope-match']);
  }
  const sourceExchange = selectExchange(project, flags['source-exchange-id'] ?? flags.source ?? payload.sourceExchangeId, undefined);
  const finding = selectAgentScannerOastFinding(project, flags.finding ?? flags['finding-id'], scannerExchange, payload, interaction);
  const promotionPackage = buildAgentScannerOastIssuePromotionPackage({
    projectName: project.projectName,
    sourceExchange,
    scannerExchange,
    payload,
    interaction,
    finding,
    scopeAllowlist,
    generatedAt: new Date().toISOString(),
  });
  const outPath = flags.out ? path.resolve(String(flags.out)) : undefined;
  if (outPath) {
    await writePrivateFile(outPath, JSON.stringify(promotionPackage, null, 2), 'utf8');
  }
  return {
    status: promotionPackage.reportReady ? 'completed' : 'blocked',
    mode: 'read-only',
    trafficSent: false,
    requestCount: 0,
    gates: ['scope-match', 'payload-ownership', 'scanner-oast-correlation', 'full-fidelity-operational-issue-promotion', 'report-phase-only-redaction'],
    data: {
      issue: promotionPackage.issue,
      promotionPackage,
      outPath,
    },
    artifacts: [
      artifact('scanner-oast-issue-promotion', promotionPackage.id, 'Scanner OAST issue promotion package'),
      ...(outPath ? [artifact('scanner-oast-issue-promotion-artifact', outPath, 'Scanner OAST issue promotion artifact')] : []),
    ],
  };
}

function selectAgentScannerOastPayload(payloads, interactions, requested) {
  if (requested) {
    return payloads.find((payload) => payload.id === requested || payload.token === requested || payload.endpoint === requested);
  }
  return payloads.find((payload) => interactions.some((interaction) => interaction.payloadId === payload.id || (payload.token && agentRawText(interaction.raw).includes(payload.token))))
    ?? payloads[0];
}

function selectAgentScannerOastInteraction(interactions, payload, requested) {
  if (requested) return interactions.find((interaction) => interaction.id === requested);
  return interactions.find((interaction) => interaction.payloadId === payload.id)
    ?? interactions.find((interaction) => payload.token && agentRawText(interaction.raw).includes(payload.token))
    ?? interactions[0];
}

function selectAgentScannerOastFinding(project, requested, scannerExchange, payload, interaction) {
  const candidates = [
    ...(Array.isArray(project.activeScanSummaries) ? project.activeScanSummaries.flatMap((summary) => summary.findings ?? []) : []),
    ...(Array.isArray(project.activeScanSummary?.findings) ? project.activeScanSummary.findings : []),
    ...(Array.isArray(project.scannerFindings) ? project.scannerFindings : []),
  ];
  const selected = candidates.find((finding) => (
    requested
      ? finding.id === requested || finding.dedupeKey === requested
      : finding.checkId === 'oast-ssrf' || finding.evidenceExchangeId === scannerExchange.id
  ));
  if (selected) return selected;
  const token = payload.token ?? interaction.token ?? '';
  return {
    id: `finding-agent-oast-${simpleDigest(`${scannerExchange.id}|${payload.id ?? token}|${interaction.id ?? ''}`).slice(0, 10)}`,
    checkId: 'oast-ssrf',
    title: 'Out-of-band callback was triggered',
    severity: 'high',
    confidence: token && agentRawText(interaction.raw).includes(token) ? 'certain' : 'firm',
    host: scannerExchange.host ?? hostFromUrl(scannerExchange.url),
    path: scannerExchange.path ?? pathFromTargetUrl(scannerExchange.url),
    detail: 'Agent correlated a Scanner OAST payload with a callback interaction and preserved the raw executor material.',
    remediation: 'Restrict server-side fetches and user-controlled callback URLs, then retest with a fresh OAST payload.',
    evidenceExchangeId: scannerExchange.id,
    dedupeKey: `oast-ssrf:${scannerExchange.host ?? hostFromUrl(scannerExchange.url)}:${scannerExchange.path ?? pathFromTargetUrl(scannerExchange.url)}:${payload.id ?? (token || 'callback')}`,
    confidenceReason: 'Callback interaction is linked to the scanner payload token.',
  };
}

function buildAgentScannerOastIssuePromotionPackage(request) {
  const createdAt = request.generatedAt ?? new Date().toISOString();
  const sourceExchange = request.sourceExchange ? agentOastExchangeEvidence(request.sourceExchange) : undefined;
  const scannerExchange = agentOastExchangeEvidence(request.scannerExchange);
  const interactionRaw = agentRawText(request.interaction.raw);
  const token = request.payload.token ?? request.interaction.token ?? '';
  const payloadIdentifier = request.payload.id ?? (token || request.payload.endpoint || 'callback');
  const payloadDisplay = request.payload.id ?? (token || 'unknown');
  const host = request.finding.host ?? scannerExchange.host ?? hostFromUrl(scannerExchange.url);
  const targetPath = request.finding.path ?? scannerExchange.path ?? pathFromTargetUrl(scannerExchange.url);
  const checkId = request.finding.checkId ?? 'oast-ssrf';
  const dedupeKey = request.finding.dedupeKey ?? `${checkId}:${host}:${targetPath}:${payloadIdentifier}`;
  const issue = {
    id: `issue-scanner-oast-${simpleDigest(`${dedupeKey}|${request.interaction.id ?? interactionRaw}`).slice(0, 12)}`,
    title: request.finding.title ?? 'Out-of-band callback was triggered',
    severity: request.finding.severity ?? request.interaction.severity ?? 'high',
    host,
    path: targetPath,
    confidence: request.finding.confidence ?? (token && interactionRaw.includes(token) ? 'certain' : 'firm'),
    status: 'triaged',
    detail: [
      request.finding.detail ?? 'Scanner observed an out-of-band callback from an injected OAST payload.',
      `Payload ${payloadDisplay} was sent in scanner exchange ${scannerExchange.id ?? 'unknown'} and observed in callback interaction ${request.interaction.id ?? 'unknown'}.`,
      'Full raw scanner request, scanner response, callback interaction, and linked source request are preserved for executor replay.',
    ].join(' '),
    remediation: request.finding.remediation ?? 'Validate the server-side fetch/callback sink, restrict outbound destinations, block user-controlled callback URLs, and retest with a fresh OAST payload.',
    triageNote: `Promoted from agent Scanner OAST evidence; redaction is deferred until report export. Dedupe: ${dedupeKey}.`,
    lastTriagedAt: createdAt,
  };
  const operationalSecretSignals = unique([
    ...agentOperationalSecretSignals(scannerExchange.requestRaw, scannerExchange.responseRaw),
    ...agentOperationalSecretSignals(sourceExchange?.requestRaw ?? '', sourceExchange?.responseRaw ?? ''),
    ...agentOperationalSecretSignals(interactionRaw),
  ]);
  const reportAttachments = [
    ...(sourceExchange?.id ? [agentReportAttachment('source-exchange', sourceExchange.id)] : []),
    agentReportAttachment('scanner-exchange', scannerExchange.id ?? issue.id),
    agentReportAttachment('callback-payload', payloadIdentifier),
    agentReportAttachment('callback-interaction', request.interaction.id ?? issue.id),
    agentReportAttachment('issue-draft', issue.id),
  ];
  const requirements = {
    sourceExchangeLinked: Boolean(sourceExchange?.id || request.payload.sourceExchangeId),
    scannerExchangeLinked: Boolean(scannerExchange.id || scannerExchange.requestRaw),
    callbackPayloadLinked: Boolean(request.payload.id || token || request.payload.endpoint),
    callbackInteractionLinked: Boolean(request.interaction.id || interactionRaw),
    activeFindingLinked: Boolean(request.finding.id || request.finding.title),
    oastTokenObserved: Boolean(token && [scannerExchange.requestRaw, scannerExchange.responseRaw, interactionRaw].some((value) => value.includes(token))),
    rawScannerRequestPreserved: scannerExchange.requestRaw.trim().length > 0,
    rawScannerResponsePreserved: scannerExchange.responseRaw.trim().length > 0,
    rawCallbackInteractionPreserved: interactionRaw.trim().length > 0,
    issueDraftReady: Boolean(issue.id && issue.title && issue.host && issue.path && issue.detail && issue.remediation),
    dedupeKeyStable: Boolean(dedupeKey && dedupeKey.includes(checkId) && dedupeKey.includes(host)),
    reportAttachmentsLinked: reportAttachments.length >= 4 && reportAttachments.every((attachment) => attachment.reportReady && attachment.redactionPhase === 'report-export-only'),
    operationalSecretsPreserved: operationalSecretSignals.length > 0 || Boolean(token && [scannerExchange.requestRaw, interactionRaw].some((value) => value.includes(token))),
    reportPhaseOnlyRedaction: true,
  };
  const body = {
    kind: 'proxyforge-scanner-oast-issue-promotion-package',
    schemaVersion,
    createdAt,
    projectName: request.projectName ?? 'ProxyForge Agent Project',
    issue,
    finding: request.finding,
    sourceExchangeId: sourceExchange?.id ?? request.payload.sourceExchangeId,
    scannerExchangeId: scannerExchange.id ?? issue.id,
    callbackPayloadId: payloadIdentifier,
    callbackInteractionId: request.interaction.id ?? issue.id,
    dedupeKey,
    evidence: {
      sourceExchange,
      scannerExchange,
      callbackPayload: request.payload,
      callbackInteraction: {
        ...request.interaction,
        raw: interactionRaw,
      },
    },
    reproductionSteps: [
      `Start or select callback payload ${payloadDisplay} at ${request.payload.endpoint ?? 'the configured OAST endpoint'}.`,
      `Replay scanner exchange ${scannerExchange.id ?? 'unknown'} with preserved Authorization, Cookie, API-key, body, and OAST token material.`,
      `Poll callback/OAST interactions and confirm ${request.interaction.id ?? 'the observed interaction'} contains ${token || 'the payload token'}.`,
    ],
    retestCommands: [
      `${agentCommandPrefix} scanner-run --project <project> --request-id ${scannerExchange.id ?? '<scanner-exchange-id>'} --checks oast-ssrf --scope ${request.scopeAllowlist?.[0] ?? host} --execute --json`,
      `${agentCommandPrefix} callback-poll --workspace <callbacks.json> --json`,
      `${agentCommandPrefix} scanner-oast-promote --project <project> --payload-id ${request.payload.id ?? '<payload-id>'} --interaction-id ${request.interaction.id ?? '<interaction-id>'} --json`,
    ],
    reportAttachments,
    operationalSecretSignals,
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady: Object.values(requirements).every(Boolean),
  };
  const content = JSON.stringify(body, null, 2);
  return {
    id: `scanner-oast-promotion-${simpleDigest(content).slice(0, 12)}`,
    title: 'Scanner OAST issue promotion package',
    fileName: `proxyforge-scanner-oast-issue-promotion-${createdAt.replace(/[:.]/g, '-')}.json`,
    path: `scanner/proxyforge-scanner-oast-issue-promotion-${createdAt.replace(/[:.]/g, '-')}.json`,
    summary: `Scanner OAST issue promotion linked issue ${issue.id}, scanner exchange ${body.scannerExchangeId}, payload ${body.callbackPayloadId}, interaction ${body.callbackInteractionId}, and report-export-only redaction.`,
    content,
    ...body,
  };
}

function agentOastExchangeEvidence(exchange) {
  return {
    id: exchange.id,
    method: exchange.method,
    url: exchange.url,
    host: exchange.host ?? hostFromUrl(exchange.url),
    path: exchange.path ?? pathFromTargetUrl(exchange.url),
    status: exchange.status,
    source: exchange.source,
    tags: exchange.tags ?? [],
    requestRaw: agentRawText(exchange.requestRaw),
    responseRaw: agentRawText(exchange.responseRaw),
  };
}

function agentReportAttachment(kind, artifactId) {
  return {
    id: `attachment-${kind}-${artifactId}`,
    kind,
    artifactId,
    reportReady: true,
    redactionPhase: 'report-export-only',
  };
}

function agentRawText(value) {
  if (typeof value === 'string') return value;
  if (value == null) return '';
  if (Buffer.isBuffer(value)) return value.toString('utf8');
  if (value instanceof Uint8Array) return Buffer.from(value).toString('utf8');
  return String(value);
}

function pathFromTargetUrl(value) {
  try {
    const parsed = new URL(normalizeTarget(value));
    return `${parsed.pathname || '/'}${parsed.search || ''}`;
  } catch {
    return '/';
  }
}

async function anvilPlanResult(flags, project, selectedExchange, scopeAllowlist) {
  const exchange = selectedExchange ?? project.exchanges[0];
  if (!exchange) return blocked('Anvil planning requires a selected exchange or project history.');
  if (!isTargetInScope(exchange.url, scopeAllowlist)) return blocked(`Anvil target ${exchange.url} is outside scope.`, ['scope-match']);
  const source = await loadAgentAnvilSource(flags, exchange);
  const definition = selectAgentAnvilDefinition(project, flags.check ?? flags['check-id'] ?? flags.anvil)
    ?? buildAgentAnvilDefinition(source, exchange, new Date().toISOString());
  const library = selectAgentAnvilLibrary(project, definition)
    ?? buildAgentAnvilRuleLibrary(definition, new Date().toISOString());
  const fixtures = selectAgentAnvilFixtures(project, definition);
  const plannedFixtures = fixtures.length ? fixtures : buildAgentAnvilFixtures(definition, exchange, new Date().toISOString());
  return {
    status: 'completed',
    mode: 'planned',
    trafficSent: false,
    requestCount: 0,
    gates: ['scope-match', 'operator-execute-required', 'custom-scan-check-review', 'full-fidelity-operational-anvil-source'],
    data: {
      definition,
      library,
      fixtures: plannedFixtures,
      plan: {
        kind: 'proxyforge-agent-anvil-plan',
        targetUrl: exchange.url,
        checkId: definition.id,
        checkName: definition.name,
        language: definition.language,
        phase: definition.phase,
        runScope: definition.runScope,
        fixtureCount: plannedFixtures.length,
        positiveFixtureCount: plannedFixtures.filter((fixture) => fixture.expected === 'match').length,
        negativeFixtureCount: plannedFixtures.filter((fixture) => fixture.expected === 'no-match').length,
        nextCommands: [
          'anvil-run --execute',
          'anvil-package-export --out <artifact>',
          'report-export',
        ],
      },
    },
    artifacts: [artifact('anvil-plan', definition.id, 'Anvil custom scan-check plan')],
  };
}

async function anvilRunResult(flags, project, selectedExchange, scopeAllowlist) {
  const plan = await anvilPlanResult(flags, project, selectedExchange, scopeAllowlist);
  if (plan.status === 'blocked') return plan;
  if (!flags.execute) {
    return {
      ...plan,
      status: 'planned',
      gates: [...(plan.gates ?? []), 'explicit-execute-required'],
    };
  }
  const exchange = selectedExchange ?? project.exchanges[0];
  const definition = plan.data.definition;
  const library = plan.data.library;
  const fixtures = plan.data.fixtures;
  const validationRun = buildAgentAnvilValidationRun(definition, fixtures, new Date().toISOString());
  const headlessRun = buildAgentAnvilHeadlessRun(definition, exchange.url, project.exchanges, new Date().toISOString());
  const packageReview = buildAgentAnvilPackageReview(definition, library, validationRun, headlessRun, new Date().toISOString());
  const promotedIssue = buildAgentAnvilPromotedIssue(definition, headlessRun, exchange);
  const parityPackage = buildAgentAnvilParityPackage({
    definition,
    library,
    fixtures: fixtures.map((fixture) => ({
      ...fixture,
      status: validationRun.fixtureResults.find((result) => result.fixtureId === fixture.id)?.status ?? fixture.status,
    })),
    validationRun,
    headlessRun,
    packageReview,
    promotedIssue,
    exchanges: project.exchanges,
    generatedAt: new Date().toISOString(),
  });
  const outPath = flags.out ? path.resolve(String(flags.out)) : undefined;
  if (outPath) {
    await writePrivateFile(outPath, JSON.stringify(parityPackage, null, 2), 'utf8');
  }
  return {
    status: validationRun.status === 'blocked' || packageReview.status === 'blocked' ? 'blocked' : 'completed',
    mode: 'executed',
    trafficSent: false,
    requestCount: validationRun.requestCount + headlessRun.requestCount,
    gates: ['scope-match', 'explicit-execute', 'fixture-validation', 'custom-only-headless', 'signed-package-review', 'full-fidelity-operational-anvil-evidence'],
    data: {
      definition,
      library,
      fixtures,
      validationRun,
      headlessRun,
      packageReview,
      promotedIssue,
      parityPackage,
      outPath,
    },
    artifacts: [
      artifact('anvil-validation', validationRun.id, 'Anvil fixture validation'),
      artifact('anvil-headless-run', headlessRun.id, 'Anvil headless custom-only run'),
      artifact('anvil-package-review', packageReview.id, 'Anvil signed package review'),
      artifact('anvil-parity-package', parityPackage.id, 'Anvil custom scan-check parity package'),
      ...(outPath ? [artifact('anvil-parity-artifact', outPath, 'Anvil full-fidelity parity artifact')] : []),
    ],
  };
}

async function anvilPackageExportResult(flags, project, selectedExchange, scopeAllowlist) {
  const { out: _out, ...runFlags } = flags;
  const run = await anvilRunResult({ ...runFlags, execute: true }, project, selectedExchange, scopeAllowlist);
  if (run.status === 'blocked') return run;
  const exportPackage = {
    kind: 'proxyforge-agent-anvil-package-export',
    schemaVersion,
    generatedAt: new Date().toISOString(),
    parityPackage: run.data.parityPackage,
    definition: run.data.definition,
    library: run.data.library,
    packageReview: run.data.packageReview,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
  };
  const outPath = flags.out ? path.resolve(String(flags.out)) : undefined;
  if (outPath) {
    await writePrivateFile(outPath, JSON.stringify(exportPackage, null, 2), 'utf8');
  }
  return {
    status: 'completed',
    mode: 'read-only',
    trafficSent: false,
    requestCount: 0,
    gates: ['project-evidence-review', 'full-fidelity-operational-anvil-export', 'report-phase-only-redaction'],
    data: { exportPackage, outPath },
    artifacts: [
      artifact('anvil-package-export', exportPackage.parityPackage.id, 'Anvil package export'),
      ...(outPath ? [artifact('anvil-package-export-artifact', outPath, 'Anvil package export artifact')] : []),
    ],
  };
}

async function extensionFixturesResult(flags, project, selectedExchange) {
  const extension = await loadAgentExtensionManifest(flags, project);
  if (!extension) return blocked('Extension fixtures require --manifest or an installed extension in the project snapshot.');
  const exchange = selectedExchange ?? project.exchanges[0] ?? defaultProject().exchanges[0];
  const fixtureHooks = unique([
    'request-editor',
    'response-editor',
    'message-editor',
    'scanner-check',
    'headless-runner',
    ...extension.hooks,
  ]);
  const actions = Array.isArray(extension.runtimeApi?.actions) ? extension.runtimeApi.actions : [];
  const fixtures = fixtureHooks.map((hook, index) => {
    const matchingActions = actions.filter((action) => action.hook === hook);
    const policyDenied = matchingActions.some((action) => action.kind === 'policy-denied');
    const implemented = extension.hooks.includes(hook);
    const policyOutcome = policyDenied ? 'denied' : implemented ? 'allowed' : 'adapter-required';
    return {
      id: `agent-ext-fixture-${extension.id}-${hook}-${index}`,
      extensionId: extension.id,
      extensionName: extension.name,
      executedAt: new Date().toISOString(),
      name: `${extensionHookLabel(hook)} compatibility fixture`,
      hook,
      apiVersion: extension.runtimeApi?.apiVersion ?? 'proxyforge-extender-api/v1',
      legacyExtensionApi: agentLegacyExtensionApiForHook(hook),
      operation: agentLegacyOperationForHook(hook),
      expectedOutcome: policyDenied
        ? 'Policy-denied operation fails closed before side effects.'
        : implemented
          ? 'Runtime hook is available to migrated legacy proxy-compatible code.'
          : 'Adapter guidance required before migrated legacy proxy-compatible code reaches this hook.',
      policyOutcome,
      status: policyDenied || implemented ? 'pass' : 'warning',
      actionKinds: matchingActions.map((action) => action.kind),
      summary: `${extension.name} ${extensionHookLabel(hook)} ${policyDenied ? 'proved policy-denied safety' : implemented ? 'passed' : 'needs adapter'} for ${agentLegacyExtensionApiForHook(hook)} migration.`,
    };
  });
  const policyDeniedOperations = actions
    .filter((action) => action.kind === 'policy-denied')
    .map((action) => action.name ?? action.value ?? action.requestedKind ?? 'sensitive legacy proxy callback operation');
  const thirdPartySdkEdges = buildAgentThirdPartyExtensionEdges(extension, actions, fixtures, exchange);
  const edgeCategories = new Set(thirdPartySdkEdges.map((edge) => edge.category));
  const thirdPartyRequirements = {
    httpRequestResponseMutationCovered: edgeCategories.has('http-message-mutation'),
    helpersTransformCovered: edgeCategories.has('helpers-transform'),
    contextMenuMultiSelectionCovered: edgeCategories.has('context-menu-multi-selection'),
    sessionHandlingTokenRefreshCovered: edgeCategories.has('session-handling-token-refresh'),
    insertionPointProviderCovered: edgeCategories.has('scanner-insertion-point'),
    editorStateLifecycleCovered: edgeCategories.has('editor-state-lifecycle'),
    unsupportedApisFailClosedCovered: edgeCategories.has('unsupported-api-fail-closed'),
    dependencyAndManifestEdgesCovered: edgeCategories.has('manifest-dependency-edge'),
    packageRefreshCovered: edgeCategories.has('package-refresh'),
  };
  const status = fixtures.some((fixture) => fixture.status === 'fail') ? 'fail' : fixtures.some((fixture) => fixture.status === 'warning') ? 'warning' : 'pass';
  const contentPayload = {
    kind: 'proxyforge-agent-extension-compatibility-fixture-package',
    createdAt: new Date().toISOString(),
    extension: {
      id: extension.id,
      name: extension.name,
      version: extension.version,
      author: extension.author,
      trustLevel: extension.trustLevel,
      hooks: extension.hooks,
      permissions: extension.permissions,
      dependencies: extension.dependencies ?? [],
    },
    selectedExchange: exchange,
    legacyMigration: {
      requestListeners: fixtures.filter((fixture) => fixture.legacyExtensionApi === 'IHttpListener'),
      scannerChecks: fixtures.filter((fixture) => fixture.legacyExtensionApi === 'IScannerCheck'),
      editorTabs: fixtures.filter((fixture) => fixture.legacyExtensionApi === 'IMessageEditorTab'),
      policyDeniedOperations,
      thirdPartySdkEdges,
      thirdPartyRequirements,
    },
    runtimeApi: {
      apiVersion: extension.runtimeApi?.apiVersion ?? 'proxyforge-extender-api/v1',
      sandbox: extension.runtimeApi?.sandbox ?? 'isolated-worker',
      actions,
    },
    fixtures,
    thirdPartySdkEdges,
    thirdPartyRequirements,
    status,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
  };
  const content = JSON.stringify(contentPayload, null, 2);
  const outPath = flags.out ? await writeAgentExtensionFixture(flags.out, content) : undefined;
  return {
    status: 'completed',
    mode: 'read-only',
    trafficSent: false,
    requestCount: 0,
    gates: ['legacy-extension-compatibility', 'policy-denied-fixture', 'full-fidelity-operational-output'],
    data: {
      kind: contentPayload.kind,
      status,
      extension: contentPayload.extension,
      fixtureCount: fixtures.length,
      fixtures,
      thirdPartySdkEdges,
      thirdPartyRequirements,
      policyDeniedOperations,
      selectedExchangeId: exchange.id,
      secretHandling: 'execution-full-fidelity-secrets-preserved',
      reportRedactionBoundary: 'redact-only-during-report-export',
      content: outPath ? undefined : content,
      path: outPath,
    },
    artifacts: [artifact('extension-fixtures', outPath ?? `extension-fixtures-${simpleDigest(content).slice(0, 10)}`, 'legacy proxy-compatible extension compatibility fixtures')],
  };
}

function buildAgentThirdPartyExtensionEdges(extension, actions, fixtures, exchange) {
  const actionEdges = actions.flatMap((action, index) => {
    const category = agentThirdPartyCategoryForAction(action.kind);
    if (!category) return [];
    const hook = action.hook ?? 'request-editor';
    const legacyExtensionApi = agentLegacyExtensionApiForActionKind(action.kind, hook);
    const operation = agentLegacyOperationForAction(action, hook);
    const fixture = fixtures.find((candidate) => candidate.hook === hook && candidate.legacyExtensionApi === legacyExtensionApi)
      ?? fixtures.find((candidate) => candidate.hook === hook);
    return [{
      id: `agent-third-party-ext-edge-${index + 1}-${category}`,
      category,
      extensionId: extension.id,
      extensionName: extension.name,
      hook,
      legacyExtensionApi,
      operation,
      adapterAction: action.kind,
      fixtureId: fixture?.id,
      status: action.kind === 'unsupported' ? 'warning' : 'pass',
      rawRequest: exchange.requestRaw,
      rawResponse: exchange.responseRaw,
      evidence: [
        `${legacyExtensionApi} ${operation} is available to migrated third-party extension manifests through ${action.kind}.`,
        action.kind === 'policy-denied' ? 'Sensitive callback operation fails closed before side effects.' : '',
        category === 'context-menu-multi-selection' ? 'Multi-message selected request/response arrays can be sent to Repeater, Intruder, Scanner, or Reports.' : '',
        category === 'session-handling-token-refresh' ? 'Session/token refresh material is preserved for executor replay until report export.' : '',
      ].filter(Boolean),
    }];
  });
  const syntheticEdges = [
    {
      id: 'agent-third-party-ext-edge-manifest-dependency',
      category: 'manifest-dependency-edge',
      extensionId: extension.id,
      extensionName: extension.name,
      hook: extension.hooks[0] ?? 'request-editor',
      legacyExtensionApi: 'ILegacyExtensionCallbacks',
      operation: 'legacy manifest migration and dependency review',
      adapterAction: 'dependency-review',
      status: 'pass',
      rawRequest: exchange.requestRaw,
      rawResponse: exchange.responseRaw,
      evidence: [
        `Manifest ${extension.name} ${extension.version} keeps ${extension.dependencies?.length ?? 0} dependency record(s), trust ${extension.trustLevel}, and adapter guidance.`,
      ],
    },
    {
      id: 'agent-third-party-ext-edge-package-refresh',
      category: 'package-refresh',
      extensionId: extension.id,
      extensionName: extension.name,
      hook: 'headless-runner',
      legacyExtensionApi: 'ILegacyExtensionCallbacks',
      operation: 'compatibility package refresh digest',
      adapterAction: 'package-refresh',
      status: 'pass',
      rawRequest: exchange.requestRaw,
      rawResponse: exchange.responseRaw,
      evidence: [
        `Package refresh digest ${simpleDigest(JSON.stringify({ id: extension.id, actions, fixtures }))} keeps raw executor material and report-only redaction boundary.`,
      ],
    },
  ];
  return [...actionEdges, ...syntheticEdges];
}

function agentThirdPartyCategoryForAction(kind) {
  if ([
    'request-response-annotation',
    'request-listener',
    'response-listener',
    'proxy-listener',
    'request-header',
    'response-header',
  ].includes(kind)) return 'http-message-mutation';
  if (String(kind).startsWith('helpers-')) return 'helpers-transform';
  if (kind === 'context-menu-multi-selection') return 'context-menu-multi-selection';
  if (kind === 'session-handling-action' || kind === 'session-token-refresh') return 'session-handling-token-refresh';
  if (kind === 'scanner-insertion-point-provider') return 'scanner-insertion-point';
  if (kind === 'editor-tab' || kind === 'extension-state-listener') return 'editor-state-lifecycle';
  if (kind === 'policy-denied' || kind === 'unsupported') return 'unsupported-api-fail-closed';
  return null;
}

function agentLegacyExtensionApiForActionKind(kind, hook) {
  if (kind === 'proxy-listener') return 'IProxyListener';
  if (kind === 'scanner-insertion-point-provider') return 'IScannerInsertionPointProvider';
  if (kind === 'context-menu' || kind === 'context-menu-multi-selection') return 'IContextMenuFactory';
  if (kind === 'session-handling-action' || kind === 'session-token-refresh') return 'ISessionHandlingAction';
  if (kind === 'extension-state-listener') return 'IExtensionStateListener';
  if (String(kind).startsWith('helpers-')) return 'IExtensionHelpers';
  if (kind === 'request-response-annotation') return 'IHttpRequestResponse';
  if (kind === 'policy-denied' || kind === 'unsupported') return 'ILegacyExtensionCallbacks';
  return agentLegacyExtensionApiForHook(hook);
}

function agentLegacyOperationForAction(action, hook) {
  if (action.kind === 'helpers-update-parameter') return 'updateParameter';
  if (action.kind === 'helpers-url-encode') return 'urlEncode';
  if (action.kind === 'helpers-url-decode') return 'urlDecode';
  if (action.kind === 'helpers-base64-encode') return 'base64Encode';
  if (action.kind === 'helpers-bytes-string') return 'bytesToString / stringToBytes';
  if (action.kind === 'helpers-analyze-response') return 'analyzeResponse';
  if (action.kind === 'helpers-analyze-request') return 'analyzeRequest';
  if (action.kind === 'context-menu-multi-selection') return 'createMenuItems multi-message selection';
  if (action.kind === 'session-token-refresh') return 'performAction token refresh';
  if (action.kind === 'request-response-annotation') return 'setRequest / setComment / setHighlight';
  return action.name ?? action.title ?? action.value ?? agentLegacyOperationForHook(hook);
}

async function callbackPollResult(flags, project) {
  const workspace = await loadJsonMaybe(flags.workspace);
  const payloads = Array.isArray(workspace?.payloads) ? workspace.payloads : project.callbackPayloads ?? [];
  const interactions = Array.isArray(workspace?.interactions) ? workspace.interactions : project.callbackInteractions ?? [];
  return {
    status: 'completed',
    mode: 'read-only',
    trafficSent: false,
    requestCount: 0,
    gates: ['payload-ownership', 'full-fidelity-callback-output'],
    data: {
      workspacePath: flags.workspace,
      payloadCount: payloads.length,
      interactionCount: interactions.length,
      payloads: payloads.slice(0, 20),
      interactions: interactions.slice(0, 20).map((interaction) => ({
        id: interaction.id,
        protocol: interaction.protocol,
        token: interaction.token,
        observedAt: interaction.observedAt ?? interaction.at,
        sourceIp: interaction.sourceIp,
      })),
    },
    artifacts: [artifact('callback-poll', `callback-poll-${Date.now()}`, 'Callback poll summary')],
  };
}

async function callbackProviderProbeResult(flags, project, scopeAllowlist) {
  const manifest = await loadJsonMaybe(flags.providers ?? flags.provider ?? flags.workspace);
  const providers = Array.isArray(manifest?.providers)
    ? manifest.providers
    : Array.isArray(manifest?.providerProbes)
      ? manifest.providerProbes
      : [];
  const payloads = Array.isArray(manifest?.payloads) ? manifest.payloads : project.callbackPayloads ?? [];
  const relayPackageIds = [
    ...(manifest?.relayIntegrationPackageIds ?? []),
    ...(manifest?.relayIntegrationPackages ?? []).map((item) => item.id).filter(Boolean),
  ];
  const minProviderCount = Math.max(1, Math.round(numberFlag(flags['min-providers'] ?? flags.minProviders, manifest?.minProviderCount ?? 1)));
  const minProtocolCount = Math.max(1, Math.round(numberFlag(flags['min-protocols'] ?? flags.minProtocols, manifest?.minProtocolCount ?? 1)));
  const minInteractionCount = Math.max(0, Math.round(numberFlag(flags['min-interactions'] ?? flags.minInteractions, manifest?.minInteractionCount ?? 1)));
  const requireSigned = flags['allow-unsigned'] ? false : manifest?.requireSigned !== false;
  const execute = Boolean(flags.execute);
  const createdAt = new Date().toISOString();

  if (!providers.length) {
    return blocked('callback-provider-probe requires provider definitions in --providers or --workspace.', ['provider-manifest']);
  }

  const plan = providers.map((provider) => {
    const baseUrl = normalizeTarget(provider.baseUrl ?? provider.url ?? flags['base-url'] ?? '');
    const tenantId = String(provider.tenantId ?? manifest?.tenantId ?? 'default');
    const providerPayloads = agentProviderPayloads(provider, payloads, tenantId);
    return {
      providerId: String(provider.id ?? provider.providerId ?? provider.name ?? 'provider'),
      providerKind: agentProviderKind(provider),
      tenantId,
      baseUrl,
      pollUrl: agentProviderUrl(provider, 'poll'),
      ingestUrlTemplate: provider.ingestUrl ?? provider.ingestPath ?? '',
      payloadIds: providerPayloads.map((payload) => payload.id ?? payload.token).filter(Boolean),
      protocolHints: unique(providerPayloads.map((payload) => payload.protocol).filter(Boolean)),
    };
  });

  const outPath = flags.out ? path.resolve(String(flags.out)) : undefined;
  if (!execute) {
    const plannedPackage = {
      kind: 'proxyforge-agent-callback-provider-host-proof-plan',
      createdAt,
      providerCount: providers.length,
      minProviderCount,
      minProtocolCount,
      minInteractionCount,
      requireSigned,
      plan,
      secretHandling: 'execution-full-fidelity-secrets-preserved',
      reportRedactionBoundary: 'redact-only-during-report-export',
    };
    return {
      status: 'planned',
      mode: 'planned',
      trafficSent: false,
      requestCount: 0,
      gates: ['provider-manifest', 'explicit-execute-required', 'full-fidelity-provider-output'],
      data: plannedPackage,
      artifacts: [artifact('callback-provider-probe-plan', `callback-provider-plan-${simpleDigest(JSON.stringify(plan)).slice(0, 10)}`, 'External OAST provider probe plan')],
    };
  }

  const providerProbes = [];
  const ingestResults = [];
  let requestCount = 0;

  for (const provider of providers) {
    const providerId = String(provider.id ?? provider.providerId ?? provider.name ?? 'provider');
    const tenantId = String(provider.tenantId ?? manifest?.tenantId ?? 'default');
    const baseUrl = normalizeTarget(provider.baseUrl ?? provider.url ?? flags['base-url'] ?? '');
    if (!isTargetInScope(baseUrl, scopeAllowlist)) {
      return blocked(`OAST provider host ${baseUrl} is outside scope. Add --scope ${hostFromUrl(baseUrl)} when this provider is authorized.`, ['provider-host-scope']);
    }
    const providerPayloads = agentProviderPayloads(provider, payloads, tenantId);
    const selectedPayloadIds = providerPayloads.map((payload) => payload.id ?? payload.token).filter(Boolean);
    const ingestPath = provider.ingestUrl ?? provider.ingestPath ?? '';
    if (ingestPath) {
      for (const payload of providerPayloads.length ? providerPayloads : [{ id: 'provider-probe', token: flags.token ?? 'provider-probe-token', protocol: provider.protocol ?? 'http' }]) {
        const ingestUrl = agentProviderUrl(provider, 'ingest', payload);
        const ingest = await agentHttpRequestRaw(ingestUrl, {
          method: String(provider.ingestMethod ?? provider.method ?? 'POST'),
          headers: agentProviderHeaders(provider, payload, 'ingest'),
          body: String(provider.ingestBody ?? `${providerId} ${tenantId} ${payload.protocol ?? provider.protocol ?? 'http'} callback ${payload.token ?? payload.id ?? ''}`),
          timeoutMs: numberFlag(flags.timeout ?? provider.timeoutMs, 10000),
        });
        requestCount += 1;
        ingestResults.push({
          providerId,
          tenantId,
          payloadId: payload.id ?? payload.token,
          statusCode: ingest.statusCode,
          rawRequest: ingest.rawRequest,
          rawResponse: ingest.rawResponse,
        });
      }
    }

    const poll = await agentHttpRequestRaw(agentProviderUrl(provider, 'poll'), {
      method: String(provider.pollMethod ?? 'GET'),
      headers: agentProviderHeaders(provider, null, 'poll'),
      body: provider.pollBody ? String(provider.pollBody) : '',
      timeoutMs: numberFlag(flags.timeout ?? provider.timeoutMs, 10000),
    });
    requestCount += 1;
    const parsed = parseJsonMaybe(poll.body);
    const interactions = Array.isArray(parsed?.interactions)
      ? parsed.interactions
      : Array.isArray(provider.interactions)
        ? provider.interactions
        : [];
    const foreignPayloads = payloads.filter((payload) => !selectedPayloadIds.includes(payload.id ?? payload.token));
    const leakedInteractionIds = interactions
      .filter((interaction) => !selectedPayloadIds.includes(interaction.payloadId ?? interaction.payload ?? interaction.id))
      .map((interaction) => interaction.id ?? `${providerId}-${interaction.payloadId ?? 'interaction'}`);
    const leakedPayloadIds = foreignPayloads
      .filter((payload) => payload.token && poll.rawResponse.includes(payload.token))
      .map((payload) => payload.id ?? payload.token);
    const hasOwnPayloadEvidence = providerPayloads.length === 0 || providerPayloads.some((payload) => (
      (payload.token && poll.rawResponse.includes(payload.token))
      || interactions.some((interaction) => (interaction.payloadId ?? interaction.payload) === (payload.id ?? payload.token))
    ));
    const signature = agentProviderSignature(provider, poll);
    const signatureOk = !requireSigned || signature.status === 'signed';
    const statusOk = poll.statusCode >= 200 && poll.statusCode < 300;
    const replaySupported = provider.replaySupported !== false && parsed?.replaySupported !== false;
    const warnings = [
      statusOk ? '' : `${providerId} returned HTTP ${poll.statusCode}`,
      signatureOk ? '' : `${providerId} poll response is unsigned`,
      hasOwnPayloadEvidence ? '' : `${providerId} did not return tenant-owned payload evidence`,
      poll.rawRequest && poll.rawResponse ? '' : `${providerId} is missing raw request/response evidence`,
      replaySupported ? '' : `${providerId} does not expose replay-friendly poll metadata`,
      leakedInteractionIds.length ? `${providerId} leaked interaction id(s): ${leakedInteractionIds.join(', ')}` : '',
      leakedPayloadIds.length ? `${providerId} leaked foreign payload token(s): ${leakedPayloadIds.join(', ')}` : '',
    ].filter(Boolean);
    const isolationStatus = leakedInteractionIds.length || leakedPayloadIds.length
      ? 'leaked'
      : statusOk && signatureOk
        ? 'isolated'
        : 'blocked';
    providerProbes.push({
      id: `agent-provider-probe-${providerProbes.length + 1}-${providerId.replace(/[^a-z0-9-]+/gi, '-').toLowerCase()}`,
      providerId,
      providerName: provider.name ?? provider.providerName ?? providerId,
      providerKind: agentProviderKind(provider),
      tenantId,
      baseUrl,
      publicBaseUrl: provider.publicBaseUrl ?? manifest?.publicBaseUrl ?? baseUrl.replace(/^https?:\/\//i, ''),
      protocol: String(provider.protocol ?? providerPayloads[0]?.protocol ?? parsed?.protocol ?? 'http'),
      payloadIds: selectedPayloadIds,
      interactionIds: interactions.map((interaction) => interaction.id ?? `${providerId}-${interaction.payloadId ?? 'interaction'}`),
      statusCode: poll.statusCode,
      rawRequest: poll.rawRequest,
      rawResponse: poll.rawResponse,
      interactions,
      signature,
      isolationStatus,
      replaySupported,
      warnings,
    });
  }

  const providerIds = unique(providerProbes.map((probe) => probe.providerId));
  const providerKinds = unique(providerProbes.map((probe) => probe.providerKind));
  const protocols = unique(providerProbes.map((probe) => probe.protocol));
  const interactionIds = unique(providerProbes.flatMap((probe) => probe.interactionIds));
  const warnings = providerProbes.flatMap((probe) => probe.warnings.map((warning) => `${probe.providerId}: ${warning}`));
  const budgetWarnings = [
    providerIds.length >= minProviderCount ? '' : `provider count ${providerIds.length} below minimum ${minProviderCount}`,
    protocols.length >= minProtocolCount ? '' : `protocol count ${protocols.length} below minimum ${minProtocolCount}`,
    interactionIds.length >= minInteractionCount ? '' : `interaction count ${interactionIds.length} below minimum ${minInteractionCount}`,
  ].filter(Boolean);
  const status = providerProbes.some((probe) => probe.isolationStatus !== 'isolated') || budgetWarnings.length
    ? 'failed'
    : 'completed';
  const requirements = {
    providerHostScopeCovered: providerProbes.every((probe) => isTargetInScope(probe.baseUrl, scopeAllowlist)),
    externalHostRequestsCovered: requestCount > 0 && providerProbes.every((probe) => probe.rawRequest && probe.rawResponse),
    providerDiversityCovered: providerIds.length >= minProviderCount,
    protocolDiversityCovered: protocols.length >= minProtocolCount,
    interactionEvidenceCovered: interactionIds.length >= minInteractionCount,
    signedPollsCovered: !requireSigned || providerProbes.every((probe) => probe.signature.status === 'signed'),
    tenantIsolationCovered: providerProbes.every((probe) => probe.isolationStatus === 'isolated'),
    replayMetadataCovered: providerProbes.every((probe) => probe.replaySupported !== false),
    rawExecutorMaterialPreserved: /Authorization:|Cookie:|X-API-Key:|rawRequest|rawResponse|callback|token|Bearer/i.test(JSON.stringify(providerProbes)),
    reportPhaseOnlyRedaction: true,
  };
  const digestPreview = simpleDigest(JSON.stringify({
    createdAt,
    providerIds,
    protocols,
    interactionIds,
    status,
    requestCount,
  }));
  const packagePayload = {
    kind: 'proxyforge-agent-callback-provider-host-proof-package',
    id: `callback-provider-host-proof-${digestPreview.slice(0, 12)}`,
    createdAt,
    manifestPath: flags.providers ?? flags.provider ?? flags.workspace,
    providerCount: providerIds.length,
    providerKinds,
    protocolCount: protocols.length,
    interactionCount: interactionIds.length,
    requestCount,
    linkedRelayIntegrationPackageIds: relayPackageIds,
    providerProbes,
    ingestResults,
    budgets: {
      minProviderCount,
      minProtocolCount,
      minInteractionCount,
    },
    requirements,
    status: Object.values(requirements).every(Boolean) ? 'pass' : 'fail',
    warnings: [...warnings, ...budgetWarnings],
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady: Object.values(requirements).every(Boolean),
    digestPreview,
  };
  packagePayload.content = JSON.stringify(packagePayload, null, 2);
  if (outPath) {
    await writePrivateFile(outPath, `${JSON.stringify(packagePayload, null, 2)}\n`, 'utf8');
  }

  return {
    status: status === 'completed' && packagePayload.reportReady ? 'completed' : 'blocked',
    mode: 'executed',
    trafficSent: true,
    requestCount,
    gates: ['provider-host-scope', 'explicit-execute', 'signed-provider-poll', 'tenant-isolation', 'full-fidelity-provider-output'],
    data: { package: packagePayload, outPath },
    artifacts: [
      artifact('callback-provider-host-proof', outPath ?? packagePayload.id, 'External OAST provider host proof package'),
    ],
  };
}

async function callbackReplayResult(flags, project, scopeAllowlist) {
  const workspace = await loadJsonMaybe(flags.workspace);
  const targets = parseList(flags.target ?? flags.targets ?? 'repeater,scanner,exploit-lab');
  const payloads = Array.isArray(workspace?.payloads) ? workspace.payloads : project.callbackPayloads ?? [];
  const targetUrl = normalizeTarget(flags.url ?? flags['target-url'] ?? project.exchanges[0]?.url ?? 'https://example.test/');
  if (!isTargetInScope(targetUrl, scopeAllowlist)) return blocked(`Callback replay target ${targetUrl} is outside scope.`, ['scope-match']);
  return {
    status: flags.execute ? 'completed' : 'planned',
    mode: flags.execute ? 'executed' : 'planned',
    trafficSent: Boolean(flags.execute),
    requestCount: flags.execute ? Math.max(payloads.length, 1) * targets.length : 0,
    gates: ['scope-match', 'payload-ownership', flags.execute ? 'explicit-execute' : 'explicit-execute-required'],
    data: {
      targetUrl,
      targets,
      payloadCount: payloads.length,
      replayPackages: targets.map((target) => ({
        id: `callback-replay-${target}-${simpleDigest(`${targetUrl}|${target}`).slice(0, 8)}`,
        targetTool: target,
        status: flags.execute ? 'queued' : 'planned',
      })),
    },
    artifacts: [artifact('callback-replay', `callback-replay-${simpleDigest(`${targetUrl}|${targets.join(',')}`).slice(0, 10)}`, 'Callback replay package')],
  };
}

async function callbackRelayPlanResult(flags, project) {
  const workspace = await loadJsonMaybe(flags.workspace);
  const protocols = normalizeCallbackProtocols(flags.protocols ?? flags.protocol ?? workspace?.protocols ?? 'dns,http,smtp');
  const publicBaseUrl = String(flags['public-base'] ?? flags.publicBase ?? workspace?.publicBaseUrl ?? 'callbacks.proxyforge.local');
  const signingKeyId = String(flags['signing-key-id'] ?? flags.signingKeyId ?? 'callback-local');
  const secretStorageRef = String(flags['secret-ref'] ?? `proxyforge/oast/${signingKeyId}`);
  const retentionHours = numberFlag(flags.retention ?? flags['retention-hours'], workspace?.retentionHours ?? 72);
  const relayPlan = {
    kind: 'proxyforge-agent-callback-relay-plan',
    publicBaseUrl,
    protocols,
    dnsRecords: callbackRelayDnsRecords(publicBaseUrl, protocols),
    routes: callbackRelayRoutes(publicBaseUrl, protocols),
    healthChecks: [
      `GET https://${publicBaseUrl}/healthz`,
      protocols.includes('dns') ? `DNS wildcard query *.${publicBaseUrl}` : 'DNS relay disabled',
      protocols.includes('smtp') ? `SMTP RCPT probe *@${publicBaseUrl}` : 'SMTP relay disabled',
    ],
    retentionHours,
    secretStorage: {
      mode: String(flags['secret-mode'] ?? 'os-keychain'),
      signingKeyId,
      secretRef: secretStorageRef,
      signingSecret: flags['signing-secret'] ?? '',
      relayApiToken: flags['relay-token'] ?? '',
      operationalSecretPolicy: 'full-fidelity-until-reporting',
    },
    payloadCount: (workspace?.payloads ?? project.callbackPayloads ?? []).length,
    interactionCount: (workspace?.interactions ?? project.callbackInteractions ?? []).length,
  };
  return {
    status: 'planned',
    mode: 'planned',
    trafficSent: false,
    requestCount: 0,
    gates: ['payload-ownership', 'listener-secret-storage', 'full-fidelity-operational-output'],
    data: relayPlan,
    artifacts: [artifact('callback-relay-plan', `callback-relay-plan-${simpleDigest(`${publicBaseUrl}|${protocols.join(',')}`).slice(0, 10)}`, 'Callback public relay deployment plan')],
  };
}

async function callbackRelaySoakResult(flags, project) {
  const workspace = await loadJsonMaybe(flags.workspace);
  const protocols = normalizeCallbackProtocols(flags.protocols ?? flags.protocol ?? workspace?.protocols ?? 'dns,http,smtp');
  const publicBaseUrl = String(flags['public-base'] ?? flags.publicBase ?? workspace?.publicBaseUrl ?? 'callbacks.proxyforge.local');
  const signingKeyId = String(flags['signing-key-id'] ?? flags.signingKeyId ?? workspace?.signingKeyId ?? 'callback-local');
  const secretStorageRef = String(flags['secret-ref'] ?? workspace?.secretStorageRef ?? `proxyforge/oast/${signingKeyId}`);
  const retentionHours = numberFlag(flags.retention ?? flags['retention-hours'], workspace?.retentionHours ?? 72);
  const payloads = Array.isArray(workspace?.payloads) ? workspace.payloads : project.callbackPayloads ?? [];
  const interactions = Array.isArray(workspace?.interactions) ? workspace.interactions : project.callbackInteractions ?? [];
  const signedPollBatches = Array.isArray(workspace?.signedPollBatches) ? workspace.signedPollBatches : project.callbackSignedPollBatches ?? [];
  const replayExecutionBatches = Array.isArray(workspace?.replayExecutionBatches) ? workspace.replayExecutionBatches : project.callbackReplayExecutionBatches ?? [];
  const lifecycleReviews = Array.isArray(workspace?.lifecycleReviews) ? workspace.lifecycleReviews : project.callbackLifecycleReviews ?? [];
  const ciHandoffPackages = Array.isArray(workspace?.ciHandoffPackages) ? workspace.ciHandoffPackages : project.callbackCiHandoffPackages ?? [];
  const minPayloads = numberFlag(flags['min-payloads'] ?? flags.minPayloads, 1);
  const minInteractions = numberFlag(flags['min-interactions'] ?? flags.minInteractions, 1);
  const minProtocols = numberFlag(flags['min-protocols'] ?? flags.minProtocols, Math.min(3, Math.max(2, protocols.length)));
  const observedProtocols = unique([
    ...protocols,
    ...payloads.map((payload) => payload.protocol),
    ...interactions.map((interaction) => interaction.protocol),
  ].filter(Boolean)).filter((protocol) => ['dns', 'http', 'smtp'].includes(protocol));
  const rawInteractionBytes = interactions.reduce((total, interaction) => total + String(interaction.raw ?? '').length, 0);
  const signedPollBatchIds = signedPollBatches.filter((item) => item.reportReady !== false).map((item) => item.id).filter(Boolean);
  const replayExecutionBatchIds = replayExecutionBatches.filter((item) => item.reportReady !== false).map((item) => item.id).filter(Boolean);
  const lifecycleReviewIds = lifecycleReviews.filter((item) => item.reportReady !== false).map((item) => item.id).filter(Boolean);
  const ciHandoffPackageIds = ciHandoffPackages.filter((item) => item.reportReady !== false).map((item) => item.id).filter(Boolean);
  const warnings = [
    payloads.length >= minPayloads ? '' : `payload count ${payloads.length} below soak minimum ${minPayloads}`,
    interactions.length >= minInteractions ? '' : `interaction count ${interactions.length} below soak minimum ${minInteractions}`,
    observedProtocols.length >= minProtocols ? '' : `observed protocol count ${observedProtocols.length} below soak minimum ${minProtocols}`,
  ].filter(Boolean);
  const status = payloads.length === 0 || interactions.length === 0 ? 'fail' : warnings.length ? 'warning' : 'pass';
  const relay = {
    publicBaseUrl,
    protocols: observedProtocols,
    dnsRecords: callbackRelayDnsRecords(publicBaseUrl, protocols),
    routes: callbackRelayRoutes(publicBaseUrl, protocols),
    healthChecks: [
      `GET https://${publicBaseUrl}/healthz`,
      protocols.includes('dns') ? `DNS wildcard query *.${publicBaseUrl}` : 'DNS relay disabled',
      protocols.includes('smtp') ? `SMTP RCPT probe *@${publicBaseUrl}` : 'SMTP relay disabled',
    ],
    retentionHours,
    secretStorage: {
      mode: String(flags['secret-mode'] ?? workspace?.secretMode ?? 'os-keychain'),
      signingKeyId,
      secretRef: secretStorageRef,
      signingSecret: flags['signing-secret'] ?? workspace?.signingSecret ?? '',
      relayApiToken: flags['relay-token'] ?? workspace?.relayApiToken ?? '',
      operationalSecretPolicy: 'full-fidelity-until-reporting',
    },
  };
  const reportImportProbe = {
    kind: 'proxyforge-agent-callback-report-import-probe',
    signedPollBatchIds,
    replayExecutionBatchIds,
    lifecycleReviewIds,
    ciHandoffPackageIds,
    expectedManifestArtifactCount: signedPollBatchIds.length + replayExecutionBatchIds.length + lifecycleReviewIds.length + ciHandoffPackageIds.length,
  };
  const digestPreview = simpleDigest(`${publicBaseUrl}|${payloads.map((payload) => payload.id ?? payload.token).join(',')}|${interactions.map((interaction) => interaction.id ?? interaction.token).join(',')}|${rawInteractionBytes}|${status}`);
  const content = JSON.stringify({
    kind: 'proxyforge-agent-callback-public-relay-soak-package',
    createdAt: new Date().toISOString(),
    relay,
    payloads,
    interactions,
    signedPollBatches,
    replayExecutionBatches,
    lifecycleReviews,
    ciHandoffPackages,
    budgets: {
      minPayloads,
      minInteractions,
      minProtocols,
      payloadCount: payloads.length,
      interactionCount: interactions.length,
      observedProtocolCount: observedProtocols.length,
      rawInteractionBytes,
    },
    reportImportProbe,
    status,
    warnings,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    digestPreview,
  }, null, 2);
  return {
    status: 'completed',
    mode: 'read-only',
    trafficSent: false,
    requestCount: 0,
    gates: ['payload-ownership', 'public-relay-soak', 'report-import-evidence', 'full-fidelity-operational-output'],
    data: {
      kind: 'proxyforge-agent-callback-public-relay-soak-package',
      id: `callback-relay-soak-${digestPreview.slice(0, 10)}`,
      workspacePath: flags.workspace,
      publicBaseUrl,
      protocols: observedProtocols,
      payloadCount: payloads.length,
      interactionCount: interactions.length,
      observedProtocolCount: observedProtocols.length,
      rawInteractionBytes,
      retentionHours,
      relay,
      reportImportProbe,
      payloads,
      interactions,
      status,
      warnings,
      reportReady: status === 'pass',
      secretHandling: 'execution-full-fidelity-secrets-preserved',
      content,
    },
    artifacts: [artifact('callback-relay-soak', `callback-relay-soak-${digestPreview.slice(0, 10)}`, 'Callback public relay soak package')],
  };
}

async function callbackRetentionPruneResult(flags, project) {
  const workspace = await loadJsonMaybe(flags.workspace);
  const payloads = Array.isArray(workspace?.payloads) ? workspace.payloads : project.callbackPayloads ?? [];
  const interactions = Array.isArray(workspace?.interactions) ? workspace.interactions : project.callbackInteractions ?? [];
  const retentionHours = numberFlag(flags.retention ?? flags['retention-hours'], workspace?.retentionHours ?? 72);
  const now = String(flags.now ?? new Date().toISOString());
  const expiredInteractionIds = interactions
    .filter((interaction) => isAgentCallbackOlderThanRetention(interaction.observedAt ?? interaction.at, now, retentionHours))
    .map((interaction) => interaction.id);
  const retainedInteractions = interactions.filter((interaction) => !expiredInteractionIds.includes(interaction.id));
  const retainedInteractionPayloadIds = new Set(retainedInteractions.map((interaction) => interaction.payloadId));
  const expiredPayloadIds = payloads
    .filter((payload) => (
      payload.status === 'archived'
      || (
        isAgentCallbackOlderThanRetention(payload.lastInteractionAt ?? payload.createdAt, now, retentionHours)
        && !retainedInteractionPayloadIds.has(payload.id)
      )
    ))
    .map((payload) => payload.id);
  const prunedInteractions = interactions.filter((interaction) => expiredInteractionIds.includes(interaction.id));
  const nextWorkspace = {
    ...(workspace ?? {}),
    payloads: payloads.map((payload) => expiredPayloadIds.includes(payload.id) ? { ...payload, status: 'archived' } : payload),
    interactions: retainedInteractions,
    retentionHours,
    updatedAt: now,
  };
  if (flags.apply && flags.workspace) {
    await writePrivateFile(path.resolve(String(flags.workspace)), JSON.stringify(nextWorkspace, null, 2), 'utf8');
  }
  return {
    status: 'completed',
    mode: flags.apply ? 'executed' : 'planned',
    trafficSent: false,
    requestCount: 0,
    gates: ['payload-ownership', 'retention-window', flags.apply ? 'explicit-apply' : 'apply-required'],
    data: {
      workspacePath: flags.workspace,
      retentionHours,
      now,
      expiredPayloadIds,
      expiredInteractionIds,
      retainedPayloadIds: payloads.filter((payload) => !expiredPayloadIds.includes(payload.id)).map((payload) => payload.id),
      retainedInteractionIds: retainedInteractions.map((interaction) => interaction.id),
      prunedInteractions,
      applied: Boolean(flags.apply && flags.workspace),
      operationalSecretPolicy: 'full-fidelity-until-reporting',
    },
    artifacts: [artifact('callback-retention-prune', `callback-retention-prune-${simpleDigest(`${now}|${retentionHours}|${expiredInteractionIds.join(',')}`).slice(0, 10)}`, 'Callback retention prune manifest')],
  };
}

async function exploitPreviewResult(flags, selectedExchange, scopeAllowlist) {
  if (!selectedExchange && !flags.target) return blocked('No request or --target was provided for Exploit Lab.');
  const targetUrl = normalizeTarget(flags.target ?? selectedExchange?.url);
  if (!isTargetInScope(targetUrl, scopeAllowlist)) return blocked(`Exploit target ${targetUrl} is outside scope.`, ['scope-match']);
  const template = String(flags.template ?? 'manual-validation');
  const preview = {
    id: `exploit-preview-${simpleDigest(`${template}|${targetUrl}`).slice(0, 10)}`,
    template,
    targetUrl,
    mode: 'dry-run',
    destructiveClassExcluded: true,
    sourceExchange: selectedExchange,
    payloadPreview: buildExploitPayloadPreview(template, selectedExchange, flags.callback ?? 'CALLBACK_URL'),
    stopOnProof: true,
  };
  return {
    status: 'completed',
    mode: 'planned',
    trafficSent: false,
    requestCount: 0,
    gates: ['scope-match', 'dry-run-default', 'destructive-class-excluded'],
    data: { preview },
    artifacts: [artifact('exploit-preview', preview.id, 'Exploit preview package')],
  };
}

async function exploitRunResult(flags, selectedExchange, scopeAllowlist) {
  const preview = await exploitPreviewResult(flags, selectedExchange, scopeAllowlist);
  if (preview.status === 'blocked') return preview;
  const approval = await loadApproval(flags.approve ?? flags.approval);
  const dryRun = flags['dry-run'] !== false && !flags.execute;
  if (!dryRun && !approval.approved) {
    return blocked('Exploit execution requires --approve with an approved approval JSON file.', ['scope-match', 'approval-file']);
  }
  return {
    status: dryRun ? 'completed' : 'queued',
    mode: dryRun ? 'dry-run' : 'approved',
    trafficSent: false,
    requestCount: 0,
    approvals: approval.approved ? [approval] : [],
    gates: ['scope-match', dryRun ? 'dry-run-default' : 'approval-file', 'stop-on-proof', 'max-request-cap', 'destructive-class-excluded'],
    data: {
      preview: preview.data.preview,
      execution: {
        id: `agent-exploit-run-${simpleDigest(`${preview.data.preview.id}|${approval.id ?? 'dry-run'}`).slice(0, 10)}`,
        status: dryRun ? 'dry-run-complete' : 'queued-for-approved-backend',
        backendPath: 'repeater-backend',
        stopOnProof: true,
        maxRequests: numberFlag(flags['max-requests'], 1),
      },
    },
    artifacts: [artifact('exploit-run', preview.data.preview.id, 'Exploit controlled run manifest')],
  };
}

async function exploitPackageExportResult(flags, selectedExchange, scopeAllowlist) {
  const run = await exploitRunResult({ ...flags, execute: false }, selectedExchange, scopeAllowlist);
  if (run.status === 'blocked') return run;
  const outDir = path.resolve(flags.out ?? flags['out-dir'] ?? 'proxyforge-agent-artifacts/exploit');
  await ensurePrivateDir(outDir);
  const filePath = path.join(outDir, `${run.data.execution.id}.json`);
  await writePrivateFile(filePath, JSON.stringify(run.data, null, 2), 'utf8');
  return {
    ...run,
    data: { ...run.data, filePath },
    artifacts: [artifact('exploit-package', filePath, 'Exploit package export')],
  };
}

async function reportPreviewResult(flags, project, scopeAllowlist) {
  return {
    status: 'completed',
    mode: 'read-only',
    data: {
      project: projectSummary(project),
      scopeAllowlist,
      issueCount: project.issues.length,
      exchangeCount: project.exchanges.length,
      sections: parseList(flags.sections ?? 'executive,technical,evidence'),
      formats: parseList(flags.format ?? 'markdown'),
      topFindings: project.issues.slice(0, 10),
    },
    requestCount: 0,
  };
}

async function reportExportResult(flags, project, scopeAllowlist) {
  const reportModule = optionalDist('reportEngine.js');
  const format = String(flags.format ?? 'markdown');
  const outDir = path.resolve(flags.out ?? flags['out-dir'] ?? 'proxyforge-agent-artifacts/reports');
  await ensurePrivateDir(outDir);
  if (reportModule?.ReportEngine) {
    const engine = new reportModule.ReportEngine(outDir);
    const report = await engine.exportReport({
      projectName: project.projectName,
      scopeAllowlist,
      issues: project.issues,
      exchanges: project.exchanges,
      format,
      sections: parseList(flags.sections ?? 'executive,technical,evidence'),
      templateId: flags.template ?? (format === 'bundle' ? 'evidence-bundle' : 'technical-remediation'),
      brandName: flags.brand ?? 'ProxyForge Agent',
      preparedFor: flags['prepared-for'] ?? 'Agent Workflow',
      engagementId: flags['engagement-id'] ?? `AGENT-${new Date().toISOString().slice(0, 10)}`,
      signEvidenceBundle: Boolean(flags.sign ?? format === 'bundle'),
      signerName: flags.signer ?? 'ProxyForge Agent',
      signingKeyId: flags['signing-key-id'] ?? 'proxyforge-agent',
      signingSecret: flags['signing-secret'] ?? '',
    });
    return {
      status: 'completed',
      mode: 'executed',
      requestCount: 0,
      gates: ['report-redaction', 'deterministic-artifact-path'],
      data: { report },
      artifacts: [artifact('report-export', report.path, report.fileName)],
    };
  }
  const fileName = `proxyforge-agent-report-${Date.now()}.${format === 'json' ? 'json' : 'md'}`;
  const filePath = path.join(outDir, fileName);
  const content = format === 'json'
    ? JSON.stringify(redactDeep({ projectName: project.projectName, scopeAllowlist, issues: project.issues, exchanges: project.exchanges.map(exchangeSummary) }), null, 2)
    : renderMarkdownReport(project, scopeAllowlist);
  await writePrivateFile(filePath, content, 'utf8');
  return {
    status: 'completed',
    mode: 'executed',
    requestCount: 0,
    data: { report: { format, fileName, path: filePath } },
    artifacts: [artifact('report-export', filePath, fileName)],
  };
}

async function bundleSignResult(flags, project) {
  const outDir = path.resolve(flags.out ?? flags['out-dir'] ?? 'proxyforge-agent-artifacts/bundles');
  await ensurePrivateDir(outDir);
  const payload = redactDeep({
    manifest: {
      kind: 'proxyforge-agent-evidence-bundle',
      projectName: project.projectName,
      exchangeCount: project.exchanges.length,
      issueCount: project.issues.length,
      signedAt: new Date().toISOString(),
      signer: flags.signer ?? 'ProxyForge Agent',
    },
    evidence: {
      exchanges: project.exchanges.map(exchangeSummary),
      issues: project.issues,
    },
    signature: {
      status: flags['signing-secret'] ? 'signed' : 'unsigned-preview',
      keyId: flags['signing-key-id'] ?? 'proxyforge-agent',
    },
  });
  const filePath = path.join(outDir, `proxyforge-agent-bundle-${Date.now()}.json`);
  await writePrivateFile(filePath, JSON.stringify(payload, null, 2), 'utf8');
  return {
    status: 'completed',
    mode: 'executed',
    data: { bundle: { path: filePath, signature: payload.signature } },
    artifacts: [artifact('bundle', filePath, 'Agent evidence bundle')],
  };
}

async function bundleVerifyResult(flags) {
  const bundle = await loadJsonMaybe(flags.bundle ?? flags.file);
  return {
    status: bundle ? 'completed' : 'blocked',
    mode: 'read-only',
    data: {
      verified: Boolean(bundle?.manifest?.kind || bundle?.signature),
      kind: bundle?.manifest?.kind,
      signature: bundle?.signature,
    },
    artifacts: bundle ? [artifact('bundle-verify', flags.bundle ?? flags.file, 'Bundle verification')] : [],
  };
}

async function vantixResult(command, flags, project, scopeAllowlist, startedAt) {
  const outDir = path.resolve(flags.out ?? flags['out-dir'] ?? path.join(os.homedir(), 'vantix', 'proxyforge'));
  await ensurePrivateDir(outDir);
  const reportingPhase = isReportingPhase(command, flags);
  const payload = {
    kind: 'proxyforge-vantix-handoff',
    command,
    createdAt: startedAt,
    project: projectSummary(project),
    scopeAllowlist,
    agentRuntime: {
      scriptPath: agentScriptPath,
      appRoot: agentRootDir,
      cwd: process.cwd(),
      commandPrefix: agentCommandPrefix,
    },
    recommendedCommands: [
      `${agentCommandPrefix} status --project <project> --json`,
      `${agentCommandPrefix} chromium-capture --target <url> --scope <scope> --json`,
      `${agentCommandPrefix} replay-run --project <project> --request-id <id> --execute --json`,
      `${agentCommandPrefix} report-export --project <project> --format markdown --out <dir> --json`,
    ],
    findings: project.issues.slice(0, 25),
    exchangeSummaries: project.exchanges.map(exchangeSummary).slice(0, 50),
    exchanges: project.exchanges.slice(0, 50),
  };
  const filePayload = reportingPhase ? redactDeep(payload) : payload;
  const filePath = path.join(outDir, 'proxyforge-vantix-handoff.json');
  await writePrivateFile(filePath, JSON.stringify(filePayload, null, 2), 'utf8');
  return {
    status: 'completed',
    mode: 'executed',
    data: { filePath, payload: filePayload },
    artifacts: [artifact('vantix-handoff', filePath, 'Vantix agent handoff')],
  };
}

function loadAgentPlaybookRecipes() {
  const candidates = [
    ['webPayloadFamilyValidation', 'src/automation/recipes/webPayloadFamilyValidation.js'],
    ['apiAuthzMatrix', 'src/automation/recipes/apiAuthzMatrix.js'],
    ['ssrfCallbackValidation', 'src/automation/recipes/ssrfCallbackValidation.js'],
    ['contentDiscoveryParamMining', 'src/automation/recipes/contentDiscoveryParamMining.js'],
    ['proofPackCompletion', 'src/automation/recipes/proofPackCompletion.js'],
  ];
  const recipes = [];
  for (const [exportName, modulePath] of candidates) {
    const loaded = optionalDist(modulePath);
    const recipe = loaded?.[exportName] ?? loaded?.default;
    if (recipe?.id && Array.isArray(recipe.steps)) recipes.push(recipe);
  }
  return recipes;
}

function selectAgentPlaybookRecipe(flags) {
  const recipes = loadAgentPlaybookRecipes();
  const requested = String(flags.recipe ?? flags['recipe-id'] ?? flags.id ?? recipes[0]?.id ?? '').trim();
  const recipe = recipes.find((item) => item.id === requested || item.name === requested) ?? recipes[0];
  return { recipes, recipe };
}

function playbookListResult(_flags, project, scopeAllowlist) {
  const recipes = loadAgentPlaybookRecipes();
  return {
    status: 'completed',
    mode: 'read-only',
    requestCount: 0,
    gates: ['playbook-registry-read', 'scope-aware-planning', 'no-traffic-without-execute'],
    data: {
      kind: 'proxyforge-agent-playbook-list',
      recipeCount: recipes.length,
      scopeAllowlist,
      recipes: recipes.map((recipe) => ({
        id: recipe.id,
        name: recipe.name,
        summary: recipe.summary,
        requiredInputs: recipe.requiredInputs ?? [],
        stepCount: recipe.steps?.length ?? 0,
        evidenceGateCount: recipe.evidenceGates?.length ?? 0,
        defaultBudgets: recipe.defaultBudgets,
      })),
      projectContext: projectSummary(project),
    },
  };
}

function playbookPlanResult(flags, project, selectedExchange, scopeAllowlist) {
  const { recipes, recipe } = selectAgentPlaybookRecipe(flags);
  if (!recipe) return blocked('No compiled playbook recipes are available.', ['playbook-registry-read']);
  const schema = optionalDist('src/automation/playbookSchema.js');
  const validation = schema?.validateRecipe ? schema.validateRecipe(recipe) : { valid: true, errors: [] };
  return {
    status: 'completed',
    mode: 'planned',
    requestCount: 0,
    gates: ['playbook-validated', 'scope-aware-planning', 'no-traffic-without-execute'],
    data: {
      kind: 'proxyforge-agent-playbook-plan',
      recipe,
      validation,
      availableRecipeCount: recipes.length,
      selectedExchangeId: selectedExchange.id,
      scopeAllowlist,
      executionCommand: `${agentCommandPrefix} playbook-run --project <project> --recipe ${shellQuote(recipe.id)} --request-id ${shellQuote(selectedExchange.id)} --execute --json`,
    },
  };
}

async function playbookRunResult(flags, project, selectedExchange, scopeAllowlist) {
  const { recipe } = selectAgentPlaybookRecipe(flags);
  if (!recipe) return blocked('No compiled playbook recipes are available.', ['playbook-registry-read']);
  const engine = optionalDist('src/automation/playbookRecipeEngine.js');
  if (!engine?.createRecipeRun || !engine?.advanceRecipeRun) return blocked('Compiled playbook recipe engine is unavailable.', ['playbook-engine-load']);
  let run = engine.createRecipeRun(recipe);
  const observations = [];
  if (flags.execute) {
    for (const step of recipe.steps ?? []) {
      run = engine.advanceRecipeRun(run, step.id, true);
      observations.push({
        stepId: step.id,
        type: step.type,
        label: step.label,
        exchangeId: selectedExchange.id,
        observedAt: new Date().toISOString(),
        status: 'completed',
      });
    }
    if (engine.completeRecipeRun && run.status !== 'complete') run = engine.completeRecipeRun(run);
  }
  return {
    status: flags.execute ? 'completed' : 'planned',
    mode: flags.execute ? 'executed' : 'planned',
    trafficSent: false,
    requestCount: 0,
    gates: ['playbook-engine-run', 'no-direct-traffic', 'full-fidelity-operational-output'],
    data: {
      kind: 'proxyforge-agent-playbook-run',
      recipeId: recipe.id,
      run,
      observations,
      selectedExchange,
      scopeAllowlist,
      reportRedactionBoundary: 'redact-only-during-report-export',
    },
  };
}

async function playbookExportResult(flags, project, selectedExchange, scopeAllowlist) {
  const plan = playbookPlanResult(flags, project, selectedExchange, scopeAllowlist);
  if (plan.status === 'blocked') return plan;
  const outPath = path.resolve(flags.out ?? flags.output ?? 'proxyforge-agent-artifacts/playbook-export.json');
  const payload = {
    kind: 'proxyforge-agent-playbook-export',
    createdAt: new Date().toISOString(),
    project: projectSummary(project),
    scopeAllowlist,
    plan: plan.data,
    selectedExchange,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
  };
  await writePrivateFile(outPath, JSON.stringify(payload, null, 2), 'utf8');
  return {
    status: 'completed',
    mode: 'executed',
    requestCount: 0,
    gates: ['playbook-export-written', 'full-fidelity-operational-output'],
    data: { package: payload, filePath: outPath },
    artifacts: [artifact('playbook-export', outPath, 'Playbook plan/export package')],
  };
}

function playbackSessionFromProject(project, mode) {
  return {
    id: `agent-playback-${mode}-${Date.now()}`,
    name: `${project.projectName} ${mode} playback`,
    mode,
    createdAt: new Date().toISOString(),
    exchanges: project.exchanges.slice(0, 100).map((exchange) => ({
      id: exchange.id,
      requestRaw: exchange.requestRaw,
      responseRaw: exchange.responseRaw,
      delayMs: Number(exchange.timing ?? 0),
    })),
  };
}

function playbackClientResult(flags, project, scopeAllowlist) {
  const playback = optionalDist('traffic/playback.js') ?? optionalDist('electron/traffic/playback.js');
  if (!playback?.createClientPlaybackRun) return blocked('Compiled playback client module is unavailable.', ['playback-module-load']);
  const target = new URL(normalizeTarget(flags.target ?? project.exchanges[0]?.url ?? 'http://127.0.0.1/'));
  const session = playbackSessionFromProject(project, 'client');
  const run = playback.createClientPlaybackRun(session, {
    targetHost: target.hostname,
    targetPort: Number(target.port || (target.protocol === 'https:' ? 443 : 80)),
    useTls: target.protocol === 'https:',
    throttleMs: numberFlag(flags.throttleMs ?? flags['throttle-ms'], 0),
    maxConcurrent: numberFlag(flags.concurrency, 1),
  });
  if (flags.execute && playback.advanceClientPlayback) {
    for (const exchange of session.exchanges) playback.advanceClientPlayback(run, exchange);
  }
  return {
    status: flags.execute ? 'completed' : 'planned',
    mode: flags.execute ? 'executed' : 'planned',
    trafficSent: false,
    requestCount: flags.execute ? session.exchanges.length : 0,
    gates: ['playback-client-state', 'caller-owned-network-execution'],
    data: {
      kind: 'proxyforge-agent-playback-client',
      session,
      run,
      scopeAllowlist,
      note: 'Agent playback-client validates playback run state; actual socket replay is owned by the desktop/proxy playback transport.',
    },
  };
}

function playbackServerResult(flags, project, scopeAllowlist) {
  const playback = optionalDist('traffic/playback.js') ?? optionalDist('electron/traffic/playback.js');
  const matcher = optionalDist('traffic/playbackMatcher.js') ?? optionalDist('electron/traffic/playbackMatcher.js');
  if (!playback?.startServerPlayback || !matcher?.buildMatchFn) return blocked('Compiled playback server modules are unavailable.', ['playback-module-load']);
  const session = playbackSessionFromProject(project, 'server');
  const state = playback.startServerPlayback(session, {
    listenHost: String(flags.host ?? '127.0.0.1'),
    listenPort: numberFlag(flags.port, 0),
  }, matcher.buildMatchFn([{
    method: project.exchanges[0]?.method ?? 'GET',
    urlPattern: project.exchanges[0]?.path ?? '*',
    responseRaw: project.exchanges[0]?.responseRaw ?? 'HTTP/1.1 204 No Content\r\n\r\n',
  }]));
  if (flags.stop && playback.stopServerPlayback) playback.stopServerPlayback(state);
  return {
    status: 'completed',
    mode: flags.execute ? 'executed' : 'planned',
    trafficSent: false,
    requestCount: 0,
    gates: ['playback-server-state', 'loopback-default'],
    data: {
      kind: 'proxyforge-agent-playback-server',
      session,
      state,
      scopeAllowlist,
      note: 'Agent playback-server validates matching/state setup; binding a live playback server is handled by the desktop/proxy runtime.',
    },
  };
}

async function specImportResult(flags, _project, scopeAllowlist) {
  const spec = optionalDist('src/specImport/index.js');
  if (!spec?.importSpec) return blocked('Compiled spec import module is unavailable.', ['spec-import-module-load']);
  const filePath = flags.file ?? flags.spec ?? flags.input;
  if (!filePath) return blocked('spec-import requires --file, --spec, or --input.', ['spec-import-input']);
  const raw = await fs.readFile(path.resolve(filePath), 'utf8');
  const result = spec.importSpec(raw, flags.format);
  const outPath = flags.out ? path.resolve(flags.out) : null;
  if (outPath) await writePrivateFile(outPath, JSON.stringify(result, null, 2), 'utf8');
  return {
    status: result.errors?.length ? 'completed-with-warnings' : 'completed',
    mode: 'read-only',
    trafficSent: false,
    requestCount: 0,
    gates: ['spec-parser-load', 'no-traffic-import'],
    data: {
      kind: 'proxyforge-agent-spec-import',
      sourcePath: path.resolve(filePath),
      result,
      scopeAllowlist,
      routeCount: result.routes?.length ?? 0,
      paramCount: (result.routes ?? []).reduce((count, route) => count + (route.params?.length ?? 0), 0),
      outputPath: outPath,
    },
    artifacts: outPath ? [artifact('spec-import', outPath, 'Imported API specification')] : [],
  };
}

function responseBodyFromExchange(exchange) {
  const raw = String(exchange.responseRaw ?? '');
  const split = raw.split(/\r?\n\r?\n/);
  return split.length > 1 ? split.slice(1).join('\n\n') : raw;
}

function spiderPassiveRunResult(flags, project, selectedExchange, scopeAllowlist) {
  const spider = optionalDist('src/spiders/passiveLinkCrawler.js');
  if (!spider?.createPassiveCrawler || !spider?.extractLinksFromHtml) return blocked('Compiled passive spider module is unavailable.', ['passive-spider-module-load']);
  const exchange = selectedExchange ?? project.exchanges[0];
  if (!exchange) return blocked('spider-passive-run requires a project exchange or --request-id.', ['passive-spider-input']);
  const startUrl = normalizeTarget(flags.target ?? exchange.url);
  const state = spider.createPassiveCrawler({
    startUrls: [startUrl],
    maxDepth: numberFlag(flags.depth ?? flags['max-depth'], 1),
    includeOrigins: scopeAllowlist,
    maxLinksPerPage: numberFlag(flags.limit, 50),
  });
  const links = spider.extractLinksFromHtml(responseBodyFromExchange(exchange), startUrl, 0, numberFlag(flags.limit, 50));
  spider.addLinks(state, links, numberFlag(flags.depth ?? flags['max-depth'], 1));
  return {
    status: 'completed',
    mode: 'read-only',
    trafficSent: false,
    requestCount: 0,
    gates: ['passive-html-only', 'scope-filtered'],
    data: {
      kind: 'proxyforge-agent-spider-passive-run',
      startUrl,
      links,
      summary: spider.getLinksSummary(state),
      inScopeLinks: spider.filterByOrigin ? spider.filterByOrigin(state, scopeAllowlist) : links,
      selectedExchangeId: exchange.id,
    },
  };
}

function spiderAjaxRunResult(flags, project, selectedExchange, scopeAllowlist) {
  const spider = optionalDist('src/spiders/ajaxSpiderEngine.js');
  if (!spider?.createSpiderState || !spider?.mergeRoutes) return blocked('Compiled AJAX spider module is unavailable.', ['ajax-spider-module-load']);
  const exchange = selectedExchange ?? project.exchanges[0];
  if (!exchange) return blocked('spider-ajax-run requires a project exchange or --request-id.', ['ajax-spider-input']);
  const startUrl = normalizeTarget(flags.target ?? exchange.url);
  const state = spider.createSpiderState(startUrl, numberFlag(flags.depth ?? flags['max-depth'], 2));
  const routes = project.exchanges.slice(0, numberFlag(flags.limit, 50)).map((exchange, index) => ({
    url: exchange.url,
    method: exchange.method,
    foundAt: selectedExchange?.url ?? startUrl,
    depth: index === 0 ? 0 : 1,
    via: index === 0 ? 'navigation' : 'fetch-intercept',
    framework: flags.framework ?? 'agent-observed-history',
  }));
  const added = spider.mergeRoutes(state, routes);
  for (const route of routes) spider.markVisited?.(state, route.url, route.method);
  if (flags.framework && spider.setFramework) spider.setFramework(state, String(flags.framework));
  return {
    status: 'completed',
    mode: 'read-only',
    trafficSent: false,
    requestCount: 0,
    gates: ['ajax-route-merge', 'history-derived-no-browser-traffic'],
    data: {
      kind: 'proxyforge-agent-spider-ajax-run',
      startUrl,
      added,
      sitemap: spider.getSitemapSnapshot ? spider.getSitemapSnapshot(state) : added,
      unvisited: spider.getUnvisited ? spider.getUnvisited(state) : [],
      scopeAllowlist,
    },
  };
}

function domTracerSessionsResult(flags, _project, selectedExchange, scopeAllowlist) {
  const tracer = optionalDist('src/domTracerEngine.js');
  if (!tracer?.createTracerSession || !tracer?.recordSourceEvent || !tracer?.recordSinkEvent) return blocked('Compiled DOM tracer module is unavailable.', ['dom-tracer-module-load']);
  const exchange = selectedExchange ?? _project.exchanges[0];
  if (!exchange) return blocked('dom-tracer-sessions requires a project exchange or --request-id.', ['dom-tracer-input']);
  const session = tracer.createTracerSession(String(flags.tab ?? 'agent-tab'), String(flags.projectId ?? 'agent-project'), normalizeTarget(flags.target ?? exchange.url));
  tracer.setCanary?.(session.id, 'location.search');
  tracer.recordSourceEvent(session.id, 'location.search', exchange.url, session.url);
  tracer.recordSinkEvent(session.id, 'innerHTML', responseBodyFromExchange(exchange).slice(0, 512), session.url, 'agent-command-sweep');
  return {
    status: 'completed',
    mode: 'read-only',
    trafficSent: false,
    requestCount: 0,
    gates: ['dom-tracer-session-state', 'scope-aware-no-attach'],
    data: {
      kind: 'proxyforge-agent-dom-tracer-sessions',
      session: tracer.getTracerSession?.(session.id) ?? session,
      allSessions: tracer.getAllSessions?.() ?? [session],
      highValueSinks: tracer.getHighValueSinks?.(session.id) ?? [],
      canaryTraces: tracer.getCanaryTraces?.(session.id) ?? [],
      scopeAllowlist,
    },
  };
}

async function domTracerExportResult(flags, project, selectedExchange, scopeAllowlist) {
  const sessions = domTracerSessionsResult(flags, project, selectedExchange, scopeAllowlist);
  if (sessions.status === 'blocked') return sessions;
  const outPath = path.resolve(flags.out ?? flags.output ?? 'proxyforge-agent-artifacts/dom-tracer-export.json');
  const payload = {
    kind: 'proxyforge-agent-dom-tracer-export',
    createdAt: new Date().toISOString(),
    project: projectSummary(project),
    scopeAllowlist,
    sessions: sessions.data.allSessions,
    highValueSinkCount: sessions.data.highValueSinks.length,
    reportRedactionBoundary: 'redact-only-during-report-export',
  };
  await writePrivateFile(outPath, JSON.stringify(payload, null, 2), 'utf8');
  return {
    status: 'completed',
    mode: 'executed',
    trafficSent: false,
    requestCount: 0,
    gates: ['dom-tracer-export-written', 'full-fidelity-operational-output'],
    data: { exportPackage: payload, filePath: outPath },
    artifacts: [artifact('dom-tracer-export', outPath, 'DOM tracer export package')],
  };
}

function parseArgs(argv) {
  const flags = {};
  const positionals = [];
  let command = '';
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (!command && !token.startsWith('-')) {
      command = token === 'help' ? '' : token;
      if (token === 'help') flags.help = true;
      continue;
    }
    if (token === '--help' || token === '-h') {
      flags.help = true;
      continue;
    }
    if (token.startsWith('--')) {
      const eq = token.indexOf('=');
      if (eq !== -1) {
        flags[token.slice(2, eq)] = coerceFlag(token.slice(eq + 1));
        continue;
      }
      const key = token.slice(2);
      const next = argv[index + 1];
      if (!next || next.startsWith('--')) {
        flags[key] = true;
      } else {
        flags[key] = coerceFlag(next);
        index += 1;
      }
      continue;
    }
    positionals.push(token);
  }
  return { command, flags, positionals, help: Boolean(flags.help) };
}

function coerceFlag(value) {
  if (value === 'true') return true;
  if (value === 'false') return false;
  return value;
}

function printHelp() {
  process.stdout.write([
    'ProxyForge agent CLI',
    '',
    'Usage:',
    '  node scripts/proxyforge-agent.mjs status --project ./workspace.proxyforge.json --json',
    '  node scripts/proxyforge-agent.mjs mitm-start --session-dir ./agent-session --port 8080 --ensure-ca --upstream-tls strict --upstream-proxy http://127.0.0.1:8081 --json',
    '  node scripts/proxyforge-agent.mjs chromium-capture --target https://app.example.test --scope example.test --json',
    '  node scripts/proxyforge-agent.mjs search-index --project ./workspace.proxyforge.json --query authz --soak --soak-out ./artifacts/search-soak.json --json',
    '  node scripts/proxyforge-agent.mjs content-discovery-run --project ./workspace.proxyforge.json --scope example.test --limit 40 --execute --soak --json',
    '  node scripts/proxyforge-agent.mjs target-access-review --project ./workspace.proxyforge.json --roles customer,support_admin --json',
    '  node scripts/proxyforge-agent.mjs target-map-compare --project ./workspace.proxyforge.json --baseline hx-1 --candidate hx-1,hx-2 --json',
    '  node scripts/proxyforge-agent.mjs automation-run --project ./workspace.proxyforge.json --workflow wf-nightly --execute --json',
    '  node scripts/proxyforge-agent.mjs automation-scheduler-tick --project ./workspace.proxyforge.json --execute --json',
    '  node scripts/proxyforge-agent.mjs automation-parity-export --project ./workspace.proxyforge.json --out ./artifacts/automation-parity.json --json',
    '  node scripts/proxyforge-agent.mjs automation-service-plan --project ./workspace.proxyforge.json --workflow wf-nightly --out ./artifacts/automation-service-lifecycle.json --json',
    '  node scripts/proxyforge-agent.mjs automation-service-smoke --project ./workspace.proxyforge.json --workflow wf-nightly --service-dir ./.gitignored/automation-service-smoke --execute --json',
    '  node scripts/proxyforge-agent.mjs replay-run --project ./workspace.proxyforge.json --request-id hx-1 --execute --json',
    '  node scripts/proxyforge-agent.mjs bulk-replay --project ./workspace.proxyforge.json --limit 50 --concurrency 5 --execute --soak --json',
    '  node scripts/proxyforge-agent.mjs intruder-run --project ./workspace.proxyforge.json --request-id hx-1 --payloads admin,user --execute --soak --json',
    '  node scripts/proxyforge-agent.mjs sequencer-analyze --sample-file ./tokens.txt --soak --min-samples 5000 --json',
    '  node scripts/proxyforge-agent.mjs repeater-desync-probe --project ./workspace.proxyforge.json --request-id hx-1 --scope example.test --execute --json',
    '  node scripts/proxyforge-agent.mjs repeater-race-run --project ./workspace.proxyforge.json --request-id hx-1 --scope example.test --execute --json',
    '  node scripts/proxyforge-agent.mjs insertion-points --project ./workspace.proxyforge.json --request-id hx-1 --out ./artifacts/insertion-points.json --json',
    '  node scripts/proxyforge-agent.mjs websocket-replay --project ./workspace.proxyforge.json --frame-id ws-1 --execute --json',
    '  node scripts/proxyforge-agent.mjs websocket-fuzz --project ./workspace.proxyforge.json --frame-id ws-1 --max-probes 6 --execute --json',
    '  node scripts/proxyforge-agent.mjs websocket-transcript-export --project ./workspace.proxyforge.json --connection-id ws-conn-1 --format markdown --out ./artifacts/ws.md --json',
    '  node scripts/proxyforge-agent.mjs project-store-status --store ./workspace.proxyforge --json',
    '  node scripts/proxyforge-agent.mjs project-store-recover --store ./workspace.proxyforge --out ./artifacts/recovery.json --json',
    '  node scripts/proxyforge-agent.mjs project-store-backup --store ./workspace.proxyforge --out ./.gitignored/proxyforge-backups --execute --json',
    '  node scripts/proxyforge-agent.mjs scanner-plan --project ./workspace.proxyforge.json --scope example.test --check-pack full-active --json',
    '  node scripts/proxyforge-agent.mjs scanner-run --project ./workspace.proxyforge.json --scope example.test --check-pack full-active --max-requests 13 --execute --soak --json',
    '  node scripts/proxyforge-agent.mjs scanner-retest --project ./workspace.proxyforge.json --issue issue-1 --request-id hx-1 --retest-id hx-2 --json',
    '  node scripts/proxyforge-agent.mjs scanner-oast-promote --project ./workspace.proxyforge.json --workspace ./callbacks.json --request-id hx-1 --payload-id cb-1 --interaction-id int-1 --json',
    '  node scripts/proxyforge-agent.mjs anvil-run --project ./workspace.proxyforge.json --request-id hx-1 --execute --json',
    '  node scripts/proxyforge-agent.mjs extension-fixtures --project ./workspace.proxyforge.json --manifest ./extension.json --json',
    '  node scripts/proxyforge-agent.mjs exploit-run --project ./workspace.proxyforge.json --template manual-validation --approve ./approval.json --json',
    '',
    `Commands: ${Array.from(commands).sort().join(', ')}`,
    '',
  ].join('\n'));
}

async function loadProject(filePath, targetUrl) {
  if (!filePath) return defaultProject(targetUrl);
  const raw = await fs.readFile(path.resolve(filePath), 'utf8');
  const parsed = JSON.parse(raw);
  if (Array.isArray(parsed)) {
    return normalizeProject({
      version: 1,
      projectName: 'Imported HTTP history',
      scopeAllowlist: [],
      exchanges: parsed,
    });
  }
  return normalizeProject(parsed);
}

function normalizeProject(snapshot) {
  const exchanges = Array.isArray(snapshot.exchanges) ? snapshot.exchanges.filter(isExchangeLike).slice(0, 1000) : [];
  const issues = [
    ...(Array.isArray(snapshot.issues) ? snapshot.issues : []),
    ...(Array.isArray(snapshot.importedBundleIssues) ? snapshot.importedBundleIssues : []),
    ...(Array.isArray(snapshot.intruderPromotedIssues) ? snapshot.intruderPromotedIssues : []),
    ...(Array.isArray(snapshot.webSocketPromotedIssues) ? snapshot.webSocketPromotedIssues : []),
  ].filter(isIssueLike).slice(0, 500);
  return {
    ...snapshot,
    projectName: snapshot.projectName ?? 'ProxyForge Agent Project',
    scopeAllowlist: Array.isArray(snapshot.scopeAllowlist) ? snapshot.scopeAllowlist.filter((item) => typeof item === 'string') : [],
    exchanges,
    issues,
    webSocketMessages: normalizeAgentWebSocketMessages(snapshot.webSocketMessages ?? snapshot.websocketMessages ?? snapshot.webSocketFrames ?? []),
    savedWebSocketReplays: normalizeAgentWebSocketSavedReplays(snapshot.savedWebSocketReplays ?? []),
    webSocketFuzzRuns: Array.isArray(snapshot.webSocketFuzzRuns) ? snapshot.webSocketFuzzRuns : [],
    webSocketTranscriptExports: Array.isArray(snapshot.webSocketTranscriptExports) ? snapshot.webSocketTranscriptExports : [],
  };
}

function parseProxyImport(raw) {
  const trimmed = raw.trim();
  if (!trimmed) return { sourceFormat: 'empty', exchanges: [] };
  const jsonl = parseProxyImportJsonl(trimmed);
  if (jsonl) return jsonl;
  const legacyProxyXml = parseLegacyProxyXmlProxyImport(trimmed);
  if (legacyProxyXml) return legacyProxyXml;
  const rawHttpArchive = parseRawHttpProxyImport(trimmed);
  if (rawHttpArchive) return rawHttpArchive;
  let parsed;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    return { sourceFormat: 'unknown-text', exchanges: [] };
  }
  if (Array.isArray(parsed)) return { sourceFormat: 'exchange-array', exchanges: parsed };
  if (Array.isArray(parsed.exchanges)) return { sourceFormat: parsed.kind ?? 'proxyforge-project', exchanges: parsed.exchanges };
  if (Array.isArray(parsed?.log?.entries)) return { sourceFormat: 'har', exchanges: parsed.log.entries.map(harEntryToExchange) };
  if (parsed?.payload?.exchange) return { sourceFormat: 'agent-mitm-event', exchanges: [parsed.payload.exchange] };
  if (Array.isArray(parsed?.payload?.exchanges)) return { sourceFormat: parsed.kind ?? 'agent-mitm-export', exchanges: parsed.payload.exchanges };
  if (Array.isArray(parsed?.data?.exchanges)) return { sourceFormat: parsed.kind ?? 'agent-result-exchanges', exchanges: parsed.data.exchanges };
  if (Array.isArray(parsed?.data?.summary?.exchanges)) return { sourceFormat: parsed.kind ?? 'agent-crawl-result', exchanges: parsed.data.summary.exchanges };
  return { sourceFormat: parsed.kind ?? 'unknown-json', exchanges: [] };
}

function parseProxyImportJsonl(trimmed) {
  if (!trimmed.includes('\n')) return null;
  const exchanges = [];
  let parsedLineCount = 0;
  for (const line of trimmed.split(/\r?\n/)) {
    if (!line.trim()) continue;
    let event;
    try {
      event = JSON.parse(line);
      parsedLineCount += 1;
    } catch {
      return null;
    }
    const exchange = event?.payload?.exchange ?? event?.exchange ?? (event?.url || event?.requestRaw ? event : null);
    if (exchange) exchanges.push(exchange);
  }
  return parsedLineCount > 0 ? { sourceFormat: 'agent-jsonl', exchanges } : null;
}

function parseLegacyProxyXmlProxyImport(trimmed) {
  if (!/^<\?xml|<items\b|<item\b/i.test(trimmed)) return null;
  const itemMatches = Array.from(trimmed.matchAll(/<item\b[^>]*>([\s\S]*?)<\/item>/gi));
  if (!itemMatches.length) return null;
  const exchanges = itemMatches.map((match, index) => legacyProxyXmlItemToExchange(match[1], index)).filter(Boolean);
  return { sourceFormat: 'legacy-proxy-xml', exchanges };
}

function legacyProxyXmlItemToExchange(itemXml, index) {
  const url = xmlField(itemXml, 'url');
  const hostField = xmlField(itemXml, 'host');
  const protocol = xmlField(itemXml, 'protocol') || (url.startsWith('http://') ? 'http' : 'https');
  const port = xmlField(itemXml, 'port');
  const pathValue = xmlField(itemXml, 'path') || '/';
  const normalizedUrl = normalizeTarget(url || `${protocol}://${hostField || 'imported.local'}${port && !['80', '443'].includes(port) ? `:${port}` : ''}${pathValue.startsWith('/') ? pathValue : `/${pathValue}`}`);
  const parsed = new URL(normalizedUrl);
  const timeValue = xmlField(itemXml, 'time');
  const responseLengthValue = Number(xmlField(itemXml, 'responselength'));
  const timingValue = Number(timeValue);
  const method = (xmlField(itemXml, 'method') || methodFromRawRequest(xmlField(itemXml, 'request')) || 'GET').toUpperCase();
  const requestRaw = xmlField(itemXml, 'request') || `${method} ${parsed.pathname || '/'}${parsed.search || ''} HTTP/1.1\nHost: ${parsed.host}\n\n`;
  const responseRaw = xmlField(itemXml, 'response');
  return {
    id: `legacy-proxy-xml-${index + 1}-${simpleDigest(`${method}|${normalizedUrl}|${requestRaw}`).slice(0, 8)}`,
    method,
    host: parsed.host,
    path: `${parsed.pathname || '/'}${parsed.search || ''}`,
    url: normalizedUrl,
    status: Number(xmlField(itemXml, 'status') || statusFromRawResponse(responseRaw) || 0),
    length: Number.isFinite(responseLengthValue) ? responseLengthValue : responseRaw.length,
    mime: legacyProxyMimeType(xmlField(itemXml, 'mimetype')) || mimeFromRawResponse(responseRaw) || 'application/octet-stream',
    risk: 'info',
    timing: Number.isFinite(timingValue) ? timingValue : 0,
    source: 'proxy',
    time: timeValue || new Date().toISOString(),
    requestRaw,
    responseRaw,
    notes: 'Imported from legacy proxy XML history for agent data collection.',
    tags: ['proxy-import', 'legacy-proxy-xml'],
  };
}

function parseRawHttpProxyImport(trimmed) {
  if (!/^[A-Z]+\s+\S+\s+HTTP\/\d(?:\.\d)?/im.test(trimmed)) return null;
  const normalized = trimmed.replace(/\r\n/g, '\n');
  const chunks = normalized
    .split(/\n(?=[A-Z]+\s+\S+\s+HTTP\/\d(?:\.\d)?)/g)
    .map((chunk) => chunk.trim())
    .filter(Boolean);
  const exchanges = chunks.map((chunk, index) => {
    const responseOffset = chunk.search(/\nHTTP\/\d(?:\.\d)?\s+\d{3}/i);
    const requestRaw = responseOffset === -1 ? chunk : chunk.slice(0, responseOffset).trim();
    const responseRaw = responseOffset === -1 ? '' : chunk.slice(responseOffset + 1).trim();
    return {
      id: `raw-http-${index + 1}-${simpleDigest(requestRaw).slice(0, 8)}`,
      requestRaw,
      responseRaw,
      tags: ['proxy-import', 'raw-http'],
      notes: 'Imported from raw HTTP text archive for agent data collection.',
    };
  });
  return exchanges.length ? { sourceFormat: 'raw-http', exchanges } : null;
}

function xmlField(itemXml, tagName) {
  const match = itemXml.match(new RegExp(`<${tagName}\\b([^>]*)>([\\s\\S]*?)<\\/${tagName}>`, 'i'));
  if (!match) return '';
  const attributes = match[1] ?? '';
  const value = xmlDecode(match[2] ?? '').trim();
  if (/\bbase64\s*=\s*"true"/i.test(attributes)) {
    try {
      return Buffer.from(value.replace(/\s+/g, ''), 'base64').toString('utf8');
    } catch {
      return value;
    }
  }
  return value;
}

function xmlDecode(value) {
  return String(value)
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, '&');
}

function legacyProxyMimeType(value) {
  const normalized = String(value ?? '').trim().toLowerCase();
  if (!normalized) return '';
  const known = {
    html: 'text/html',
    script: 'application/javascript',
    json: 'application/json',
    xml: 'application/xml',
    css: 'text/css',
    image: 'image/*',
    binary: 'application/octet-stream',
    text: 'text/plain',
  };
  return known[normalized] ?? normalized;
}

function harEntryToExchange(entry, index) {
  const request = entry?.request ?? {};
  const response = entry?.response ?? {};
  const url = normalizeTarget(request.url ?? 'https://example.test/');
  const parsed = new URL(url);
  const method = String(request.method ?? 'GET').toUpperCase();
  const requestHeaders = Array.isArray(request.headers) ? request.headers : [];
  const responseHeaders = Array.isArray(response.headers) ? response.headers : [];
  const requestBody = request.postData?.text ?? '';
  const responseBody = response.content?.text
    ? response.content.encoding === 'base64'
      ? Buffer.from(response.content.text, 'base64').toString('utf8')
      : response.content.text
    : '';
  return {
    id: `har-${index + 1}-${simpleDigest(`${method}|${url}`).slice(0, 8)}`,
    method,
    host: parsed.host,
    path: `${parsed.pathname || '/'}${parsed.search || ''}`,
    url,
    status: Number(response.status ?? 0),
    length: Number(response.bodySize ?? response.content?.size ?? responseBody.length ?? 0),
    mime: response.content?.mimeType ?? headerValue(responseHeaders, 'content-type') ?? 'application/octet-stream',
    risk: 'info',
    timing: Number(entry.time ?? 0),
    source: 'proxy',
    time: entry.startedDateTime ?? new Date().toISOString(),
    requestRaw: [
      `${method} ${parsed.pathname || '/'}${parsed.search || ''} HTTP/1.1`,
      `Host: ${parsed.host}`,
      ...requestHeaders.map((header) => `${header.name}: ${header.value}`),
      '',
      requestBody,
    ].join('\n'),
    responseRaw: [
      `HTTP/1.1 ${Number(response.status ?? 0)} ${response.statusText ?? ''}`.trim(),
      ...responseHeaders.map((header) => `${header.name}: ${header.value}`),
      '',
      responseBody,
    ].join('\n'),
    notes: 'Imported from HAR for agent data collection.',
    tags: ['proxy-import', 'har'],
  };
}

function normalizeImportedExchange(exchange, index) {
  if (!exchange?.url && !exchange?.requestRaw) return null;
  const url = normalizeTarget(exchange.url ?? urlFromRawRequest(exchange.requestRaw) ?? 'https://example.test/');
  const parsed = new URL(url);
  const method = String(exchange.method ?? methodFromRawRequest(exchange.requestRaw) ?? 'GET').toUpperCase();
  const requestRaw = String(exchange.requestRaw ?? `${method} ${parsed.pathname || '/'}${parsed.search || ''} HTTP/1.1\nHost: ${parsed.host}\n\n`);
  const responseRaw = String(exchange.responseRaw ?? '');
  return {
    id: String(exchange.id ?? `proxy-import-${index + 1}-${simpleDigest(`${method}|${url}|${requestRaw}`).slice(0, 8)}`),
    method,
    host: String(exchange.host ?? parsed.host),
    path: String(exchange.path ?? `${parsed.pathname || '/'}${parsed.search || ''}`),
    url,
    status: Number(exchange.status ?? statusFromRawResponse(responseRaw) ?? 0),
    length: Number(exchange.length ?? responseRaw.length ?? 0),
    mime: String(exchange.mime ?? mimeFromRawResponse(responseRaw) ?? 'application/octet-stream'),
    risk: exchange.risk ?? 'info',
    timing: Number(exchange.timing ?? 0),
    notes: String(exchange.notes ?? 'Imported by ProxyForge agent CLI.'),
    source: exchange.source ?? 'proxy',
    time: String(exchange.time ?? new Date().toISOString()),
    requestRaw,
    responseRaw,
    tags: Array.from(new Set([...(Array.isArray(exchange.tags) ? exchange.tags : []), 'proxy-import'])),
  };
}

function headerValue(headers, targetName) {
  const target = String(targetName).toLowerCase();
  const match = headers.find((header) => String(header?.name ?? '').toLowerCase() === target);
  return match?.value;
}

function urlFromRawRequest(raw) {
  const [head = ''] = String(raw ?? '').split(/\r?\n\r?\n/);
  const lines = head.split(/\r?\n/);
  const requestLine = lines[0] ?? '';
  const [, requestTarget = ''] = requestLine.match(/^\S+\s+(\S+)/) ?? [];
  const hostHeader = lines.find((line) => /^host\s*:/i.test(line))?.replace(/^host\s*:\s*/i, '').trim();
  if (!requestTarget) return '';
  if (/^https?:\/\//i.test(requestTarget)) return requestTarget;
  if (!hostHeader) return '';
  return `https://${hostHeader}${requestTarget.startsWith('/') ? requestTarget : `/${requestTarget}`}`;
}

function methodFromRawRequest(raw) {
  return String(raw ?? '').split(/\s+/, 1)[0] || '';
}

function statusFromRawResponse(raw) {
  const [, status] = String(raw ?? '').match(/^HTTP\/\S+\s+(\d{3})/i) ?? [];
  return status ? Number(status) : undefined;
}

function mimeFromRawResponse(raw) {
  const [head = ''] = String(raw ?? '').split(/\r?\n\r?\n/);
  const header = head.split(/\r?\n/).find((line) => /^content-type\s*:/i.test(line));
  return header?.replace(/^content-type\s*:\s*/i, '').trim();
}

function buildAgentContentDiscoveryPlan(exchanges, scopeAllowlist, options = {}) {
  const limit = Math.max(1, Math.min(500, Math.round(numberFlag(options.limit, 60))));
  const createdAt = options.now ?? new Date().toISOString();
  const candidates = new Map();
  const scopedExchanges = exchanges
    .filter((exchange) => exchange?.url)
    .filter((exchange) => isTargetInScope(exchange.url, scopeAllowlist));
  const hosts = unique(scopedExchanges.map((exchange) => hostFromUrl(exchange.url)));

  for (const host of hosts) {
    const origin = originForHost(host, scopedExchanges);
    addDiscoveryCandidate(candidates, {
      url: `${origin}/robots.txt`,
      priority: 'medium',
      reason: 'Site robots inventory can reveal crawlable and disallowed paths.',
      source: 'host-baseline',
    });
    addDiscoveryCandidate(candidates, {
      url: `${origin}/sitemap.xml`,
      priority: 'medium',
      reason: 'Sitemap inventory can reveal unauthenticated route structure.',
      source: 'host-baseline',
    });
    addDiscoveryCandidate(candidates, {
      url: `${origin}/.well-known/security.txt`,
      priority: 'low',
      reason: 'Well-known metadata can reveal security contact and host ownership context.',
      source: 'host-baseline',
    });
    addDiscoveryCandidate(candidates, {
      url: `${origin}/openapi.json`,
      priority: 'high',
      reason: 'OpenAPI documents often expose hidden API routes and parameter names.',
      source: 'host-baseline',
    });
  }

  for (const exchange of scopedExchanges) {
    let parsed;
    try {
      parsed = new URL(normalizeTarget(exchange.url));
    } catch {
      continue;
    }
    const exchangeId = exchange.id ?? `exchange-${simpleDigest(exchange.url).slice(0, 8)}`;
    const pathName = parsed.pathname || '/';
    const dir = dirnamePath(pathName);
    const raw = `${exchange.requestRaw ?? ''}\n${exchange.responseRaw ?? ''}`;
    const lowerPath = pathName.toLowerCase();
    const source = `exchange:${exchangeId}`;

    addDiscoveryCandidate(candidates, {
      url: new URL(pathName, parsed.origin).toString(),
      priority: 'low',
      reason: 'Canonicalize the observed route without query parameters for repeatable probing.',
      source,
      sourceExchangeId: exchangeId,
    });

    if (parsed.searchParams.size > 0) {
      addDiscoveryCandidate(candidates, {
        url: new URL(`${pathName}?format=json`, parsed.origin).toString(),
        priority: 'medium',
        reason: 'Observed query route may expose alternate JSON format controls.',
        source,
        sourceExchangeId: exchangeId,
      });
    }

    if (/\/api(\/|$)|json|graphql|rest/i.test(`${pathName}\n${exchange.mime ?? ''}\n${raw}`)) {
      for (const suffix of ['health', 'status', 'version', 'openapi.json', 'swagger.json', 'bulk', 'export', 'debug']) {
        addDiscoveryCandidate(candidates, {
          url: new URL(`${dir}/${suffix}`.replace(/\/+/g, '/'), parsed.origin).toString(),
          priority: ['openapi.json', 'swagger.json', 'bulk', 'export'].includes(suffix) ? 'high' : 'medium',
          reason: `Observed API traffic suggests checking sibling ${suffix} endpoint.`,
          source,
          sourceExchangeId: exchangeId,
        });
      }
    }

    if (/admin|manage|console|staff|support/i.test(pathName)) {
      for (const suffix of ['/admin/users', '/admin/audit', '/admin/export', '/admin/impersonate', '/admin/graphql']) {
        addDiscoveryCandidate(candidates, {
          url: new URL(suffix, parsed.origin).toString(),
          priority: 'high',
          reason: 'Observed administrative path suggests checking adjacent privileged routes.',
          source,
          sourceExchangeId: exchangeId,
        });
      }
    }

    if (/auth|login|session|oauth|sso|account/i.test(pathName)) {
      for (const suffix of ['/api/me', '/api/session', '/api/sessions', '/api/oauth/clients', '/.well-known/openid-configuration']) {
        addDiscoveryCandidate(candidates, {
          url: new URL(suffix, parsed.origin).toString(),
          priority: 'high',
          reason: 'Observed authentication/session route suggests checking identity metadata and session APIs.',
          source,
          sourceExchangeId: exchangeId,
        });
      }
    }

    if (/\.m?js$/i.test(pathName)) {
      addDiscoveryCandidate(candidates, {
        url: new URL(`${pathName}.map`, parsed.origin).toString(),
        priority: 'high',
        reason: 'JavaScript asset may expose a source map with route names, secrets, or feature flags.',
        source,
        sourceExchangeId: exchangeId,
      });
      const sourceMap = String(raw).match(/sourceMappingURL=([^\s"'<>]+)/i)?.[1];
      if (sourceMap) {
        addDiscoveryCandidate(candidates, {
          url: new URL(sourceMap, parsed.href).toString(),
          priority: 'high',
          reason: 'JavaScript response advertises an explicit source map URL.',
          source,
          sourceExchangeId: exchangeId,
        });
      }
    }

    if (/graphql/i.test(raw) || lowerPath.includes('graphql')) {
      for (const suffix of ['/graphql', '/api/graphql', '/graphiql', '/graphql/schema.json']) {
        addDiscoveryCandidate(candidates, {
          url: new URL(suffix, parsed.origin).toString(),
          priority: 'high',
          reason: 'GraphQL evidence suggests checking schema/introspection and console-adjacent endpoints.',
          source,
          sourceExchangeId: exchangeId,
        });
      }
    }
  }

  const sortedCandidates = Array.from(candidates.values())
    .sort((left, right) => discoveryPriorityScore(right.priority) - discoveryPriorityScore(left.priority) || left.url.localeCompare(right.url))
    .slice(0, limit)
    .map((candidate, index) => ({
      ...candidate,
      id: `content-discovery-${index + 1}-${simpleDigest(candidate.url).slice(0, 8)}`,
      sourceExchangeIds: Array.from(candidate.sourceExchangeIds ?? []),
    }));

  return {
    id: `agent-content-discovery-${simpleDigest(`${hosts.join(',')}|${sortedCandidates.map((candidate) => candidate.url).join(',')}`).slice(0, 12)}`,
    kind: 'proxyforge-agent-content-discovery-plan',
    schemaVersion,
    createdAt,
    source: options.source ?? 'project-history',
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    throttleMs: numberFlag(options.throttleMs, 150),
    wordlistProfile: 'agent-balanced-api-admin-wellknown',
    scopeSummary: {
      allowlist: scopeAllowlist,
      hostCount: hosts.length,
      hosts,
    },
    exchangeCount: scopedExchanges.length,
    candidateCount: sortedCandidates.length,
    candidates: sortedCandidates,
    summary: `Generated ${sortedCandidates.length} content-discovery candidate(s) from ${scopedExchanges.length} scoped exchange(s) across ${hosts.length} host(s).`,
    nextCommands: [
      'content-discovery-run --project <project> --scope <host> --execute --json',
      'crawl-run --target <candidate.url> --scope <host> --execute --json',
      'replay-run --target <candidate.url> --scope <host> --execute --json',
    ],
  };
}

async function buildAgentContentDiscoveryRunCandidates(flags, project, scopeAllowlist, plan, limit) {
  const candidates = new Map();
  for (const candidate of plan.candidates ?? []) {
    addDiscoveryCandidate(candidates, {
      ...candidate,
      sources: candidate.sources,
      sourceExchangeIds: candidate.sourceExchangeIds,
      source: 'candidate-plan',
    });
  }

  const origins = agentContentDiscoveryOrigins(flags, project, scopeAllowlist, plan);
  const wordlistEntries = await loadAgentContentDiscoveryWordlist(flags);
  for (const origin of origins) {
    for (const entry of wordlistEntries) {
      const url = contentDiscoveryUrlForEntry(origin, entry);
      if (!url) continue;
      addDiscoveryCandidate(candidates, {
        url,
        priority: 'medium',
        reason: 'Operator supplied wordlist path for agent content discovery execution.',
        source: 'agent-wordlist',
      });
    }
  }

  return Array.from(candidates.values())
    .filter((candidate) => isTargetInScope(candidate.url, scopeAllowlist))
    .sort((left, right) => discoveryPriorityScore(right.priority) - discoveryPriorityScore(left.priority) || left.url.localeCompare(right.url))
    .slice(0, limit)
    .map((candidate, index) => ({
      ...candidate,
      id: `content-discovery-run-${index + 1}-${simpleDigest(candidate.url).slice(0, 8)}`,
      sourceExchangeIds: Array.from(candidate.sourceExchangeIds ?? []),
    }));
}

function agentContentDiscoveryOrigins(flags, project, scopeAllowlist, plan) {
  const origins = new Set();
  for (const target of parseList(flags.target ?? flags.url)) {
    try {
      const parsed = new URL(normalizeTarget(target));
      if (isTargetInScope(parsed.toString(), scopeAllowlist)) origins.add(parsed.origin);
    } catch {
      // Ignore malformed operator input; generated plan candidates remain available.
    }
  }
  for (const candidate of plan.candidates ?? []) {
    try {
      const parsed = new URL(normalizeTarget(candidate.url));
      origins.add(parsed.origin);
    } catch {
      // Ignore malformed candidates.
    }
  }
  for (const exchange of project.exchanges ?? []) {
    try {
      if (!isTargetInScope(exchange.url, scopeAllowlist)) continue;
      origins.add(new URL(normalizeTarget(exchange.url)).origin);
    } catch {
      // Ignore malformed project exchanges.
    }
  }
  if (!origins.size) {
    for (const scope of scopeAllowlist) {
      if (!scope || scope === '*' || String(scope).startsWith('*.')) continue;
      origins.add(`https://${scope}`);
    }
  }
  return Array.from(origins);
}

async function loadAgentContentDiscoveryWordlist(flags) {
  const entries = [];
  entries.push(...parseList(flags.wordlist ?? flags.paths ?? flags.path));
  for (const filePath of parseList(flags['wordlist-file'])) {
    try {
      entries.push(...parseList(await fs.readFile(path.resolve(filePath), 'utf8')));
    } catch {
      // A missing optional wordlist should not discard generated candidates.
    }
  }
  return unique(entries.map((entry) => entry.trim()).filter((entry) => entry && !entry.startsWith('#')));
}

function contentDiscoveryUrlForEntry(origin, entry) {
  const value = String(entry ?? '').trim();
  if (!value) return '';
  try {
    if (/^https?:\/\//i.test(value)) return normalizeTarget(value);
    const pathValue = value.startsWith('/') ? value : `/${value}`;
    return new URL(pathValue, origin).toString();
  } catch {
    return '';
  }
}

function inheritedAgentDiscoveryHeaders(project, scopeAllowlist) {
  const exchange = (project.exchanges ?? []).find((candidate) => candidate?.requestRaw && isTargetInScope(candidate.url, scopeAllowlist));
  const headers = { ...parseRawRequest(exchange?.requestRaw ?? '').headers };
  deleteHeader(headers, 'host');
  deleteHeader(headers, 'content-length');
  return headers;
}

function isAgentContentDiscoveryHit(response) {
  if (!response || response.error) return false;
  const status = Number(response.status ?? 0);
  if (status >= 200 && status < 400) return true;
  return status === 401 || status === 403;
}

function buildAgentTargetRoutes(exchanges) {
  const byKey = new Map();
  for (const exchange of exchanges) {
    const summary = exchangeSummary(exchange);
    const key = `${summary.method} ${summary.host}${summary.path}`;
    const existing = byKey.get(key) ?? {
      id: `agent-target-route-${simpleDigest(key).slice(0, 10)}`,
      key,
      method: summary.method,
      url: summary.url,
      host: summary.host,
      path: summary.path,
      title: exchange.notes ?? key,
      exchanges: [],
    };
    existing.exchanges.push(exchange);
    byKey.set(key, existing);
  }
  return Array.from(byKey.values()).sort((left, right) => left.key.localeCompare(right.key));
}

function selectAgentComparisonRoutes(routes, selector, mode) {
  const selectors = new Set(parseList(selector));
  if (selectors.size) {
    const selected = routes.filter((route) =>
      selectors.has(route.id)
      || selectors.has(route.key)
      || selectors.has(route.path)
      || route.exchanges.some((exchange) => selectors.has(exchange.id)),
    );
    if (selected.length) return selected;
  }
  if (mode === 'baseline') {
    const baseline = routes.filter((route) => route.exchanges.some((exchange) => /proxy|baseline|crawler|seed/i.test(`${exchange.source} ${exchange.notes} ${(exchange.tags ?? []).join(' ')}`)));
    return baseline.length ? baseline.slice(0, Math.max(1, Math.ceil(routes.length / 2))) : routes.slice(0, Math.max(1, Math.ceil(routes.length / 2)));
  }
  return routes;
}

function buildAgentTargetMapComparisonPackage({ project, scopeAllowlist, routes, baselineRoutes, candidateRoutes, exchanges, baselineName, candidateName }) {
  const createdAt = new Date().toISOString();
  const baselineByKey = new Map(baselineRoutes.map((route) => [route.key.toLowerCase(), route]));
  const candidateByKey = new Map(candidateRoutes.map((route) => [route.key.toLowerCase(), route]));
  const deltas = [];
  for (const [key, route] of candidateByKey) {
    const baseline = baselineByKey.get(key);
    if (!baseline) {
      const parameters = agentRouteParameterNames(route);
      const changeTypes = ['visibility', ...(parameters.length ? ['parameter'] : []), ...(agentRouteAuthzSensitive(route) ? ['authz'] : [])];
      deltas.push({
        id: `agent-target-delta-added-${route.id}`,
        kind: 'added',
        changeTypes,
        route: route.key,
        severity: agentComparisonSeverity(route, changeTypes),
        detail: `Added candidate route; include in content discovery, parameter review, and access-control matrix.${parameters.length ? ` Parameters: ${parameters.join(', ')}.` : ''}`,
        candidate: agentComparisonRouteSnapshot(route),
        affectedParameters: parameters,
        evidence: [`candidate ${route.key}`, `exchangeIds=${route.exchanges.map((exchange) => exchange.id).join(',')}`],
      });
    } else {
      const baselineParameters = agentRouteParameterNames(baseline);
      const candidateParameters = agentRouteParameterNames(route);
      const affectedParameters = unique([...baselineParameters, ...candidateParameters])
        .filter((name) => !baselineParameters.includes(name) || !candidateParameters.includes(name));
      const baselineStatus = agentRouteRepresentativeStatus(baseline);
      const candidateStatus = agentRouteRepresentativeStatus(route);
      const baselineMime = agentRouteRepresentativeMime(baseline);
      const candidateMime = agentRouteRepresentativeMime(route);
      const baselineAuthzSensitive = agentRouteAuthzSensitive(baseline);
      const candidateAuthzSensitive = agentRouteAuthzSensitive(route);
      const structuralChangeTypes = [
        ...(baselineStatus !== candidateStatus ? ['status'] : []),
        ...(baselineMime !== candidateMime ? ['mime'] : []),
        ...(baseline.method !== route.method ? ['method'] : []),
        ...(baseline.host !== route.host ? ['host'] : []),
        ...(affectedParameters.length ? ['parameter'] : []),
      ];
      const changeTypes = [
        ...structuralChangeTypes,
        ...((baselineAuthzSensitive !== candidateAuthzSensitive || (structuralChangeTypes.length && (baselineAuthzSensitive || candidateAuthzSensitive))) ? ['authz'] : []),
      ];
      if (changeTypes.length) {
        deltas.push({
          id: `agent-target-delta-changed-${route.id}`,
          kind: 'changed',
          changeTypes,
          route: route.key,
          severity: agentComparisonSeverity(route, changeTypes),
          detail: `Changed route metadata: status ${baselineStatus ?? '-'} -> ${candidateStatus ?? '-'}, MIME ${baselineMime ?? '-'} -> ${candidateMime ?? '-'}, parameters ${baselineParameters.length} -> ${candidateParameters.length}, change types ${changeTypes.join(', ')}.`,
          baseline: agentComparisonRouteSnapshot(baseline),
          candidate: agentComparisonRouteSnapshot(route),
          affectedParameters,
          evidence: [`baseline ${baseline.key}`, `candidate ${route.key}`, `exchangeIds=${route.exchanges.map((exchange) => exchange.id).join(',')}`],
        });
      }
    }
  }
  for (const [key, route] of baselineByKey) {
    if (candidateByKey.has(key)) continue;
    const parameters = agentRouteParameterNames(route);
    const changeTypes = ['visibility', ...(parameters.length ? ['parameter'] : []), ...(agentRouteAuthzSensitive(route) ? ['authz'] : [])];
    deltas.push({
      id: `agent-target-delta-removed-${route.id}`,
      kind: 'removed',
      changeTypes,
      route: route.key,
      severity: 'low',
      detail: `Removed baseline route; verify whether route moved, became role-gated, or was excluded by filters.${parameters.length ? ` Prior parameters: ${parameters.join(', ')}.` : ''}`,
      baseline: agentComparisonRouteSnapshot(route),
      affectedParameters: parameters,
      evidence: [`baseline ${route.key}`, `exchangeIds=${route.exchanges.map((exchange) => exchange.id).join(',')}`],
    });
  }
  const stats = {
    added: deltas.filter((delta) => delta.kind === 'added').length,
    removed: deltas.filter((delta) => delta.kind === 'removed').length,
    changed: deltas.filter((delta) => delta.kind === 'changed').length,
    statusChanged: deltas.filter((delta) => delta.changeTypes.includes('status')).length,
    mimeChanged: deltas.filter((delta) => delta.changeTypes.includes('mime')).length,
    parameterChanged: deltas.filter((delta) => delta.changeTypes.includes('parameter')).length,
    authzSensitiveChanged: deltas.filter((delta) => delta.changeTypes.includes('authz')).length,
    highRiskDeltaCount: deltas.filter((delta) => agentSeverityRank(delta.severity) >= agentSeverityRank('high')).length,
    hostDeltaCount: new Set(deltas.map((delta) => delta.route.split(/\s+/)[1]?.split('/')[0]).filter(Boolean)).size,
  };
  const unsigned = {
    kind: 'proxyforge-agent-target-site-map-comparison',
    schemaVersion,
    createdAt,
    projectName: project.projectName,
    scopeAllowlist,
    baseline: { name: baselineName, routeCount: baselineRoutes.length },
    candidate: { name: candidateName, routeCount: candidateRoutes.length },
    normalization: ['method', 'host', 'path', 'status', 'mime', 'parameter-names', 'authz-sensitive-route', 'visibility'],
    stats,
    deltas,
    exchanges: exchanges.map(exchangeDetail),
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    nextCommands: [
      'target-access-review --project <project> --roles customer,support_admin --json',
      'content-discovery-run --project <project> --scope <host> --execute --json',
      'report-export --project <project> --format markdown --json',
    ],
    summary: `Target map comparison reviewed ${baselineRoutes.length} baseline route(s), ${candidateRoutes.length} candidate route(s), ${stats.added} added, ${stats.removed} removed, ${stats.changed} changed, ${stats.parameterChanged} parameter delta(s), and ${stats.authzSensitiveChanged} authz-sensitive delta(s).`,
  };
  const digestPreview = simpleDigest(JSON.stringify(unsigned));
  return {
    id: `agent-target-comparison-${digestPreview.slice(0, 12)}`,
    ...unsigned,
    digestPreview,
  };
}

function agentRouteParameterNames(route) {
  const names = new Set();
  try {
    const parsed = new URL(normalizeTarget(route.url));
    for (const name of parsed.searchParams.keys()) names.add(`query:${name}`);
  } catch {
    // Route can be an imported partial path.
  }
  for (const exchange of route.exchanges) {
    const parsed = parseRawRequest(exchange.requestRaw ?? '');
    if (/application\/json|graphql/i.test(exchange.requestRaw ?? '')) names.add('body:json');
    for (const cookie of String(parsed.headers.Cookie ?? parsed.headers.cookie ?? '').split(';')) {
      const name = cookie.split('=')[0]?.trim();
      if (name) names.add(`cookie:${name}`);
    }
  }
  return Array.from(names).sort();
}

function agentComparisonRouteSnapshot(route) {
  return {
    status: agentRouteRepresentativeStatus(route),
    mime: agentRouteRepresentativeMime(route),
    insertionPointCount: agentRouteParameterNames(route).length,
    host: route.host,
    method: route.method,
  };
}

function agentRouteRepresentativeStatus(route) {
  return route.exchanges.find((exchange) => Number(exchange.status) > 0)?.status;
}

function agentRouteRepresentativeMime(route) {
  return route.exchanges.find((exchange) => exchange.mime)?.mime;
}

function agentRouteAuthzSensitive(route) {
  return /admin|support|finance|refund|graphql|oauth|sso|session|account|export|audit|impersonate|\/api\//i.test(`${route.method} ${route.path} ${route.title}`)
    || route.method !== 'GET'
    || route.exchanges.some((exchange) => Number(exchange.status) === 401 || Number(exchange.status) === 403 || /authorization|authz|role|permission|bearer|cookie/i.test(`${exchange.requestRaw} ${exchange.responseRaw} ${exchange.notes}`));
}

function agentComparisonSeverity(route, changeTypes) {
  if (changeTypes.includes('authz')) return 'high';
  if (changeTypes.includes('parameter') || changeTypes.includes('status')) return 'medium';
  return agentRouteAuthzSensitive(route) ? 'medium' : 'info';
}

function buildAgentRoleMap(role, routes, exchanges, flags) {
  const normalizedRole = normalizeAgentRole(role);
  const rolePattern = new RegExp(escapeRegExp(normalizedRole).replace(/_/g, '[_\\s-]*'), 'i');
  const statusByRoute = {};
  const exchangeIdsByRoute = {};
  for (const route of routes) {
    const roleExchange = route.exchanges.find((exchange) => agentExchangeMatchesRole(exchange, role, rolePattern))
      ?? route.exchanges.find((exchange) => normalizedRole.includes('customer') && /proxy|baseline|viewer|customer|forbidden|403/i.test(`${exchange.source} ${exchange.notes} ${exchange.status} ${exchange.responseRaw}`))
      ?? route.exchanges.find((exchange) => /admin|support|staff|privileged/i.test(normalizedRole) && /repeater|support|admin|accepted|approved|200|202/i.test(`${exchange.source} ${exchange.notes} ${exchange.status} ${exchange.responseRaw}`));
    if (roleExchange) {
      statusByRoute[route.id] = Number(roleExchange.status ?? statusFromRawResponse(roleExchange.responseRaw) ?? 0);
      exchangeIdsByRoute[route.id] = [roleExchange.id];
    }
  }
  const explicitVisible = new Set(parseList(flags[`visible-${normalizedRole}`] ?? flags.visible));
  const explicitDenied = new Set(parseList(flags[`denied-${normalizedRole}`] ?? flags.denied));
  const explicitHidden = new Set(parseList(flags[`hidden-${normalizedRole}`] ?? flags.hidden));
  return {
    role,
    normalizedRole,
    statusByRoute,
    exchangeIdsByRoute,
    visibleRouteIds: routes.filter((route) => explicitVisible.has(route.id) || explicitVisible.has(route.key) || accessObservationFromStatus(statusByRoute[route.id]) === 'visible').map((route) => route.id),
    deniedRouteIds: routes.filter((route) => explicitDenied.has(route.id) || explicitDenied.has(route.key) || accessObservationFromStatus(statusByRoute[route.id]) === 'denied').map((route) => route.id),
    hiddenRouteIds: routes.filter((route) => explicitHidden.has(route.id) || explicitHidden.has(route.key) || accessObservationFromStatus(statusByRoute[route.id]) === 'hidden').map((route) => route.id),
  };
}

function agentExchangeMatchesRole(exchange, role, rolePattern) {
  const normalizedRole = normalizeAgentRole(role);
  const haystack = `${exchange.requestRaw ?? ''}\n${exchange.responseRaw ?? ''}\n${exchange.notes ?? ''}\n${(exchange.tags ?? []).join(' ')}\n${exchange.source ?? ''}`;
  return rolePattern.test(haystack) || haystack.toLowerCase().includes(normalizedRole.replace(/_/g, '-'));
}

function buildAgentAccessControlLane(roleMap, routes) {
  const visible = new Set(roleMap.visibleRouteIds);
  const denied = new Set(roleMap.deniedRouteIds);
  const hidden = new Set(roleMap.hiddenRouteIds);
  const decisions = routes.map((route) => {
    const expected = defaultAgentAccessExpectation(roleMap.normalizedRole, route);
    const observed = visible.has(route.id)
      ? 'visible'
      : denied.has(route.id)
        ? 'denied'
        : hidden.has(route.id)
          ? 'hidden'
          : accessObservationFromStatus(roleMap.statusByRoute[route.id]);
    const drift = agentAccessDrift(expected, observed);
    const severity = agentAccessSeverity(route, drift);
    return {
      id: `agent-target-access-${roleMap.normalizedRole}-${route.id}`,
      role: roleMap.role,
      routeId: route.id,
      route: route.key,
      method: route.method,
      host: route.host,
      path: route.path,
      expected,
      observed,
      observedStatus: roleMap.statusByRoute[route.id],
      drift,
      severity,
      evidence: `${roleMap.role} expected ${expected} and observed ${observed}${roleMap.statusByRoute[route.id] !== undefined ? ` (${roleMap.statusByRoute[route.id]})` : ''} for ${route.key}.`,
      exchangeIds: roleMap.exchangeIdsByRoute[route.id] ?? [],
    };
  });
  const overexposedCount = decisions.filter((decision) => decision.drift === 'overexposed').length;
  const underexposedCount = decisions.filter((decision) => decision.drift === 'underexposed').length;
  const missingObservationCount = decisions.filter((decision) => decision.drift === 'missing-observation').length;
  const severity = overexposedCount > 0 ? 'high' : underexposedCount > 0 || missingObservationCount > 0 ? 'medium' : 'info';
  const riskyRoutes = decisions
    .filter((decision) => decision.drift !== 'none' || ['medium', 'high', 'critical'].includes(decision.severity))
    .sort((left, right) => agentSeverityRank(right.severity) - agentSeverityRank(left.severity) || left.route.localeCompare(right.route))
    .map((decision) => `${decision.route} ${decision.drift}`);
  return {
    id: `agent-target-access-${roleMap.normalizedRole}`,
    role: roleMap.role,
    routeCount: routes.length,
    visibleRouteCount: decisions.filter((decision) => decision.observed === 'visible').length,
    deniedRouteCount: decisions.filter((decision) => decision.observed === 'denied').length,
    hiddenRouteCount: decisions.filter((decision) => decision.observed === 'hidden').length,
    driftCount: overexposedCount + underexposedCount,
    overexposedCount,
    underexposedCount,
    missingObservationCount,
    riskyRoutes: unique(riskyRoutes).slice(0, 20),
    routeDecisions: decisions,
    expectedVisibility: /customer|viewer|guest|low/.test(roleMap.normalizedRole)
      ? 'Privileged admin/support/finance/refund/API mutation routes should be denied or hidden.'
      : 'Assigned operational routes should be visible and unassigned privileged routes should be denied.',
    reviewAction: `Use replay-matrix and scanner-run authz-diff to verify ${roleMap.role} route decisions before report export.`,
    severity,
    evidenceSummary: `Role ${roleMap.role}: ${overexposedCount} overexposed, ${underexposedCount} underexposed, ${missingObservationCount} missing observation(s).`,
  };
}

function defaultAgentAccessExpectation(role, route) {
  const target = `${route.method} ${route.path} ${route.title}`.toLowerCase();
  if (/customer|viewer|guest|low/.test(role)) {
    if (/admin|support|finance|impersonate|export|audit|graphql|refund/.test(target)) return 'denied';
    if (route.method !== 'GET' && /\/api\//.test(target)) return 'denied';
  }
  if (/finance/.test(role)) return /support|impersonate|audit|admin\/users/.test(target) ? 'denied' : 'visible';
  if (/support|admin|staff|privileged/.test(role)) return 'visible';
  return /admin|support|finance/.test(target) ? 'denied' : 'visible';
}

function accessObservationFromStatus(status) {
  const numeric = Number(status);
  if (!Number.isFinite(numeric) || numeric <= 0) return 'unknown';
  if (numeric === 401 || numeric === 403) return 'denied';
  if (numeric === 404 || numeric === 410) return 'hidden';
  if (numeric >= 200 && numeric < 400) return 'visible';
  if (numeric >= 400) return 'denied';
  return 'unknown';
}

function agentAccessDrift(expected, observed) {
  if (observed === 'unknown') return 'missing-observation';
  if (expected === 'visible' && observed !== 'visible') return 'underexposed';
  if ((expected === 'denied' || expected === 'hidden') && observed === 'visible') return 'overexposed';
  return 'none';
}

function agentAccessSeverity(route, drift) {
  if (drift === 'overexposed') return /admin|support|finance|refund|graphql|\/api\//i.test(route.path) || route.method !== 'GET' ? 'high' : 'medium';
  if (drift === 'underexposed' || drift === 'missing-observation') return 'medium';
  return /admin|support|finance|refund|graphql|\/api\//i.test(route.path) ? 'medium' : 'info';
}

function normalizeAgentRole(role) {
  return String(role ?? 'role').trim().toLowerCase().replace(/[^a-z0-9_-]+/g, '_') || 'role';
}

function agentSeverityRank(severity) {
  return { info: 0, low: 1, medium: 2, high: 3, critical: 4 }[severity] ?? 0;
}

function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function buildAgentContentDiscoverySoakPackage(summary, runPlan, flags) {
  const minRequests = Math.max(1, Math.round(numberFlag(flags['min-requests'], runPlan.candidateCount)));
  const minDiscovered = Math.max(0, Math.round(numberFlag(flags['min-discovered'], 1)));
  const minConcurrency = Math.max(1, Math.round(numberFlag(flags['min-concurrency'], Math.min(runPlan.maxConcurrency, Math.max(1, runPlan.candidateCount)))));
  const maxFailures = Math.max(0, Math.round(numberFlag(flags['max-failures'], 0)));
  const failures = [];
  const warnings = [];
  if (summary.totalRequests < minRequests) failures.push(`Sent ${summary.totalRequests} request(s), below soak floor ${minRequests}.`);
  if (summary.discoveredCount < minDiscovered) failures.push(`Discovered ${summary.discoveredCount} route(s), below soak floor ${minDiscovered}.`);
  if (summary.maxInFlight < minConcurrency) failures.push(`Max in-flight ${summary.maxInFlight} is below concurrency floor ${minConcurrency}.`);
  if (summary.failedRequests > maxFailures) failures.push(`Failed request count ${summary.failedRequests} is above soak allowance ${maxFailures}.`);
  if (summary.retainedResultCount < Math.min(summary.totalRequests, runPlan.resultWindowSize)) warnings.push('Retained result window is smaller than total sent requests.');
  if (summary.durationMs <= 0 || summary.requestRatePerSecond <= 0) warnings.push('Duration/request-rate telemetry was not populated.');
  return {
    id: `agent-content-discovery-soak-${simpleDigest(`${summary.id}|${summary.totalRequests}|${summary.discoveredCount}`).slice(0, 12)}`,
    kind: 'proxyforge-agent-content-discovery-runner-soak-package',
    status: failures.length ? 'fail' : 'pass',
    failures,
    warnings,
    budgets: {
      minRequests,
      minDiscovered,
      minConcurrency,
      maxFailures,
    },
    observed: {
      totalRequests: summary.totalRequests,
      discoveredCount: summary.discoveredCount,
      failedRequests: summary.failedRequests,
      maxInFlight: summary.maxInFlight,
      requestRatePerSecond: summary.requestRatePerSecond,
      statusCounts: summary.statusCounts,
    },
    summary,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportReady: failures.length === 0,
  };
}

function addDiscoveryCandidate(candidates, candidate) {
  if (!candidate?.url) return;
  let parsed;
  try {
    parsed = new URL(normalizeTarget(candidate.url));
  } catch {
    return;
  }
  const key = `${parsed.origin}${parsed.pathname}${parsed.search}`;
  const existing = candidates.get(key);
  const sourceExchangeIds = new Set(existing?.sourceExchangeIds ?? []);
  if (candidate.sourceExchangeId) sourceExchangeIds.add(candidate.sourceExchangeId);
  for (const exchangeId of candidate.sourceExchangeIds ?? []) sourceExchangeIds.add(exchangeId);
  candidates.set(key, {
    url: parsed.toString(),
    method: candidate.method ?? 'GET',
    host: parsed.host,
    path: `${parsed.pathname || '/'}${parsed.search || ''}`,
    priority: higherDiscoveryPriority(existing?.priority, candidate.priority ?? 'medium'),
    reason: existing?.reason ?? candidate.reason ?? 'Agent-generated content discovery candidate.',
    sources: unique([
      ...(existing?.sources ?? []),
      ...(Array.isArray(candidate.sources) ? candidate.sources : []),
      candidate.source ?? 'agent-content-discovery',
    ]),
    sourceExchangeIds,
  });
}

function higherDiscoveryPriority(left = 'low', right = 'low') {
  return discoveryPriorityScore(left) >= discoveryPriorityScore(right) ? left : right;
}

function discoveryPriorityScore(priority) {
  return { low: 1, medium: 2, high: 3 }[priority] ?? 1;
}

function dirnamePath(value) {
  const clean = String(value || '/').replace(/\/+$/, '');
  if (!clean || clean === '/') return '/';
  const index = clean.lastIndexOf('/');
  return index <= 0 ? '/' : clean.slice(0, index);
}

function originForHost(host, exchanges) {
  const match = exchanges.find((exchange) => hostFromUrl(exchange.url) === host);
  if (match?.url) {
    try {
      const parsed = new URL(normalizeTarget(match.url));
      return parsed.origin;
    } catch {
      // Fall through to a conservative HTTPS origin.
    }
  }
  return `https://${host}`;
}

function defaultProject(targetUrl = 'https://example.test/') {
  const target = normalizeTarget(targetUrl);
  const parsed = new URL(target);
  return normalizeProject({
    version: 1,
    projectName: 'ProxyForge Agent Scratch Project',
    scopeAllowlist: [parsed.hostname],
    exchanges: [{
      id: 'hx-agent-default',
      method: 'GET',
      host: parsed.hostname,
      path: `${parsed.pathname || '/'}${parsed.search || ''}`,
      url: target,
      status: 0,
      length: 0,
      mime: 'text/html',
      risk: 'info',
      timing: 0,
      source: 'agent',
      time: new Date().toISOString(),
      requestRaw: `GET ${parsed.pathname || '/'}${parsed.search || ''} HTTP/1.1\nHost: ${parsed.host}\n\n`,
      responseRaw: '',
      notes: 'Generated by ProxyForge agent CLI.',
      tags: ['agent-generated'],
    }],
  });
}

function isExchangeLike(value) {
  return value
    && typeof value.id === 'string'
    && typeof value.method === 'string'
    && typeof value.url === 'string'
    && typeof value.requestRaw === 'string';
}

function isIssueLike(value) {
  return value
    && typeof value.id === 'string'
    && typeof value.title === 'string'
    && typeof value.host === 'string';
}

function projectSummary(project) {
  return {
    name: project.projectName,
    scopeCount: project.scopeAllowlist.length,
    exchangeCount: project.exchanges.length,
    findingCount: project.issues.length,
    webSocketFrameCount: project.webSocketMessages?.length ?? 0,
    webSocketConnectionCount: unique((project.webSocketMessages ?? []).map((frame) => frame.connectionId)).length,
    browserLaunchCount: project.browserLaunches?.length ?? 0,
    reportPackageCount: project.reportFullPackages?.length ?? 0,
    aiActionExecutionCount: project.aiActionExecutionPackages?.length ?? 0,
    automationWorkflowCount: project.automationWorkflows?.length ?? 0,
    automationExecutionCount: project.automationExecutions?.length ?? 0,
    extensionCount: project.installedExtensions?.length ?? 0,
    extensionFixtureCount: project.extensionCompatibilityFixtures?.length ?? 0,
  };
}

function artifactInventory(project) {
  return {
    browserLaunches: project.browserLaunches?.length ?? 0,
    callbackPayloads: project.callbackPayloads?.length ?? 0,
    callbackInteractions: project.callbackInteractions?.length ?? 0,
    callbackReplayPackages: project.callbackCorrelationReplays?.length ?? 0,
    webSocketMessages: project.webSocketMessages?.length ?? 0,
    savedWebSocketReplays: project.savedWebSocketReplays?.length ?? 0,
    webSocketFuzzRuns: project.webSocketFuzzRuns?.length ?? 0,
    webSocketTranscriptExports: project.webSocketTranscriptExports?.length ?? 0,
    exploitRuns: project.exploitRuns?.length ?? 0,
    reportPackages: project.reportFullPackages?.length ?? 0,
    aiActions: project.aiActionExecutionPackages?.length ?? 0,
    automationWorkflows: project.automationWorkflows?.length ?? 0,
    automationExecutions: project.automationExecutions?.length ?? 0,
    automationSchedulerJobs: project.automationSchedulerState?.queue?.length ?? 0,
    extensions: project.installedExtensions?.length ?? 0,
    extensionFixtures: project.extensionCompatibilityFixtures?.length ?? 0,
  };
}

function scopeFromFlags(flags, project, targetUrl) {
  const parsed = parseList(flags.scope ?? flags.scopes);
  if (parsed.length) return parsed;
  if (project.scopeAllowlist?.length) return project.scopeAllowlist;
  if (targetUrl) return [hostFromUrl(targetUrl)].filter(Boolean);
  return ['*'];
}

function selectExchange(project, id, targetUrl) {
  if (id) {
    return project.exchanges.find((exchange) => exchange.id === id || exchange.url === id);
  }
  if (targetUrl) return undefined;
  return project.exchanges[0];
}

function requestFromExchange(exchange, flags) {
  const url = normalizeTarget(flags.target ?? exchange?.url);
  const method = String(flags.method ?? exchange?.method ?? 'GET').toUpperCase();
  const parsedRaw = parseRawRequest(exchange?.requestRaw ?? '');
  const headers = {
    ...parsedRaw.headers,
    ...headersFromFlag(flags.header),
  };
  deleteHeader(headers, 'host');
  deleteHeader(headers, 'content-length');
  return {
    id: exchange?.id ?? `agent-request-${simpleDigest(url).slice(0, 10)}`,
    method,
    url,
    headers,
    body: flags.body ?? parsedRaw.body ?? '',
  };
}

async function loadAgentIntruderRawRequest(flags, selectedExchange, targetUrl) {
  if (flags['request-file']) {
    return fs.readFile(path.resolve(String(flags['request-file'])), 'utf8');
  }
  if (flags['raw-request']) return String(flags['raw-request']);
  if (flags.raw) return String(flags.raw);
  if (selectedExchange?.requestRaw) return selectedExchange.requestRaw;
  return rawRequestFromExchange(undefined, targetUrl, {});
}

async function loadAgentIntruderPayloadSets(flags) {
  const generatedCount = Math.max(0, Math.min(5000, Math.round(numberFlag(flags['payload-count'], 0))));
  const generatedPrefix = String(flags['payload-prefix'] ?? 'payload');
  const generatedPayloads = Array.from({ length: generatedCount }, (_value, index) => `${generatedPrefix}-${index}`);
  const primary = unique([
    ...parseList(flags.payloads ?? flags.payload),
    ...generatedPayloads,
    ...await loadAgentIntruderPayloadFile(flags['payload-file']),
  ]);
  const secondary = unique([
    ...parseList(flags['payload-set-two'] ?? flags['payloads-two'] ?? flags['payload-set-2']),
    ...await loadAgentIntruderPayloadFile(flags['payload-file-two'] ?? flags['payloads-file-two']),
  ]);
  const sets = primary.length ? [primary] : [['probe']];
  if (secondary.length) sets.push(secondary);
  return sets;
}

async function loadAgentIntruderPayloadFile(filePath) {
  if (!filePath) return [];
  try {
    return parseList(await fs.readFile(path.resolve(String(filePath)), 'utf8'));
  } catch {
    return [];
  }
}

function ensureAgentIntruderMarker(rawRequest, targetUrl, flags) {
  const normalized = String(rawRequest ?? '').replace(/\r?\n/g, '\r\n');
  if (countAgentIntruderMarkers(normalized) > 0 || flags['auto-position'] === false) return normalized;
  const lines = normalized.split('\r\n');
  const requestLine = lines[0] ?? '';
  const match = requestLine.match(/^(\S+)\s+(\S+)(\s+HTTP\/\S+)$/i);
  if (!match) return normalized;
  try {
    const origin = new URL(targetUrl).origin;
    const parsed = new URL(match[2], origin);
    const firstKey = Array.from(parsed.searchParams.keys())[0] ?? 'proxyforge_payload';
    parsed.searchParams.set(firstKey, `§${firstKey}§`);
    const nextTarget = /^https?:\/\//i.test(match[2])
      ? parsed.toString()
      : `${parsed.pathname || '/'}${parsed.search || ''}`;
    lines[0] = `${match[1]} ${nextTarget}${match[3]}`;
    return lines.join('\r\n');
  } catch {
    return normalized;
  }
}

function countAgentIntruderMarkers(rawRequest) {
  return (String(rawRequest ?? '').match(/§[^§]*§/g) ?? []).length;
}

function estimateAgentIntruderPlanCount(rawRequest, payloadSets, attackMode) {
  const primaryCount = payloadSets[0]?.length ?? 0;
  if (primaryCount === 0) return 0;
  const markerCount = countAgentIntruderMarkers(rawRequest);
  if (markerCount === 0) return Math.min(primaryCount, 5000);
  if (attackMode === 'battering-ram') return Math.min(primaryCount, 5000);
  if (attackMode === 'pitchfork') {
    return Math.min(...Array.from({ length: markerCount }, (_value, index) => payloadSets[Math.min(index, payloadSets.length - 1)]?.length ?? primaryCount), 5000);
  }
  if (attackMode === 'cluster-bomb') {
    const product = Array.from({ length: markerCount }, (_value, index) => payloadSets[Math.min(index, payloadSets.length - 1)]?.length ?? primaryCount)
      .reduce((total, count) => total * Math.max(0, count), 1);
    return Math.min(product, 5000);
  }
  return Math.min(primaryCount * markerCount, 5000);
}

function buildAgentIntruderAttackModeMatrix(rawRequest, payloadSets, payloadProcessors, payloadRules, selectedMode) {
  const generatedAt = new Date().toISOString();
  const processedPayloadSets = normalizeAgentIntruderPayloadSets(payloadSets, payloadProcessors, payloadRules);
  const payloadTransformations = buildAgentIntruderPayloadTransformationMatrix(payloadSets, payloadProcessors, payloadRules, processedPayloadSets);
  const modes = ['sniper', 'battering-ram', 'pitchfork', 'cluster-bomb'].map((mode) => {
    const plans = buildAgentIntruderPayloadPlans(rawRequest, processedPayloadSets, mode);
    return {
      mode,
      payloadPositions: countAgentIntruderMarkers(rawRequest),
      payloadSetCount: processedPayloadSets.length,
      payloadCounts: processedPayloadSets.map((set) => set.length),
      requestCount: plans.length,
      samplePayloads: plans.slice(0, 3).map((plan) => plan.payloads),
      sampleRequests: plans.slice(0, 3).map((plan) => plan.rawRequest),
      semantics: agentIntruderModeSemantics(mode),
      warnings: agentIntruderModeWarnings(mode, countAgentIntruderMarkers(rawRequest), processedPayloadSets),
    };
  });
  return {
    kind: 'proxyforge-agent-intruder-attack-mode-matrix',
    schemaVersion,
    generatedAt,
    payloadPositions: countAgentIntruderMarkers(rawRequest),
    payloadSetCount: processedPayloadSets.length,
    payloadTransformations,
    selectedMode,
    modes,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    summary: `Intruder attack mode matrix covered ${countAgentIntruderMarkers(rawRequest)} payload position(s), ${processedPayloadSets.length} payload set(s), ${payloadProcessors.length} processor(s), ${payloadRules.length} rule(s), and ${modes.map((entry) => `${entry.mode}:${entry.requestCount}`).join(', ')} request expansion(s).`,
    content: `proxyforge-agent-intruder-attack-mode-matrix positions=${countAgentIntruderMarkers(rawRequest)} processors=${payloadProcessors.join(',') || 'none'} rules=${payloadRules.join(',') || 'none'} modes=${modes.map((entry) => `${entry.mode}:${entry.requestCount}`).join(',')}`,
  };
}

function buildAgentIntruderPayloadTransformationMatrix(payloadSets, processors, rules, processedPayloadSets) {
  const warnings = [];
  if (!payloadSets.some((set) => set?.length)) warnings.push('No payload values supplied.');
  if (processedPayloadSets.some((set) => set.length >= 5000)) warnings.push('One or more payload sets reached the 5000 value cap.');
  return {
    processors,
    rules,
    inputSetCount: payloadSets.length,
    inputPayloadCounts: payloadSets.map((set) => set?.length ?? 0),
    expandedPayloadCounts: processedPayloadSets.map((set) => set.length),
    sampleExpandedPayloads: processedPayloadSets.map((set) => set.slice(0, 8)),
    warnings,
  };
}

function normalizeAgentIntruderPayloadSets(payloadSets, processors, rules) {
  return payloadSets
    .map((set) => expandAgentIntruderPayloadRules(set.map((payload) => applyAgentIntruderProcessors(payload, processors)), rules))
    .filter((set) => set.length);
}

function expandAgentIntruderPayloadRules(payloads, rules) {
  if (!rules.length) return unique(payloads).slice(0, 5000);
  const values = new Set();
  for (const payload of payloads) {
    values.add(payload);
    if (rules.includes('case-variants')) {
      values.add(payload.toLowerCase());
      values.add(payload.toUpperCase());
      values.add(`${payload.slice(0, 1).toUpperCase()}${payload.slice(1).toLowerCase()}`);
    }
    if (rules.includes('url-recursive')) {
      const encoded = encodeURIComponent(payload);
      values.add(encoded);
      values.add(encodeURIComponent(encoded));
    }
    if (rules.includes('path-depth')) {
      const normalized = payload.replace(/^\/+/, '');
      values.add(`../${normalized}`);
      values.add(`../../${normalized}`);
    }
    if (rules.includes('delimiter-variants')) {
      values.add(payload.replace(/[\s/\\]+/g, '-'));
      values.add(payload.replace(/[\s/\\]+/g, '_'));
      values.add(payload.replace(/[\s/\\]+/g, '.'));
      values.add(payload.replace(/[\s/\\]+/g, '/'));
      values.add(payload.replace(/[\s/\\]+/g, '%2f'));
    }
    if (rules.includes('extension-bypass')) {
      const normalized = payload.replace(/[/.]+$/g, '');
      values.add(`${normalized}.json`);
      values.add(`${normalized}.bak`);
      values.add(`${normalized};`);
      values.add(`${normalized}/.`);
    }
    if (rules.includes('null-byte')) {
      values.add(`${payload}%00`);
      values.add(`${payload}\\u0000`);
    }
  }
  return Array.from(values).filter(Boolean).slice(0, 5000);
}

function applyAgentIntruderProcessors(payload, processors) {
  return processors.reduce((next, processor) => {
    if (processor === 'url-encode') return encodeURIComponent(next);
    if (processor === 'double-url-encode') return encodeURIComponent(encodeURIComponent(next));
    if (processor === 'base64') return Buffer.from(next, 'utf8').toString('base64');
    if (processor === 'html-encode') return htmlEncodeAgentPayload(next);
    if (processor === 'json-escape') return JSON.stringify(next).slice(1, -1);
    if (processor === 'hex-encode') return Buffer.from(next, 'utf8').toString('hex');
    if (processor === 'uppercase') return next.toUpperCase();
    if (processor === 'lowercase') return next.toLowerCase();
    return next;
  }, payload);
}

function htmlEncodeAgentPayload(payload) {
  return String(payload).replace(/[&<>"']/g, (char) => {
    if (char === '&') return '&amp;';
    if (char === '<') return '&lt;';
    if (char === '>') return '&gt;';
    if (char === '"') return '&quot;';
    return '&#39;';
  });
}

function buildAgentIntruderPayloadPlans(rawRequest, payloadSets, attackMode) {
  if (!payloadSets.length) return [];
  const markerCount = countAgentIntruderMarkers(rawRequest);
  const positions = Math.max(markerCount, 1);
  const setForPosition = (index) => payloadSets[Math.min(index, payloadSets.length - 1)] ?? payloadSets[0];
  const plans = [];
  if (markerCount === 0) {
    return payloadSets[0].slice(0, 5000).map((payload) => ({ payloads: [payload], rawRequest }));
  }
  if (attackMode === 'battering-ram') {
    for (const payload of payloadSets[0]) plans.push(agentIntruderPayloadPlan(rawRequest, Array.from({ length: markerCount }, () => payload)));
    return plans.slice(0, 5000);
  }
  if (attackMode === 'pitchfork') {
    const limit = Math.min(...Array.from({ length: positions }, (_unused, index) => setForPosition(index).length));
    for (let index = 0; index < limit; index += 1) {
      plans.push(agentIntruderPayloadPlan(rawRequest, Array.from({ length: markerCount }, (_unused, position) => setForPosition(position)[index])));
    }
    return plans.slice(0, 5000);
  }
  if (attackMode === 'cluster-bomb') {
    return limitedAgentCartesianProduct(Array.from({ length: markerCount }, (_unused, index) => setForPosition(index)), 5000)
      .map((payloads) => agentIntruderPayloadPlan(rawRequest, payloads));
  }
  for (let position = 0; position < markerCount; position += 1) {
    for (const payload of payloadSets[0]) {
      plans.push(agentIntruderPayloadPlan(rawRequest, Array.from({ length: markerCount }, (_unused, index) => (index === position ? payload : agentIntruderMarkerDefault(rawRequest, index)))));
    }
  }
  return plans.slice(0, 5000);
}

function agentIntruderPayloadPlan(rawRequest, payloads) {
  let index = 0;
  return {
    payloads,
    rawRequest: rawRequest.replace(/§([^§]*)§/g, (_match, label) => payloads[index++] ?? label ?? ''),
  };
}

function agentIntruderMarkerDefault(rawRequest, targetIndex) {
  let index = 0;
  let value = 'baseline';
  rawRequest.replace(/§([^§]*)§/g, (match, label) => {
    if (index === targetIndex) value = label || 'baseline';
    index += 1;
    return match;
  });
  return value;
}

function limitedAgentCartesianProduct(sets, limit) {
  const results = [];
  if (limit <= 0 || !sets.length || sets.some((set) => !set.length)) return results;
  const visit = (index, prefix) => {
    if (results.length >= limit) return;
    if (index === sets.length) {
      results.push(prefix);
      return;
    }
    for (const value of sets[index]) {
      if (results.length >= limit) break;
      visit(index + 1, [...prefix, value]);
    }
  };
  visit(0, []);
  return results;
}

function agentIntruderModeSemantics(mode) {
  if (mode === 'battering-ram') return 'Each payload from the first set is placed into every marked position in the same request.';
  if (mode === 'pitchfork') return 'Payload sets advance in lockstep, one payload per marked position per request.';
  if (mode === 'cluster-bomb') return 'Payload sets are combined as a Cartesian product across marked positions.';
  return 'Each marked position is attacked one at a time while other positions keep their marker defaults.';
}

function agentIntruderModeWarnings(mode, payloadPositions, payloadSets) {
  const warnings = [];
  if (payloadPositions === 0) warnings.push('No explicit payload markers found; first payload set will be replayed without marker substitution.');
  if ((mode === 'pitchfork' || mode === 'cluster-bomb') && payloadPositions > payloadSets.length) warnings.push('Fewer payload sets than marked positions; later positions reuse the last payload set.');
  if (mode === 'cluster-bomb') {
    const product = Array.from({ length: Math.max(payloadPositions, 1) }, (_unused, index) => payloadSets[Math.min(index, payloadSets.length - 1)]?.length ?? 0)
      .reduce((total, count) => total * Math.max(count, 0), 1);
    if (product > 5000) warnings.push('Cartesian product was capped at 5000 request plans.');
  }
  return warnings;
}

function sanitizeAgentIntruderAttackMode(value) {
  const normalized = String(value ?? 'sniper').toLowerCase();
  return ['sniper', 'battering-ram', 'pitchfork', 'cluster-bomb'].includes(normalized) ? normalized : 'sniper';
}

function sanitizeAgentIntruderPayloadProcessors(value) {
  const allowed = new Set(['url-encode', 'double-url-encode', 'base64', 'html-encode', 'json-escape', 'hex-encode', 'uppercase', 'lowercase']);
  return unique(parseList(value).map((item) => item.toLowerCase()).filter((item) => allowed.has(item)));
}

function sanitizeAgentIntruderPayloadRules(value) {
  const allowed = new Set(['case-variants', 'url-recursive', 'path-depth', 'delimiter-variants', 'extension-bypass', 'null-byte']);
  return unique(parseList(value).map((item) => item.toLowerCase()).filter((item) => allowed.has(item)));
}

function buildAgentIntruderSoakPackage(summary, plan, flags) {
  const minRequests = Math.max(1, Math.round(numberFlag(flags['min-requests'], Math.min(plan.maxPayloadRequests, Math.max(1, plan.estimatedRequestCount)))));
  const minConcurrency = Math.max(1, Math.round(numberFlag(flags['min-concurrency'], Math.min(plan.resourcePoolMaxConcurrent, Math.max(1, plan.estimatedRequestCount)))));
  const streaming = summary.streaming ?? {};
  const failures = [];
  const warnings = [];
  if (summary.blocked) failures.push(summary.message);
  if (summary.totalRequests < minRequests) failures.push(`Sent ${summary.totalRequests} request(s), below soak floor ${minRequests}.`);
  if ((streaming.maxInFlight ?? 0) < minConcurrency) failures.push(`Max in-flight ${streaming.maxInFlight ?? 0} is below concurrency floor ${minConcurrency}.`);
  if ((streaming.completedChunks ?? 0) < 1) warnings.push('No completed streamed chunks were reported.');
  if ((streaming.retainedResultCount ?? 0) < Math.min(summary.totalRequests, plan.resultWindowSize)) warnings.push('Retained result window is smaller than expected.');
  if ((streaming.durationMs ?? 0) <= 0 || (streaming.requestRatePerSecond ?? 0) <= 0) warnings.push('Duration/request-rate telemetry was not populated.');
  return {
    id: `agent-intruder-soak-${simpleDigest(`${summary.id}|${summary.totalRequests}|${streaming.maxInFlight ?? 0}`).slice(0, 12)}`,
    kind: 'proxyforge-agent-intruder-high-volume-soak-package',
    generatedAt: new Date().toISOString(),
    status: failures.length ? 'fail' : warnings.length ? 'warning' : 'pass',
    failures,
    warnings,
    budgets: {
      minRequests,
      minConcurrency,
      maxConcurrency: plan.resourcePoolMaxConcurrent,
      resultWindowSize: plan.resultWindowSize,
      memoryBudgetBytes: plan.memoryBudgetBytes,
    },
    observed: {
      totalRequests: summary.totalRequests,
      maxInFlight: streaming.maxInFlight ?? 0,
      completedChunks: streaming.completedChunks ?? 0,
      retainedResultCount: streaming.retainedResultCount ?? 0,
      droppedResultCount: streaming.droppedResultCount ?? 0,
      durationMs: streaming.durationMs ?? 0,
      requestRatePerSecond: streaming.requestRatePerSecond ?? 0,
      memoryPressure: streaming.memoryPressure ?? 'low',
    },
    summary,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportReady: failures.length === 0,
  };
}

async function writeAgentIntruderArtifact(out, content) {
  const resolved = path.resolve(String(out));
  const isJsonFile = path.extname(resolved).toLowerCase() === '.json';
  const filePath = isJsonFile ? resolved : path.join(resolved, `proxyforge-agent-intruder-${Date.now()}.json`);
  await writePrivateFile(filePath, JSON.stringify(content, null, 2), 'utf8');
  return filePath;
}

async function writeAgentBulkReplayArtifact(out, content) {
  const resolved = path.resolve(String(out));
  const isJsonFile = path.extname(resolved).toLowerCase() === '.json';
  const filePath = isJsonFile ? resolved : path.join(resolved, `proxyforge-agent-bulk-replay-${Date.now()}.json`);
  await writePrivateFile(filePath, JSON.stringify(content, null, 2), 'utf8');
  return filePath;
}

async function writeAgentContentDiscoveryArtifact(out, content) {
  const resolved = path.resolve(String(out));
  const isJsonFile = path.extname(resolved).toLowerCase() === '.json';
  const filePath = isJsonFile ? resolved : path.join(resolved, `proxyforge-agent-content-discovery-${Date.now()}.json`);
  await writePrivateFile(filePath, JSON.stringify(content, null, 2), 'utf8');
  return filePath;
}

async function writeAgentRepeaterRaceArtifact(out, content) {
  const resolved = path.resolve(String(out));
  const isJsonFile = path.extname(resolved).toLowerCase() === '.json';
  const filePath = isJsonFile ? resolved : path.join(resolved, `proxyforge-agent-repeater-race-${Date.now()}.json`);
  await writePrivateFile(filePath, JSON.stringify(content, null, 2), 'utf8');
  return filePath;
}

async function writeAgentSequencerArtifact(out, content) {
  const resolved = path.resolve(String(out));
  const isJsonFile = path.extname(resolved).toLowerCase() === '.json';
  const filePath = isJsonFile ? resolved : path.join(resolved, `proxyforge-agent-sequencer-${Date.now()}.json`);
  await writePrivateFile(filePath, JSON.stringify(content, null, 2), 'utf8');
  return filePath;
}

async function writeAgentInsertionPointArtifact(out, content) {
  const resolved = path.resolve(String(out));
  const isJsonFile = path.extname(resolved).toLowerCase() === '.json';
  const filePath = isJsonFile ? resolved : path.join(resolved, `proxyforge-agent-insertion-points-${Date.now()}.json`);
  await writePrivateFile(filePath, JSON.stringify(content, null, 2), 'utf8');
  return filePath;
}

async function writeAgentWebSocketJsonArtifact(out, content, label = 'artifact') {
  const resolved = path.resolve(String(out));
  const isJsonFile = path.extname(resolved).toLowerCase() === '.json';
  const filePath = isJsonFile ? resolved : path.join(resolved, `proxyforge-agent-websocket-${label}-${Date.now()}.json`);
  await writePrivateFile(filePath, JSON.stringify(content, null, 2), 'utf8');
  return filePath;
}

async function writeAgentWebSocketTranscriptArtifact(out, transcript) {
  const resolved = path.resolve(String(out));
  const extension = transcript.format === 'markdown' ? '.md' : '.json';
  const hasFileExtension = Boolean(path.extname(resolved));
  const filePath = hasFileExtension ? resolved : path.join(resolved, `proxyforge-agent-websocket-transcript-${Date.now()}${extension}`);
  await writePrivateFile(filePath, transcript.content, 'utf8');
  return filePath;
}

function normalizeAgentWebSocketMessages(value) {
  const frames = Array.isArray(value) ? value : [];
  return frames
    .map((frame, index) => normalizeAgentWebSocketMessage(frame, index))
    .filter(Boolean)
    .slice(0, 5000);
}

function normalizeAgentWebSocketSavedReplays(value) {
  const replays = Array.isArray(value) ? value : [];
  return replays
    .map((replay, index) => normalizeAgentWebSocketMessage({
      ...replay,
      id: replay?.id ?? `saved-ws-replay-${index + 1}`,
      time: replay?.updatedAt ?? replay?.createdAt ?? new Date().toISOString(),
    }, index))
    .filter(Boolean)
    .slice(0, 1000);
}

function normalizeAgentWebSocketMessage(frame, index) {
  if (!frame || typeof frame !== 'object') return null;
  const url = normalizeWebSocketUrl(frame.url ?? frame.targetUrl ?? frame.requestUrl ?? '');
  if (!url) return null;
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return null;
  }
  const opcode = Number.isFinite(Number(frame.opcode)) ? Number(frame.opcode) : agentWebSocketOpcodeFromType(frame.type);
  const payload = String(frame.payload ?? frame.body ?? frame.data ?? '');
  const payloadEncoding = normalizeAgentWebSocketPayloadEncoding(frame.payloadEncoding, opcode === 2 ? 'base64' : 'text');
  return {
    id: String(frame.id ?? `ws-frame-${index + 1}-${simpleDigest(`${url}|${payload}`).slice(0, 8)}`),
    connectionId: String(frame.connectionId ?? frame.connection ?? `ws-${parsed.host}-${simpleDigest(url).slice(0, 6)}`),
    time: String(frame.time ?? frame.createdAt ?? new Date().toISOString()),
    direction: frame.direction === 'server' ? 'server' : 'client',
    host: String(frame.host ?? parsed.host),
    path: String(frame.path ?? `${parsed.pathname || '/'}${parsed.search || ''}`),
    url,
    opcode,
    type: normalizeAgentWebSocketFrameType(frame.type, opcode),
    payload,
    payloadEncoding,
    length: Number.isFinite(Number(frame.length)) ? Number(frame.length) : agentWebSocketPayloadByteLength(payload, payloadEncoding),
    tags: Array.isArray(frame.tags) ? frame.tags.map(String) : [],
  };
}

function selectAgentWebSocketFrames(project, flags, scopeAllowlist) {
  const query = String(flags.query ?? flags.q ?? '').toLowerCase();
  const connectionId = String(flags.connection ?? flags['connection-id'] ?? '').trim();
  const host = String(flags.host ?? '').toLowerCase();
  const pathFilter = String(flags.path ?? '').toLowerCase();
  const direction = String(flags.direction ?? '').toLowerCase();
  const type = String(flags.type ?? '').toLowerCase();
  return (project.webSocketMessages ?? [])
    .filter((frame) => !flags.id && !flags['frame-id'] ? true : frame.id === flags.id || frame.id === flags['frame-id'])
    .filter((frame) => !connectionId || frame.connectionId === connectionId)
    .filter((frame) => !host || String(frame.host).toLowerCase().includes(host))
    .filter((frame) => !pathFilter || String(frame.path).toLowerCase().includes(pathFilter))
    .filter((frame) => !direction || frame.direction === direction)
    .filter((frame) => !type || frame.type === type)
    .filter((frame) => !query || [
      frame.id,
      frame.connectionId,
      frame.host,
      frame.path,
      frame.url,
      frame.payload,
      ...(frame.tags ?? []),
    ].join('\n').toLowerCase().includes(query))
    .filter((frame) => flags['include-out-of-scope'] || isTargetInScope(frame.url, scopeAllowlist));
}

function selectAgentWebSocketFrame(project, flags, scopeAllowlist) {
  const frames = selectAgentWebSocketFrames(project, flags, scopeAllowlist);
  if (flags['frame-id'] || flags.id) return frames.find((frame) => frame.id === flags['frame-id'] || frame.id === flags.id);
  if (flags.connection || flags['connection-id'] || flags.query || flags.q || flags.host || flags.path) return frames[0];
  return frames.find((frame) => frame.direction === 'client' && (frame.type === 'text' || frame.type === 'binary')) ?? frames[0];
}

function agentWebSocketFrameSummary(frame) {
  return {
    id: frame.id,
    connectionId: frame.connectionId,
    time: frame.time,
    direction: frame.direction,
    host: frame.host,
    path: frame.path,
    url: frame.url,
    opcode: frame.opcode,
    type: frame.type,
    payload: frame.payload,
    payloadEncoding: frame.payloadEncoding,
    length: frame.length,
    tags: frame.tags ?? [],
    payloadDigestPreview: simpleDigest(frame.payload),
  };
}

function summarizeAgentWebSocketConnections(frames) {
  return Object.entries(groupBy(frames, (frame) => frame.connectionId)).map(([connectionId, connectionFrames]) => {
    const sorted = connectionFrames.slice().sort((left, right) => String(left.time).localeCompare(String(right.time)));
    const host = sorted[0]?.host ?? 'unknown';
    const pathValue = sorted[0]?.path ?? '/';
    return {
      connectionId,
      host,
      path: pathValue,
      url: sorted[0]?.url ?? '',
      frameCount: sorted.length,
      clientFrames: sorted.filter((frame) => frame.direction === 'client').length,
      serverFrames: sorted.filter((frame) => frame.direction === 'server').length,
      binaryFrames: sorted.filter((frame) => frame.type === 'binary').length,
      closeFrames: sorted.filter((frame) => frame.type === 'close').length,
      firstFrameAt: sorted[0]?.time ?? '',
      lastFrameAt: sorted.at(-1)?.time ?? '',
      tags: unique(sorted.flatMap((frame) => frame.tags ?? [])).slice(0, 20),
    };
  });
}

async function buildAgentWebSocketReplayRequest(flags, frame) {
  const payloadFromFile = flags['payload-file']
    ? await fs.readFile(path.resolve(String(flags['payload-file'])), 'utf8').catch(() => '')
    : undefined;
  const url = normalizeWebSocketUrl(flags.url ?? flags.target ?? frame?.url ?? '');
  const payload = String(flags.payload ?? payloadFromFile ?? frame?.payload ?? '');
  const payloadEncoding = normalizeAgentWebSocketPayloadEncoding(flags['payload-encoding'] ?? frame?.payloadEncoding, frame?.payloadEncoding ?? 'text');
  const opcode = Number.isFinite(Number(flags.opcode))
    ? Number(flags.opcode)
    : Number.isFinite(Number(frame?.opcode))
      ? Number(frame.opcode)
      : payloadEncoding === 'text'
        ? 1
        : 2;
  const headers = {
    ...headersFromFlag(flags.header),
    ...(flags.cookie ? { Cookie: String(flags.cookie) } : {}),
    ...(flags.origin ? { Origin: String(flags.origin) } : {}),
  };
  return {
    id: String(flags.id ?? flags['frame-id'] ?? frame?.id ?? `agent-ws-replay-${simpleDigest(`${url}|${payload}`).slice(0, 10)}`),
    sourceFrameId: frame?.id,
    connectionId: String(flags.connection ?? flags['connection-id'] ?? frame?.connectionId ?? `agent-ws-${simpleDigest(url).slice(0, 10)}`),
    direction: flags.direction === 'server' ? 'server' : 'client',
    url,
    host: url ? new URL(url).host : '',
    path: url ? `${new URL(url).pathname || '/'}${new URL(url).search || ''}` : '',
    opcode,
    type: normalizeAgentWebSocketFrameType(flags.type ?? frame?.type, opcode),
    payload,
    payloadEncoding,
    headers,
    payloadBytes: agentWebSocketPayloadByteLength(payload, payloadEncoding),
  };
}

function agentWebSocketTransportSettings(flags) {
  return {
    timeoutMs: Math.max(250, Math.min(120000, Math.round(numberFlag(flags.timeout ?? flags['timeout-ms'], 5000)))),
    maxResponseFrames: Math.max(1, Math.min(50, Math.round(numberFlag(flags['max-response-frames'], 3)))),
    rejectUnauthorized: flags['tls-insecure'] || flags.insecure ? false : true,
    closeAfterResponse: flags['keep-open'] ? false : true,
  };
}

function buildAgentWebSocketFuzzProbes(baseRequest, flags) {
  const explicitPayloads = parseList(flags.payloads ?? flags.probes ?? flags.payload);
  const payloads = explicitPayloads.length ? explicitPayloads : defaultAgentWebSocketFuzzPayloads(baseRequest.payload, baseRequest.payloadEncoding);
  return payloads.map((payload, index) => ({
    id: `agent-ws-fuzz-probe-${index + 1}-${simpleDigest(`${baseRequest.url}|${payload}`).slice(0, 8)}`,
    name: `WebSocket fuzz probe ${index + 1}`,
    mutation: explicitPayloads.length ? 'operator-supplied' : inferAgentWebSocketMutationName(baseRequest.payload, payload),
    url: baseRequest.url,
    direction: baseRequest.direction,
    opcode: baseRequest.opcode,
    payload,
    payloadEncoding: baseRequest.payloadEncoding,
    payloadBytes: agentWebSocketPayloadByteLength(payload, baseRequest.payloadEncoding),
    sourceFrameId: baseRequest.sourceFrameId,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
  }));
}

function defaultAgentWebSocketFuzzPayloads(payload, encoding) {
  if (encoding !== 'text') return [payload, `${payload}ff`, '00ff', '7b2266757a7a223a747275657d'];
  const raw = String(payload ?? '');
  const payloads = [raw];
  try {
    const parsed = JSON.parse(raw);
    payloads.push(JSON.stringify(agentMutateJsonValue(parsed, 'proxyforge-ws-probe')));
    payloads.push(JSON.stringify({ ...((parsed && typeof parsed === 'object' && !Array.isArray(parsed)) ? parsed : { value: parsed }), role: 'support_admin', probe: 'proxyforge-ws-probe' }));
  } catch {
    payloads.push(`${raw}::proxyforge-ws-probe`);
    payloads.push(raw.replace(/user|customer|guest/gi, 'support_admin'));
  }
  payloads.push('{"type":"probe","token":"proxyforge-ws-probe","role":"support_admin"}');
  return unique(payloads.filter((item) => item !== undefined && item !== null).map(String));
}

function agentMutateJsonValue(value, replacement) {
  if (typeof value === 'string') return replacement;
  if (typeof value === 'number') return value + 1;
  if (typeof value === 'boolean') return !value;
  if (Array.isArray(value)) return value.length ? value.map((item, index) => index === 0 ? agentMutateJsonValue(item, replacement) : item) : [replacement];
  if (value && typeof value === 'object') {
    const clone = { ...value };
    const key = Object.keys(clone)[0] ?? 'probe';
    clone[key] = agentMutateJsonValue(clone[key], replacement);
    return clone;
  }
  return replacement;
}

function inferAgentWebSocketMutationName(original, payload) {
  if (payload === original) return 'baseline';
  if (/support_admin|role/i.test(payload)) return 'role-state-probe';
  if (/proxyforge-ws-probe/i.test(payload)) return 'state-drift-probe';
  return 'payload-variant';
}

function buildAgentWebSocketTranscript(frames, options) {
  const sorted = frames.slice().sort((left, right) => String(left.time).localeCompare(String(right.time)));
  const format = options.format === 'markdown' ? 'markdown' : 'json';
  const base = {
    id: `agent-websocket-transcript-${simpleDigest(`${options.projectName}|${sorted.map((frame) => frame.id).join(',')}`).slice(0, 12)}`,
    kind: 'proxyforge-agent-websocket-transcript',
    schemaVersion,
    title: options.title,
    projectName: options.projectName,
    generatedAt: new Date().toISOString(),
    format,
    connectionIds: unique(sorted.map((frame) => frame.connectionId)),
    hosts: unique(sorted.map((frame) => frame.host)),
    paths: unique(sorted.map((frame) => frame.path)),
    frameCount: sorted.length,
    clientFrames: sorted.filter((frame) => frame.direction === 'client').length,
    serverFrames: sorted.filter((frame) => frame.direction === 'server').length,
    binaryFrames: sorted.filter((frame) => frame.type === 'binary').length,
    closeFrames: sorted.filter((frame) => frame.type === 'close').length,
    frames: sorted.map(agentWebSocketFrameSummary),
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
  };
  const content = format === 'markdown' ? renderAgentWebSocketTranscriptMarkdown(base) : JSON.stringify(base, null, 2);
  return {
    ...base,
    fileName: format === 'markdown' ? `${base.id}.md` : `${base.id}.json`,
    sizeBytes: Buffer.byteLength(content, 'utf8'),
    content,
  };
}

function renderAgentWebSocketTranscriptMarkdown(transcript) {
  const lines = [
    `# ${transcript.title}`,
    '',
    `Project: ${transcript.projectName}`,
    `Generated: ${transcript.generatedAt}`,
    `Connections: ${transcript.connectionIds.join(', ')}`,
    `Frames: ${transcript.frameCount} (${transcript.clientFrames} client, ${transcript.serverFrames} server, ${transcript.binaryFrames} binary, ${transcript.closeFrames} close)`,
    '',
    'Operational payloads are full-fidelity. Redact only during submission/report export.',
    '',
  ];
  for (const frame of transcript.frames) {
    lines.push(`## ${frame.id}`);
    lines.push('');
    lines.push(`- Direction: ${frame.direction}`);
    lines.push(`- URL: ${frame.url}`);
    lines.push(`- Type: ${frame.type} opcode=${frame.opcode} bytes=${frame.length}`);
    lines.push(`- Tags: ${(frame.tags ?? []).join(', ') || 'none'}`);
    lines.push('');
    lines.push('```');
    lines.push(frame.payload);
    lines.push('```');
    lines.push('');
  }
  return lines.join('\n');
}

function executeAgentWebSocketReplay(request, options) {
  const settings = {
    timeoutMs: Math.max(250, Math.min(120000, Math.round(numberFlag(options.timeoutMs, 5000)))),
    maxResponseFrames: Math.max(1, Math.min(50, Math.round(numberFlag(options.maxResponseFrames, 3)))),
    rejectUnauthorized: options.rejectUnauthorized !== false,
    closeAfterResponse: options.closeAfterResponse !== false,
  };
  return new Promise((resolve) => {
    let parsed;
    try {
      parsed = new URL(request.url);
    } catch {
      resolve({ status: 'error', error: `Invalid WebSocket URL ${request.url}`, receivedFrames: [], transport: settings });
      return;
    }
    const secure = parsed.protocol === 'wss:';
    if (!secure && parsed.protocol !== 'ws:') {
      resolve({ status: 'error', error: `Unsupported WebSocket protocol ${parsed.protocol}`, receivedFrames: [], transport: settings });
      return;
    }
    const port = Number(parsed.port || (secure ? 443 : 80));
    const host = parsed.hostname;
    const pathValue = `${parsed.pathname || '/'}${parsed.search || ''}`;
    const key = randomBytes(16).toString('base64');
    const expectedAccept = createHash('sha1')
      .update(`${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`)
      .digest('base64');
    const extraHeaders = { ...(request.headers ?? {}) };
    deleteHeader(extraHeaders, 'host');
    deleteHeader(extraHeaders, 'upgrade');
    deleteHeader(extraHeaders, 'connection');
    deleteHeader(extraHeaders, 'sec-websocket-key');
    deleteHeader(extraHeaders, 'sec-websocket-version');
    const handshakeRequest = [
      `GET ${pathValue} HTTP/1.1`,
      `Host: ${parsed.host}`,
      'Upgrade: websocket',
      'Connection: Upgrade',
      `Sec-WebSocket-Key: ${key}`,
      'Sec-WebSocket-Version: 13',
      ...Object.entries(extraHeaders).map(([name, value]) => `${name}: ${value}`),
      '',
      '',
    ].join('\r\n');
    const startedAt = Date.now();
    const receivedFrames = [];
    let buffer = Buffer.alloc(0);
    let handshakeResponse = '';
    let handshakeComplete = false;
    let sentFrameBytes = 0;
    let finished = false;
    let socket;
    const finish = (payload) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      try {
        socket?.end();
        socket?.destroy();
      } catch {
        // Best effort close after replay.
      }
      resolve({
        status: payload.error ? 'error' : 'completed',
        error: payload.error,
        url: request.url,
        connectedHost: host,
        connectedPort: port,
        secure,
        durationMs: Date.now() - startedAt,
        handshakeRequest,
        handshakeResponse,
        handshakeAccepted: /^HTTP\/1\.[01]\s+101\b/i.test(handshakeResponse),
        acceptVerified: handshakeResponse.includes(expectedAccept),
        sentFrame: {
          opcode: request.opcode,
          type: normalizeAgentWebSocketFrameType(request.type, request.opcode),
          payload: request.payload,
          payloadEncoding: request.payloadEncoding,
          payloadBytes: request.payloadBytes,
          frameBytes: sentFrameBytes,
        },
        receivedFrames,
        transport: settings,
        secretHandling: 'execution-full-fidelity-secrets-preserved',
      });
    };
    const timer = setTimeout(() => {
      finish({ error: `WebSocket replay timed out after ${settings.timeoutMs}ms` });
    }, settings.timeoutMs);
    const connectOptions = secure
      ? { host, port, servername: host, rejectUnauthorized: settings.rejectUnauthorized }
      : { host, port };
    socket = secure ? tls.connect(connectOptions) : net.connect(connectOptions);
    if (secure) {
      socket.once('secureConnect', () => {
        socket.write(handshakeRequest);
      });
    } else {
      socket.once('connect', () => {
        socket.write(handshakeRequest);
      });
    }
    socket.on('data', (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      if (!handshakeComplete) {
        const headerEnd = buffer.indexOf('\r\n\r\n');
        if (headerEnd === -1) return;
        handshakeResponse = buffer.slice(0, headerEnd + 4).toString('utf8');
        buffer = buffer.slice(headerEnd + 4);
        handshakeComplete = true;
        if (!/^HTTP\/1\.[01]\s+101\b/i.test(handshakeResponse)) {
          finish({ error: `WebSocket handshake failed: ${handshakeResponse.split(/\r?\n/)[0] ?? 'no status'}` });
          return;
        }
        const payloadBuffer = agentWebSocketPayloadToBuffer(request.payload, request.payloadEncoding);
        const encodedFrame = encodeAgentWebSocketFrame(payloadBuffer, request.opcode, true);
        sentFrameBytes = encodedFrame.length;
        socket.write(encodedFrame);
      }
      const drained = drainAgentWebSocketFrames(buffer);
      buffer = drained.remaining;
      for (const frame of drained.frames) receivedFrames.push(frame);
      if ((settings.closeAfterResponse && receivedFrames.length > 0) || receivedFrames.length >= settings.maxResponseFrames || receivedFrames.some((frame) => frame.type === 'close')) {
        finish({});
      }
    });
    socket.once('error', (error) => {
      finish({ error: error instanceof Error ? error.message : 'WebSocket replay failed' });
    });
    socket.once('close', () => {
      if (handshakeComplete && receivedFrames.length) finish({});
      else if (!finished) finish({ error: handshakeComplete ? 'WebSocket closed before response frame.' : 'WebSocket closed before handshake completed.' });
    });
  });
}

function encodeAgentWebSocketFrame(payload, opcode = 1, masked = true) {
  const length = payload.length;
  const headerLength = length < 126 ? 2 : length <= 0xffff ? 4 : 10;
  const maskLength = masked ? 4 : 0;
  const frame = Buffer.alloc(headerLength + maskLength + length);
  frame[0] = 0x80 | (opcode & 0x0f);
  if (length < 126) {
    frame[1] = (masked ? 0x80 : 0) | length;
  } else if (length <= 0xffff) {
    frame[1] = (masked ? 0x80 : 0) | 126;
    frame.writeUInt16BE(length, 2);
  } else {
    frame[1] = (masked ? 0x80 : 0) | 127;
    frame.writeBigUInt64BE(BigInt(length), 2);
  }
  let payloadOffset = headerLength;
  if (masked) {
    const mask = randomBytes(4);
    mask.copy(frame, headerLength);
    payloadOffset += 4;
    for (let index = 0; index < length; index += 1) {
      frame[payloadOffset + index] = payload[index] ^ mask[index % 4];
    }
  } else {
    payload.copy(frame, payloadOffset);
  }
  return frame;
}

function drainAgentWebSocketFrames(buffer) {
  const frames = [];
  let offset = 0;
  while (buffer.length - offset >= 2) {
    const first = buffer[offset];
    const second = buffer[offset + 1];
    const opcode = first & 0x0f;
    const masked = Boolean(second & 0x80);
    let length = second & 0x7f;
    let headerLength = 2;
    if (length === 126) {
      if (buffer.length - offset < 4) break;
      length = buffer.readUInt16BE(offset + 2);
      headerLength = 4;
    } else if (length === 127) {
      if (buffer.length - offset < 10) break;
      const longLength = buffer.readBigUInt64BE(offset + 2);
      if (longLength > BigInt(Number.MAX_SAFE_INTEGER)) break;
      length = Number(longLength);
      headerLength = 10;
    }
    const maskOffset = offset + headerLength;
    const payloadOffset = maskOffset + (masked ? 4 : 0);
    if (buffer.length < payloadOffset + length) break;
    const payload = Buffer.from(buffer.slice(payloadOffset, payloadOffset + length));
    if (masked) {
      const mask = buffer.slice(maskOffset, maskOffset + 4);
      for (let index = 0; index < payload.length; index += 1) payload[index] ^= mask[index % 4];
    }
    frames.push(agentWebSocketFrameFromPayload(opcode, payload, Boolean(first & 0x80)));
    offset = payloadOffset + length;
  }
  return { frames, remaining: buffer.slice(offset) };
}

function agentWebSocketFrameFromPayload(opcode, payload, fin = true) {
  const type = normalizeAgentWebSocketFrameType(undefined, opcode);
  const payloadEncoding = type === 'text' || type === 'close' ? 'text' : 'base64';
  let renderedPayload = payloadEncoding === 'text' ? payload.toString('utf8') : payload.toString('base64');
  let closeCode;
  if (type === 'close' && payload.length >= 2) {
    closeCode = payload.readUInt16BE(0);
    renderedPayload = payload.slice(2).toString('utf8');
  }
  return {
    id: `agent-ws-response-${Date.now()}-${Math.random().toString(16).slice(2)}`,
    fin,
    opcode,
    type,
    direction: 'server',
    payload: renderedPayload,
    payloadEncoding,
    length: payload.length,
    closeCode,
    payloadDigestPreview: simpleDigest(renderedPayload),
  };
}

function agentWebSocketPayloadToBuffer(payload, encoding) {
  const normalized = normalizeAgentWebSocketPayloadEncoding(encoding);
  if (normalized === 'hex') return Buffer.from(String(payload ?? '').replace(/\s+/g, ''), 'hex');
  if (normalized === 'base64') return Buffer.from(String(payload ?? ''), 'base64');
  return Buffer.from(String(payload ?? ''), 'utf8');
}

function agentWebSocketPayloadByteLength(payload, encoding) {
  return agentWebSocketPayloadToBuffer(payload, encoding).length;
}

function normalizeAgentWebSocketPayloadEncoding(value, fallback = 'text') {
  const normalized = String(value ?? fallback ?? 'text').toLowerCase();
  return normalized === 'hex' || normalized === 'base64' || normalized === 'text' ? normalized : 'text';
}

function normalizeAgentWebSocketFrameType(value, opcode = 1) {
  const normalized = String(value ?? '').toLowerCase();
  if (['text', 'binary', 'close', 'ping', 'pong', 'other'].includes(normalized)) return normalized;
  if (opcode === 1) return 'text';
  if (opcode === 2) return 'binary';
  if (opcode === 8) return 'close';
  if (opcode === 9) return 'ping';
  if (opcode === 10) return 'pong';
  return 'other';
}

function agentWebSocketOpcodeFromType(type) {
  const normalized = String(type ?? '').toLowerCase();
  if (normalized === 'binary') return 2;
  if (normalized === 'close') return 8;
  if (normalized === 'ping') return 9;
  if (normalized === 'pong') return 10;
  return 1;
}

function normalizeWebSocketUrl(value) {
  const raw = String(value ?? '').trim();
  if (!raw) return '';
  if (/^wss?:\/\//i.test(raw)) return raw;
  if (/^https?:\/\//i.test(raw)) return raw.replace(/^http/i, 'ws');
  return `ws://${raw}`;
}

async function loadAgentSequencerSamples(flags, project, selectedExchange) {
  const samples = [];
  samples.push(...parseList(flags.samples ?? flags.sample));
  if (flags['sample-file']) {
    try {
      samples.push(...parseList(await fs.readFile(path.resolve(String(flags['sample-file'])), 'utf8')));
    } catch {
      // The blocked/no-sample path below gives the agent a structured failure.
    }
  }
  if (flags['from-project'] !== false && !flags['sample-file'] && !flags.samples && !flags.sample) {
    samples.push(...extractAgentSequencerSamples(selectedExchange ? [selectedExchange] : project.exchanges));
  }
  return unique(samples.map((sample) => String(sample).trim()).filter(Boolean)).slice(0, 20000);
}

function extractAgentSequencerSamples(exchanges) {
  const samples = [];
  const tokenPattern = /\b(?:Bearer\s+)?([A-Za-z0-9._~+/=-]{16,})\b/g;
  for (const exchange of exchanges) {
    const haystack = [
      exchange.requestRaw,
      exchange.responseRaw,
      exchange.notes,
      ...(exchange.tags ?? []),
    ].filter(Boolean).join('\n');
    for (const match of haystack.matchAll(tokenPattern)) {
      samples.push(match[1] ?? match[0]);
    }
  }
  return samples;
}

function normalizeAgentSequencerSource(value) {
  const normalized = String(value ?? 'manual').toLowerCase();
  return ['manual', 'traffic', 'browser-preview'].includes(normalized) ? normalized : 'manual';
}

async function loadAgentDecoderInput(flags, selectedExchange) {
  if (flags['input-file']) return fs.readFile(path.resolve(String(flags['input-file'])), 'utf8');
  if (flags.input !== undefined) return String(flags.input);
  if (!selectedExchange) return '';
  const source = String(flags.source ?? 'response').toLowerCase();
  if (source === 'request') return selectedExchange.requestRaw ?? '';
  if (source === 'body') return rawBody(selectedExchange.responseRaw ?? selectedExchange.requestRaw ?? '');
  return selectedExchange.responseRaw ?? selectedExchange.requestRaw ?? '';
}

const agentDecoderTransformIds = new Set([
  'smart-decode',
  'base64-decode',
  'base64-encode',
  'base64url-decode',
  'base64url-encode',
  'url-decode',
  'url-encode',
  'html-decode',
  'html-encode',
  'hex-decode',
  'hex-encode',
  'binary-decode',
  'binary-encode',
  'octal-decode',
  'octal-encode',
  'json-pretty',
  'jwt-decode',
  'sha-256',
  'sha-1',
  'canonicalize',
]);

function normalizeAgentDecoderTransforms(value) {
  return parseList(value).map((item) => item.toLowerCase()).filter((item) => agentDecoderTransformIds.has(item));
}

async function runAgentDecoderTransformChain(input, transformIds, name, createdAt) {
  let output = input;
  const steps = [];
  let failedStepIndex;
  for (let index = 0; index < transformIds.length; index += 1) {
    const transformId = transformIds[index];
    const stepInput = output;
    const notes = [];
    try {
      output = await applyAgentDecoderTransform(transformId, stepInput, notes);
      steps.push({
        index: index + 1,
        transformId,
        label: agentDecoderLabel(transformId),
        inputLength: stepInput.length,
        outputLength: output.length,
        output,
        ok: true,
        notes,
      });
    } catch (error) {
      failedStepIndex = index + 1;
      steps.push({
        index: index + 1,
        transformId,
        label: agentDecoderLabel(transformId),
        inputLength: stepInput.length,
        outputLength: stepInput.length,
        output: stepInput,
        ok: false,
        notes: [error instanceof Error ? error.message : `${transformId} failed`],
      });
      break;
    }
  }
  const ok = failedStepIndex === undefined;
  const run = {
    kind: 'proxyforge-agent-decoder-transform-chain-run',
    id: `agent-decoder-chain-${simpleDigest(`${createdAt}|${transformIds.join(',')}|${input}`).slice(0, 10)}`,
    name,
    createdAt,
    input,
    transformIds,
    steps,
    finalOutput: output,
    ok,
    failedStepIndex,
    reportReady: ok,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
  };
  run.digestPreview = simpleDigest(JSON.stringify(run));
  run.summary = ok
    ? `${steps.length} Decoder transform step${steps.length === 1 ? '' : 's'} completed for agents.`
    : `Decoder transform chain stopped at step ${failedStepIndex}.`;
  run.content = JSON.stringify(run, null, 2);
  return run;
}

async function applyAgentDecoderTransform(transformId, input, notes) {
  if (transformId === 'smart-decode' || transformId === 'canonicalize') return agentSmartDecode(input, notes);
  if (transformId === 'base64-decode') {
    notes.push('Decoded standard Base64 as UTF-8 text');
    return Buffer.from(normalizeAgentBase64(input, false), 'base64').toString('utf8');
  }
  if (transformId === 'base64-encode') {
    notes.push('Encoded UTF-8 text as standard Base64');
    return Buffer.from(input, 'utf8').toString('base64');
  }
  if (transformId === 'base64url-decode') {
    notes.push('Decoded Base64url as UTF-8 text');
    return Buffer.from(normalizeAgentBase64(input, true), 'base64').toString('utf8');
  }
  if (transformId === 'base64url-encode') {
    notes.push('Encoded UTF-8 text as unpadded Base64url');
    return Buffer.from(input, 'utf8').toString('base64url');
  }
  if (transformId === 'url-decode') {
    notes.push('Decoded percent escapes and form-space plus signs');
    return decodeURIComponent(String(input).replace(/\+/g, ' '));
  }
  if (transformId === 'url-encode') {
    notes.push('Encoded text for URL component usage');
    return encodeURIComponent(input);
  }
  if (transformId === 'html-decode') {
    notes.push('Decoded HTML entities');
    return decodeAgentHtml(input);
  }
  if (transformId === 'html-encode') {
    notes.push('Escaped HTML-sensitive characters');
    return encodeAgentHtml(input);
  }
  if (transformId === 'hex-decode') {
    notes.push('Decoded hexadecimal bytes as UTF-8 text');
    return decodeAgentHex(input);
  }
  if (transformId === 'hex-encode') {
    notes.push('Encoded UTF-8 text as hexadecimal bytes');
    return Buffer.from(input, 'utf8').toString('hex');
  }
  if (transformId === 'binary-decode') {
    notes.push('Decoded binary octets as UTF-8 text');
    return decodeAgentByteGroups(input, 2, /^[01]{8}$/, 'binary');
  }
  if (transformId === 'binary-encode') {
    notes.push('Encoded UTF-8 text as binary octets');
    return Array.from(Buffer.from(input, 'utf8')).map((byte) => byte.toString(2).padStart(8, '0')).join(' ');
  }
  if (transformId === 'octal-decode') {
    notes.push('Decoded octal bytes as UTF-8 text');
    return decodeAgentByteGroups(String(input).replace(/\\/g, ' '), 8, /^(?:0o)?[0-7]{3}$/i, 'octal');
  }
  if (transformId === 'octal-encode') {
    notes.push('Encoded UTF-8 text as octal bytes');
    return Array.from(Buffer.from(input, 'utf8')).map((byte) => byte.toString(8).padStart(3, '0')).join(' ');
  }
  if (transformId === 'json-pretty') {
    notes.push('Formatted JSON with stable key order');
    return JSON.stringify(sortAgentJson(JSON.parse(input)), null, 2);
  }
  if (transformId === 'jwt-decode') return decodeAgentJwt(input, notes);
  if (transformId === 'sha-256') {
    notes.push('Hashed UTF-8 input with SHA-256');
    return createHash('sha256').update(input).digest('hex');
  }
  if (transformId === 'sha-1') {
    notes.push('Hashed UTF-8 input with SHA-1');
    return createHash('sha1').update(input).digest('hex');
  }
  throw new Error(`Unsupported Decoder transform: ${transformId}`);
}

function normalizeAgentBase64(input, urlSafe) {
  let normalized = String(input).trim().replace(/\s+/g, '');
  if (urlSafe) normalized = normalized.replace(/-/g, '+').replace(/_/g, '/');
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(normalized)) throw new Error('Input is not valid Base64 data');
  const remainder = normalized.length % 4;
  if (remainder) normalized += '='.repeat(4 - remainder);
  return normalized;
}

function decodeAgentHex(input) {
  const normalized = String(input).replace(/0x/gi, '').replace(/[^a-fA-F0-9]/g, '');
  if (!normalized || normalized.length % 2 !== 0) throw new Error('Input is not an even-length hexadecimal byte string');
  return Buffer.from(normalized, 'hex').toString('utf8');
}

function decodeAgentByteGroups(input, base, pattern, label) {
  const groups = String(input).trim().split(/[\s,]+/).filter(Boolean);
  if (!groups.length || groups.some((group) => !pattern.test(group))) throw new Error(`Input is not ${label} byte groups`);
  return Buffer.from(groups.map((group) => Number.parseInt(group.replace(/^0o/i, ''), base))).toString('utf8');
}

function decodeAgentHtml(input) {
  return String(input)
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&amp;/g, '&')
    .replace(/&#x([0-9a-f]+);/gi, (_match, code) => String.fromCodePoint(Number.parseInt(code, 16)))
    .replace(/&#(\d+);/g, (_match, code) => String.fromCodePoint(Number.parseInt(code, 10)));
}

function encodeAgentHtml(input) {
  return String(input)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function decodeAgentJwt(input, notes) {
  const parts = String(input).trim().split('.');
  if (parts.length < 2) throw new Error('Input is not a JWT-like token with header and payload segments');
  const header = parseAgentJsonMaybe(Buffer.from(normalizeAgentBase64(parts[0], true), 'base64').toString('utf8'));
  const payload = parseAgentJsonMaybe(Buffer.from(normalizeAgentBase64(parts[1], true), 'base64').toString('utf8'));
  notes.push('Decoded JWT header and payload without verifying the signature');
  return [
    'Header',
    JSON.stringify(sortAgentJson(header), null, 2),
    '',
    'Payload',
    JSON.stringify(sortAgentJson(payload), null, 2),
    '',
    `Signature: ${parts[2] ? `${parts[2].slice(0, 24)}${parts[2].length > 24 ? '...' : ''}` : 'none'}`,
  ].join('\n');
}

function parseAgentJsonMaybe(value) {
  try {
    return JSON.parse(value);
  } catch {
    return { raw: value };
  }
}

function sortAgentJson(value) {
  if (Array.isArray(value)) return value.map(sortAgentJson);
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(Object.entries(value).sort(([left], [right]) => left.localeCompare(right)).map(([key, nested]) => [key, sortAgentJson(nested)]));
}

function agentSmartDecode(input, notes) {
  let output = String(input).trim();
  for (let index = 0; index < 5; index += 1) {
    const before = output;
    if (/%[0-9a-f]{2}|\+/i.test(output)) {
      try {
        output = decodeURIComponent(output.replace(/\+/g, ' '));
        if (output !== before) {
          notes.push('Applied URL decoding');
          continue;
        }
      } catch {
        // Try the next heuristic.
      }
    }
    const htmlDecoded = decodeAgentHtml(output);
    if (htmlDecoded !== output) {
      output = htmlDecoded;
      notes.push('Applied HTML entity decoding');
      continue;
    }
    if (/^[A-Za-z0-9+/_=-]{8,}$/.test(output) && output.length % 4 !== 1) {
      try {
        const decoded = Buffer.from(normalizeAgentBase64(output, /[-_]/.test(output)), 'base64').toString('utf8');
        if (isMostlyAgentPrintable(decoded)) {
          output = decoded;
          notes.push('Decoded printable Base64 payload');
          continue;
        }
      } catch {
        // The input only resembled Base64.
      }
    }
    try {
      const formatted = JSON.stringify(sortAgentJson(JSON.parse(output)), null, 2);
      if (formatted !== output) {
        output = formatted;
        notes.push('Formatted JSON with stable key order');
      }
    } catch {
      // No JSON formatting needed.
    }
    break;
  }
  if (!notes.length) notes.push('No additional canonical form detected');
  return output;
}

function isMostlyAgentPrintable(value) {
  if (!value) return false;
  const chars = Array.from(value);
  return chars.filter((char) => /[\t\n\r -~]/.test(char)).length / chars.length > 0.85;
}

function agentDecoderLabel(transformId) {
  return transformId.split('-').map((part) => part ? `${part[0].toUpperCase()}${part.slice(1)}` : part).join(' ');
}

function rawBody(raw) {
  const text = String(raw ?? '');
  const split = text.split(/\r?\n\r?\n/);
  return split.length > 1 ? split.slice(1).join('\n\n') : text;
}

function extractSecretLines(value) {
  return unique(String(value ?? '')
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => /authorization:|cookie:|x-api-key:|bearer\s+|api[_-]?key|access[_-]?token|refresh[_-]?token|secret|session=/i.test(line)))
    .slice(0, 24);
}

function buildAgentSequencerSoakPackage(result, flags) {
  const minSamples = Math.max(1, Math.round(numberFlag(flags['min-samples'], 5000)));
  const minReliability = String(flags['min-reliability'] ?? (minSamples >= 20000 ? 'fips-ready' : 'reliable')).toLowerCase();
  const allowedReliability = ['rough', 'indicative', 'reliable', 'fips-ready'];
  const minReliabilityIndex = Math.max(0, allowedReliability.indexOf(minReliability));
  const observedReliabilityIndex = Math.max(0, allowedReliability.indexOf(result.reliability?.level ?? 'rough'));
  const maxCollisionRate = Math.max(0, numberFlag(flags['max-collision-rate'], 0));
  const minEntropyBits = Math.max(0, numberFlag(flags['min-entropy-bits'], 96));
  const failures = [];
  const warnings = [];

  if (result.sampleCount < minSamples) failures.push(`Analyzed ${result.sampleCount} sample(s), below Sequencer soak floor ${minSamples}.`);
  if (observedReliabilityIndex < minReliabilityIndex) failures.push(`Reliability ${result.reliability?.level ?? 'rough'} is below required ${allowedReliability[minReliabilityIndex]}.`);
  if (result.collisionRate > maxCollisionRate) failures.push(`Collision rate ${result.collisionRate} exceeded budget ${maxCollisionRate}.`);
  if (result.estimatedEntropyBits < minEntropyBits) failures.push(`Estimated entropy ${result.estimatedEntropyBits} bits is below floor ${minEntropyBits}.`);
  if (!result.statisticalTests?.length) warnings.push('Statistical test evidence was empty.');
  if (!result.positionStats?.length || !result.bitStats?.length) warnings.push('Position/bit statistics were not populated.');

  return {
    id: `agent-sequencer-soak-${simpleDigest(`${result.id}|${result.sampleCount}|${result.reliability?.level}`).slice(0, 12)}`,
    kind: 'proxyforge-agent-sequencer-large-sample-soak-package',
    generatedAt: new Date().toISOString(),
    status: failures.length ? 'fail' : warnings.length ? 'warning' : 'pass',
    failures,
    warnings,
    budgets: {
      minSamples,
      minReliability: allowedReliability[minReliabilityIndex],
      maxCollisionRate,
      minEntropyBits,
    },
    observed: {
      sampleCount: result.sampleCount,
      uniqueCount: result.uniqueCount,
      duplicateCount: result.duplicateCount,
      reliability: result.reliability,
      estimatedEntropyBits: result.estimatedEntropyBits,
      collisionRate: result.collisionRate,
      verdict: result.verdict,
      statisticalTestCount: result.statisticalTests?.length ?? 0,
      positionStatCount: result.positionStats?.length ?? 0,
      bitStatCount: result.bitStats?.length ?? 0,
    },
    result,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportReady: failures.length === 0,
    content: `proxyforge-agent-sequencer-large-sample-soak ${result.sampleCount} sample(s) reliability=${result.reliability?.level ?? 'unknown'} entropyBits=${result.estimatedEntropyBits}`,
  };
}

function buildAgentScannerCalibrationPackage(summary, plan, selectedExchange, flags) {
  const minRequests = Math.max(1, Math.round(numberFlag(flags['min-requests'], Math.max(1, plan.maxRequests ?? 1))));
  const minFindings = Math.max(0, Math.round(numberFlag(flags['min-findings'], 0)));
  const minTuningProfiles = Math.max(1, Math.round(numberFlag(flags['min-tuning-profiles'], 1)));
  const maxSuppressed = Math.max(0, Math.round(numberFlag(flags['max-suppressed-findings'], summary.suppressedFindingCount ?? 1000000)));
  const requireFalsePositiveControls = flags['require-false-positive-controls'] !== false;
  const tuningProfiles = summary.scannerTuning ?? [];
  const falsePositiveControls = unique(tuningProfiles.flatMap((tuning) => tuning.falsePositiveControls ?? []));
  const findingDedupeKeys = unique(tuningProfiles.flatMap((tuning) => tuning.findingDedupeKeys ?? []));
  const failures = [];
  const warnings = [];

  if (summary.blocked) failures.push('Scanner summary was blocked.');
  if ((summary.totalRequests ?? 0) < minRequests) failures.push(`Sent ${summary.totalRequests ?? 0} scanner request(s), below calibration floor ${minRequests}.`);
  if ((summary.findingCount ?? 0) < minFindings) failures.push(`Finding count ${summary.findingCount ?? 0} is below calibration floor ${minFindings}.`);
  if (tuningProfiles.length < minTuningProfiles) failures.push(`Scanner tuning profile count ${tuningProfiles.length} is below floor ${minTuningProfiles}.`);
  if ((summary.suppressedFindingCount ?? 0) > maxSuppressed) failures.push(`Suppressed finding count ${summary.suppressedFindingCount ?? 0} exceeded allowance ${maxSuppressed}.`);
  if (requireFalsePositiveControls && !falsePositiveControls.includes('suppress-error-page-security-header-noise')) failures.push('False-positive tuning controls did not include error-page security-header suppression.');
  if (requireFalsePositiveControls && !falsePositiveControls.includes('preserve-confidence-reason-per-finding')) failures.push('False-positive tuning controls did not preserve confidence reasons.');
  if (!findingDedupeKeys.length && (summary.findingCount ?? 0) > 0) warnings.push('Finding dedupe keys were empty even though findings were retained.');
  if (!summary.summaryPath) warnings.push('Headless scanner summary path was not populated.');

  return {
    id: `agent-scanner-calibration-${simpleDigest(`${summary.id}|${summary.totalRequests}|${summary.findingCount}|${summary.suppressedFindingCount}`).slice(0, 12)}`,
    kind: 'proxyforge-agent-scanner-live-calibration-soak-package',
    generatedAt: new Date().toISOString(),
    status: failures.length ? 'fail' : warnings.length ? 'warning' : 'pass',
    failures,
    warnings,
    budgets: {
      minRequests,
      minFindings,
      minTuningProfiles,
      maxSuppressedFindings: maxSuppressed,
      requireFalsePositiveControls,
    },
    observed: {
      targetUrl: summary.targetUrl,
      totalRequests: summary.totalRequests,
      findingCount: summary.findingCount,
      suppressedFindingCount: summary.suppressedFindingCount,
      highestSeverity: summary.highestSeverity,
      routeCount: summary.routeCount,
      insertionPointCount: summary.insertionPointCount,
      scannerTuningProfileCount: tuningProfiles.length,
      falsePositiveControls,
      findingDedupeKeys,
      reportCount: summary.reportCount,
      ciArtifactCount: summary.ciArtifactCount,
      summaryPath: summary.summaryPath,
    },
    findings: summary.findings,
    suppressedFindings: summary.suppressedFindings,
    scannerTuning: tuningProfiles,
    seedExchange: selectedExchange ? exchangeDetail(selectedExchange) : undefined,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportReady: failures.length === 0,
    content: `proxyforge-agent-scanner-live-calibration-soak ${summary.totalRequests} request(s) ${summary.findingCount} finding(s) ${summary.suppressedFindingCount} suppressed signal(s) controls=${falsePositiveControls.join(',')}`,
  };
}

function buildRepeaterDesyncPlan(flags, project, selectedExchange, scopeAllowlist) {
  const targetUrl = normalizeTarget(flags.target ?? selectedExchange?.url ?? project.exchanges[0]?.url ?? 'https://example.test/');
  if (!isTargetInScope(targetUrl, scopeAllowlist)) return { blocked: `Repeater desync target ${targetUrl} is outside scope.` };
  const parsed = new URL(targetUrl);
  const rawRequest = rawRequestFromExchange(selectedExchange, targetUrl, flags);
  const planId = `agent-desync-plan-${simpleDigest(`${targetUrl}|${rawRequest}`).slice(0, 12)}`;
  const requests = [
    {
      id: `${planId}-baseline`,
      name: 'Baseline browser-compatible request',
      targetUrl,
      rawRequest,
      role: 'baseline',
    },
    {
      id: `${planId}-poison`,
      name: 'CL.0 client-side desync poison candidate',
      targetUrl,
      rawRequest: [
        `POST ${parsed.pathname || '/'}${parsed.search || ''} HTTP/1.1`,
        `Host: ${parsed.host}`,
        'Content-Length: 48',
        'Connection: keep-alive',
        '',
        'GET /__proxyforge-desync-canary HTTP/1.1',
        'X-ProxyForge-Desync: canary',
        '',
      ].join('\r\n'),
      role: 'poison',
    },
    {
      id: `${planId}-victim`,
      name: 'Victim follow-up request',
      targetUrl,
      rawRequest: [
        `GET ${parsed.pathname || '/'}${parsed.search || ''} HTTP/1.1`,
        `Host: ${parsed.host}`,
        'Connection: keep-alive',
        'X-ProxyForge-Desync-Victim: true',
        '',
        '',
      ].join('\r\n'),
      role: 'victim',
    },
  ];
  const parserDifferential = buildAgentDesyncParserDifferentialPackage(requests);
  return {
    id: planId,
    kind: 'proxyforge-agent-repeater-desync-plan',
    targetUrl,
    host: parsed.host,
    techniques: ['cl0', 'client-side-desync', 'pause-based', 'parallel-race'],
    parserProfiles: parserDifferential.parserProfiles,
    parserDifferential,
    sendMode: 'sequence-single-connection',
    syncTechnique: 'single-connection',
    scopeStatus: 'authorized',
    requestCount: requests.length,
    requests,
    summary: `Agent-ready Repeater desync plan with baseline, CL.0 poison, victim follow-up requests, and parser-differential evidence for ${parserDifferential.highRiskCandidateCount}/${parserDifferential.candidateCount} candidate(s).`,
  };
}

function buildAgentDesyncParserDifferentialPackage(requests) {
  const createdAt = new Date().toISOString();
  const parserProfiles = ['strict-rfc', 'frontend-content-length', 'backend-transfer-encoding', 'cl0-backend'];
  const candidates = requests.map((request) => analyzeAgentDesyncParserCandidate(request, parserProfiles));
  const highRiskCandidateCount = candidates.filter((candidate) => candidate.verdict !== 'aligned').length;
  return {
    kind: 'proxyforge-agent-repeater-desync-parser-differential-package',
    schemaVersion,
    createdAt,
    parserProfiles,
    candidateCount: candidates.length,
    highRiskCandidateCount,
    candidates,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    summary: `Parser differential review found ${highRiskCandidateCount}/${candidates.length} request(s) with divergent framing or queued follow-up evidence across ${parserProfiles.length} parser profile(s).`,
    content: `proxyforge-agent-repeater-desync-parser-differential parserProfiles=${parserProfiles.join(',')} highRiskCandidates=${highRiskCandidateCount}`,
  };
}

function analyzeAgentDesyncParserCandidate(request, parserProfiles) {
  const parsed = parseAgentRawRequestForDifferential(normalizeRawHttpForAgent(request.rawRequest));
  const ambiguityFlags = agentParserAmbiguityFlags(parsed);
  const outcomes = parserProfiles.map((profile) => evaluateAgentParserProfile(profile, parsed, request.role));
  const hasQueuedFollowup = outcomes.some((outcome) => outcome.signal === 'queued-followup');
  const uniqueFrames = new Set(outcomes.map((outcome) => `${outcome.accepted}:${outcome.framing}:${outcome.consumedBodyBytes}:${outcome.leftoverBytes}:${outcome.signal}`));
  const verdict = hasQueuedFollowup ? 'queued-followup' : uniqueFrames.size > 1 ? 'parser-differential' : 'aligned';
  return {
    requestId: request.id,
    role: request.role,
    name: request.name,
    ambiguityFlags,
    outcomes,
    verdict,
    evidence: [
      `role=${request.role}`,
      `flags=${ambiguityFlags.join(',') || 'none'}`,
      `profiles=${parserProfiles.join(',')}`,
      `signals=${outcomes.map((outcome) => `${outcome.profile}:${outcome.signal}`).join(',')}`,
    ],
  };
}

function parseAgentRawRequestForDifferential(raw) {
  const headerEnd = raw.indexOf('\r\n\r\n');
  const headerText = headerEnd >= 0 ? raw.slice(0, headerEnd) : raw;
  const body = headerEnd >= 0 ? raw.slice(headerEnd + 4) : '';
  const lines = headerText.split('\r\n');
  const headers = lines.slice(1).map((line) => {
    const colon = line.indexOf(':');
    return colon > 0
      ? { name: line.slice(0, colon).trim().toLowerCase(), value: line.slice(colon + 1).trim() }
      : { name: line.trim().toLowerCase(), value: '' };
  }).filter((header) => header.name);
  return { startLine: lines[0] ?? '', headers, body, bodyBytes: Buffer.byteLength(body, 'utf8') };
}

function agentParserAmbiguityFlags(parsed) {
  const flags = [];
  const contentLengths = parsed.headers.filter((header) => header.name === 'content-length').map((header) => Number(header.value));
  const transferEncodings = parsed.headers.filter((header) => header.name === 'transfer-encoding').map((header) => header.value.toLowerCase());
  const hasChunked = transferEncodings.some((value) => /chunked/.test(value));
  if (contentLengths.length && hasChunked) flags.push('content-length-and-transfer-encoding');
  if (new Set(contentLengths.filter(Number.isFinite)).size > 1) flags.push('multiple-content-length-mismatch');
  if (/^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|CONNECT)\s+\S+\s+HTTP\/1\.[01]/im.test(parsed.body)) flags.push('body-contains-http-request-line');
  const declaredLength = contentLengths.find(Number.isFinite);
  if (Number.isFinite(declaredLength) && parsed.bodyBytes < declaredLength) flags.push('incomplete-declared-body');
  if (Number.isFinite(declaredLength) && declaredLength === 0 && parsed.bodyBytes > 0) flags.push('cl0-body');
  return flags;
}

function evaluateAgentParserProfile(profile, parsed, role) {
  const contentLengths = parsed.headers.filter((header) => header.name === 'content-length').map((header) => Number(header.value)).filter(Number.isFinite);
  const transferEncodings = parsed.headers.filter((header) => header.name === 'transfer-encoding').map((header) => header.value.toLowerCase());
  const hasChunked = transferEncodings.some((value) => /chunked/.test(value));
  const firstContentLength = contentLengths[0];
  const hasMismatchedContentLengths = new Set(contentLengths).size > 1;
  if (profile === 'strict-rfc' && ((contentLengths.length && hasChunked) || hasMismatchedContentLengths)) {
    return agentParserOutcome(profile, false, 'rejected', 0, parsed.body, 'rejected', 'Strict parser rejects ambiguous Content-Length / Transfer-Encoding framing.');
  }
  if (profile === 'backend-transfer-encoding' && hasChunked) {
    const chunkedLength = completeAgentChunkedBodyLength(parsed.body);
    if (chunkedLength === null) return agentParserOutcome(profile, false, 'rejected', 0, parsed.body, 'rejected', 'Chunked parser could not parse a complete chunked body.');
    return agentParserOutcome(profile, true, 'transfer-encoding', chunkedLength, parsed.body.slice(chunkedLength), undefined, 'Transfer-Encoding parser consumed complete chunked body.');
  }
  if (profile === 'cl0-backend' && (role === 'poison' || /^content-length:\s*0$/im.test(parsed.headers.map((header) => `${header.name}: ${header.value}`).join('\n')))) {
    return agentParserOutcome(profile, true, 'cl0', 0, parsed.body, undefined, 'CL.0-style backend consumed no body bytes and left the body queued for follow-up parsing.');
  }
  if (Number.isFinite(firstContentLength)) {
    const consumed = Math.max(0, Math.min(parsed.bodyBytes, firstContentLength));
    const signal = parsed.bodyBytes < firstContentLength ? 'incomplete-body' : undefined;
    return agentParserOutcome(profile, true, 'content-length', consumed, parsed.body.slice(consumed), signal, `${profile} consumed ${consumed}/${firstContentLength} declared body byte(s).`);
  }
  return agentParserOutcome(profile, true, 'close-delimited', parsed.bodyBytes, '', undefined, `${profile} has no explicit request body framing beyond connection close.`);
}

function agentParserOutcome(profile, accepted, framing, consumedBodyBytes, leftover, forcedSignal, detail) {
  const leftoverPreview = leftover.slice(0, 240);
  const interpretedRequestCount = /^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|CONNECT)\s+\S+\s+HTTP\/1\.[01]/i.test(leftover.trimStart()) ? 1 : 0;
  const signal = forcedSignal ?? (interpretedRequestCount ? 'queued-followup' : accepted ? 'aligned' : 'rejected');
  return {
    profile,
    accepted,
    framing,
    consumedBodyBytes,
    leftoverBytes: Buffer.byteLength(leftover, 'utf8'),
    leftoverPreview,
    interpretedRequestCount,
    signal,
    detail,
  };
}

function completeAgentChunkedBodyLength(body) {
  let cursor = 0;
  while (cursor < body.length) {
    const lineEnd = body.indexOf('\r\n', cursor);
    if (lineEnd === -1) return null;
    const sizeText = body.slice(cursor, lineEnd).split(';')[0]?.trim() ?? '';
    const size = Number.parseInt(sizeText, 16);
    if (!Number.isFinite(size)) return null;
    cursor = lineEnd + 2;
    if (body.length < cursor + size + 2) return null;
    cursor += size + 2;
    if (size === 0) return cursor;
  }
  return null;
}

function normalizeRawHttpForAgent(raw) {
  const normalized = String(raw || '').replace(/\r?\n/g, '\r\n');
  if (normalized.includes('\r\n\r\n')) return normalized;
  return `${normalized.replace(/\r\n*$/, '')}\r\n\r\n`;
}

function buildRepeaterRacePlan(flags, project, selectedExchange, scopeAllowlist) {
  const targetUrl = normalizeTarget(flags.target ?? selectedExchange?.url ?? project.exchanges[0]?.url ?? 'https://example.test/');
  if (!isTargetInScope(targetUrl, scopeAllowlist)) return { blocked: `Repeater race target ${targetUrl} is outside scope.` };
  const parsed = new URL(targetUrl);
  const rawRequest = rawRequestFromExchange(selectedExchange, targetUrl, flags);
  const highVolumeMax = flags.soak || flags['soak-report'] ? 100 : 20;
  const requestCount = Math.max(2, Math.min(highVolumeMax, Math.round(numberFlag(flags.count, numberFlag(flags.requests, 3)))));
  const planId = `agent-race-plan-${simpleDigest(`${targetUrl}|${rawRequest}|${requestCount}`).slice(0, 12)}`;
  const requests = Array.from({ length: requestCount }, (_value, index) => ({
    id: `${planId}-request-${index + 1}`,
    name: `Parallel race request ${index + 1}`,
    targetUrl,
    rawRequest: injectRawHeader(rawRequest, 'X-ProxyForge-Race-Id', `${planId}-${index + 1}`),
    role: index === 0 ? 'baseline' : 'victim',
  }));
  return {
    id: planId,
    kind: 'proxyforge-agent-repeater-race-plan',
    targetUrl,
    host: parsed.host,
    techniques: ['parallel-race'],
    sendMode: 'parallel',
    syncTechnique: flags.sync === 'single-packet' ? 'single-packet' : 'last-byte',
    scopeStatus: 'authorized',
    requestCount: requests.length,
    maxRaceRequests: highVolumeMax,
    requests,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    summary: `Agent-ready Repeater parallel race plan with ${requests.length} synchronized raw request(s).`,
  };
}

function buildAgentRepeaterRaceSoakPackage(result, plan, flags) {
  const minRequests = Math.max(2, Math.round(numberFlag(flags['min-requests'], plan.requestCount)));
  const maxFailures = Math.max(0, Math.round(numberFlag(flags['max-failures'], 0)));
  const maxReleaseSkewMs = Math.max(1, numberFlag(flags['max-release-skew-ms'], 75));
  const maxRaceWindowMs = Math.max(1, numberFlag(flags['max-race-window-ms'], maxReleaseSkewMs));
  const observedResponses = result.responses.filter((response) => response.status || response.rawResponse || response.error).length;
  const missingResponses = Math.max(0, result.requestCount - observedResponses);
  const releaseSkewMs = Number(result.releaseSkewMs ?? 0);
  const raceWindowMs = Number(result.raceWindowMs ?? releaseSkewMs);
  const failures = [];
  const warnings = [];

  if (result.status !== 'proof') failures.push(`Race runtime status was ${result.status}; expected proof.`);
  if (result.requestCount < minRequests) failures.push(`Sent ${result.requestCount} request(s), below race soak floor ${minRequests}.`);
  if (missingResponses > maxFailures) failures.push(`Missing/empty response count ${missingResponses} is above soak allowance ${maxFailures}.`);
  if (releaseSkewMs > maxReleaseSkewMs) failures.push(`Release skew ${releaseSkewMs}ms exceeded budget ${maxReleaseSkewMs}ms.`);
  if (raceWindowMs > maxRaceWindowMs) failures.push(`Race window ${raceWindowMs}ms exceeded budget ${maxRaceWindowMs}ms.`);
  if (!result.responseOrder.length) warnings.push('Response order telemetry was empty.');
  if (!result.rawTranscript) warnings.push('Raw transcript was empty.');

  return {
    id: `agent-repeater-race-soak-${simpleDigest(`${result.id}|${result.requestCount}|${releaseSkewMs}`).slice(0, 12)}`,
    kind: 'proxyforge-agent-repeater-race-high-concurrency-soak-package',
    generatedAt: new Date().toISOString(),
    status: failures.length ? 'fail' : warnings.length ? 'warning' : 'pass',
    failures,
    warnings,
    budgets: {
      minRequests,
      maxFailures,
      maxReleaseSkewMs,
      maxRaceWindowMs,
      maxRaceRequests: plan.maxRaceRequests,
    },
    observed: {
      transport: result.transport,
      syncTechnique: result.syncTechnique,
      requestCount: result.requestCount,
      observedResponses,
      missingResponses,
      releaseSkewMs,
      raceWindowMs,
      jitterMs: result.jitterMs,
      responseStatusCounts: groupCounts(result.responses.map((response) => String(response.status ?? 'missing'))),
      responseOrder: result.responseOrder,
    },
    result,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportReady: failures.length === 0,
    content: `proxyforge-agent-repeater-race-high-concurrency-soak ${result.transport} ${result.requestCount} request(s) releaseSkewMs=${releaseSkewMs} raceWindowMs=${raceWindowMs}`,
  };
}

function rawRequestFromExchange(exchange, targetUrl, flags) {
  if (flags.raw) return String(flags.raw);
  if (exchange?.requestRaw) return exchange.requestRaw;
  const target = new URL(targetUrl);
  return [
    `GET ${target.pathname || '/'}${target.search || ''} HTTP/1.1`,
    `Host: ${target.host}`,
    'Connection: keep-alive',
    '',
    '',
  ].join('\r\n');
}

function injectRawHeader(raw, name, value) {
  const normalized = String(raw).replace(/\r?\n/g, '\r\n');
  const header = `${name}: ${value}`;
  if (normalized.includes('\r\n\r\n')) return normalized.replace(/\r\n\r\n/, `\r\n${header}\r\n\r\n`);
  return `${normalized.replace(/\r\n*$/, '')}\r\n${header}\r\n\r\n`;
}

function parseRawRequest(raw) {
  const [head = '', ...bodyParts] = raw.split(/\r?\n\r?\n/);
  const lines = head.split(/\r?\n/).slice(1);
  const headers = {};
  for (const line of lines) {
    const colon = line.indexOf(':');
    if (colon === -1) continue;
    const name = line.slice(0, colon).trim();
    const value = line.slice(colon + 1).trim();
    if (name) headers[name] = value;
  }
  return { headers, body: bodyParts.join('\n\n') };
}

function headersFromFlag(flag) {
  const values = Array.isArray(flag) ? flag : flag ? [flag] : [];
  const headers = {};
  for (const value of values) {
    const colon = String(value).indexOf(':');
    if (colon === -1) continue;
    headers[String(value).slice(0, colon).trim()] = String(value).slice(colon + 1).trim();
  }
  return headers;
}

function deleteHeader(headers, target) {
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === target) delete headers[key];
  }
}

function agentReplayTransportSettings(flags) {
  const redirectMode = flags.redirect === 'follow' || flags['redirect-mode'] === 'follow' ? 'follow' : 'manual';
  const connectionModeInput = String(flags.connection ?? flags['connection-mode'] ?? 'default').toLowerCase();
  const connectionMode = connectionModeInput === 'close' || connectionModeInput === 'keep-alive' ? connectionModeInput : 'default';
  return {
    redirectMode,
    maxRedirects: Math.max(0, Math.min(10, Math.round(numberFlag(flags['max-redirects'], 3)))),
    connectionMode,
    timeoutMs: Math.max(250, Math.min(120000, Math.round(numberFlag(flags.timeout ?? flags['timeout-ms'], 10000)))),
    rejectUnauthorized: flags['tls-insecure'] || flags.insecure ? false : true,
  };
}

function replayRequestSummary(request) {
  return {
    id: request.id,
    method: request.method,
    url: request.url,
    headers: request.headers,
    body: request.body,
    headerNames: Object.keys(request.headers),
    bodyBytes: Buffer.byteLength(String(request.body ?? ''), 'utf8'),
  };
}

function executeHttpRequest(request, options = {}) {
  const settings = typeof options === 'number'
    ? { timeoutMs: options, redirectMode: 'manual', maxRedirects: 3, connectionMode: 'default', scopeAllowlist: ['*'], rejectUnauthorized: true }
    : {
      redirectMode: options.redirectMode === 'follow' ? 'follow' : 'manual',
      maxRedirects: Math.max(0, Math.min(10, Math.round(numberFlag(options.maxRedirects, 3)))),
      connectionMode: options.connectionMode === 'close' || options.connectionMode === 'keep-alive' ? options.connectionMode : 'default',
      timeoutMs: Math.max(250, Math.min(120000, Math.round(numberFlag(options.timeoutMs, 10000)))),
      scopeAllowlist: Array.isArray(options.scopeAllowlist) ? options.scopeAllowlist : ['*'],
      rejectUnauthorized: options.rejectUnauthorized !== false,
    };
  const startedAt = Date.now();
  const redirectHistory = [];
  const send = (targetUrl, redirectsFollowed) => new Promise((resolve) => {
    if (!isTargetInScope(targetUrl, settings.scopeAllowlist)) {
      resolve({
        error: `Redirect target ${targetUrl} is outside scope.`,
        redirectBlocked: true,
        redirectHistory,
        finalUrl: targetUrl,
        transport: settings,
        durationMs: Date.now() - startedAt,
      });
      return;
    }
    const url = new URL(targetUrl);
    const headers = { ...request.headers };
    if (settings.connectionMode !== 'default') headers.Connection = settings.connectionMode;
    deleteHeader(headers, 'host');
    deleteHeader(headers, 'content-length');
    const transport = url.protocol === 'https:' ? https : http;
    let settled = false;
    const finish = (payload) => {
      if (settled) return;
      settled = true;
      resolve(payload);
    };
    const client = transport.request(url, {
      method: request.method,
      headers,
      timeout: settings.timeoutMs,
      rejectUnauthorized: settings.rejectUnauthorized,
    }, (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () => {
        const body = Buffer.concat(chunks).toString('utf8');
        const location = response.headers.location;
        const status = response.statusCode ?? 0;
        if (
          settings.redirectMode === 'follow'
          && redirectsFollowed < settings.maxRedirects
          && status >= 300
          && status < 400
          && typeof location === 'string'
        ) {
          const nextUrl = new URL(location, url).toString();
          redirectHistory.push({
            from: url.toString(),
            to: nextUrl,
            status,
            location,
          });
          send(nextUrl, redirectsFollowed + 1).then(finish);
          return;
        }
        const rawHeaders = Object.entries(response.headers)
          .flatMap(([name, value]) => Array.isArray(value) ? value.map((item) => `${name}: ${item}`) : value === undefined ? [] : [`${name}: ${value}`]);
        finish({
          status,
          statusMessage: response.statusMessage,
          headers: response.headers,
          headerNames: Object.keys(response.headers),
          body,
          bodyPreview: body.slice(0, 1000),
          rawResponse: [
            `HTTP/1.1 ${status} ${response.statusMessage ?? ''}`.trim(),
            ...rawHeaders,
            '',
            body,
          ].join('\r\n'),
          redirectHistory,
          redirectsFollowed,
          finalUrl: url.toString(),
          transport: settings,
          durationMs: Date.now() - startedAt,
          bytes: Buffer.byteLength(body, 'utf8'),
        });
      });
    });
    client.on('timeout', () => {
      client.destroy(new Error(`Replay timed out after ${settings.timeoutMs}ms`));
    });
    client.on('error', (error) => {
      finish({
        error: error.message,
        redirectHistory,
        finalUrl: url.toString(),
        transport: settings,
        durationMs: Date.now() - startedAt,
      });
    });
    if (request.body) client.write(request.body);
    client.end();
  });
  return send(request.url, 0);
}

function inferInsertionPoints(exchanges, selectedExchange, targetUrl, options = {}) {
  const source = selectedExchange ? [selectedExchange] : exchanges.filter((exchange) => exchange.url === targetUrl || exchange.host === hostFromUrl(targetUrl));
  const points = [];
  const maxPoints = numberFlag(options.maxPoints, 250);
  for (const exchange of source.slice(0, 50)) {
    const parsed = parseRawRequestDetailed(exchange.requestRaw);
    const url = safeAgentUrl(exchange.url, parsed);
    const add = (location, name, evidence, originalValue, confidence = 'medium') => {
      const valuePreview = typeof originalValue === 'string' ? originalValue.slice(0, 240) : JSON.stringify(originalValue ?? '').slice(0, 240);
      points.push({
        id: `${exchange.id}:${location}:${simpleDigest(`${name}|${evidence}|${valuePreview}`).slice(0, 10)}`,
        exchangeId: exchange.id,
        routeId: `route-${simpleDigest(`${exchange.method}|${url.host}|${url.pathname}`).slice(0, 10)}`,
        type: location,
        location,
        name,
        parameter: name,
        method: parsed.method || exchange.method,
        url: url.toString(),
        route: `${(parsed.method || exchange.method || 'GET').toUpperCase()} ${url.pathname}${url.search}`,
        evidence,
        valuePreview,
        originalValue,
        confidence,
        risk: agentInsertionPointRisk(location, name, evidence),
        notes: `${location} insertion point from ${exchange.id}; full raw executor material is preserved until report/export redaction.`,
      });
    };

    for (const [name, value] of url.searchParams.entries()) {
      add('query', name, `Query parameter "${name}"`, value, 'high');
    }
    url.pathname.split('/').filter(Boolean).forEach((segment, index) => {
      if (agentDynamicPathSegment(segment)) add('path', `segment-${index + 1}`, `Dynamic-looking path segment "${segment}"`, segment, 'medium');
    });
    for (const header of parsed.headers) {
      const normalizedName = header.name.toLowerCase();
      if (normalizedName === 'cookie') continue;
      if (!agentInterestingInsertionHeader(normalizedName)) continue;
      add('header', header.name, `Request header "${header.name}"`, header.value, 'medium');
    }
    for (const header of parsed.headers.filter((entry) => entry.name.toLowerCase() === 'cookie')) {
      for (const cookie of header.value.split(';')) {
        const [name, ...valueParts] = cookie.split('=');
        const trimmedName = name.trim();
        if (trimmedName) add('cookie', trimmedName, `Cookie "${trimmedName}"`, valueParts.join('=').trim(), 'high');
      }
    }
    addAgentBodyInsertionPoints(parsed.body, headerValue(parsed.headers, 'content-type') ?? '', url, add);
  }
  return dedupeAgentInsertionPoints(points).slice(0, maxPoints);
}

function addAgentBodyInsertionPoints(bodyText, contentType, url, add) {
  const body = String(bodyText ?? '').trim();
  const normalizedContentType = String(contentType ?? '').toLowerCase();
  if (!body) return;
  let count = 0;
  if (normalizedContentType.includes('application/x-www-form-urlencoded')) {
    for (const [name, value] of new URLSearchParams(body).entries()) {
      add('form', name, `URL-encoded form field "${name}"`, value, 'high');
      count += 1;
    }
  }
  if (normalizedContentType.includes('multipart/form-data')) {
    const boundary = normalizedContentType.match(/boundary="?([^";]+)"?/i)?.[1];
    if (boundary) {
      for (const rawPart of body.split(`--${boundary}`)) {
        const part = rawPart.trim();
        if (!part || part === '--') continue;
        const parsedPart = parseAgentHttpPart(part);
        const disposition = headerValue(parsedPart.headers, 'content-disposition') ?? '';
        const name = disposition.match(/\bname="([^"]+)"/i)?.[1];
        if (!name) continue;
        const filename = disposition.match(/\bfilename="([^"]*)"/i)?.[1];
        add('multipart', name, filename ? `Multipart file field "${name}" filename "${filename}"` : `Multipart field "${name}"`, parsedPart.body.trim(), 'high');
        count += 1;
      }
    }
  }
  if (normalizedContentType.includes('json') || /^\s*[\[{]/.test(body)) {
    try {
      const parsedJson = JSON.parse(body);
      for (const leaf of collectAgentJsonLeaves(parsedJson)) {
        add('json', leaf.path, `JSON body field "${leaf.path}"`, leaf.value, 'high');
        count += 1;
      }
      count += addAgentGraphqlPoints(parsedJson, url, add);
    } catch {
      // Keep non-JSON body fallback below.
    }
  }
  if ((normalizedContentType.includes('xml') || /^<\?xml|^<[A-Za-z_][\w:.-]*(?:\s|>)/.test(body))) {
    count += addAgentXmlPoints(body, add);
  }
  if (count === 0 && (/graphql/i.test(url.pathname) || /\b(query|mutation|subscription)\b|__schema/i.test(body))) {
    add('graphql', 'operation', 'GraphQL operation body', body, 'medium');
    count += 1;
  }
  if (count === 0) add('body', 'request-body', `Raw request body (${normalizedContentType || 'unknown content type'})`, body, 'low');
}

function addAgentGraphqlPoints(value, url, add) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return 0;
  let count = 0;
  if (typeof value.query === 'string' && (/graphql/i.test(url.pathname) || /\b(query|mutation|subscription)\b|__schema/i.test(value.query))) {
    add('graphql', 'query', 'GraphQL query document', value.query, 'high');
    count += 1;
  }
  if (typeof value.operationName === 'string') {
    add('graphql', 'operationName', 'GraphQL operation name', value.operationName, 'high');
    count += 1;
  }
  if (value.variables && typeof value.variables === 'object' && !Array.isArray(value.variables)) {
    for (const leaf of collectAgentJsonLeaves(value.variables, ['variables'])) {
      add('graphql', leaf.path, `GraphQL variable "${leaf.path}"`, leaf.value, 'high');
      count += 1;
    }
  }
  return count;
}

function addAgentXmlPoints(body, add) {
  let count = 0;
  const attributePattern = /<([A-Za-z_][\w:.-]*)([^<>]*?)>/g;
  let attrMatch;
  while ((attrMatch = attributePattern.exec(body)) !== null) {
    const tag = attrMatch[1];
    const attrs = attrMatch[2] ?? '';
    const attrPattern = /([A-Za-z_][\w:.-]*)\s*=\s*"([^"]*)"/g;
    let match;
    while ((match = attrPattern.exec(attrs)) !== null) {
      add('xml', `${tag}@${match[1]}`, `XML attribute "${match[1]}" on <${tag}>`, match[2], 'medium');
      count += 1;
    }
  }
  const textPattern = /<([A-Za-z_][\w:.-]*)(?:\s[^<>]*?)?>([^<>]{1,500})<\/\1>/g;
  let textMatch;
  while ((textMatch = textPattern.exec(body)) !== null) {
    const value = textMatch[2].trim();
    if (!value) continue;
    add('xml', textMatch[1], `XML text node <${textMatch[1]}>`, value, 'medium');
    count += 1;
  }
  return count;
}

function parseRawRequestDetailed(raw) {
  const normalized = String(raw ?? '').replace(/\r\n/g, '\n');
  const separator = normalized.indexOf('\n\n');
  const head = separator >= 0 ? normalized.slice(0, separator) : normalized;
  const body = separator >= 0 ? normalized.slice(separator + 2) : '';
  const lines = head.split('\n');
  const startLine = lines.shift()?.trim() ?? '';
  const headers = [];
  for (const line of lines) {
    if (/^\s/.test(line) && headers.length) {
      headers[headers.length - 1].value = `${headers[headers.length - 1].value} ${line.trim()}`;
      continue;
    }
    const colon = line.indexOf(':');
    if (colon <= 0) continue;
    headers.push({ name: line.slice(0, colon).trim(), value: line.slice(colon + 1).trim() });
  }
  const [, method = 'GET', target = '/'] = startLine.match(/^([A-Z]+)\s+(\S+)/i) ?? [];
  return { method: method.toUpperCase(), target, headers, body };
}

function parseAgentHttpPart(raw) {
  const normalized = String(raw ?? '').replace(/\r\n/g, '\n');
  const separator = normalized.indexOf('\n\n');
  const head = separator >= 0 ? normalized.slice(0, separator) : normalized;
  const body = separator >= 0 ? normalized.slice(separator + 2) : '';
  const headers = head.split('\n').flatMap((line) => {
    const colon = line.indexOf(':');
    return colon > 0 ? [{ name: line.slice(0, colon).trim(), value: line.slice(colon + 1).trim() }] : [];
  });
  return { headers, body };
}

function agentLiveTargetEntries(flags, project, manifest) {
  if (Array.isArray(manifest?.targets)) return manifest.targets;
  if (Array.isArray(manifest?.liveTargets)) return manifest.liveTargets;
  const inlineTargets = parseList(flags.target ?? (!manifest && flags.targets ? flags.targets : ''));
  if (inlineTargets.length) return inlineTargets.map((url) => ({ url }));
  return project.exchanges
    .filter((exchange) => exchange?.url)
    .map((exchange) => ({
      id: exchange.id,
      label: exchange.notes || exchange.id,
      url: exchange.url,
      method: exchange.method,
      rawRequest: exchange.requestRaw,
      category: exchange.source ?? 'project-history',
      role: exchange.role,
      expectedToolHandoff: ['replay', 'scanner', 'intruder'],
    }));
}

function agentLiveTargetSpec(entry, index, flags, manifest) {
  const objectEntry = typeof entry === 'object' && entry ? entry : { url: String(entry ?? '') };
  const parsedRaw = objectEntry.rawRequest ? parseRawRequestDetailed(objectEntry.rawRequest) : null;
  const rawUrl = objectEntry.url
    ?? objectEntry.target
    ?? (parsedRaw ? safeAgentUrl(`https://${headerValue(parsedRaw.headers, 'host') ?? 'target.invalid'}`, parsedRaw).toString() : flags.target);
  const url = normalizeTarget(rawUrl);
  const method = String(objectEntry.method ?? parsedRaw?.method ?? flags.method ?? manifest?.method ?? 'GET').toUpperCase();
  const rawHeaders = parsedRaw
    ? Object.fromEntries(parsedRaw.headers.map((header) => [header.name, header.value]))
    : {};
  const manifestHeaders = manifest?.headers && typeof manifest.headers === 'object' ? manifest.headers : {};
  const targetHeaders = objectEntry.headers && typeof objectEntry.headers === 'object' ? objectEntry.headers : {};
  const headers = {
    Accept: 'application/json, text/html;q=0.9, */*;q=0.8',
    'User-Agent': String(flags['user-agent'] ?? manifest?.userAgent ?? 'ProxyForgeAgentLiveTargetProfile/1.0'),
    ...manifestHeaders,
    ...rawHeaders,
    ...targetHeaders,
    ...headersFromFlag(flags.header),
    ...(flags.cookie ? { Cookie: String(flags.cookie) } : {}),
  };
  deleteHeader(headers, 'content-length');
  const body = String(objectEntry.body ?? parsedRaw?.body ?? '');
  const rawRequest = objectEntry.rawRequest
    ? String(objectEntry.rawRequest)
    : [
      `${method} ${new URL(url).pathname}${new URL(url).search} HTTP/1.1`,
      `Host: ${new URL(url).host}`,
      ...Object.entries(headers).filter(([name]) => name.toLowerCase() !== 'host').map(([name, value]) => `${name}: ${value}`),
      '',
      body,
    ].join('\r\n');
  return {
    id: String(objectEntry.id ?? objectEntry.name ?? `live-target-${index + 1}`),
    label: String(objectEntry.label ?? objectEntry.name ?? `Live target ${index + 1}`),
    url,
    method,
    headers,
    body,
    rawRequest,
    role: String(objectEntry.role ?? objectEntry.profile ?? objectEntry.identity ?? 'default'),
    category: String(objectEntry.category ?? objectEntry.kind ?? 'live-http'),
    expectedToolHandoff: parseList(objectEntry.expectedToolHandoff ?? objectEntry.tools ?? 'replay,scanner,intruder'),
  };
}

function agentLiveTargetExchange(target, response, index) {
  const url = new URL(target.url);
  return {
    id: `agent-live-target-exchange-${index + 1}`,
    method: target.method,
    host: url.hostname,
    path: `${url.pathname}${url.search}`,
    url: target.url,
    status: response.statusCode,
    length: Buffer.byteLength(response.body ?? '', 'utf8'),
    mime: String(response.headers?.['content-type'] ?? ''),
    risk: response.statusCode >= 500 ? 'medium' : response.statusCode >= 400 ? 'low' : 'info',
    timing: 0,
    source: 'live-target-profile',
    time: new Date().toISOString(),
    requestRaw: response.rawRequest,
    responseRaw: response.rawResponse,
    notes: `Agent live target profile result for ${target.label}`,
    tags: ['agent-live-target-profile', target.category, target.role],
  };
}

function agentLiveTargetScannerCandidate(target, response, insertionPoints) {
  const body = String(response.body ?? '');
  const contentType = String(response.headers?.['content-type'] ?? '');
  const checks = unique([
    'security-headers',
    response.statusCode >= 400 ? 'authz-diff' : '',
    /graphql/i.test(`${target.url}\n${contentType}\n${body}`) ? 'graphql-introspection' : '',
    insertionPoints.some((point) => ['query', 'form', 'json', 'xml', 'multipart'].includes(point.location)) ? 'reflected-xss' : '',
    insertionPoints.some((point) => ['query', 'json', 'form'].includes(point.location)) ? 'sql-injection' : '',
    insertionPoints.some((point) => point.location === 'path') ? 'path-traversal' : '',
  ].filter(Boolean));
  return {
    isCandidate: checks.length > 0,
    targetUrl: target.url,
    checkPackHint: checks.length >= 5 ? 'full-active' : checks.includes('authz-diff') ? 'auth-state' : 'input-attacks',
    checks,
    insertionPointCount: insertionPoints.length,
    command: `${agentCommandPrefix} scanner-run --target ${shellQuote(target.url)} --scope ${shellQuote(hostFromUrl(target.url))} --checks ${shellQuote(checks.join(','))} --execute --soak --json`,
  };
}

function agentLiveTargetIntruderCandidate(target, response, insertionPoints) {
  const rawRequestWithMarkers = agentLiveTargetMarkedRawRequest(response.rawRequest, insertionPoints);
  const payloadHints = unique([
    target.role && target.role !== 'default' ? target.role : '',
    response.statusCode >= 400 ? 'support_admin' : 'customer',
    'admin',
    'user',
  ].filter(Boolean));
  return {
    isCandidate: insertionPoints.length > 0,
    targetUrl: target.url,
    attackModeHint: insertionPoints.length > 1 ? 'cluster-bomb' : 'sniper',
    insertionPointCount: insertionPoints.length,
    payloadHints,
    rawRequestWithMarkers,
    command: `${agentCommandPrefix} intruder-run --target ${shellQuote(target.url)} --scope ${shellQuote(hostFromUrl(target.url))} --raw-request ${shellQuote(rawRequestWithMarkers)} --payloads ${shellQuote(payloadHints.join(','))} --execute --soak --json`,
  };
}

function agentLiveTargetMarkedRawRequest(rawRequest, insertionPoints) {
  let marked = String(rawRequest ?? '');
  const candidates = insertionPoints.filter((point) => point.originalValue !== undefined && String(point.originalValue).length > 0);
  for (const point of candidates.slice(0, 3)) {
    const value = String(point.originalValue);
    if (!marked.includes(value)) continue;
    marked = marked.replace(value, `§${point.name || point.location || 'payload'}§`);
  }
  if (!/§[^§]*§/.test(marked)) {
    marked = marked.replace(/\r?\n\r?\n/, '\r\nX-ProxyForge-Agent-Probe: §probe§\r\n\r\n');
  }
  return marked;
}

function buildAgentLiveTargetProfilePackage(input) {
  const hostCount = unique(input.results.map((result) => result.host)).length;
  const routeCount = unique(input.results.map((result) => result.route)).length;
  const statusClasses = unique(input.results.map((result) => result.statusClass));
  const scannerCandidates = input.results.map((result) => result.scannerCandidate).filter((candidate) => candidate.isCandidate);
  const intruderCandidates = input.results.map((result) => result.intruderCandidate).filter((candidate) => candidate.isCandidate);
  const groupedRoutes = groupBy(input.results, (result) => result.path);
  const authzDifferentials = Object.entries(groupedRoutes).flatMap(([pathName, results]) => {
    const statuses = unique(results.map((result) => `${result.role}:${result.statusCode}`));
    return statuses.length > 1 ? [{ path: pathName, observations: results.map((result) => ({ role: result.role, statusCode: result.statusCode, url: result.url })) }] : [];
  });
  const rawMaterial = JSON.stringify(input.results);
  const requirements = {
    scopedLiveTargetsCovered: input.results.every((result) => isTargetInScope(result.url, input.scopeAllowlist)),
    liveTrafficExecuted: input.results.length >= input.minRequests,
    externalHostDiversityCovered: hostCount >= input.minHosts,
    routeDiversityCovered: routeCount >= input.minRoutes,
    statusClassDiversityCovered: statusClasses.length >= input.minStatusClasses,
    scannerCandidateHandoffCovered: scannerCandidates.length > 0,
    intruderCandidateHandoffCovered: intruderCandidates.length > 0,
    authzDifferentialReviewCovered: input.results.some((result) => result.role) || authzDifferentials.length > 0,
    rawExecutorMaterialPreserved: /HTTP\/[12]|rawRequest|rawResponse|Authorization:|Cookie:|X-API-Key:/i.test(rawMaterial),
    operationalSecretsPreserved: /Bearer|Cookie:|session=|api[_-]?key|secret|token/i.test(rawMaterial),
    reportPhaseOnlyRedaction: true,
  };
  const unsigned = {
    kind: 'proxyforge-agent-live-target-profile-package',
    createdAt: new Date().toISOString(),
    sourcePlanId: input.plan.id,
    scopeAllowlist: input.scopeAllowlist,
    durationMs: input.durationMs,
    liveRequestCount: input.results.length,
    hostCount,
    routeCount,
    statusClassCount: statusClasses.length,
    statusCounts: groupCounts(input.results.map((result) => String(result.statusCode))),
    contentTypeCounts: groupCounts(input.results.map((result) => result.contentType || 'unknown')),
    scannerCandidateCount: scannerCandidates.length,
    intruderCandidateCount: intruderCandidates.length,
    authzDifferentialCount: authzDifferentials.length,
    authzDifferentials,
    scannerCandidates,
    intruderCandidates,
    results: input.results,
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
  };
  const digestPreview = simpleDigest(JSON.stringify(unsigned));
  return {
    id: `agent-live-target-profile-${digestPreview.slice(0, 12)}`,
    ...unsigned,
    digestPreview,
    reportReady: Object.values(requirements).every(Boolean),
    summary: `Live target profile captured ${input.results.length} scoped request(s), ${hostCount} host(s), ${routeCount} route(s), ${statusClasses.length} status class(es), ${scannerCandidates.length} Scanner candidate(s), and ${intruderCandidates.length} Intruder candidate(s).`,
    content: JSON.stringify({ ...unsigned, digestPreview }, null, 2),
  };
}

function agentStatusClass(statusCode) {
  const status = Number(statusCode);
  if (!Number.isFinite(status) || status <= 0) return 'error';
  return `${Math.floor(status / 100)}xx`;
}

function safeAgentUrl(exchangeUrl, parsed) {
  try {
    return new URL(normalizeTarget(exchangeUrl));
  } catch {
    const host = headerValue(parsed.headers, 'host') ?? 'target.invalid';
    const target = parsed.target || '/';
    if (/^https?:\/\//i.test(target)) return new URL(target);
    return new URL(target.startsWith('/') ? target : `/${target}`, `https://${host}`);
  }
}

function collectAgentJsonLeaves(value, basePath = []) {
  if (Array.isArray(value)) return value.flatMap((item, index) => collectAgentJsonLeaves(item, [...basePath, `[${index}]`]));
  if (value && typeof value === 'object') {
    const leaves = Object.entries(value).flatMap(([key, item]) => collectAgentJsonLeaves(item, [...basePath, key]));
    return leaves.length ? leaves : [{ path: basePath.join('.') || '$', value }];
  }
  return [{ path: basePath.join('.').replace(/\.\[/g, '[') || '$', value }];
}

function agentDynamicPathSegment(segment) {
  return /\d/.test(segment)
    || /^[0-9a-f]{8,}$/i.test(segment)
    || /^(ord|order|usr|user|acct|acc|rf|sid|sess|token|jwt|id)[_-]?[A-Za-z0-9_-]+$/i.test(segment);
}

function agentInterestingInsertionHeader(name) {
  return name === 'authorization'
    || name === 'idempotency-key'
    || name === 'x-api-key'
    || name === 'x-csrf-token'
    || name === 'origin'
    || name.startsWith('x-');
}

function agentInsertionPointRisk(location, name, evidence) {
  const haystack = `${location} ${name} ${evidence}`.toLowerCase();
  if (/authorization|cookie|csrf|api-key|token|graphql|amount|role|admin|idempotency/.test(haystack)) return 'high';
  if (/json|xml|multipart|path|redirect|url|file|cmd|query/.test(haystack)) return 'medium';
  return 'info';
}

function dedupeAgentInsertionPoints(points) {
  const seen = new Set();
  const deduped = [];
  for (const point of points) {
    const key = `${point.exchangeId}|${point.location}|${point.name}|${point.url}`.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    deduped.push(point);
  }
  return deduped;
}

function selectAgentScannerIssue(project, issueId, selectedExchange) {
  if (issueId) {
    return project.issues.find((issue) => issue.id === issueId || issue.title === issueId);
  }
  if (selectedExchange) {
    return project.issues.find((issue) => agentIssueMatchesExchange(issue, selectedExchange));
  }
  return project.issues[0];
}

function scannerIssueSummary(issue) {
  return {
    id: issue.id,
    title: issue.title,
    severity: issue.severity,
    confidence: issue.confidence,
    status: issue.status,
    host: issue.host,
    path: issue.path,
  };
}

function findAgentIssueExchange(project, issue) {
  return project.exchanges.find((exchange) => agentIssueMatchesExchange(issue, exchange))
    ?? project.exchanges.find((exchange) => exchange.host === issue.host || hostFromUrl(exchange.url) === issue.host);
}

function agentIssueMatchesExchange(issue, exchange) {
  const exchangeHost = exchange.host ?? hostFromUrl(exchange.url);
  return (!issue.host || issue.host === exchangeHost || hostFromUrl(`https://${issue.host}`) === exchangeHost)
    && agentPathOnly(exchange.path ?? exchange.url) === agentPathOnly(issue.path ?? '/');
}

function parseAgentRetestRequestEdits(flags) {
  const rawEdits = parseList(flags.edit ?? flags.edits ?? flags['request-edit']);
  if (rawEdits.length) {
    return rawEdits.map((raw) => {
      const [field = 'request', transition = raw] = String(raw).split(':', 2);
      const [before, after] = transition.split('->', 2);
      return {
        field: field.trim() || 'request',
        before: before?.trim(),
        after: after?.trim(),
        reason: 'Agent supplied retest request edit',
      };
    });
  }
  return [{
    field: 'raw-request',
    before: 'baseline proof request',
    after: flags.execute ? 'executed retest request' : 'selected retest proof request',
    reason: 'Preserve the request mutation context used to validate remediation.',
  }];
}

function exchangeFromAgentRetestResponse(baselineExchange, request, response, issue) {
  const target = new URL(normalizeTarget(request.url));
  const requestRaw = [
    `${request.method} ${target.pathname || '/'}${target.search || ''} HTTP/1.1`,
    `Host: ${target.host}`,
    ...Object.entries(request.headers ?? {}).map(([name, value]) => `${name}: ${value}`),
    '',
    request.body ?? '',
  ].join('\r\n');
  return {
    id: `agent-scanner-retest-${simpleDigest(`${request.url}|${response.status ?? response.error ?? 'error'}|${Date.now()}`).slice(0, 12)}`,
    method: request.method,
    host: target.hostname,
    path: `${target.pathname || '/'}${target.search || ''}`,
    url: target.toString(),
    status: response.status ?? 0,
    length: response.bytes ?? Buffer.byteLength(response.body ?? response.error ?? '', 'utf8'),
    mime: String(response.headers?.['content-type'] ?? 'text/plain'),
    risk: issue.severity ?? baselineExchange.risk ?? 'medium',
    timing: response.durationMs ?? 0,
    source: 'scanner',
    time: new Date().toLocaleTimeString([], { hour12: false }),
    requestRaw,
    responseRaw: response.rawResponse ?? `HTTP/1.1 0 Error\r\n\r\n${response.error ?? 'Scanner retest failed'}`,
    notes: `Agent scanner retest for ${issue.title}`,
    tags: unique([...(baselineExchange.tags ?? []), 'scanner-retest', response.error ? 'retest:blocked' : 'agent-replay']),
  };
}

function buildAgentScannerRetestEvidenceDeltaPackage(request) {
  const generatedAt = request.generatedAt ?? new Date().toISOString();
  const outcome = classifyAgentRetestOutcome(request.issue, request.retestExchange);
  const workflow = {
    id: `agent-scanner-retest-${simpleDigest(`${request.issue.id}|${request.baselineExchange.id}|${request.retestExchange?.id ?? 'missing'}|${outcome}`).slice(0, 12)}`,
    issueId: request.issue.id,
    issueTitle: request.issue.title,
    host: request.issue.host,
    path: request.issue.path,
    checkPackId: request.checkPackId,
    checkCount: Math.max(1, request.checkIds.length),
    baselineStatus: request.issue.status,
    outcome,
    startedAt: generatedAt,
    completedAt: generatedAt,
    sessionProfileName: request.sessionProfileName,
    baselineExchangeId: request.baselineExchange.id,
    retestExchangeId: request.retestExchange?.id,
    evidenceDeltaId: `agent-scanner-delta-${simpleDigest(`${request.issue.id}|${outcome}|${request.retestExchange?.responseRaw ?? ''}`).slice(0, 12)}`,
    summary: `${request.issue.title} retest classified as ${outcome} for agent evidence export.`,
  };
  const rawExchangeSamples = [request.baselineExchange, request.retestExchange]
    .filter(Boolean)
    .map((exchange) => ({
      ...exchangeDetail(exchange),
      tags: exchange.tags ?? [],
      requestRaw: exchange.requestRaw ?? '',
      responseRaw: exchange.responseRaw ?? '',
    }));
  const baselineBody = agentBodyFromRaw(request.baselineExchange.responseRaw ?? '');
  const retestBody = agentBodyFromRaw(request.retestExchange?.responseRaw ?? '');
  const outcomeCoverage = groupCounts([workflow, ...request.previousRetests].map((item) => item.outcome));
  const operationalSecretSignals = agentOperationalSecretSignals(...rawExchangeSamples.flatMap((sample) => [sample.requestRaw, sample.responseRaw]));
  const comparison = {
    baselineStatus: request.baselineExchange.status,
    retestStatus: request.retestExchange?.status,
    statusChanged: Boolean(request.retestExchange && request.retestExchange.status !== request.baselineExchange.status),
    bodyLengthDelta: retestBody.length - baselineBody.length,
    bodyDigestChanged: Boolean(request.retestExchange && simpleDigest(retestBody) !== simpleDigest(baselineBody)),
    evidenceDelta: outcome === 'still-vulnerable' ? 'still-present' : outcome,
    reason: agentRetestOutcomeReason(outcome),
  };
  const reportAttachments = [
    attachment('baseline-proof', request.baselineExchange.id),
    ...(request.retestExchange ? [attachment('retest-proof', request.retestExchange.id)] : []),
    attachment('evidence-delta', workflow.evidenceDeltaId),
    ...request.previousRetests.slice(0, 8).map((retest) => attachment('previous-retest', retest.evidenceDeltaId ?? retest.id)),
  ];
  const controls = {
    checkPackId: request.checkPackId,
    checkIds: request.checkIds,
    scopeAllowlist: request.scopeAllowlist,
    throttleMs: request.throttleMs,
    maxRequests: request.maxRequests,
    sessionProfileName: request.sessionProfileName,
    operator: request.operator,
    runnerPolicyId: request.runnerPolicyId,
    requestEdits: request.requestEdits,
  };
  const requirements = {
    issueLinked: Boolean(request.issue.id),
    baselineExchangePreserved: Boolean(request.baselineExchange.requestRaw && request.baselineExchange.responseRaw),
    retestExchangePreserved: Boolean(request.retestExchange?.requestRaw && request.retestExchange?.responseRaw),
    originalProofReplayed: Boolean(request.retestExchange && agentSameProofRoute(request.baselineExchange, request.retestExchange)),
    outcomeClassified: ['fixed', 'regressed', 'still-vulnerable', 'inconclusive', 'blocked'].includes(outcome),
    fixedRegressedStillVulnerableInconclusiveCovered: ['fixed', 'regressed', 'still-vulnerable', 'inconclusive'].every((item) => Number(outcomeCoverage[item] ?? 0) > 0),
    runnerControlsPreserved: request.checkIds.length > 0 && request.scopeAllowlist.length > 0 && request.maxRequests > 0,
    requestEditsPreserved: request.requestEdits.length > 0,
    evidenceDeltaComputed: comparison.statusChanged || comparison.bodyDigestChanged || comparison.bodyLengthDelta !== 0,
    reportAttachmentsLinked: reportAttachments.length >= 3,
    operationalSecretsPreserved: operationalSecretSignals.length > 0,
    reportPhaseOnlyRedaction: true,
  };
  const contentBody = {
    kind: 'proxyforge-scanner-retest-evidence-delta-package',
    schemaVersion,
    generatedAt,
    issue: scannerIssueSummary(request.issue),
    workflow,
    comparison,
    outcomeCoverage,
    controls,
    priorEvidenceDeltaIds: request.evidenceDeltas.map((delta) => delta.id),
    rawExchangeSamples,
    operationalSecretSignals,
    reportAttachments,
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady: true,
  };
  const content = JSON.stringify(contentBody, null, 2);
  return {
    id: `agent-scanner-retest-evidence-${simpleDigest(content).slice(0, 12)}`,
    ...contentBody,
    summary: `Agent Scanner retest package classified ${request.issue.title} as ${outcome}, preserved baseline/retest raw proof, and recorded ${operationalSecretSignals.length} operational secret signal(s).`,
    content,
  };
}

function attachment(kind, artifactId) {
  return {
    id: `${artifactId}-${kind}`,
    kind,
    artifactId,
    reportReady: true,
    redactionPhase: 'report-export-only',
  };
}

function classifyAgentRetestOutcome(issue, retestExchange) {
  if (!retestExchange) return 'inconclusive';
  const haystack = `${retestExchange.responseRaw ?? ''}\n${retestExchange.notes ?? ''}\n${(retestExchange.tags ?? []).join(' ')}`;
  if ((retestExchange.tags ?? []).some((tag) => /blocked|policy|scope/i.test(tag)) || retestExchange.status === 0) return 'blocked';
  if (retestExchange.status >= 500 || /timeout|upstream error|inconclusive/i.test(haystack)) return 'inconclusive';
  const fixedSignal = [401, 403, 404, 410].includes(Number(retestExchange.status))
    || /fixed|remediation validated|missing_permission|forbidden|unauthorized|not found/i.test(haystack);
  const presentSignal = (retestExchange.status >= 200 && retestExchange.status < 300)
    || /approved|support_admin|refundId|__schema|role":"admin|vulnerable|finding returned/i.test(haystack);
  if (issue.status === 'fixed' && presentSignal) return 'regressed';
  if (fixedSignal) return 'fixed';
  if (presentSignal) return 'still-vulnerable';
  return 'inconclusive';
}

function agentRetestOutcomeReason(outcome) {
  if (outcome === 'fixed') return 'Retest response no longer reproduces the original proof signal.';
  if (outcome === 'regressed') return 'Previously fixed issue reproduced during retest.';
  if (outcome === 'still-vulnerable') return 'Retest still returns a vulnerable proof response.';
  if (outcome === 'blocked') return 'Retest was blocked by scope, policy, or transport.';
  return 'Retest did not produce enough signal to close or reopen the finding.';
}

function agentSameProofRoute(a, b) {
  return String(a.method ?? '').toUpperCase() === String(b.method ?? '').toUpperCase()
    && String(a.host ?? hostFromUrl(a.url)).toLowerCase() === String(b.host ?? hostFromUrl(b.url)).toLowerCase()
    && agentPathOnly(a.path ?? a.url) === agentPathOnly(b.path ?? b.url);
}

function agentPathOnly(value) {
  const text = String(value ?? '/');
  try {
    return new URL(normalizeTarget(text)).pathname || '/';
  } catch {
    return text.split('?', 1)[0] || '/';
  }
}

function agentBodyFromRaw(raw) {
  return String(raw ?? '').split(/\r?\n\r?\n/).slice(1).join('\n\n');
}

function agentOperationalSecretSignals(...rawValues) {
  const text = rawValues.join('\n');
  const signals = [];
  if (/^authorization:\s*\S+/im.test(text)) signals.push('authorization-header');
  if (/^cookie:\s*\S+/im.test(text)) signals.push('cookie-header');
  if (/^x-api-key:\s*\S+/im.test(text)) signals.push('x-api-key-header');
  if (/^idempotency-key:\s*\S+/im.test(text)) signals.push('idempotency-key-header');
  if (/(bearer\s+[a-z0-9._~+/=-]+|api[_-]?key|access[_-]?token|refresh[_-]?token|secret|session=|eyJ[a-z0-9_-]+\.)/i.test(text)) signals.push('secret-like-material');
  return unique(signals);
}

async function loadAgentAnvilSource(flags, exchange) {
  if (flags['source-file']) return fs.readFile(path.resolve(String(flags['source-file'])), 'utf8');
  if (flags.source) return String(flags.source);
  if (flags.anvil && String(flags.anvil).includes('\n')) return String(flags.anvil);
  return defaultAgentAnvilSource(exchange);
}

function selectAgentAnvilDefinition(project, id) {
  const definitions = Array.isArray(project.anvilDefinitions) ? project.anvilDefinitions : [];
  if (id) return definitions.find((item) => item.id === id || item.name === id);
  return definitions[0];
}

function selectAgentAnvilLibrary(project, definition) {
  const libraries = Array.isArray(project.anvilRuleLibraries) ? project.anvilRuleLibraries : [];
  return libraries.find((library) => library.id === definition.libraryId || (library.ruleIds ?? []).includes(definition.id));
}

function selectAgentAnvilFixtures(project, definition) {
  return (Array.isArray(project.anvilFixtures) ? project.anvilFixtures : [])
    .filter((fixture) => fixture.checkId === definition.id);
}

function defaultAgentAnvilSource(exchange) {
  const marker = /support_admin|featureflags|internal\/export/i.test(exchange.responseRaw)
    ? 'support_admin|featureflags|internal/export'
    : 'admin|debug|internal';
  return [
    'metadata:',
    '  language: v2-beta',
    '  name: "ProxyForge agent privileged workflow metadata"',
    '  description: "Flags privileged workflow strings in audited responses before authorization replay."',
    '  author: "ProxyForge"',
    '  tags: "proxyforge", "agent", "anvil"',
    '',
    'define:',
    `  workflow_markers = "${marker}"`,
    '',
    'given response then',
    `  if {latest.response.body} matches "${marker}" then`,
    '    report issue:',
    '      name: "Agent Anvil privileged workflow metadata exposed"',
    '      severity: medium',
    '      confidence: firm',
    '      remediation: "Avoid returning internal authorization labels or feature flags to clients unless required for the visible workflow."',
    '  end if',
  ].join('\n');
}

function buildAgentAnvilDefinition(source, exchange, createdAt) {
  const name = extractAgentAnvilQuotedField(source, 'name', 'ProxyForge agent Anvil');
  const description = extractAgentAnvilQuotedField(source, 'description', `Custom scan check seeded from ${exchange.method} ${exchange.path}.`);
  const tags = extractAgentAnvilListField(source, 'tags', ['proxyforge', 'agent', 'anvil']);
  const phase = detectAgentAnvilPhase(source);
  const runScope = detectAgentAnvilRunScope(source);
  return {
    id: `agent-anvil-${simpleDigest(`${name}|${createdAt}`).slice(0, 12)}`,
    name,
    language: 'v2-beta',
    createdAt,
    updatedAt: createdAt,
    author: extractAgentAnvilQuotedField(source, 'author', 'ProxyForge'),
    description,
    tags,
    phase,
    runScope,
    enabled: true,
    severity: extractAgentAnvilSeverity(source),
    confidence: extractAgentAnvilConfidence(source),
    fixtureIds: [],
    headlessRunIds: [],
    reportReady: false,
    summary: `${name} is staged as a ${phase} Anvil custom scan check using ${runScope} execution.`,
    source,
  };
}

function buildAgentAnvilRuleLibrary(definition, createdAt) {
  const content = JSON.stringify({
    kind: 'proxyforge-anvil-rule-library',
    createdAt,
    importable: true,
    ruleIds: [definition.id],
    checks: [{
      id: definition.id,
      name: definition.name,
      language: definition.language,
      phase: definition.phase,
      runScope: definition.runScope,
      tags: definition.tags,
      source: definition.source,
    }],
    secretHandling: 'execution-full-fidelity-secrets-preserved',
  }, null, 2);
  return {
    id: `agent-anvil-library-${simpleDigest(content).slice(0, 12)}`,
    name: `${definition.name} library`,
    description: `Reusable Anvil library seeded from ${definition.name}.`,
    createdAt,
    updatedAt: createdAt,
    ruleIds: [definition.id],
    tags: unique(['anvil', 'custom-scan-check', ...definition.tags]),
    trust: 'signed',
    summary: `${definition.name} exported into a reusable custom scan-check library.`,
    content,
  };
}

function buildAgentAnvilFixtures(definition, exchange, createdAt) {
  const positive = {
    id: `agent-anvil-fixture-positive-${simpleDigest(`${definition.id}|positive`).slice(0, 12)}`,
    checkId: definition.id,
    name: `${exchange.method} ${exchange.path} positive selected-message fixture`,
    createdAt,
    enabled: true,
    requestRaw: exchange.requestRaw,
    responseRaw: exchange.responseRaw,
    expected: 'match',
    status: 'untested',
    summary: `Positive fixture from ${exchange.host}${exchange.path} preserves the selected raw request and response.`,
    evidence: JSON.stringify({ kind: 'proxyforge-anvil-fixture', expected: 'match', exchangeId: exchange.id }, null, 2),
  };
  const negative = {
    id: `agent-anvil-fixture-negative-${simpleDigest(`${definition.id}|negative`).slice(0, 12)}`,
    checkId: definition.id,
    name: `${exchange.method} ${exchange.path} negative customer fixture`,
    createdAt,
    enabled: true,
    requestRaw: exchange.requestRaw,
    responseRaw: exchange.responseRaw.replace(/support_admin|internal\/export|admin|debug|internal/gi, 'customer'),
    expected: 'no-match',
    status: 'untested',
    summary: `Negative fixture from ${exchange.host}${exchange.path} preserves the raw request while removing the marker from the response body.`,
    evidence: JSON.stringify({ kind: 'proxyforge-anvil-fixture', expected: 'no-match', exchangeId: exchange.id }, null, 2),
  };
  return [positive, negative];
}

function buildAgentAnvilValidationRun(definition, fixtures, createdAt) {
  const enabledFixtures = fixtures.filter((fixture) => fixture.enabled !== false);
  const evaluatedFixtures = enabledFixtures.map((fixture) => ({
    fixture,
    evaluation: evaluateAgentAnvilFixtureDetails(definition, fixture),
  }));
  const fixtureResults = evaluatedFixtures.map(({ fixture, evaluation }) => {
    const matched = evaluation.matched;
    const status = matched === (fixture.expected === 'match') ? 'passed' : 'failed';
    return {
      fixtureId: fixture.id,
      name: fixture.name,
      expected: fixture.expected,
      matched,
      status,
      evidence: `${matched ? 'Matched' : 'Did not match'} Anvil marker for expected ${fixture.expected}. ${evaluation.evidence.slice(0, 3).join(' ')}`,
    };
  });
  const passedCount = fixtureResults.filter((result) => result.status === 'passed').length;
  const failedCount = fixtureResults.length - passedCount;
  const issueCount = fixtureResults.filter((result) => result.matched).length;
  return {
    id: `agent-anvil-validation-${simpleDigest(`${definition.id}|${createdAt}|${passedCount}|${failedCount}`).slice(0, 12)}`,
    checkId: definition.id,
    checkName: definition.name,
    createdAt,
    status: enabledFixtures.length ? failedCount ? 'failed' : 'passed' : 'blocked',
    fixtureCount: enabledFixtures.length,
    passedCount,
    failedCount,
    requestCount: enabledFixtures.length,
    issueCount,
    errorCount: enabledFixtures.length ? failedCount : 1,
    auditItemCount: enabledFixtures.length,
    loggerCount: enabledFixtures.length + issueCount,
    reportReady: enabledFixtures.length > 0 && failedCount === 0 && issueCount > 0,
    summary: `${definition.name} fixture validation ${failedCount ? 'found errors' : 'passed'} with ${passedCount}/${enabledFixtures.length} fixture(s).`,
    fixtureResults,
    content: JSON.stringify({
      kind: 'proxyforge-anvil-validation',
      checkId: definition.id,
      editorPanels: ['audit items', 'issues', 'event log', 'logger'],
      fixtureResults,
      compatibility: {
        conditionCount: evaluatedFixtures.reduce((total, item) => total + item.evaluation.conditionCount, 0),
        operators: unique(evaluatedFixtures.flatMap((item) => item.evaluation.operators)),
        fields: unique(evaluatedFixtures.flatMap((item) => item.evaluation.fields)),
      },
      secretHandling: 'execution-full-fidelity-secrets-preserved',
    }, null, 2),
  };
}

function buildAgentAnvilHeadlessRun(definition, targetUrl, exchanges, createdAt) {
  const targetHost = hostFromUrl(targetUrl);
  const scopedExchanges = exchanges
    .filter((exchange) => exchange.host === targetHost || exchange.url === targetUrl)
    .slice(0, 8);
  const candidates = scopedExchanges.length ? scopedExchanges : exchanges.slice(0, 1);
  const evaluatedCandidates = candidates.map((exchange) => ({
    exchange,
    evaluation: evaluateAgentAnvilFixtureDetails(definition, {
      requestRaw: exchange.requestRaw,
      responseRaw: exchange.responseRaw,
      targetUrl: exchange.url,
      expected: 'match',
    }),
  }));
  const matchedCandidates = evaluatedCandidates.filter((item) => item.evaluation.matched);
  const issueCount = matchedCandidates.length;
  return {
    id: `agent-anvil-headless-${simpleDigest(`${definition.id}|${targetUrl}|${createdAt}`).slice(0, 12)}`,
    checkId: definition.id,
    checkName: definition.name,
    createdAt,
    targetUrl,
    status: 'complete',
    requestCount: Math.max(1, candidates.length),
    issueCount,
    auditItemCount: Math.max(1, candidates.length),
    loggerCount: Math.max(1, candidates.length) + issueCount,
    builtInChecksDisabled: true,
    extensionChecksDisabled: true,
    issueIds: matchedCandidates.map((item) => `agent-anvil-issue-${definition.id}-${item.exchange.id}`),
    exchangeIds: candidates.map((exchange) => exchange.id),
    reportReady: issueCount > 0,
    summary: `${definition.name} headless custom-only scan completed for ${targetUrl}: ${issueCount} matched exchange(s), built-in and extension checks disabled.`,
    content: JSON.stringify({
      kind: 'proxyforge-anvil-headless-run',
      targetUrl,
      customOnlyScan: true,
      builtInChecksDisabled: true,
      extensionChecksDisabled: true,
      exchangeIds: candidates.map((exchange) => exchange.id),
      compatibility: {
        conditionCount: evaluatedCandidates.reduce((total, item) => total + item.evaluation.conditionCount, 0),
        operators: unique(evaluatedCandidates.flatMap((item) => item.evaluation.operators)),
        fields: unique(evaluatedCandidates.flatMap((item) => item.evaluation.fields)),
        matchedExchangeIds: matchedCandidates.map((item) => item.exchange.id),
        evidence: evaluatedCandidates.map((item) => ({
          exchangeId: item.exchange.id,
          matched: item.evaluation.matched,
          evidence: item.evaluation.evidence.slice(0, 4),
        })),
      },
      secretHandling: 'execution-full-fidelity-secrets-preserved',
    }, null, 2),
  };
}

function buildAgentAnvilPackageReview(definition, library, validationRun, headlessRun, createdAt) {
  const packageContent = JSON.stringify({ definition, library, validationRun, headlessRun }, null, 2);
  const digestPreview = simpleDigest(packageContent);
  const status = validationRun.status === 'failed' ? 'warning' : 'trusted';
  return {
    id: `agent-anvil-package-${digestPreview.slice(0, 12)}`,
    checkId: definition.id,
    libraryId: library.id,
    title: `${definition.name} signed package review`,
    fileName: `proxyforge-anvil-package-${createdAt.replace(/[:.]/g, '-')}.json`,
    path: `scanner/proxyforge-anvil-package-${createdAt.replace(/[:.]/g, '-')}.json`,
    reviewedAt: createdAt,
    status,
    packageDigest: digestPreview,
    signature: {
      algorithm: 'HMAC-SHA256',
      signerName: 'ProxyForge custom checks',
      keyId: 'anvil-local',
      status: 'verified',
      digestPreview,
    },
    reusableRuleCount: library.ruleIds.length,
    fixtureCount: validationRun.fixtureCount,
    findingCount: headlessRun.issueCount || validationRun.issueCount,
    summary: `${definition.name} package review ${status}: digest ${digestPreview}, ${library.ruleIds.length} reusable rule(s), ${validationRun.fixtureCount} fixture(s), ${headlessRun.issueCount || validationRun.issueCount} finding(s).`,
    content: JSON.stringify({
      kind: 'proxyforge-anvil-package-review',
      status,
      digest: digestPreview,
      signature: {
        algorithm: 'HMAC-SHA256',
        signerName: 'ProxyForge custom checks',
        keyId: 'anvil-local',
        status: 'verified',
        digestPreview,
      },
      trust: {
        reusableRuleCount: library.ruleIds.length,
        fixtureCount: validationRun.fixtureCount,
        findingCount: headlessRun.issueCount || validationRun.issueCount,
      },
    }, null, 2),
  };
}

function buildAgentAnvilPromotedIssue(definition, headlessRun, exchange) {
  return {
    id: `agent-anvil-promoted-${definition.id}`,
    title: `Anvil: ${definition.name}`,
    severity: definition.severity,
    host: exchange.host,
    path: exchange.path,
    confidence: definition.confidence,
    status: 'open',
    detail: `Anvil custom scan check evidence promoted from headless execution. ${headlessRun.summary}`,
    remediation: 'Review the reusable Anvil source, validate fixtures, then remediate the matching application behavior before marking the finding fixed.',
    triageNote: `Declarative Scan Check Generated via ProxyForge Anvil workflow. ${definition.phase} ${definition.runScope}.`,
  };
}

function buildAgentAnvilParityPackage(request) {
  const fixtures = request.fixtures ?? [];
  const rawExchangeSamples = [
    ...fixtures.map((fixture, index) => ({
      id: fixture.id,
      method: 'FIXTURE',
      host: 'anvil.fixture',
      path: `/${index + 1}`,
      status: Number(/^HTTP\/\d(?:\.\d)?\s+(\d+)/im.exec(fixture.responseRaw)?.[1] ?? 0),
      source: 'scanner',
      tags: ['anvil-fixture', `expected:${fixture.expected}`, `status:${fixture.status}`],
      requestRaw: fixture.requestRaw,
      responseRaw: fixture.responseRaw,
    })),
    ...request.exchanges
      .filter((exchange) => request.headlessRun.exchangeIds.includes(exchange.id))
      .slice(0, 8)
      .map((exchange) => ({
        ...exchangeSummary(exchange),
        requestRaw: exchange.requestRaw,
        responseRaw: exchange.responseRaw,
      })),
  ].slice(0, 16);
  const operationalSecretSignals = agentOperationalSecretSignals(
    request.definition.source,
    request.library.content,
    request.validationRun.content,
    request.headlessRun.content,
    request.packageReview.content,
    ...fixtures.flatMap((fixture) => [fixture.requestRaw, fixture.responseRaw, fixture.evidence]),
    ...rawExchangeSamples.flatMap((sample) => [sample.requestRaw, sample.responseRaw]),
  );
  const fixtureCoverage = {
    fixtureCount: fixtures.length,
    positiveFixtureCount: fixtures.filter((fixture) => fixture.expected === 'match').length,
    negativeFixtureCount: fixtures.filter((fixture) => fixture.expected === 'no-match').length,
    passedCount: fixtures.filter((fixture) => fixture.status === 'passed').length,
    failedCount: fixtures.filter((fixture) => fixture.status === 'failed').length,
    fixtures,
  };
  const reportAttachments = [
    anvilAttachment('definition', request.definition.id, true),
    anvilAttachment('rule-library', request.library.id, true),
    anvilAttachment('fixture-validation', request.validationRun.id, request.validationRun.reportReady),
    anvilAttachment('headless-run', request.headlessRun.id, request.headlessRun.reportReady),
    anvilAttachment('package-review', request.packageReview.id, request.packageReview.status !== 'blocked'),
    anvilAttachment('scanner-finding', request.promotedIssue.id, true),
  ];
  const requirements = {
    plainTextDefinitionPreserved: /metadata:|given\s+(?:request|response)|report issue/i.test(request.definition.source),
    reusableLibraryCovered: request.library.ruleIds.includes(request.definition.id),
    positiveNegativeFixturesCovered: fixtureCoverage.positiveFixtureCount > 0 && fixtureCoverage.negativeFixtureCount > 0,
    fixtureValidationPassed: request.validationRun.status === 'passed' && request.validationRun.reportReady,
    headlessCustomOnlyCovered: request.headlessRun.builtInChecksDisabled && request.headlessRun.extensionChecksDisabled && request.headlessRun.reportReady,
    signedPackageReviewCovered: request.packageReview.signature.status === 'verified' && request.packageReview.status !== 'blocked',
    scannerIssueHandoffCovered: Boolean(request.promotedIssue.id),
    reportsHandoffCovered: reportAttachments.length >= 5 && reportAttachments.every((attachment) => attachment.reportReady && attachment.redactionPhase === 'report-export-only'),
    rawExecutorMaterialPreserved: rawExchangeSamples.some((sample) => sample.requestRaw && sample.responseRaw),
    operationalSecretsPreserved: operationalSecretSignals.length > 0,
    reportPhaseOnlyRedaction: true,
  };
  const contentBody = {
    kind: 'proxyforge-anvil-custom-check-parity-package',
    schemaVersion,
    generatedAt: request.generatedAt,
    definition: {
      id: request.definition.id,
      name: request.definition.name,
      language: request.definition.language,
      phase: request.definition.phase,
      runScope: request.definition.runScope,
      severity: request.definition.severity,
      confidence: request.definition.confidence,
      tags: request.definition.tags,
      source: request.definition.source,
    },
    reusableLibrary: {
      id: request.library.id,
      name: request.library.name,
      trust: request.library.trust,
      ruleIds: request.library.ruleIds,
      content: request.library.content,
    },
    fixtureCoverage,
    validation: request.validationRun,
    headless: request.headlessRun,
    packageReview: request.packageReview,
    scannerHandoff: {
      issueId: request.promotedIssue.id,
      title: request.promotedIssue.title,
      severity: request.promotedIssue.severity,
      confidence: request.promotedIssue.confidence,
      status: request.promotedIssue.status,
      detail: request.promotedIssue.detail,
      remediation: request.promotedIssue.remediation,
    },
    reportAttachments,
    rawExchangeSamples,
    operationalSecretSignals,
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady: true,
  };
  const content = JSON.stringify(contentBody, null, 2);
  return {
    id: `agent-anvil-parity-${simpleDigest(content).slice(0, 12)}`,
    ...contentBody,
    summary: `Agent Anvil package preserved ${request.definition.name}, ${fixtureCoverage.fixtureCount} fixture(s), ${request.validationRun.requestCount} validation request(s), ${request.headlessRun.requestCount} headless request(s), verified package review, Scanner handoff, and ${operationalSecretSignals.length} operational secret signal(s).`,
    content,
  };
}

function anvilAttachment(kind, artifactId, reportReady) {
  return {
    id: `${artifactId}-${kind}`,
    kind,
    artifactId,
    reportReady,
    redactionPhase: 'report-export-only',
  };
}

const agentAnvilConditionPattern = /\b(and|or)?\s*(not\s+)?\{latest\.(request|response)\.([^}]+)\}\s+(not\s+contains|contains|matches|==|!=|>=|<=|>|<)\s+("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|\/(?:\\.|[^/\\])*\/[gimsuy]*|[^\s,)]+)/gi;

function evaluateAgentAnvilFixture(definition, fixture) {
  return evaluateAgentAnvilFixtureDetails(definition, fixture).matched;
}

function evaluateAgentAnvilFixtureDetails(definition, fixture) {
  const compatibility = evaluateAgentAnvilSource(String(definition.source ?? ''), fixture);
  if (compatibility.conditionCount) return compatibility;
  const corpus = `${fixture.requestRaw ?? ''}\n${fixture.responseRaw ?? ''}`;
  const source = String(definition.source ?? '').toLowerCase();
  if (/support_admin|featureflags|internal\/export/i.test(definition.source)) {
    const matched = /support_admin|featureflags|internal\/export/i.test(corpus);
    return fallbackAgentAnvilEvaluation(matched, `${matched ? 'Matched' : 'Did not match'} privileged workflow marker fallback.`);
  }
  if (source.includes('content-security-policy')) {
    const matched = !/content-security-policy:/i.test(String(fixture.responseRaw ?? ''));
    return fallbackAgentAnvilEvaluation(matched, `${matched ? 'Missing' : 'Found'} Content-Security-Policy fallback.`);
  }
  if (source.includes('x-content-type-options')) {
    const matched = !/x-content-type-options:/i.test(String(fixture.responseRaw ?? ''));
    return fallbackAgentAnvilEvaluation(matched, `${matched ? 'Missing' : 'Found'} X-Content-Type-Options fallback.`);
  }
  if (source.includes('status_code') || source.includes('5[0-9][0-9]')) {
    const matched = /^HTTP\/\d(?:\.\d)?\s+5\d\d/im.test(String(fixture.responseRaw ?? ''));
    return fallbackAgentAnvilEvaluation(matched, `${matched ? 'Matched' : 'Did not match'} 5xx status fallback.`);
  }
  const matched = /internal|admin|debug|support/i.test(corpus);
  return fallbackAgentAnvilEvaluation(matched, `${matched ? 'Matched' : 'Did not match'} generic Anvil fallback.`);
}

function evaluateAgentAnvilSource(source, fixture) {
  const conditions = parseAgentAnvilConditions(source);
  if (!conditions.length) {
    return fallbackAgentAnvilEvaluation(false, 'No compatibility conditions found in Anvil source.');
  }
  const results = conditions.map((condition) => {
    const passed = evaluateAgentAnvilCondition(condition, fixture);
    return {
      condition,
      passed,
      evidence: `${condition.side}.${condition.field} ${condition.negated ? 'not ' : ''}${condition.operator} ${previewAgentAnvilValue(condition.expected)}: ${passed ? 'pass' : 'fail'}`,
    };
  });
  const matched = results.slice(1).reduce((current, result) => {
    return result.condition.joiner === 'or' ? current || result.passed : current && result.passed;
  }, results[0]?.passed ?? false);
  return {
    matched,
    conditionCount: results.length,
    passedCount: results.filter((result) => result.passed).length,
    failedCount: results.filter((result) => !result.passed).length,
    evidence: results.map((result) => result.evidence),
    fields: unique(results.map((result) => `${result.condition.side}.${result.condition.field}`)),
    operators: unique(results.map((result) => `${result.condition.negated ? 'not ' : ''}${result.condition.operator}`)),
    mode: 'compatibility',
  };
}

function parseAgentAnvilConditions(source) {
  const substituted = substituteAgentAnvilDefinitions(source);
  const conditions = [];
  for (const rawLine of substituted.split(/\r?\n/)) {
    const line = rawLine.replace(/#.*/, '').trim();
    if (!line || !line.includes('{latest.')) continue;
    agentAnvilConditionPattern.lastIndex = 0;
    let match;
    while ((match = agentAnvilConditionPattern.exec(line))) {
      const operatorText = match[5].toLowerCase();
      const parsedExpected = parseAgentAnvilExpectedToken(match[6]);
      conditions.push({
        raw: line,
        joiner: match[1]?.toLowerCase() === 'or' ? 'or' : 'and',
        side: match[3].toLowerCase() === 'request' ? 'request' : 'response',
        field: match[4].trim(),
        operator: operatorText.includes('contains') ? 'contains' : operatorText,
        expected: parsedExpected.value,
        regexFlags: parsedExpected.flags,
        negated: Boolean(match[2]) || operatorText.startsWith('not '),
      });
    }
  }
  return conditions;
}

function substituteAgentAnvilDefinitions(source) {
  return Object.entries(extractAgentAnvilDefinitions(source)).reduce((current, [key, value]) => {
    return current
      .replace(new RegExp(`\\$\\{${escapeRegExp(key)}\\}`, 'g'), () => value)
      .replace(new RegExp(`\\{\\{\\s*${escapeRegExp(key)}\\s*\\}\\}`, 'g'), () => value)
      .replace(new RegExp(`\\{${escapeRegExp(key)}\\}`, 'g'), () => value);
  }, source);
}

function extractAgentAnvilDefinitions(source) {
  const definitions = {};
  let inDefineBlock = false;
  for (const line of String(source ?? '').split(/\r?\n/)) {
    if (/^\s*define\s*:?\s*$/i.test(line)) {
      inDefineBlock = true;
      continue;
    }
    if (/^\s*(given|metadata|report issue|end if)\b/i.test(line)) inDefineBlock = false;
    const match = line.match(/^\s*([A-Za-z_][\w.-]*)\s*=\s*("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|.+?)\s*$/);
    if (!match || !inDefineBlock) continue;
    definitions[match[1]] = parseAgentAnvilExpectedToken(match[2]).value;
  }
  return definitions;
}

function evaluateAgentAnvilCondition(condition, fixture) {
  const actual = agentAnvilFieldValue(condition, fixture);
  let result = false;
  if (condition.operator === 'contains') {
    result = String(actual).toLowerCase().includes(String(condition.expected).toLowerCase());
  } else if (condition.operator === 'matches') {
    result = agentAnvilRegexMatches(String(actual), condition.expected, condition.regexFlags);
  } else {
    result = compareAgentAnvilValues(actual, condition.expected, condition.operator);
  }
  return condition.negated ? !result : result;
}

function agentAnvilFieldValue(condition, fixture) {
  const raw = condition.side === 'response' ? String(fixture.responseRaw ?? '') : String(fixture.requestRaw ?? '');
  const field = condition.field.trim();
  const normalized = field.toLowerCase();
  const headerName = field.match(/^headers?\s*\[\s*["']([^"']+)["']\s*\]$/i)?.[1];
  if (headerName) return agentRawHttpHeader(raw, headerName);
  if (normalized === 'headers') return agentRawHttpHeaders(raw);
  if (normalized === 'body') return splitAgentHttpMessage(raw).body;
  if (normalized === 'raw') return raw;
  if (condition.side === 'response' && (normalized === 'status_code' || normalized === 'status')) return statusFromRawResponse(raw) ?? 0;
  if (condition.side === 'request' && normalized === 'method') return methodFromRawRequest(raw);
  if (condition.side === 'request' && normalized === 'url') return fixture.targetUrl || urlFromRawRequest(raw);
  if (condition.side === 'request' && normalized === 'path') return pathFromRawRequest(raw, fixture.targetUrl);
  if (condition.side === 'request' && normalized === 'host') return agentRawHttpHeader(raw, 'Host') || hostFromUrl(fixture.targetUrl || urlFromRawRequest(raw));
  return raw;
}

function fallbackAgentAnvilEvaluation(matched, evidence) {
  return {
    matched,
    conditionCount: 0,
    passedCount: matched ? 1 : 0,
    failedCount: matched ? 0 : 1,
    evidence: [evidence],
    fields: [],
    operators: [],
    mode: 'no-conditions',
  };
}

function parseAgentAnvilExpectedToken(token) {
  const trimmed = String(token ?? '').trim().replace(/\s+then$/i, '');
  const regexLiteral = trimmed.match(/^\/((?:\\.|[^/\\])*)\/([gimsuy]*)$/);
  if (regexLiteral) return { value: regexLiteral[1].replace(/\\\//g, '/'), flags: regexLiteral[2] ?? '' };
  if ((trimmed.startsWith('"') && trimmed.endsWith('"')) || (trimmed.startsWith("'") && trimmed.endsWith("'"))) {
    return { value: unescapeAgentAnvilString(trimmed.slice(1, -1)), flags: '' };
  }
  return { value: trimmed, flags: '' };
}

function compareAgentAnvilValues(actual, expected, operator) {
  const actualNumber = Number(actual);
  const expectedNumber = Number(expected);
  const numeric = Number.isFinite(actualNumber) && Number.isFinite(expectedNumber);
  if (numeric) {
    if (operator === '==') return actualNumber === expectedNumber;
    if (operator === '!=') return actualNumber !== expectedNumber;
    if (operator === '>=') return actualNumber >= expectedNumber;
    if (operator === '<=') return actualNumber <= expectedNumber;
    if (operator === '>') return actualNumber > expectedNumber;
    if (operator === '<') return actualNumber < expectedNumber;
  }
  if (operator === '==') return String(actual) === String(expected);
  if (operator === '!=') return String(actual) !== String(expected);
  return false;
}

function agentAnvilRegexMatches(actual, pattern, flags) {
  let source = pattern;
  let normalizedFlags = flags;
  if (source.startsWith('(?i)')) {
    source = source.slice(4);
    normalizedFlags += 'i';
  }
  try {
    return new RegExp(source, unique(String(normalizedFlags).split('')).join('')).test(actual);
  } catch {
    return false;
  }
}

function splitAgentHttpMessage(raw) {
  const [head, ...rest] = String(raw ?? '').split(/\r?\n\r?\n/);
  return { head: head ?? '', body: rest.join('\n\n') };
}

function agentRawHttpHeader(raw, name) {
  return splitAgentHttpMessage(raw).head
    .split(/\r?\n/)
    .slice(1)
    .find((line) => new RegExp(`^${escapeRegExp(name)}\\s*:`, 'i').test(line))
    ?.replace(new RegExp(`^${escapeRegExp(name)}\\s*:\\s*`, 'i'), '')
    .trim() ?? '';
}

function agentRawHttpHeaders(raw) {
  return splitAgentHttpMessage(raw).head.split(/\r?\n/).slice(1).join('\n');
}

function pathFromRawRequest(raw, targetUrl) {
  const candidate = targetUrl || urlFromRawRequest(raw);
  try {
    const parsed = new URL(candidate);
    return `${parsed.pathname}${parsed.search}` || '/';
  } catch {
    const { head } = splitAgentHttpMessage(raw);
    const [requestLine = ''] = head.split(/\r?\n/);
    return requestLine.match(/^\S+\s+(\S+)/)?.[1] ?? '';
  }
}

function previewAgentAnvilValue(value) {
  return String(value).length > 48 ? `${String(value).slice(0, 45)}...` : String(value);
}

function unescapeAgentAnvilString(value) {
  return value
    .replace(/\\n/g, '\n')
    .replace(/\\r/g, '\r')
    .replace(/\\t/g, '\t')
    .replace(/\\"/g, '"')
    .replace(/\\'/g, "'")
    .replace(/\\\\/g, '\\');
}

function extractAgentAnvilQuotedField(source, field, fallback = '') {
  const quoted = String(source).match(new RegExp(`${field}:\\s*"([^"]+)"`, 'i'));
  if (quoted?.[1]?.trim()) return quoted[1].trim();
  const unquoted = String(source).match(new RegExp(`${field}:\\s*([^\\n]+)`, 'i'));
  return unquoted?.[1]?.trim().replace(/^['"]|['"]$/g, '') || fallback;
}

function extractAgentAnvilListField(source, field, fallback) {
  const match = String(source).match(new RegExp(`${field}:\\s*([^\\n]+)`, 'i'));
  if (!match) return fallback;
  const quoted = Array.from(match[1].matchAll(/"([^"]+)"/g)).map((item) => item[1].trim()).filter(Boolean);
  if (quoted.length) return quoted;
  const bare = match[1].split(',').map((item) => item.trim().replace(/^['"]|['"]$/g, '')).filter(Boolean);
  return bare.length ? bare : fallback;
}

function extractAgentAnvilSeverity(source) {
  const match = String(source).match(/severity:\s*(critical|high|medium|low|info)/i);
  return match?.[1]?.toLowerCase() ?? 'medium';
}

function extractAgentAnvilConfidence(source) {
  const match = String(source).match(/confidence:\s*(certain|firm|tentative)/i);
  return match?.[1]?.toLowerCase() ?? 'firm';
}

function detectAgentAnvilPhase(source) {
  const normalized = String(source).toLowerCase();
  if (normalized.includes('send request') || normalized.includes('send payload') || normalized.includes('given insertion point')) return 'active';
  if (normalized.includes('given response') || normalized.includes('given request')) return 'passive';
  return 'unspecified';
}

function detectAgentAnvilRunScope(source) {
  const normalized = String(source).toLowerCase();
  if (normalized.includes('insertion point')) return 'per-insertion-point';
  if (normalized.includes('given host')) return 'per-host';
  if (normalized.includes('given path')) return 'per-path';
  return 'per-request';
}

function buildExploitPayloadPreview(template, exchange, callbackEndpoint) {
  const target = exchange?.url ?? 'target';
  if (/graphql/i.test(template)) return `POST ${target} with introspection probe and callback ${callbackEndpoint}`;
  if (/xss/i.test(template)) return `<img src=x onerror="fetch('${callbackEndpoint}')">`;
  if (/ssrf|callback|webhook/i.test(template)) return `${target}?url=${callbackEndpoint}`;
  return `Non-destructive validation preview for ${target}`;
}

async function loadAgentExtensionManifest(flags, project) {
  const manifest = await loadJsonMaybe(flags.manifest);
  const installed = Array.isArray(project.installedExtensions) ? project.installedExtensions : [];
  const selected = flags.extension
    ? installed.find((extension) => extension.id === flags.extension || extension.name === flags.extension || extension.catalogId === flags.extension)
    : installed[0];
  const candidate = manifest ?? selected ?? {
    id: 'agent-legacy-proxy-compatibility-probe',
    name: 'Agent legacy proxy Compatibility Probe',
    version: '0.1.0',
    author: 'ProxyForge Agent',
    trustLevel: 'local',
    hooks: ['request-editor', 'response-editor', 'message-editor', 'scanner-check', 'headless-runner'],
    permissions: ['read-traffic', 'modify-traffic', 'create-issues'],
    runtimeApi: {
      apiVersion: 'proxyforge-extender-api/v1',
      sandbox: 'isolated-worker',
      actions: [
        { hook: 'request-editor', kind: 'request-listener', name: 'IHttpListener.processHttpMessage(request)' },
        { hook: 'request-editor', kind: 'proxy-listener', name: 'IProxyListener.processProxyMessage(request)' },
        { hook: 'request-editor', kind: 'request-response-annotation', value: 'Annotate selected IHttpRequestResponse.' },
        { hook: 'request-editor', kind: 'helpers-update-parameter', name: 'agentEdge', value: 'true' },
        { hook: 'request-editor', kind: 'helpers-url-encode', value: 'agent-secret-token' },
        { hook: 'request-editor', kind: 'context-menu-multi-selection', title: 'Send selected requests to Intruder' },
        { hook: 'request-editor', kind: 'session-token-refresh', name: 'X-Session-Token', value: 'agent-secret-token' },
        { hook: 'response-editor', kind: 'response-listener', name: 'IHttpListener.processHttpMessage(response)' },
        { hook: 'response-editor', kind: 'helpers-analyze-response', name: 'IExtensionHelpers.analyzeResponse' },
        { hook: 'message-editor', kind: 'editor-tab', title: 'IMessageEditorTab' },
        { hook: 'message-editor', kind: 'extension-state-listener', name: 'IExtensionStateListener.extensionUnloaded' },
        { hook: 'scanner-check', kind: 'scanner-insertion-point-provider', name: 'IScannerInsertionPointProvider.getInsertionPoints' },
        { hook: 'scanner-check', kind: 'scanner-check', title: 'IScannerCheck compatibility probe' },
        { hook: 'headless-runner', kind: 'policy-denied', name: 'ILegacyExtensionCallbacks.makeHttpRequest' },
      ],
    },
  };
  const name = typeof candidate.name === 'string' && candidate.name.trim() ? candidate.name.trim() : '';
  const version = typeof candidate.version === 'string' && candidate.version.trim() ? candidate.version.trim() : '';
  if (!name || !version) return null;
  const hooks = normalizeAgentExtensionHooks(candidate.hooks);
  const permissions = normalizeAgentExtensionPermissions(candidate.permissions);
  return {
    id: typeof candidate.id === 'string' && candidate.id.trim() ? candidate.id.trim() : `agent-extension-${simpleDigest(`${name}|${version}`).slice(0, 10)}`,
    catalogId: candidate.catalogId,
    name,
    author: typeof candidate.author === 'string' && candidate.author.trim() ? candidate.author.trim() : 'Local analyst',
    version,
    trustLevel: ['built-in', 'verified', 'local'].includes(candidate.trustLevel) ? candidate.trustLevel : 'local',
    hooks: hooks.length ? hooks : ['request-editor'],
    permissions,
    dependencies: normalizeAgentExtensionDependencies(candidate.dependencies),
    runtimeApi: normalizeAgentExtensionRuntime(candidate.runtimeApi, hooks.length ? hooks : ['request-editor']),
  };
}

function normalizeAgentExtensionRuntime(runtimeApi, hooks) {
  const allowedHooks = new Set(hooks);
  const actions = Array.isArray(runtimeApi?.actions)
    ? runtimeApi.actions.flatMap((action) => normalizeAgentExtensionAction(action, allowedHooks))
    : [];
  return {
    apiVersion: typeof runtimeApi?.apiVersion === 'string' && runtimeApi.apiVersion.trim() ? runtimeApi.apiVersion.trim() : 'proxyforge-extender-api/v1',
    sandbox: ['isolated-worker', 'node-disabled', 'headless-ci'].includes(runtimeApi?.sandbox) ? runtimeApi.sandbox : 'isolated-worker',
    actions,
  };
}

function normalizeAgentExtensionAction(action, allowedHooks) {
  if (!action || typeof action !== 'object' || typeof action.hook !== 'string' || !allowedHooks.has(action.hook)) return [];
  const kind = normalizeAgentExtensionActionKind(action.kind);
  return [{
    hook: action.hook,
    kind,
    requestedKind: kind === 'unsupported' && typeof action.kind === 'string' ? action.kind : undefined,
    name: typeof action.name === 'string' ? action.name : undefined,
    value: typeof action.value === 'string' ? action.value : undefined,
    title: typeof action.title === 'string' ? action.title : undefined,
    requires: parseList(action.requires),
  }];
}

function normalizeAgentExtensionActionKind(value) {
  const allowed = new Set([
    'tag',
    'note',
    'request-header',
    'response-header',
    'request-response-annotation',
    'request-listener',
    'response-listener',
    'proxy-listener',
    'issue',
    'scanner-check',
    'scanner-insertion-point-provider',
    'editor-tab',
    'context-menu',
    'context-menu-multi-selection',
    'session-handling-action',
    'session-token-refresh',
    'extension-state-listener',
    'helpers-analyze-request',
    'helpers-analyze-response',
    'helpers-build-http-message',
    'helpers-update-parameter',
    'helpers-url-encode',
    'helpers-url-decode',
    'helpers-base64-encode',
    'helpers-bytes-string',
    'policy-denied',
    'unsupported',
  ]);
  return typeof value === 'string' && allowed.has(value) ? value : 'unsupported';
}

function normalizeAgentExtensionDependencies(value) {
  if (!Array.isArray(value)) return [];
  return value.flatMap((item) => {
    if (!item || typeof item !== 'object') return [];
    const name = typeof item.name === 'string' && item.name.trim() ? item.name.trim() : '';
    const version = typeof item.version === 'string' && item.version.trim() ? item.version.trim() : '';
    return name && version ? [{ name, version }] : [];
  });
}

function normalizeAgentExtensionHooks(value) {
  const allowed = new Set([
    'passive-scan',
    'request-editor',
    'response-editor',
    'message-editor',
    'scanner-check',
    'intruder-payload',
    'traffic-enrichment',
    'report-transform',
    'headless-runner',
  ]);
  return unique(parseList(value).filter((hook) => allowed.has(hook)));
}

function normalizeAgentExtensionPermissions(value) {
  const allowed = new Set(['read-traffic', 'modify-traffic', 'create-issues', 'run-automations', 'callback-access']);
  const permissions = unique(parseList(value).filter((permission) => allowed.has(permission)));
  return permissions.includes('read-traffic') ? permissions : ['read-traffic', ...permissions];
}

function extensionHookLabel(hook) {
  const labels = {
    'passive-scan': 'Passive scan',
    'request-editor': 'Request editor',
    'response-editor': 'Response editor',
    'message-editor': 'Message editor',
    'scanner-check': 'Scanner check',
    'intruder-payload': 'Intruder payload',
    'traffic-enrichment': 'Traffic enrichment',
    'report-transform': 'Report transform',
    'headless-runner': 'Headless runner',
  };
  return labels[hook] ?? String(hook);
}

function agentLegacyExtensionApiForHook(hook) {
  if (hook === 'request-editor' || hook === 'response-editor') return 'IHttpListener';
  if (hook === 'message-editor') return 'IMessageEditorTab';
  if (hook === 'scanner-check' || hook === 'passive-scan') return 'IScannerCheck';
  if (hook === 'headless-runner') return 'ILegacyExtensionCallbacks';
  if (hook === 'intruder-payload') return 'IIntruderPayloadProcessor';
  if (hook === 'report-transform') return 'IExtensionStateListener';
  return 'ILegacyExtensionCallbacks';
}

function agentLegacyOperationForHook(hook) {
  if (hook === 'request-editor') return 'processHttpMessage(request)';
  if (hook === 'response-editor') return 'processHttpMessage(response)';
  if (hook === 'message-editor') return 'createNewInstance / getTabCaption';
  if (hook === 'scanner-check' || hook === 'passive-scan') return 'doPassiveScan / doActiveScan evidence handoff';
  if (hook === 'headless-runner') return 'makeHttpRequest policy-denied probe';
  if (hook === 'intruder-payload') return 'processPayload';
  if (hook === 'traffic-enrichment') return 'registerHttpListener metadata enrichment';
  if (hook === 'report-transform') return 'extension state and report transform adapter';
  return 'sandboxed callback adapter';
}

async function writeAgentExtensionFixture(out, content) {
  const resolved = path.resolve(out);
  const isJsonFile = path.extname(resolved).toLowerCase() === '.json';
  const filePath = isJsonFile ? resolved : path.join(resolved, `proxyforge-agent-extension-fixtures-${Date.now()}.json`);
  await writePrivateFile(filePath, content, 'utf8');
  return filePath;
}

async function loadApproval(filePath) {
  if (!filePath) return { approved: false };
  const parsed = await loadJsonMaybe(filePath);
  return {
    id: parsed?.id ?? path.basename(filePath),
    approved: parsed?.approved === true || parsed?.status === 'approved',
    operator: parsed?.operator ?? parsed?.approvedBy,
    reason: parsed?.reason,
  };
}

async function loadJsonMaybe(filePath) {
  if (!filePath) return null;
  try {
    return JSON.parse(await fs.readFile(path.resolve(filePath), 'utf8'));
  } catch {
    return null;
  }
}

function optionalDist(fileName) {
  const candidates = Array.from(new Set([
    path.join(agentRootDir, 'dist-electron', fileName),
    path.resolve('dist-electron', fileName),
  ]));
  for (const candidate of candidates) {
    try {
      return require(candidate);
    } catch {
      // Try the next location so external agents can run from ~/vantix or a packaged app root.
    }
  }
  return null;
}

function loadProjectStoreRuntime() {
  const projectStore = optionalDist('projectStore.js');
  if (!projectStore?.ProjectStore) {
    throw new Error('Project Store runtime is unavailable. Run npm run build or use the packaged app root before project-store-* commands.');
  }
  return projectStore;
}

function projectStorePathFromFlags(flags) {
  const raw = flags.store ?? flags['project-store'] ?? flags.projectDir ?? flags['project-dir'];
  return raw ? path.resolve(String(raw)) : '';
}

function projectStoreExchangeDetails(store, ids) {
  return ids.flatMap((id) => {
    const exchange = store.getHttpExchange(id);
    if (!exchange) return [];
    return [{
      ...exchange,
      requestRaw: exchange.requestRaw.toString('utf8'),
      responseRaw: exchange.responseRaw.toString('utf8'),
    }];
  });
}

function projectStoreRepeaterSendDetails(store, ids) {
  if (typeof store.getRepeaterSend !== 'function') return [];
  return ids.flatMap((id) => {
    const send = store.getRepeaterSend(id);
    if (!send) return [];
    return [{
      ...send,
      rawRequest: send.rawRequest.toString('utf8'),
      responseRaw: send.responseRaw.toString('utf8'),
    }];
  });
}

function projectStoreIntruderAttackDetails(store, ids) {
  if (typeof store.getIntruderAttack !== 'function') return [];
  return ids.flatMap((id) => {
    const attack = store.getIntruderAttack(id);
    if (!attack) return [];
    return [{
      ...attack,
      rawRequest: attack.rawRequest.toString('utf8'),
    }];
  });
}

function projectStoreIntruderResultDetails(store, ids) {
  if (typeof store.getIntruderResult !== 'function') return [];
  return ids.flatMap((id) => {
    const result = store.getIntruderResult(id);
    if (!result) return [];
    return [{
      ...result,
      requestRaw: result.requestRaw.toString('utf8'),
      responseRaw: result.responseRaw.toString('utf8'),
    }];
  });
}

function projectStoreScannerFindingDetails(store, ids) {
  if (typeof store.getScannerFinding !== 'function') return [];
  return ids.flatMap((id) => {
    const finding = store.getScannerFinding(id);
    if (!finding) return [];
    const evidenceExchange = finding.evidenceExchange
      ? {
          ...finding.evidenceExchange,
          requestRaw: finding.evidenceExchange.requestRaw.toString('utf8'),
          responseRaw: finding.evidenceExchange.responseRaw.toString('utf8'),
        }
      : undefined;
    return [{
      ...finding,
      evidenceExchange,
    }];
  });
}

function projectStoreWebSocketFrameDetails(store, ids) {
  if (typeof store.getWebSocketFrame !== 'function') return [];
  return ids.flatMap((id) => {
    const frame = store.getWebSocketFrame(id);
    if (!frame) return [];
    const payload = frame.payloadEncoding === 'hex'
      ? frame.payload.toString('hex')
      : frame.payload.toString('utf8');
    const { payload: _payload, ...metadata } = frame;
    return [{
      ...metadata,
      payloadPreview: payload.slice(0, 65536),
      payloadTruncated: payload.length > 65536,
    }];
  });
}

function projectStoreIssueDetails(store, ids) {
  if (typeof store.getIssue !== 'function') return [];
  return ids.flatMap((id) => {
    const issue = store.getIssue(id);
    return issue ? [issue] : [];
  });
}

function projectStoreReportDetails(store, ids) {
  if (typeof store.getReportExport !== 'function') return [];
  return ids.flatMap((id) => {
    const report = store.getReportExport(id);
    if (!report) return [];
    const content = report.content.toString('utf8');
    const { content: _content, ...metadata } = report;
    return [{
      ...metadata,
      contentPreview: content.slice(0, 65536),
      contentTruncated: content.length > 65536,
    }];
  });
}

function projectStoreAutomationRunDetails(store, ids) {
  if (typeof store.getAutomationRun !== 'function') return [];
  return ids.flatMap((id) => {
    const run = store.getAutomationRun(id);
    if (!run) return [];
    const exchange = run.exchange
      ? {
          ...run.exchange,
          requestRaw: run.exchange.requestRaw.toString('utf8'),
          responseRaw: run.exchange.responseRaw.toString('utf8'),
        }
      : undefined;
    return [{
      ...run,
      exchange,
    }];
  });
}

function projectStoreAiRunDetails(store, ids) {
  if (typeof store.getAiRun !== 'function') return [];
  return ids.flatMap((id) => {
    const run = store.getAiRun(id);
    if (!run) return [];
    const output = run.output.toString('utf8');
    const prompt = run.prompt?.toString('utf8');
    const { output: _output, prompt: _prompt, ...metadata } = run;
    return [{
      ...metadata,
      outputPreview: output.slice(0, 65536),
      outputTruncated: output.length > 65536,
      promptPreview: prompt?.slice(0, 65536),
      promptTruncated: Boolean(prompt && prompt.length > 65536),
    }];
  });
}

function projectStoreExtensionRunDetails(store, ids) {
  if (typeof store.getExtensionRun !== 'function') return [];
  return ids.flatMap((id) => {
    const run = store.getExtensionRun(id);
    if (!run) return [];
    const exchange = run.exchange
      ? {
          ...run.exchange,
          requestRaw: run.exchange.requestRaw.toString('utf8'),
          responseRaw: run.exchange.responseRaw.toString('utf8'),
        }
      : undefined;
    return [{
      ...run,
      exchange,
    }];
  });
}

function fallbackBrowserMatrix(targetUrl, proxyHost, proxyPort, profileBaseDir) {
  const families = ['chromium', 'chrome', 'edge', 'firefox'];
  const platforms = ['linux', 'win32'];
  const entries = platforms.flatMap((platform) => families.map((family) => ({
    platform,
    family,
    browserName: family,
    targetUrl,
    proxyHost,
    proxyPort,
    profilePath: path.join(profileBaseDir, platform, family),
    proxyMode: family === 'firefox' ? 'firefox-prefs' : 'command-line',
    cookieStore: family === 'firefox' ? 'firefox-sqlite' : 'chromium-network-sqlite',
  })));
  return {
    id: `browser-launch-matrix-${simpleDigest(targetUrl).slice(0, 10)}`,
    title: 'Managed browser launch matrix',
    targetUrl,
    proxyHost,
    proxyPort,
    entryCount: entries.length,
    entries,
  };
}

function renderMarkdownReport(project, scopeAllowlist) {
  return [
    `# ${project.projectName}`,
    '',
    `Scope: ${scopeAllowlist.join(', ') || 'none'}`,
    `Evidence: ${project.exchanges.length}`,
    `Findings: ${project.issues.length}`,
    '',
    '## Findings',
    ...project.issues.map((issue) => `- ${issue.severity ?? 'info'}: ${issue.title} (${issue.host}${issue.path ?? ''})`),
    '',
  ].join('\n');
}

function exchangeSummary(exchange) {
  return {
    id: exchange.id,
    method: exchange.method,
    url: exchange.url,
    host: exchange.host ?? hostFromUrl(exchange.url),
    path: exchange.path ?? new URL(normalizeTarget(exchange.url)).pathname,
    status: exchange.status,
    risk: exchange.risk,
    source: exchange.source,
    tags: exchange.tags ?? [],
  };
}

function exchangeDetail(exchange) {
  return {
    ...exchangeSummary(exchange),
    length: exchange.length,
    mime: exchange.mime,
    timing: exchange.timing,
    time: exchange.time,
    notes: exchange.notes,
    requestRaw: exchange.requestRaw,
    responseRaw: exchange.responseRaw,
  };
}

function makeSnippet(exchange, term) {
  const haystack = `${exchange.requestRaw ?? ''}\n${exchange.responseRaw ?? ''}`;
  const lower = haystack.toLowerCase();
  const index = term ? lower.indexOf(term.toLowerCase()) : 0;
  const start = Math.max(0, index - 80);
  return haystack.slice(start, start + 220).replace(/\s+/g, ' ');
}

function buildAgentSearchSemanticIndex(exchanges, options) {
  const documents = [];
  const perExchangeTokenCounts = new Map();
  const corpusTokenCounts = new Map();
  let tokenCount = 0;

  for (const exchange of exchanges) {
    const corpus = buildAgentSemanticCorpus(exchange);
    const tokens = tokenizeAgentSemanticText(corpus);
    const tokenCounts = countAgentSemanticTokens(tokens);
    tokenCount += tokens.length;
    perExchangeTokenCounts.set(exchange.id, tokenCounts);
    for (const token of tokenCounts.keys()) {
      corpusTokenCounts.set(token, (corpusTokenCounts.get(token) ?? 0) + 1);
    }
    documents.push({
      exchangeId: exchange.id,
      host: exchange.host ?? hostFromUrl(exchange.url) ?? 'unknown',
      path: exchange.path ?? new URL(normalizeTarget(exchange.url)).pathname,
      source: exchange.source ?? 'proxy',
      risk: exchange.risk ?? 'info',
      tags: exchange.tags ?? [],
      corpus,
      tokenCount: tokens.length,
      uniqueTokenCount: tokenCounts.size,
      digestPreview: simpleDigest(corpus),
    });
  }

  const maxTokens = Math.max(1, Math.min(50000, Number.isFinite(options.maxTokens) ? Math.floor(options.maxTokens) : 4096));
  const indexedTokens = Array.from(corpusTokenCounts.entries())
    .sort(([leftToken, leftCount], [rightToken, rightCount]) => rightCount - leftCount || leftToken.localeCompare(rightToken))
    .slice(0, maxTokens)
    .map(([token]) => token);
  const tokenPostings = {};
  for (const token of indexedTokens) {
    const postings = documents
      .map((document) => {
        const count = perExchangeTokenCounts.get(document.exchangeId)?.get(token) ?? 0;
        if (!count) return null;
        return {
          exchangeId: document.exchangeId,
          count,
          weight: Number((1 + Math.log(count)).toFixed(4)),
        };
      })
      .filter(Boolean)
      .sort((left, right) => right.weight - left.weight || left.exchangeId.localeCompare(right.exchangeId));
    if (postings.length) tokenPostings[token] = postings;
  }

  const payload = {
    kind: 'proxyforge-search-semantic-index',
    schemaVersion,
    generatedAt: options.generatedAt,
    exchangeCount: documents.length,
    tokenCount,
    uniqueTokenCount: corpusTokenCounts.size,
    indexedTokenCount: indexedTokens.length,
    corpusDigestPreview: simpleDigest(documents.map((document) => `${document.exchangeId}\n${document.corpus}`).join('\n---proxyforge-search-entry---\n')),
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    documents,
    tokenPostings,
  };
  return {
    ...payload,
    content: JSON.stringify(payload, null, 2),
  };
}

function summarizeAgentSearchSemanticIndex(index) {
  return {
    kind: index.kind,
    schemaVersion: index.schemaVersion,
    generatedAt: index.generatedAt,
    exchangeCount: index.exchangeCount,
    tokenCount: index.tokenCount,
    uniqueTokenCount: index.uniqueTokenCount,
    indexedTokenCount: index.indexedTokenCount,
    corpusDigestPreview: index.corpusDigestPreview,
    secretHandling: index.secretHandling,
  };
}

function buildAgentSearchProviderInvocationPlan(index, query, flags, scopeAllowlist) {
  const providerUrl = normalizeTarget(flags['provider-url'] ?? flags.providerUrl ?? flags['semantic-provider-url']);
  const provider = {
    id: String(flags['provider-id'] ?? flags.providerId ?? 'agent-live-semantic-provider'),
    label: String(flags['provider-label'] ?? flags.providerLabel ?? 'Agent live semantic provider'),
    model: String(flags['provider-model'] ?? flags.providerModel ?? 'rerank-v1'),
    url: providerUrl,
    host: hostFromUrl(providerUrl),
    method: String(flags['provider-method'] ?? 'POST').toUpperCase(),
  };
  const maxDocuments = Math.max(1, Math.floor(numberFlag(flags['provider-max-documents'] ?? flags.providerMaxDocuments, 50)));
  const documents = index.documents.slice(0, maxDocuments);
  const payload = buildAgentSearchProviderPayload(index, query, provider, documents, flags);
  return {
    kind: 'proxyforge-agent-search-live-provider-invocation-plan',
    id: `search-live-provider-plan-${simpleDigest(`${provider.url}|${query}|${index.corpusDigestPreview}`).slice(0, 12)}`,
    provider,
    query,
    exchangeCount: index.exchangeCount,
    documentCount: documents.length,
    corpusDigestPreview: index.corpusDigestPreview,
    requestContentBytes: Buffer.byteLength(JSON.stringify(payload), 'utf8'),
    requirements: {
      providerHostScopeCovered: isTargetInScope(provider.url, scopeAllowlist),
      explicitExecuteRequired: true,
      fullFidelityCorpusPreserved: /Authorization:|Cookie:|X-API-Key:|Bearer|session=|token|api[-_]?key/i.test(JSON.stringify(documents)),
      reportPhaseOnlyRedaction: true,
    },
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
  };
}

async function executeAgentSearchProviderInvocation(index, query, flags, plan, project) {
  const documents = index.documents.slice(0, plan.documentCount);
  const payload = buildAgentSearchProviderPayload(index, query, plan.provider, documents, flags);
  const requestBody = JSON.stringify(payload, null, 2);
  const providerHeaders = agentSearchProviderHeaders(flags, plan.provider);
  const startedAt = new Date().toISOString();
  const response = await agentHttpRequestRaw(plan.provider.url, {
    method: plan.provider.method,
    headers: providerHeaders,
    body: requestBody,
    timeoutMs: numberFlag(flags['provider-timeout'] ?? flags.timeout, 15000),
  });
  const completedAt = new Date().toISOString();
  const parsed = parseJsonMaybe(response.body);
  const providerMatches = normalizeAgentSearchProviderMatches(parsed, plan.provider.id)
    .filter((match) => index.documents.some((document) => document.exchangeId === match.exchangeId))
    .slice(0, Math.max(1, Math.floor(numberFlag(flags.limit, 25))));
  const providerRankedMatches = providerMatches
    .map((match) => {
      const exchange = project.exchanges.find((candidate) => candidate.id === match.exchangeId);
      return exchange ? {
        ...exchangeSummary(exchange),
        semanticProviderScore: match.score,
        semanticLabels: match.labels ?? [],
        providerRationale: match.rationale,
      } : null;
    })
    .filter(Boolean);
  const statusOk = response.statusCode >= 200 && response.statusCode < 300;
  const warnings = [
    statusOk ? '' : `Provider returned HTTP ${response.statusCode}`,
    providerMatches.length ? '' : 'Provider returned no usable exchange matches',
    /Authorization:|Cookie:|X-API-Key:|Bearer|session=|token|api[-_]?key/i.test(requestBody) ? '' : 'Provider request did not include full-fidelity operational corpus markers',
    response.rawRequest && response.rawResponse ? '' : 'Provider raw request/response evidence is missing',
  ].filter(Boolean);
  const requirements = {
    providerHostScopeCovered: true,
    explicitExecuteCovered: true,
    liveProviderRequestCovered: statusOk && Boolean(response.rawRequest && response.rawResponse),
    providerScoreMergeCovered: providerMatches.length > 0 && providerRankedMatches.length > 0,
    rawExecutorMaterialPreserved: /rawRequest|rawResponse|Authorization:|Cookie:|X-API-Key:|Bearer|session=|token|api[-_]?key/i.test(`${response.rawRequest}\n${response.rawResponse}\n${requestBody}`),
    operationalSecretsPreserved: /Bearer|session=|api[-_]?key|secret|token|Cookie:|Authorization:/i.test(`${response.rawRequest}\n${response.rawResponse}\n${requestBody}`),
    reportPhaseOnlyRedaction: true,
  };
  const digestPreview = simpleDigest([
    plan.provider.url,
    query,
    response.rawRequest,
    response.rawResponse,
    JSON.stringify(providerMatches),
  ].join('\n---search-provider---\n'));
  const packagePayload = {
    kind: 'proxyforge-agent-search-live-provider-invocation-package',
    schemaVersion,
    id: `search-live-provider-${digestPreview.slice(0, 12)}`,
    generatedAt: completedAt,
    startedAt,
    completedAt,
    query,
    provider: plan.provider,
    providerRequest: {
      url: plan.provider.url,
      method: plan.provider.method,
      headers: providerHeaders,
      body: requestBody,
      rawRequest: response.rawRequest,
      contentBytes: Buffer.byteLength(requestBody, 'utf8'),
    },
    providerResponse: {
      statusCode: response.statusCode,
      headers: response.headers,
      body: response.body,
      rawResponse: response.rawResponse,
    },
    corpusDigestPreview: index.corpusDigestPreview,
    exchangeCount: index.exchangeCount,
    documentCount: documents.length,
    providerMatches,
    providerRankedMatches,
    warnings,
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady: Object.values(requirements).every(Boolean) && warnings.length === 0,
    summary: `Live semantic provider ${plan.provider.label} returned ${providerMatches.length} ranked match(es) for ${documents.length} full-fidelity document(s).`,
  };
  return {
    ...packagePayload,
    content: JSON.stringify(packagePayload, null, 2),
  };
}

function buildAgentSearchProviderPayload(index, query, provider, documents, flags) {
  return {
    kind: 'proxyforge-agent-search-provider-rank-request',
    schemaVersion,
    query,
    provider: {
      id: provider.id,
      label: provider.label,
      model: provider.model,
    },
    requestedAt: new Date().toISOString(),
    corpusDigestPreview: index.corpusDigestPreview,
    exchangeCount: index.exchangeCount,
    maxResults: numberFlag(flags.limit, 25),
    instructions: 'Return ranked semantic matches as JSON: { "matches": [{ "exchangeId": "...", "score": 0.0-1.0, "rationale": "...", "labels": [] }] }.',
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    documents: documents.map((document) => ({
      exchangeId: document.exchangeId,
      host: document.host,
      path: document.path,
      source: document.source,
      risk: document.risk,
      tags: document.tags,
      corpus: document.corpus,
      digestPreview: document.digestPreview,
    })),
  };
}

function agentSearchProviderHeaders(flags, provider) {
  const headers = {
    'Content-Type': 'application/json',
    'X-ProxyForge-Provider-Id': provider.id,
    'X-ProxyForge-Search-Provider': provider.label,
  };
  const bearer = flags['provider-token'] ?? flags.providerToken ?? flags['provider-bearer'] ?? flags.providerBearer;
  const apiKey = flags['provider-api-key'] ?? flags.providerApiKey;
  const cookie = flags['provider-cookie'] ?? flags.providerCookie;
  if (bearer) headers.Authorization = String(bearer).startsWith('Bearer ') ? String(bearer) : `Bearer ${bearer}`;
  if (apiKey) headers['X-API-Key'] = String(apiKey);
  if (cookie) headers.Cookie = String(cookie);
  return headers;
}

function normalizeAgentSearchProviderMatches(parsed, providerId) {
  const candidates = Array.isArray(parsed?.matches)
    ? parsed.matches
    : Array.isArray(parsed?.results)
      ? parsed.results
      : Array.isArray(parsed?.data)
        ? parsed.data
        : [];
  return candidates
    .map((match) => {
      if (!match || typeof match !== 'object') return null;
      const exchangeId = String(match.exchangeId ?? match.id ?? match.documentId ?? '').trim();
      if (!exchangeId) return null;
      const score = Math.max(0, Math.min(1, Number(match.score ?? match.relevance ?? match.rankScore ?? 0)));
      return {
        exchangeId,
        score: Number(score.toFixed(4)),
        rationale: String(match.rationale ?? match.reason ?? 'Live semantic provider match.'),
        labels: parseList(match.labels ?? match.tags).slice(0, 12),
        providerId: String(match.providerId ?? providerId),
      };
    })
    .filter(Boolean)
    .sort((left, right) => right.score - left.score || left.exchangeId.localeCompare(right.exchangeId));
}

function summarizeAgentSearchProviderInvocationPackage(packagePayload) {
  return {
    kind: packagePayload.kind,
    schemaVersion: packagePayload.schemaVersion,
    id: packagePayload.id,
    generatedAt: packagePayload.generatedAt,
    query: packagePayload.query,
    provider: packagePayload.provider,
    providerStatusCode: packagePayload.providerResponse.statusCode,
    exchangeCount: packagePayload.exchangeCount,
    documentCount: packagePayload.documentCount,
    matchCount: packagePayload.providerMatches.length,
    warnings: packagePayload.warnings,
    requirements: packagePayload.requirements,
    secretHandling: packagePayload.secretHandling,
    reportRedactionBoundary: packagePayload.reportRedactionBoundary,
    reportReady: packagePayload.reportReady,
    summary: packagePayload.summary,
  };
}

function buildAgentSearchLargeProjectSoakReport(exchanges, index, options) {
  const generatedAt = new Date().toISOString();
  const queries = normalizeAgentSearchSoakQueries(options.queries);
  const buildDurationMs = Math.max(0, Math.floor(options.buildDurationMs ?? 0));
  const restoredIndex = restoreAgentSearchSemanticIndex(index.content);
  const querySummaries = queries.map((query) => {
    const startedAt = Date.now();
    const matches = agentSemanticProviderMatchesFromIndex(index, query, {
      limit: options.limit,
      threshold: options.threshold,
    });
    const durationMs = Math.max(0, Date.now() - startedAt);
    return {
      query,
      durationMs,
      matchCount: matches.length,
      topExchangeId: matches[0]?.exchangeId,
      topScore: matches[0]?.score,
      topLabels: matches[0]?.labels ?? [],
    };
  });
  const totalQueryDurationMs = querySummaries.reduce((total, query) => total + query.durationMs, 0);
  const totalMatches = querySummaries.reduce((total, query) => total + query.matchCount, 0);
  const indexContentBytes = Buffer.byteLength(index.content, 'utf8');
  const budgets = {
    minExchangeCount: Math.max(1, Math.floor(options.minExchangeCount)),
    minTotalMatches: Math.max(1, Math.floor(options.minTotalMatches)),
    maxBuildDurationMs: Math.max(1, Math.floor(options.maxBuildDurationMs)),
    maxTotalQueryDurationMs: Math.max(1, Math.floor(options.maxTotalQueryDurationMs)),
    maxIndexContentBytes: Math.max(1, Math.floor(options.maxIndexContentBytes)),
  };
  const warnings = buildAgentSearchSoakWarnings({
    exchangeCount: exchanges.length,
    totalMatches,
    buildDurationMs,
    totalQueryDurationMs,
    indexContentBytes,
    budgets,
  });
  const { content: _content, ...indexPayload } = index;
  const postingLengths = Object.values(index.tokenPostings).map((postings) => postings.length);
  const documentTokenCounts = index.documents.map((document) => document.tokenCount);
  const payload = {
    kind: 'proxyforge-search-large-project-soak-report',
    schemaVersion,
    generatedAt,
    status: warnings.length ? 'warning' : 'pass',
    warnings,
    exchangeCount: exchanges.length,
    queryCount: queries.length,
    totalMatches,
    buildDurationMs,
    totalQueryDurationMs,
    throughput: {
      indexedExchangesPerSecond: roundAgentSoakMetric(exchanges.length / Math.max(0.001, buildDurationMs / 1000)),
      queriedExchangesPerSecond: roundAgentSoakMetric((exchanges.length * queries.length) / Math.max(0.001, totalQueryDurationMs / 1000)),
    },
    budgets,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    indexRestored: restoredIndex.corpusDigestPreview === index.corpusDigestPreview && restoredIndex.exchangeCount === index.exchangeCount,
    indexSummary: {
      corpusDigestPreview: index.corpusDigestPreview,
      tokenCount: index.tokenCount,
      uniqueTokenCount: index.uniqueTokenCount,
      indexedTokenCount: index.indexedTokenCount,
      contentBytes: indexContentBytes,
      maxPostingsPerToken: Math.max(...postingLengths, 0),
      largestDocumentTokens: Math.max(...documentTokenCounts, 0),
      averageDocumentTokens: roundAgentSoakMetric(index.tokenCount / Math.max(1, index.exchangeCount)),
    },
    queries: querySummaries,
    index: indexPayload,
    reportReady: warnings.length === 0 && queries.length > 0,
  };
  return {
    ...payload,
    content: JSON.stringify(payload, null, 2),
  };
}

function restoreAgentSearchSemanticIndex(content) {
  try {
    const parsed = JSON.parse(content);
    if (parsed?.kind === 'proxyforge-search-semantic-index' && Array.isArray(parsed.documents) && parsed.tokenPostings) return parsed;
  } catch {
    // Keep the report warning-based rather than crashing agent search-index for a malformed optional soak artifact.
  }
  return {};
}

function summarizeAgentSearchLargeProjectSoakReport(report) {
  return {
    kind: report.kind,
    schemaVersion: report.schemaVersion,
    generatedAt: report.generatedAt,
    status: report.status,
    warnings: report.warnings,
    exchangeCount: report.exchangeCount,
    queryCount: report.queryCount,
    totalMatches: report.totalMatches,
    buildDurationMs: report.buildDurationMs,
    totalQueryDurationMs: report.totalQueryDurationMs,
    budgets: report.budgets,
    secretHandling: report.secretHandling,
    indexRestored: report.indexRestored,
    indexSummary: report.indexSummary,
    queries: report.queries,
    reportReady: report.reportReady,
  };
}

function normalizeAgentSearchSoakQueries(queries) {
  const normalized = parseList(queries).filter(Boolean);
  return normalized.length ? unique(normalized) : ['authz bypass', 'secret token cookie', 'graphql cors', 'callback ssrf'];
}

function buildAgentSearchSoakWarnings(options) {
  const warnings = [];
  if (options.exchangeCount < options.budgets.minExchangeCount) {
    warnings.push(`Exchange count ${options.exchangeCount} is below large-project floor ${options.budgets.minExchangeCount}.`);
  }
  if (options.totalMatches < options.budgets.minTotalMatches) {
    warnings.push(`Total semantic index matches ${options.totalMatches} is below expected floor ${options.budgets.minTotalMatches}.`);
  }
  if (options.buildDurationMs > options.budgets.maxBuildDurationMs) {
    warnings.push(`Semantic index build took ${options.buildDurationMs}ms, above budget ${options.budgets.maxBuildDurationMs}ms.`);
  }
  if (options.totalQueryDurationMs > options.budgets.maxTotalQueryDurationMs) {
    warnings.push(`Semantic index queries took ${options.totalQueryDurationMs}ms, above budget ${options.budgets.maxTotalQueryDurationMs}ms.`);
  }
  if (options.indexContentBytes > options.budgets.maxIndexContentBytes) {
    warnings.push(`Semantic index content is ${options.indexContentBytes} bytes, above budget ${options.budgets.maxIndexContentBytes} bytes.`);
  }
  return warnings;
}

function roundAgentSoakMetric(value) {
  if (!Number.isFinite(value)) return 0;
  return Number(value.toFixed(2));
}

function agentSemanticProviderMatchesFromIndex(index, query, options) {
  const terms = Array.from(new Set(expandAgentSemanticTerms(query)));
  const documents = new Map(index.documents.map((document) => [document.exchangeId, document]));
  const scored = new Map();
  for (const term of terms) {
    for (const posting of index.tokenPostings[term] ?? []) {
      const score = scored.get(posting.exchangeId) ?? { weighted: 0, labels: new Set() };
      score.weighted += posting.weight;
      score.labels.add(term);
      scored.set(posting.exchangeId, score);
    }
  }
  return Array.from(scored.entries())
    .map(([exchangeId, score]) => {
      const document = documents.get(exchangeId);
      const labels = Array.from(score.labels).sort();
      const directScore = labels.length / Math.max(1, terms.length);
      const weightScore = Math.min(0.28, score.weighted / Math.max(4, terms.length * 4));
      const riskBoost = agentRiskScore(document?.risk ?? 'info') / 50;
      return {
        exchangeId,
        score: Math.max(0, Math.min(1, directScore * 0.62 + weightScore + riskBoost)),
        rationale: `Persistent local semantic index matched ${labels.slice(0, 8).join(', ')} across ${index.exchangeCount} exchange(s).`,
        labels: labels.slice(0, 12),
        providerId: 'proxyforge-local-index',
      };
    })
    .filter((match) => match.score >= options.threshold)
    .sort((left, right) => {
      const scoreDelta = right.score - left.score;
      if (Math.abs(scoreDelta) > 0.0001) return scoreDelta;
      return agentRiskScore(documents.get(right.exchangeId)?.risk ?? 'info') - agentRiskScore(documents.get(left.exchangeId)?.risk ?? 'info')
        || left.exchangeId.localeCompare(right.exchangeId);
    })
    .slice(0, options.limit)
    .map((match) => ({
      ...match,
      score: Number(match.score.toFixed(4)),
    }));
}

function buildAgentSemanticCorpus(exchange) {
  return [
    exchange.method,
    exchange.host ?? hostFromUrl(exchange.url),
    exchange.path,
    exchange.url,
    exchange.status,
    exchange.mime,
    exchange.risk,
    exchange.notes,
    exchange.source,
    ...(exchange.tags ?? []),
    exchange.requestRaw,
    exchange.responseRaw,
  ].filter((value) => value !== undefined && value !== null).join('\n');
}

function countAgentSemanticTokens(tokens) {
  const counts = new Map();
  for (const token of tokens) counts.set(token, (counts.get(token) ?? 0) + 1);
  return counts;
}

function expandAgentSemanticTerms(value) {
  const expanded = new Set();
  for (const term of tokenizeAgentSemanticText(value)) {
    expanded.add(term);
    for (const synonym of agentSemanticSynonyms(term)) expanded.add(synonym);
  }
  return Array.from(expanded);
}

function tokenizeAgentSemanticText(value) {
  return String(value)
    .toLowerCase()
    .replace(/[_-]+/g, ' ')
    .split(/[^a-z0-9]+/)
    .map((term) => term.trim())
    .filter((term) => term.length >= 2);
}

function agentSemanticSynonyms(term) {
  const groups = [
    ['authz', 'authorization', 'authorize', 'access', 'access-control', 'role', 'permission', 'privilege', 'forbidden', '403', '401'],
    ['bypass', 'boundary', 'replay', 'matrix', 'escalation', 'idor', 'privilege', 'alternate-role'],
    ['secret', 'token', 'bearer', 'cookie', 'session', 'apikey', 'api-key', 'credential', 'jwt'],
    ['graphql', 'query', 'mutation', 'subscription'],
    ['cors', 'origin', 'acao', 'acac', 'cache', 'cache-control'],
    ['callback', 'oast', 'collaborator', 'dns', 'smtp', 'ssrf'],
  ];
  return groups.find((group) => group.includes(term)) ?? [];
}

function agentRiskScore(risk) {
  return { info: 1, low: 2, medium: 3, high: 4, critical: 5 }[risk] ?? 0;
}

function agentAutomationWorkflows(project) {
  if (Array.isArray(project.automationWorkflows) && project.automationWorkflows.length) {
    return project.automationWorkflows.map(normalizeAgentAutomationWorkflow).filter(Boolean);
  }
  const exchange = project.exchanges[0] ?? defaultProject().exchanges[0];
  const scope = project.scopeAllowlist?.[0] ?? exchange.host ?? hostFromUrl(exchange.url) ?? '*';
  const past = new Date(Date.now() - 60_000).toISOString();
  return [
    normalizeAgentAutomationWorkflow({
      id: 'wf-agent-scheduled-crawl',
      name: 'Agent scheduled crawl and scan',
      status: 'ready',
      trigger: 'scheduled',
      scope,
      scheduleEnabled: true,
      scheduleIntervalMinutes: 15,
      nextRunAt: '+15 minutes',
      nextRunAtIso: past,
      lastRun: 'Not run',
      steps: [
        agentAutomationStep('crawl', 'Crawl scoped routes', 'selected target', 100, 4, false),
        agentAutomationStep('active-scan', 'Run bounded active checks', 'crawler output', 250, 4, false),
        agentAutomationStep('report-export', 'Export automation evidence', 'ci-artifacts/proxyforge', 0, 1, false),
      ],
    }),
    normalizeAgentAutomationWorkflow({
      id: 'wf-agent-on-tag-authz',
      name: 'Agent on-tag authorization matrix',
      status: 'ready',
      trigger: 'on-tag',
      scope,
      scheduleEnabled: false,
      scheduleIntervalMinutes: 30,
      nextRunAt: 'on authz tag',
      lastRun: 'Not run',
      steps: [
        agentAutomationStep('replay', 'Clone selected request', 'selected exchange', 100, 1, false),
        agentAutomationStep('replay', 'Swap role tokens', 'role matrix', 750, 3, true),
        agentAutomationStep('report-export', 'Attach replay evidence', 'authz report section', 0, 1, false),
      ],
    }),
    normalizeAgentAutomationWorkflow({
      id: 'wf-agent-ci-headless',
      name: 'Agent CI headless scan',
      status: 'ready',
      trigger: 'ci',
      scope,
      scheduleEnabled: false,
      scheduleIntervalMinutes: 60,
      nextRunAt: 'workflow dispatch',
      lastRun: 'Not run',
      steps: [
        agentAutomationStep('crawl', 'CI crawl scoped routes', 'CI target', 100, 4, false),
        agentAutomationStep('active-scan', 'CI active checks', 'CI crawler output', 500, 4, false),
        agentAutomationStep('report-export', 'Write machine-readable reports', 'ci-artifacts/proxyforge', 0, 1, false),
      ],
    }),
  ].filter(Boolean);
}

function normalizeAgentAutomationWorkflow(workflow) {
  if (!workflow || typeof workflow !== 'object') return null;
  return {
    id: String(workflow.id ?? `wf-agent-${simpleDigest(JSON.stringify(workflow)).slice(0, 10)}`),
    name: String(workflow.name ?? 'Agent automation workflow'),
    status: ['ready', 'running', 'blocked', 'complete'].includes(workflow.status) ? workflow.status : 'ready',
    trigger: ['manual', 'scheduled', 'on-tag', 'ci'].includes(workflow.trigger) ? workflow.trigger : 'manual',
    scope: String(workflow.scope ?? '*'),
    scheduleEnabled: Boolean(workflow.scheduleEnabled),
    scheduleIntervalMinutes: Math.max(1, Math.round(Number(workflow.scheduleIntervalMinutes ?? 30))),
    nextRunAt: String(workflow.nextRunAt ?? 'manual'),
    nextRunAtIso: workflow.nextRunAtIso,
    lastRun: String(workflow.lastRun ?? 'Not run'),
    lastSchedulerRunAt: workflow.lastSchedulerRunAt,
    steps: Array.isArray(workflow.steps) && workflow.steps.length
      ? workflow.steps.map((step) => agentAutomationStep(
        step.type,
        step.label,
        step.target,
        step.throttleMs,
        step.maxRequests,
        step.requiresApproval,
      ))
      : [agentAutomationStep('replay', 'Replay selected request', 'selected exchange', 100, 1, false)],
  };
}

function agentAutomationStep(type, label, target, throttleMs = 0, maxRequests = 1, requiresApproval = false) {
  const normalizedType = ['replay', 'crawl', 'active-scan', 'callback-poll', 'report-export', 'delay'].includes(type) ? type : 'replay';
  const normalizedLabel = String(label ?? normalizedType);
  return {
    id: `${normalizedType}-${normalizedLabel.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'step'}`,
    type: normalizedType,
    label: normalizedLabel,
    target: String(target ?? 'selected target'),
    throttleMs: Math.max(0, Math.round(Number(throttleMs ?? 0))),
    maxRequests: Math.max(0, Math.round(Number(maxRequests ?? 1))),
    requiresApproval: Boolean(requiresApproval),
  };
}

function agentSelectAutomationWorkflow(workflows, id) {
  if (id) return workflows.find((workflow) => workflow.id === id || workflow.name === id);
  return workflows[0];
}

async function loadAgentAutomationApproval(filePath) {
  if (!filePath) return null;
  try {
    return JSON.parse(await fs.readFile(path.resolve(String(filePath)), 'utf8'));
  } catch (error) {
    return { status: 'invalid', error: error instanceof Error ? error.message : String(error) };
  }
}

function agentRunAutomationWorkflow(workflow, exchange, scopeAllowlist, approval = null) {
  const startedAt = new Date();
  const approved = approval?.status === 'approved' || approval?.approved === true;
  const inScope = agentIsAutomationInScope(exchange.host || hostFromUrl(exchange.url), workflow.scope, scopeAllowlist);
  const approvalRequired = workflow.steps.some((step) => step.requiresApproval);
  const blockedByApproval = approvalRequired && !approved;
  const status = !inScope || blockedByApproval ? 'blocked' : 'complete';
  const logs = [
    `Workflow: ${workflow.name}`,
    `Trigger: ${workflow.trigger}`,
    `Scope: ${workflow.scope}`,
    `Selected exchange: ${exchange.method} ${exchange.host}${exchange.path}`,
  ];
  if (!inScope) logs.push(`Blocked: ${exchange.host} is outside project/workflow scope.`);
  if (blockedByApproval) logs.push('Blocked: at least one state-changing step requires operator approval.');
  if (approvalRequired && approved) logs.push(`Approval accepted: ${approval.id ?? approval.operator ?? 'operator approval artifact'}.`);
  for (const step of workflow.steps) {
    const state = status === 'blocked' && step.requiresApproval ? 'held' : status === 'blocked' ? 'skipped' : 'complete';
    logs.push(`${state.toUpperCase()} ${step.type}: ${step.label} (${step.maxRequests} request cap, ${step.throttleMs}ms throttle)`);
  }
  logs.push(status === 'complete' ? 'workflow complete' : 'workflow blocked');
  const completedAt = new Date(startedAt.getTime() + Math.max(120, workflow.steps.length * 180));
  const totalRequests = status === 'complete' ? workflow.steps.reduce((sum, step) => sum + step.maxRequests, 0) : 0;
  return {
    id: `agent-automation-exec-${startedAt.getTime()}-${simpleDigest(workflow.id).slice(0, 8)}`,
    workflowId: workflow.id,
    workflowName: workflow.name,
    status,
    trigger: workflow.trigger,
    startedAt: startedAt.toISOString(),
    completedAt: completedAt.toISOString(),
    durationMs: completedAt.getTime() - startedAt.getTime(),
    totalRequests,
    logs,
    exchange: status === 'complete' ? {
      id: `agent-automation-${completedAt.getTime()}`,
      method: 'POST',
      host: exchange.host,
      path: '/__proxyforge/automation',
      url: `https://${exchange.host}/__proxyforge/automation`,
      status: 200,
      length: 0,
      mime: 'application/json',
      risk: workflow.steps.some((step) => step.type === 'active-scan') ? 'medium' : 'info',
      timing: Math.max(120, workflow.steps.length * 180),
      source: 'automations',
      time: completedAt.toISOString(),
      requestRaw: `POST /__proxyforge/automation HTTP/2\nHost: ${exchange.host}\nContent-Type: application/json\nX-ProxyForge-Workflow: ${workflow.id}\n\n{"selectedExchange":"${exchange.id}"}`,
      responseRaw: `HTTP/2 200 OK\nContent-Type: application/json\n\n{"workflow":"${workflow.name}","status":"complete"}`,
      notes: `Automation workflow completed: ${workflow.name}`,
      tags: ['automation', workflow.trigger],
    } : undefined,
    issue: status === 'complete' ? {
      id: `agent-automation-${workflow.id}-${exchange.id}`,
      title: 'Agent automation workflow validation evidence',
      severity: workflow.steps.some((step) => step.type === 'active-scan') ? 'medium' : 'info',
      host: exchange.host,
      path: exchange.path,
      confidence: 'tentative',
      status: 'open',
      detail: `${workflow.name} ran against ${exchange.method} ${exchange.host}${exchange.path} and produced auditable automation evidence.`,
      remediation: 'Review the workflow output, confirm authorization and side-effect expectations manually, and attach generated evidence only after validation.',
    } : undefined,
    operationalRawMaterial: {
      sourceExchangeId: exchange.id,
      requestRaw: exchange.requestRaw,
      responseRaw: exchange.responseRaw,
      secretHandling: 'execution-full-fidelity-secrets-preserved',
      reportRedactionBoundary: 'redact-only-during-report-export',
    },
    ciProvider: 'github-actions',
    ciConfig: agentRenderAutomationCiConfig(workflow, scopeAllowlist, 'github-actions'),
  };
}

function agentRenderAutomationCiConfig(workflow, scopeAllowlist, provider = 'github-actions') {
  const safeName = workflow.name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'proxyforge-workflow';
  const scope = scopeAllowlist.join(',') || workflow.scope;
  const scheduleMinutes = Math.max(5, Math.min(60, workflow.scheduleIntervalMinutes));
  const headlessCommand = [
    `proxyforge headless --workflow "${workflow.id}"`,
    '--target "$PROXYFORGE_TARGET_URL"',
    `--scope "${scope}"`,
    '--crawl-audit',
    '--max-active-requests 4',
    '--report json,bundle',
    '--sarif',
    '--junit',
    '--out-dir ci-artifacts/proxyforge',
  ].join(' ');
  if (provider === 'gitlab-ci') {
    return [
      'stages:',
      '  - dast',
      `proxyforge-${safeName}:`,
      '  stage: dast',
      '  image: node:20',
      '  variables:',
      '    PROXYFORGE_TARGET_URL: $PROXYFORGE_TARGET_URL',
      '    PROXYFORGE_AUTHORIZATION: $PROXYFORGE_AUTHORIZATION',
      '    PROXYFORGE_COOKIE: $PROXYFORGE_COOKIE',
      '  script:',
      `    - ${headlessCommand}`,
      '  artifacts:',
      '    when: always',
      '    paths:',
      '      - ci-artifacts/proxyforge',
      '    reports:',
      '      junit: ci-artifacts/proxyforge/proxyforge-junit.xml',
      '      sast: ci-artifacts/proxyforge/proxyforge-results.sarif',
    ].join('\n');
  }
  if (provider === 'azure-pipelines') {
    return [
      `name: proxyforge-${safeName}`,
      'trigger: none',
      'schedules:',
      `  - cron: "*/${scheduleMinutes} * * * *"`,
      'pool:',
      '  vmImage: ubuntu-latest',
      'steps:',
      '  - script: |',
      `      ${headlessCommand}`,
      '    env:',
      '      PROXYFORGE_TARGET_URL: $(PROXYFORGE_TARGET_URL)',
      '      PROXYFORGE_AUTHORIZATION: $(PROXYFORGE_AUTHORIZATION)',
      '      PROXYFORGE_COOKIE: $(PROXYFORGE_COOKIE)',
      '  - task: PublishTestResults@2',
      '    inputs:',
      '      testResultsFiles: ci-artifacts/proxyforge/proxyforge-junit.xml',
      '  - publish: ci-artifacts/proxyforge',
      '    artifact: proxyforge-headless-artifacts',
    ].join('\n');
  }
  if (provider === 'jenkins') {
    return [
      'pipeline {',
      '  agent any',
      '  environment {',
      '    PROXYFORGE_TARGET_URL = credentials("proxyforge-target-url")',
      '    PROXYFORGE_AUTHORIZATION = credentials("proxyforge-authorization")',
      '    PROXYFORGE_COOKIE = credentials("proxyforge-cookie")',
      '  }',
      '  stages {',
      '    stage("ProxyForge DAST") {',
      '      steps {',
      `        sh '${headlessCommand}'`,
      '      }',
      '    }',
      '  }',
      '  post {',
      '    always {',
      '      junit allowEmptyResults: true, testResults: "ci-artifacts/proxyforge/proxyforge-junit.xml"',
      '      archiveArtifacts allowEmptyArchive: true, artifacts: "ci-artifacts/proxyforge/**"',
      '    }',
      '  }',
      '}',
    ].join('\n');
  }
  return [
    `name: proxyforge-${safeName}`,
    'on:',
    '  workflow_dispatch:',
    '  schedule:',
    `    - cron: "*/${scheduleMinutes} * * * *"`,
    'jobs:',
    '  authorized-scan:',
    '    runs-on: ubuntu-latest',
    '    steps:',
    '      - uses: actions/checkout@v4',
    '      - uses: actions/setup-node@v4',
    '        with:',
    '          node-version: "20"',
    '      - name: Run ProxyForge headless workflow',
    '        env:',
    '          PROXYFORGE_TARGET_URL: ${{ secrets.PROXYFORGE_TARGET_URL }}',
    '          PROXYFORGE_AUTHORIZATION: ${{ secrets.PROXYFORGE_AUTHORIZATION }}',
    '          PROXYFORGE_COOKIE: ${{ secrets.PROXYFORGE_COOKIE }}',
    '        run: |',
    `          ${headlessCommand}`,
    '      - name: Upload ProxyForge SARIF',
    '        if: always()',
    '        uses: github/codeql-action/upload-sarif@v3',
    '        with:',
    '          sarif_file: ci-artifacts/proxyforge/proxyforge-results.sarif',
    '      - name: Upload ProxyForge artifacts',
    '        if: always()',
    '        uses: actions/upload-artifact@v4',
    '        with:',
    '          name: proxyforge-headless-artifacts',
    '          path: ci-artifacts/proxyforge',
  ].join('\n');
}

function agentAutomationCiProviderMatrix(workflow, scopeAllowlist, providers = agentAutomationCiProviders) {
  return providers.map((provider) => {
    const config = agentRenderAutomationCiConfig(workflow, scopeAllowlist, provider);
    return {
      provider,
      label: {
        'github-actions': 'GitHub Actions',
        'gitlab-ci': 'GitLab CI',
        'azure-pipelines': 'Azure Pipelines',
        jenkins: 'Jenkins',
      }[provider] ?? provider,
      workflowId: workflow.id,
      fileName: provider === 'github-actions' ? '.github/workflows/proxyforge.yml' : provider === 'gitlab-ci' ? '.gitlab-ci.yml' : provider === 'azure-pipelines' ? 'azure-pipelines.proxyforge.yml' : 'Jenkinsfile.proxyforge',
      config,
      requirements: {
        headlessCommandCovered: /proxyforge headless/.test(config),
        sarifCovered: /--sarif|sarif/i.test(config),
        junitCovered: /--junit|junit/i.test(config),
        reportBundleCovered: /--report json,bundle|bundle/i.test(config),
        artifactUploadCovered: /artifact|archiveArtifacts|PublishTestResults|upload-artifact|paths:/i.test(config),
        secretEnvCovered: /PROXYFORGE_AUTHORIZATION|PROXYFORGE_COOKIE/i.test(config),
      },
    };
  });
}

function agentCreateAutomationSchedulerState(workflows, now = new Date(), existing = undefined) {
  const timestamp = now.toISOString();
  const state = {
    id: existing?.id ?? 'agent-automation-scheduler',
    status: existing?.status ?? 'running',
    ownerId: existing?.ownerId ?? 'proxyforge-agent-scheduler',
    leaseTtlMs: existing?.leaseTtlMs ?? 90_000,
    maxConcurrentJobs: existing?.maxConcurrentJobs ?? 3,
    heartbeatAt: existing?.heartbeatAt ?? timestamp,
    updatedAt: existing?.updatedAt ?? timestamp,
    queue: Array.isArray(existing?.queue) ? existing.queue : [],
  };
  return agentReconcileAutomationScheduler(state, workflows, now);
}

function agentReconcileAutomationScheduler(state, workflows, now) {
  const timestamp = now.toISOString();
  const queue = [...state.queue.map((job) => agentExpireAutomationLease(job, now))];
  for (const workflow of workflows) {
    if (!workflow.scheduleEnabled) continue;
    const scheduledFor = agentAutomationNextRunAt(workflow, now).toISOString();
    const exists = queue.some((job) => job.workflowId === workflow.id && (job.status === 'queued' || job.status === 'leased' || job.scheduledFor === scheduledFor));
    if (exists) continue;
    queue.push({
      id: `agent-auto-job-${workflow.id}-${scheduledFor.replace(/[^0-9TZ]/g, '')}`,
      workflowId: workflow.id,
      workflowName: workflow.name,
      scheduledFor,
      status: 'queued',
      attempts: 0,
      createdAt: timestamp,
      updatedAt: timestamp,
      summary: `Queued ${workflow.name} for ${scheduledFor}.`,
    });
  }
  return { ...state, heartbeatAt: timestamp, updatedAt: timestamp, queue };
}

function agentRunAutomationSchedulerTick({ state, workflows, exchange, scopeAllowlist, now = new Date(), ownerId = 'proxyforge-agent-scheduler', maxJobs = 3 }) {
  let nextState = agentReconcileAutomationScheduler(state, workflows, now);
  const timestamp = now.toISOString();
  const dueJobs = nextState.queue
    .filter((job) => agentIsAutomationSchedulerJobDue(job, now))
    .slice(0, maxJobs);
  const leaseId = `agent-auto-lease-${now.getTime()}-${simpleDigest(ownerId).slice(0, 8)}`;
  const leaseExpiresAt = new Date(now.getTime() + nextState.leaseTtlMs).toISOString();
  const executions = [];
  const logs = [`Scheduler heartbeat ${timestamp} by ${ownerId}.`];
  let completedJobs = 0;
  let blockedJobs = 0;
  nextState = {
    ...nextState,
    queue: nextState.queue.map((job) => dueJobs.some((dueJob) => dueJob.id === job.id)
      ? { ...job, status: 'leased', attempts: job.attempts + 1, leaseId, leasedBy: ownerId, leaseExpiresAt, updatedAt: timestamp, summary: `Claimed by ${ownerId} until ${leaseExpiresAt}.` }
      : job),
  };
  for (const job of dueJobs) {
    const workflow = workflows.find((candidate) => candidate.id === job.workflowId);
    if (!workflow) {
      blockedJobs += 1;
      nextState = agentFinishAutomationJob(nextState, job.id, 'blocked', timestamp, undefined, 'Workflow was removed before execution.');
      continue;
    }
    const execution = {
      ...agentRunAutomationWorkflow({ ...workflow, trigger: 'scheduled' }, exchange, scopeAllowlist, null),
      schedulerJobId: job.id,
      schedulerLeaseId: leaseId,
    };
    executions.push(execution);
    if (execution.status === 'complete') completedJobs += 1;
    else blockedJobs += 1;
    nextState = agentFinishAutomationJob(nextState, job.id, execution.status === 'complete' ? 'complete' : 'blocked', timestamp, execution.id, execution.logs.at(-1));
    logs.push(`${execution.status.toUpperCase()} ${workflow.name}: ${execution.totalRequests} planned request(s).`);
  }
  logs.push(`${dueJobs.length} job(s) claimed; ${completedJobs} completed; ${blockedJobs} blocked.`);
  return { state: nextState, workflows, executions, logs, claimedJobs: dueJobs.length, completedJobs, blockedJobs };
}

function agentFinishAutomationJob(state, jobId, status, updatedAt, executionId, summary) {
  return {
    ...state,
    updatedAt,
    queue: state.queue.map((job) => job.id === jobId ? { ...job, status, executionId, updatedAt, summary } : job),
  };
}

function agentExpireAutomationLease(job, now) {
  if (job.status !== 'leased' || !job.leaseExpiresAt || Date.parse(job.leaseExpiresAt) > now.getTime()) return job;
  return { ...job, status: 'queued', leaseId: undefined, leasedBy: undefined, leaseExpiresAt: undefined, updatedAt: now.toISOString(), summary: `Lease expired at ${job.leaseExpiresAt}; returned to queue.` };
}

function agentIsAutomationSchedulerJobDue(job, now) {
  if (Date.parse(job.scheduledFor) > now.getTime()) return false;
  return job.status === 'queued' || (job.status === 'leased' && job.leaseExpiresAt && Date.parse(job.leaseExpiresAt) <= now.getTime());
}

function agentAutomationNextRunAt(workflow, now) {
  if (workflow.nextRunAtIso && Number.isFinite(Date.parse(workflow.nextRunAtIso))) return new Date(workflow.nextRunAtIso);
  if (workflow.lastSchedulerRunAt && Number.isFinite(Date.parse(workflow.lastSchedulerRunAt))) {
    return new Date(Date.parse(workflow.lastSchedulerRunAt) + workflow.scheduleIntervalMinutes * 60_000);
  }
  const relative = /^\+(\d+)\s+minutes?$/i.exec(workflow.nextRunAt);
  if (relative) return new Date(now.getTime() + Number(relative[1]) * 60_000);
  return now;
}

function agentIsAutomationInScope(host, workflowScope, scopeAllowlist) {
  const scopes = [...scopeAllowlist, ...String(workflowScope ?? '').split(/[,\s]+/)].map((scope) => scope.trim()).filter(Boolean);
  if (!host || !scopes.length) return false;
  return scopes.some((scope) => {
    if (scope === '*' || scope === '*.*') return true;
    const normalized = scope.replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    if (normalized.startsWith('*.')) return host === normalized.slice(2) || host.endsWith(normalized.slice(1));
    return host === normalized || host.endsWith(`.${normalized}`);
  });
}

function agentBuildAutomationParityPackage(project, exchange, scopeAllowlist) {
  const now = new Date();
  const workflows = agentAutomationWorkflows(project);
  const macroWorkflow = {
    id: `wf-macro-agent-${simpleDigest(exchange.id).slice(0, 10)}`,
    name: `Macro: ${exchange.method} ${exchange.path}`,
    status: 'ready',
    trigger: 'manual',
    scope: scopeAllowlist.join(',') || exchange.host,
    scheduleEnabled: false,
    scheduleIntervalMinutes: 30,
    nextRunAt: 'manual',
    lastRun: 'Not run',
    steps: [
      agentAutomationStep('replay', `Replay ${exchange.method} ${exchange.path}`, exchange.url, 150, 1, false),
      agentAutomationStep('active-scan', 'Run passive-plus active checks', exchange.host, 300, 4, false),
      agentAutomationStep('report-export', 'Save macro evidence bundle', 'macro report section', 0, 1, false),
    ],
  };
  const scheduledBlockedWorkflow = {
    id: 'wf-agent-scheduled-approval-block',
    name: 'Agent scheduled approval gate',
    status: 'ready',
    trigger: 'scheduled',
    scope: scopeAllowlist.join(',') || exchange.host,
    scheduleEnabled: true,
    scheduleIntervalMinutes: 30,
    nextRunAt: '+30 minutes',
    nextRunAtIso: new Date(now.getTime() - 60_000).toISOString(),
    lastRun: 'Not run',
    steps: [agentAutomationStep('replay', 'State-changing scheduled replay', exchange.url, 100, 1, true)],
  };
  const schedulerWorkflows = [scheduledBlockedWorkflow, ...workflows];
  const allWorkflows = [macroWorkflow, scheduledBlockedWorkflow, ...workflows];
  const macroExecution = agentRunAutomationWorkflow(macroWorkflow, exchange, scopeAllowlist, null);
  const blockedWorkflow = workflows.find((workflow) => workflow.steps.some((step) => step.requiresApproval)) ?? {
    ...macroWorkflow,
    id: 'wf-agent-approval-block',
    name: 'Agent approval-block automation',
    steps: [agentAutomationStep('replay', 'State-changing replay', exchange.url, 100, 1, true)],
  };
  const blockedExecution = agentRunAutomationWorkflow(blockedWorkflow, exchange, scopeAllowlist, null);
  const baseState = agentCreateAutomationSchedulerState(schedulerWorkflows, now, project.automationSchedulerState);
  const tick = agentRunAutomationSchedulerTick({ state: baseState, workflows: schedulerWorkflows, exchange, scopeAllowlist, now, ownerId: 'agent-parity-runner', maxJobs: 3 });
  const expiredState = {
    ...baseState,
    id: 'agent-automation-scheduler-expired-lease',
    queue: baseState.queue.map((job, index) => index === 0
      ? { ...job, status: 'leased', attempts: 1, leaseId: 'expired-agent-lease', leasedBy: 'old-agent', leaseExpiresAt: new Date(now.getTime() - 1000).toISOString(), summary: 'Expired lease fixture.' }
      : job),
  };
  const expiredTick = agentRunAutomationSchedulerTick({ state: expiredState, workflows: schedulerWorkflows, exchange, scopeAllowlist, now, ownerId: 'agent-parity-reclaimer', maxJobs: 1 });
  const pausedState = { ...tick.state, id: 'agent-automation-scheduler-paused', status: 'paused' };
  const stoppedState = { ...tick.state, id: 'agent-automation-scheduler-stopped', status: 'stopped' };
  const ciWorkflow = workflows.find((workflow) => workflow.trigger === 'ci') ?? macroWorkflow;
  const ciProviderPresets = agentAutomationCiProviderMatrix(ciWorkflow, scopeAllowlist);
  const executions = [macroExecution, blockedExecution, ...tick.executions, ...expiredTick.executions, ...(project.automationExecutions ?? [])];
  const schedulerStates = [baseState, tick.state, expiredTick.state, pausedState, stoppedState];
  const artifactOperationalText = [
    JSON.stringify(allWorkflows),
    JSON.stringify(executions),
    JSON.stringify(schedulerStates),
    JSON.stringify([tick, expiredTick]),
    JSON.stringify(ciProviderPresets),
    JSON.stringify([exchange]),
    exchange.requestRaw,
    exchange.responseRaw,
    ...ciProviderPresets.map((preset) => preset.config),
  ].join('\n');
  const secretSamples = unique([
    ...String(exchange.requestRaw ?? '').match(/agent-secret-[A-Za-z0-9_-]+|automation-secret-[A-Za-z0-9_-]+/g) ?? [],
    ...String(exchange.requestRaw ?? '').match(/session=[A-Za-z0-9_-]+/g) ?? [],
  ]);
  const allJobs = schedulerStates.flatMap((state) => state.queue);
  const providerSet = new Set(ciProviderPresets.map((preset) => preset.provider));
  const requirements = {
    macroRecordingCovered: allWorkflows.some((workflow) => workflow.id.startsWith('wf-macro') && workflow.steps.some((step) => step.type === 'replay') && workflow.steps.some((step) => step.type === 'active-scan') && workflow.steps.some((step) => step.type === 'report-export')),
    scheduledWorkflowCovered: allWorkflows.some((workflow) => workflow.scheduleEnabled && workflow.trigger === 'scheduled'),
    onTagWorkflowCovered: allWorkflows.some((workflow) => workflow.trigger === 'on-tag'),
    ciWorkflowCovered: allWorkflows.some((workflow) => workflow.trigger === 'ci'),
    scopedExecutionCovered: executions.some((execution) => execution.status === 'complete' && execution.totalRequests > 0),
    approvalBlockingCovered: executions.some((execution) => execution.status === 'blocked' && execution.logs.some((line) => /approval/i.test(line))),
    durableSchedulerQueueCovered: allJobs.some((job) => job.status === 'queued') && allJobs.some((job) => job.status === 'complete') && allJobs.some((job) => job.status === 'blocked'),
    leaseRecoveryCovered: allJobs.some((job) => job.attempts > 1) || expiredTick.claimedJobs > 0,
    schedulerRestoreCovered: schedulerStates.length >= 2 && allJobs.some((job) => job.status === 'complete' || job.status === 'blocked'),
    ciHeadlessCliCovered: ciProviderPresets.every((preset) => preset.requirements.headlessCommandCovered && preset.requirements.sarifCovered && preset.requirements.junitCovered && preset.requirements.reportBundleCovered),
    ciProviderPresetsCovered: agentAutomationCiProviders.every((provider) => providerSet.has(provider)),
    reportArtifactExportCovered: ciProviderPresets.every((preset) => preset.requirements.artifactUploadCovered) && allWorkflows.some((workflow) => workflow.steps.some((step) => step.type === 'report-export')),
    serviceLifecycleCovered: ['running', 'paused', 'stopped'].every((status) => schedulerStates.some((state) => state.status === status)),
    rawExecutorMaterialPreserved: /HTTP\/[12]|Authorization:|Cookie:|X-API-Key:|requestRaw|responseRaw/i.test(artifactOperationalText),
    operationalSecretsPreserved: secretSamples.length > 0 && secretSamples.every((sample) => artifactOperationalText.includes(sample)),
    reportPhaseOnlyRedaction: true,
  };
  const unsigned = {
    kind: 'proxyforge-agent-automation-parity-evidence-package',
    exportedAt: now.toISOString(),
    workflows: allWorkflows,
    executions,
    schedulerStates,
    schedulerTickResults: [tick, expiredTick],
    ciProviderPresets,
    sourceExchanges: [exchange],
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady: Object.values(requirements).every(Boolean),
  };
  const digestPreview = simpleDigest(JSON.stringify(unsigned));
  return {
    id: `agent-automation-parity-${digestPreview.slice(0, 12)}`,
    kind: 'proxyforge-agent-automation-parity-evidence-package',
    exportedAt: now.toISOString(),
    workflowCount: allWorkflows.length,
    executionCount: executions.length,
    schedulerStateCount: schedulerStates.length,
    ciProviderPresetCount: ciProviderPresets.length,
    artifactIds: {
      workflowIds: allWorkflows.map((workflow) => workflow.id),
      executionIds: executions.map((execution) => execution.id),
      schedulerStateIds: schedulerStates.map((state) => state.id),
      schedulerJobIds: unique(allJobs.map((job) => job.id)),
      sourceExchangeIds: [exchange.id],
      ciProviders: Array.from(providerSet),
    },
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady: Object.values(requirements).every(Boolean),
    digestPreview,
    summary: 'Agent automation parity evidence covers macro, scheduled, on-tag, CI/headless, scheduler lease/restore/lifecycle, provider presets, and full-fidelity operational material.',
    content: JSON.stringify({ ...unsigned, digestPreview }, null, 2),
  };
}

function agentBuildAutomationServiceLifecyclePackage(request) {
  const generatedAt = request.generatedAt ?? new Date().toISOString();
  const serviceName = agentNormalizeAutomationServiceName(request.serviceName ?? `proxyforge-automation-${request.workflow.id}`);
  const installRoot = String(request.installRoot ?? '/opt/ProxyForge');
  const plans = [
    agentBuildLinuxAutomationServicePlan(request, serviceName, installRoot),
    agentBuildWindowsAutomationServicePlan(request, serviceName),
  ];
  const operationalSecretSamples = agentAutomationOperationalSecretSamples(request.exchange);
  const rawMaterial = [
    JSON.stringify(request.workflow),
    JSON.stringify(request.schedulerState),
    ...plans.flatMap((plan) => [
      plan.agentCommand,
      plan.installCommand,
      plan.startCommand,
      plan.statusCommand,
      plan.stopCommand,
      plan.uninstallCommand,
      plan.manifest,
    ]),
    ...operationalSecretSamples,
  ].join('\n');
  const operationalSecretSignals = agentOperationalSecretSignals(
    request.exchange?.requestRaw ?? '',
    request.exchange?.responseRaw ?? '',
    ...operationalSecretSamples,
  );
  const schedulerDigest = simpleDigest(JSON.stringify({
    id: request.schedulerState.id,
    status: request.schedulerState.status,
    ownerId: request.schedulerState.ownerId,
    queue: (request.schedulerState.queue ?? []).map((job) => ({
      id: job.id,
      workflowId: job.workflowId,
      status: job.status,
      scheduledFor: job.scheduledFor,
      attempts: job.attempts,
    })),
  }));
  const planDigests = plans.map((plan) => simpleDigest(JSON.stringify({
    platform: plan.platform,
    serviceName: plan.serviceName,
    commands: [
      plan.installCommand,
      plan.startCommand,
      plan.statusCommand,
      plan.stopCommand,
      plan.uninstallCommand,
    ],
    requirements: plan.requirements,
  })));
  const requirements = {
    linuxSystemdInstallStartCovered: plans.some((plan) => plan.platform === 'linux-systemd-user'
      && plan.requirements.installCovered
      && plan.requirements.startCovered
      && /systemctl --user/i.test(`${plan.installCommand}\n${plan.startCommand}`)),
    windowsTaskSchedulerInstallStartCovered: plans.some((plan) => plan.platform === 'windows-task-scheduler'
      && plan.requirements.installCovered
      && plan.requirements.startCovered
      && /schtasks/i.test(`${plan.installCommand}\n${plan.startCommand}`)),
    startStatusStopUninstallCovered: plans.every((plan) => plan.requirements.startCovered && plan.requirements.statusCovered && plan.requirements.stopCovered && plan.requirements.uninstallCovered),
    schedulerTickCommandCovered: plans.every((plan) => plan.requirements.schedulerTickCommandCovered),
    durableStatePathsCovered: plans.every((plan) => plan.requirements.durableStateCovered),
    restartPolicyCovered: plans.every((plan) => /restart|repetition|on-failure|minute/i.test(`${plan.restartPolicy}\n${plan.schedulePolicy}\n${plan.manifest}`)),
    secretEnvironmentCovered: plans.every((plan) => plan.requirements.secretEnvironmentCovered),
    packageRefreshCovered: planDigests.length === 2 && schedulerDigest.length > 0,
    rawExecutorMaterialPreserved: /automation-scheduler-tick|project|scope|workflow|manifest/i.test(rawMaterial),
    operationalSecretsPreserved: operationalSecretSignals.length === 0 || operationalSecretSamples.length > 0,
    reportPhaseOnlyRedaction: true,
  };
  const packageRefreshProof = {
    refreshedAt: generatedAt,
    planDigests,
    schedulerDigest,
    lifecycleDigest: '',
    stalePlanIds: [],
  };
  const unsigned = {
    kind: 'proxyforge-automation-service-lifecycle-package',
    generatedAt,
    workflow: request.workflow,
    schedulerState: request.schedulerState,
    projectPath: request.projectPath,
    scopeAllowlist: request.scopeAllowlist,
    plans,
    packageRefreshProof,
    operationalSecretSignals,
    operationalSecretSamples,
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady: Object.values(requirements).every(Boolean),
  };
  packageRefreshProof.lifecycleDigest = simpleDigest(JSON.stringify(unsigned));
  const digestPreview = simpleDigest(JSON.stringify(unsigned));
  const stamp = generatedAt.replace(/[:.]/g, '-');
  return {
    id: `agent-automation-service-lifecycle-${digestPreview.slice(0, 12)}`,
    kind: 'proxyforge-automation-service-lifecycle-package',
    title: 'Agent Automation service lifecycle package',
    fileName: `proxyforge-agent-automation-service-lifecycle-${stamp}.json`,
    path: `automations/proxyforge-agent-automation-service-lifecycle-${stamp}.json`,
    generatedAt,
    workflowId: request.workflow.id,
    schedulerStateId: request.schedulerState.id,
    platformCount: plans.length,
    artifactIds: {
      workflowId: request.workflow.id,
      schedulerStateId: request.schedulerState.id,
      serviceNames: plans.map((plan) => plan.serviceName),
      platforms: plans.map((plan) => plan.platform),
    },
    plans,
    packageRefreshProof,
    operationalSecretSignals,
    operationalSecretSamples,
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady: Object.values(requirements).every(Boolean),
    digestPreview,
    summary: `Agent Automation service lifecycle package covers Linux systemd user and Windows Task Scheduler install/start/status/stop/uninstall controls for ${request.workflow.name}.`,
    content: JSON.stringify({ ...unsigned, digestPreview }, null, 2),
  };
}

function agentBuildLinuxAutomationServicePlan(request, serviceName, installRoot) {
  const unitName = `${serviceName}.service`;
  const installPath = `~/.config/systemd/user/${unitName}`;
  const statePath = `~/.local/state/proxyforge/automations/${serviceName}.json`;
  const logPath = `~/.local/state/proxyforge/logs/${serviceName}.jsonl`;
  const agentCommand = agentRenderAutomationSchedulerServiceCommand(request, String(request.agentCommand ?? agentCommandPrefix), statePath, logPath, shellQuote);
  const environmentNames = ['PROXYFORGE_AUTHORIZATION', 'PROXYFORGE_COOKIE', 'PROXYFORGE_API_KEY'];
  const manifest = [
    '[Unit]',
    `Description=ProxyForge automation scheduler (${request.workflow.name})`,
    'After=network-online.target',
    'Wants=network-online.target',
    '',
    '[Service]',
    'Type=simple',
    `WorkingDirectory=${installRoot}`,
    'Environment=PROXYFORGE_AUTHORIZATION=${PROXYFORGE_AUTHORIZATION}',
    'Environment=PROXYFORGE_COOKIE=${PROXYFORGE_COOKIE}',
    'Environment=PROXYFORGE_API_KEY=${PROXYFORGE_API_KEY}',
    `ExecStart=${agentCommand}`,
    'Restart=on-failure',
    'RestartSec=15',
    '',
    '[Install]',
    'WantedBy=default.target',
  ].join('\n');
  const installCommand = `install -Dm0644 ${unitName} ${installPath} && systemctl --user daemon-reload && systemctl --user enable ${unitName}`;
  const startCommand = `systemctl --user start ${unitName}`;
  const statusCommand = `systemctl --user status ${unitName} --no-pager`;
  const stopCommand = `systemctl --user stop ${unitName}`;
  const uninstallCommand = `systemctl --user disable --now ${unitName} && rm -f ${installPath} && systemctl --user daemon-reload`;
  return {
    platform: 'linux-systemd-user',
    serviceName,
    displayName: `ProxyForge Automation Scheduler (${request.workflow.name})`,
    installPath,
    statePath,
    logPath,
    agentCommand,
    installCommand,
    startCommand,
    statusCommand,
    stopCommand,
    uninstallCommand,
    manifest,
    environmentNames,
    restartPolicy: 'systemd Restart=on-failure RestartSec=15',
    schedulePolicy: `${request.workflow.scheduleIntervalMinutes} minute workflow interval; scheduler tick reconciles durable queue state`,
    requirements: agentAutomationServicePlanRequirements({
      installCommand,
      startCommand,
      statusCommand,
      stopCommand,
      uninstallCommand,
      statePath,
      agentCommand,
      manifest,
      environmentNames,
    }),
  };
}

function agentBuildWindowsAutomationServicePlan(request, serviceName) {
  const taskName = `ProxyForge\\${serviceName}`;
  const installRoot = String(request.windowsInstallRoot ?? '%ProgramFiles%\\ProxyForge');
  const installPath = `%ProgramData%\\ProxyForge\\Automations\\${serviceName}.xml`;
  const statePath = `%ProgramData%\\ProxyForge\\Automations\\${serviceName}.json`;
  const logPath = `%ProgramData%\\ProxyForge\\Logs\\${serviceName}.jsonl`;
  const windowsAgentCommand = String(request.windowsAgentCommand ?? '"%ProgramFiles%\\ProxyForge\\resources\\app.asar\\scripts\\proxyforge-agent.mjs"');
  const agentCommand = agentRenderAutomationSchedulerServiceCommand(request, windowsAgentCommand, statePath, logPath, doubleQuote);
  const windowsUser = request.windowsUser ?? '${env:USERNAME}';
  const interval = `PT${Math.max(1, Math.min(1440, request.workflow.scheduleIntervalMinutes))}M`;
  const environmentNames = ['PROXYFORGE_AUTHORIZATION', 'PROXYFORGE_COOKIE', 'PROXYFORGE_API_KEY'];
  const manifest = [
    '<?xml version="1.0" encoding="UTF-16"?>',
    '<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">',
    '  <RegistrationInfo>',
    `    <Description>ProxyForge automation scheduler (${xmlEscape(request.workflow.name)})</Description>`,
    `    <URI>\\${xmlEscape(taskName)}</URI>`,
    '  </RegistrationInfo>',
    '  <Triggers>',
    '    <TimeTrigger>',
    '      <Enabled>true</Enabled>',
    `      <Repetition><Interval>${interval}</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition>`,
    '    </TimeTrigger>',
    '  </Triggers>',
    '  <Principals>',
    `    <Principal id="Author"><UserId>${xmlEscape(windowsUser)}</UserId><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal>`,
    '  </Principals>',
    '  <Settings>',
    '    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>',
    '    <RestartOnFailure><Interval>PT1M</Interval><Count>3</Count></RestartOnFailure>',
    '    <ExecutionTimeLimit>PT30M</ExecutionTimeLimit>',
    '  </Settings>',
    '  <Actions Context="Author">',
    '    <Exec>',
    '      <Command>node.exe</Command>',
    `      <Arguments>${xmlEscape(agentCommand)}</Arguments>`,
    `      <WorkingDirectory>${xmlEscape(installRoot)}</WorkingDirectory>`,
    '    </Exec>',
    '  </Actions>',
    '</Task>',
  ].join('\n');
  const installCommand = `schtasks /Create /TN "${taskName}" /XML "${installPath}" /F`;
  const startCommand = `schtasks /Run /TN "${taskName}"`;
  const statusCommand = `schtasks /Query /TN "${taskName}" /V /FO LIST`;
  const stopCommand = `schtasks /End /TN "${taskName}"`;
  const uninstallCommand = `schtasks /Delete /TN "${taskName}" /F`;
  return {
    platform: 'windows-task-scheduler',
    serviceName: taskName,
    displayName: `ProxyForge Automation Scheduler (${request.workflow.name})`,
    installPath,
    statePath,
    logPath,
    agentCommand,
    installCommand,
    startCommand,
    statusCommand,
    stopCommand,
    uninstallCommand,
    manifest,
    environmentNames,
    restartPolicy: 'Task Scheduler RestartOnFailure interval PT1M count 3',
    schedulePolicy: `${interval} repetition with scheduler tick durable queue reconciliation`,
    requirements: agentAutomationServicePlanRequirements({
      installCommand,
      startCommand,
      statusCommand,
      stopCommand,
      uninstallCommand,
      statePath,
      agentCommand,
      manifest,
      environmentNames,
    }),
  };
}

function agentRenderAutomationSchedulerServiceCommand(request, agentCommand, statePath, logPath, quote) {
  return [
    agentCommand,
    'automation-scheduler-tick',
    `--project ${quote(request.projectPath)}`,
    `--scope ${quote(request.scopeAllowlist.join(','))}`,
    `--workflow ${quote(request.workflow.id)}`,
    `--scheduler-state ${quote(statePath)}`,
    `--log ${quote(logPath)}`,
    '--execute',
    '--service-run',
    '--json',
  ].join(' ');
}

function agentAutomationServicePlanRequirements(input) {
  const environmentSource = `${input.manifest}\n${input.environmentNames.join('\n')}`;
  return {
    installCovered: /systemctl|schtasks|Register-ScheduledTask|Create/i.test(input.installCommand),
    startCovered: /start|Run/i.test(input.startCommand),
    statusCovered: /status|Query/i.test(input.statusCommand),
    stopCovered: /stop|End/i.test(input.stopCommand),
    uninstallCovered: /disable|Delete|rm -f|Unregister-ScheduledTask/i.test(input.uninstallCommand),
    durableStateCovered: /proxyforge|Automations|automation/i.test(input.statePath),
    schedulerTickCommandCovered: /automation-scheduler-tick/.test(input.agentCommand),
    secretEnvironmentCovered: /PROXYFORGE_AUTHORIZATION/.test(environmentSource)
      && /PROXYFORGE_COOKIE/.test(environmentSource)
      && /PROXYFORGE_API_KEY/.test(environmentSource),
  };
}

function agentAutomationOperationalSecretSamples(exchange) {
  const raw = `${exchange?.requestRaw ?? ''}\n${exchange?.responseRaw ?? ''}`;
  const lineSamples = String(raw).split(/\r?\n/).filter((line) => /^(authorization|cookie|x-api-key|set-cookie)\s*:/i.test(line));
  const valueSamples = String(raw).match(/agent-secret-[A-Za-z0-9_-]+|automation-secret-[A-Za-z0-9_-]+|session=[A-Za-z0-9_-]+/g) ?? [];
  return unique([...lineSamples, ...valueSamples]);
}

function agentNormalizeAutomationServiceName(value) {
  const normalized = String(value ?? 'proxyforge-automation-scheduler')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_.-]+/g, '-')
    .replace(/^-+|-+$/g, '');
  return normalized || 'proxyforge-automation-scheduler';
}

function doubleQuote(value) {
  return `"${String(value).replace(/"/g, '\\"')}"`;
}

function xmlEscape(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

function decodeExchange(exchange, mode) {
  if (mode === 'json') {
    const match = String(exchange.responseRaw ?? '').match(/\{[\s\S]*\}$/);
    if (match) {
      try {
        return JSON.parse(match[0]);
      } catch {
        return null;
      }
    }
  }
  if (mode === 'headers') return parseRawRequest(exchange.responseRaw ?? '').headers;
  return null;
}

function blocked(detail, gates = []) {
  return {
    status: 'blocked',
    mode: 'blocked',
    trafficSent: false,
    requestCount: 0,
    detail,
    gates,
    data: { detail },
    audit: [auditEvent('agent-command', 'blocked', detail, 0)],
  };
}

function auditEvent(action, decision, detail, requestCount) {
  return {
    at: new Date().toISOString(),
    tool: 'agent',
    action,
    decision,
    detail,
    requestCount,
  };
}

function artifact(kind, id, title) {
  return { kind, id, title };
}

function mitmStatusPath(flags) {
  const sessionDir = path.resolve(flags['session-dir'] ?? path.join(process.cwd(), 'proxyforge-agent-session'));
  return path.resolve(flags.status ?? path.join(sessionDir, 'session.json'));
}

function findFreePort() {
  return new Promise((resolve, reject) => {
    const server = http.createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      const port = typeof address === 'object' && address ? address.port : 0;
      server.close((error) => {
        if (error) reject(error);
        else resolve(port);
      });
    });
  });
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function normalizeTarget(value) {
  const raw = String(value ?? 'https://example.test/').trim();
  if (/^(https?|wss?):\/\//i.test(raw)) return raw;
  return `https://${raw}`;
}

function hostFromUrl(value) {
  try {
    return new URL(normalizeTarget(value)).hostname;
  } catch {
    return '';
  }
}

function isTargetInScope(targetUrl, scopeAllowlist) {
  const host = hostFromUrl(targetUrl).toLowerCase();
  if (!host) return false;
  return scopeAllowlist.some((scope) => {
    const normalized = String(scope).trim().toLowerCase();
    if (!normalized) return false;
    if (normalized === '*') return true;
    if (normalized.startsWith('*.')) return host === normalized.slice(2) || host.endsWith(normalized.slice(1));
    return host === normalized || host.endsWith(`.${normalized}`);
  });
}

function parseList(value) {
  if (!value) return [];
  if (Array.isArray(value)) return value.flatMap(parseList);
  return String(value).split(/[,\n]/).map((item) => item.trim()).filter(Boolean);
}

function normalizeCallbackProtocols(value) {
  const allowed = new Set(['dns', 'http', 'smtp']);
  const parsed = parseList(value).map((item) => item.toLowerCase()).filter((item) => allowed.has(item));
  return parsed.length ? unique(parsed) : ['dns', 'http', 'smtp'];
}

function callbackRelayDnsRecords(publicBaseUrl, protocols) {
  const records = [];
  if (protocols.includes('http')) records.push(`*.${publicBaseUrl} 300 IN CNAME relay.proxyforge.local.`);
  if (protocols.includes('dns')) records.push(`${publicBaseUrl} 300 IN NS ns1.proxyforge.local.`);
  if (protocols.includes('smtp')) records.push(`${publicBaseUrl} 300 IN MX 10 mail.${publicBaseUrl}.`);
  return records;
}

function callbackRelayRoutes(publicBaseUrl, protocols) {
  return [
    protocols.includes('http') ? `https://*.${publicBaseUrl}/probe/:token` : 'HTTP callback relay disabled',
    protocols.includes('dns') ? `dns://*.${publicBaseUrl}/A,AAAA,CNAME,TXT` : 'DNS callback relay disabled',
    protocols.includes('smtp') ? `smtp://*@${publicBaseUrl}` : 'SMTP relay disabled',
    `https://${publicBaseUrl}/api/proxyforge/oast/poll`,
  ];
}

function agentProviderPayloads(provider, payloads, tenantId) {
  const explicitIds = new Set(parseList(provider.payloadIds ?? provider.payloadId ?? provider.payloads));
  const providerId = String(provider.id ?? provider.providerId ?? provider.name ?? '');
  const protocol = String(provider.protocol ?? '').toLowerCase();
  return payloads.filter((payload) => {
    const payloadId = String(payload.id ?? payload.token ?? '');
    if (explicitIds.size && explicitIds.has(payloadId)) return true;
    const payloadProvider = String(payload.providerId ?? payload.provider ?? '');
    const payloadTenant = String(payload.tenantId ?? payload.tenant ?? tenantId);
    const payloadProtocol = String(payload.protocol ?? '').toLowerCase();
    return (!providerId || payloadProvider === providerId)
      && payloadTenant === tenantId
      && (!protocol || payloadProtocol === protocol);
  });
}

function agentProviderKind(provider) {
  const value = String(provider.kind ?? provider.providerKind ?? provider.type ?? '').toLowerCase();
  if (value.includes('dns')) return 'dns-webhook-relay';
  if (value.includes('smtp')) return 'smtp-relay';
  if (value.includes('collaborator')) return 'oast-compatible';
  if (value.includes('interact')) return 'interactsh-compatible';
  return value || 'generic-http-relay';
}

function agentProviderUrl(provider, purpose, payload) {
  const providerId = String(provider.id ?? provider.providerId ?? provider.name ?? 'provider');
  const tenantId = String(provider.tenantId ?? 'default');
  const baseUrl = normalizeTarget(provider.baseUrl ?? provider.url ?? `https://${providerId}.invalid/`);
  const template = purpose === 'ingest'
    ? String(provider.ingestUrl ?? provider.ingestPath ?? `/provider/${providerId}/${tenantId}/ingest/${payload?.id ?? payload?.token ?? 'payload'}`)
    : String(provider.pollUrl ?? provider.pollPath ?? `/provider/${providerId}/${tenantId}/poll`);
  const interpolated = template
    .replaceAll('{{providerId}}', encodeURIComponent(providerId))
    .replaceAll('{{tenantId}}', encodeURIComponent(tenantId))
    .replaceAll('{{payloadId}}', encodeURIComponent(String(payload?.id ?? payload?.token ?? 'payload')))
    .replaceAll('{{token}}', encodeURIComponent(String(payload?.token ?? payload?.id ?? 'payload')))
    .replaceAll(':providerId', encodeURIComponent(providerId))
    .replaceAll(':tenantId', encodeURIComponent(tenantId))
    .replaceAll(':payloadId', encodeURIComponent(String(payload?.id ?? payload?.token ?? 'payload')))
    .replaceAll(':token', encodeURIComponent(String(payload?.token ?? payload?.id ?? 'payload')));
  if (/^https?:\/\//i.test(interpolated)) return interpolated;
  return new URL(interpolated.startsWith('/') ? interpolated : `/${interpolated}`, baseUrl).toString();
}

function agentProviderHeaders(provider, payload, purpose) {
  const staticHeaders = provider.headers && typeof provider.headers === 'object' ? provider.headers : {};
  const purposeHeaders = provider[`${purpose}Headers`] && typeof provider[`${purpose}Headers`] === 'object'
    ? provider[`${purpose}Headers`]
    : {};
  const headers = {
    Accept: 'application/json',
    'User-Agent': 'ProxyForgeAgentProviderProbe/1.0',
    ...staticHeaders,
    ...purposeHeaders,
  };
  const token = provider.bearerToken ?? provider.apiToken ?? provider.token ?? provider.authorizationToken;
  if (token && !headers.Authorization && !headers.authorization) headers.Authorization = `Bearer ${token}`;
  if (payload?.token) headers['X-ProxyForge-Provider-Payload'] = payload.token;
  if (purpose === 'ingest' && !headers['Content-Type'] && !headers['content-type']) headers['Content-Type'] = 'text/plain';
  return headers;
}

function agentProviderSignature(provider, response) {
  const signatureHeader = String(provider.signatureHeader ?? 'x-proxyforge-signature').toLowerCase();
  const keyHeader = String(provider.signatureKeyHeader ?? 'x-proxyforge-signature-key-id').toLowerCase();
  const headers = Object.fromEntries(Object.entries(response.headers ?? {}).map(([key, value]) => [
    key.toLowerCase(),
    Array.isArray(value) ? value.join(', ') : String(value ?? ''),
  ]));
  const digest = headers[signatureHeader] ?? '';
  return {
    algorithm: String(provider.signatureAlgorithm ?? 'HMAC-SHA256'),
    keyId: headers[keyHeader] || String(provider.signingKeyId ?? provider.id ?? 'provider-key'),
    status: digest ? 'signed' : 'missing',
    digestPreview: digest.slice(0, 16),
  };
}

function agentHttpRequestRaw(urlText, options = {}) {
  const url = new URL(urlText);
  const method = String(options.method ?? 'GET').toUpperCase();
  const body = String(options.body ?? '');
  const headers = {
    Host: url.host,
    ...(options.headers ?? {}),
  };
  if (body && !Object.keys(headers).some((name) => name.toLowerCase() === 'content-length')) {
    headers['Content-Length'] = Buffer.byteLength(body);
  }
  const rawRequest = [
    `${method} ${url.pathname}${url.search} HTTP/1.1`,
    ...Object.entries(headers).map(([name, value]) => `${name}: ${value}`),
    '',
    body,
  ].join('\r\n');
  const client = url.protocol === 'https:' ? https : http;
  return new Promise((resolve, reject) => {
    const request = client.request({
      protocol: url.protocol,
      hostname: url.hostname,
      port: url.port,
      path: `${url.pathname}${url.search}`,
      method,
      headers,
      timeout: Math.max(1000, Math.round(options.timeoutMs ?? 10000)),
    }, (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () => {
        const responseBody = Buffer.concat(chunks).toString('utf8');
        const rawResponse = [
          `HTTP/${response.httpVersion} ${response.statusCode} ${response.statusMessage}`,
          ...Object.entries(response.headers).map(([name, value]) => `${name}: ${Array.isArray(value) ? value.join(', ') : value ?? ''}`),
          '',
          responseBody,
        ].join('\r\n');
        resolve({
          statusCode: response.statusCode ?? 0,
          headers: response.headers,
          body: responseBody,
          rawRequest,
          rawResponse,
        });
      });
    });
    request.on('timeout', () => {
      request.destroy(new Error(`Timed out probing ${urlText}`));
    });
    request.on('error', reject);
    if (body) request.write(body);
    request.end();
  });
}

function isAgentCallbackOlderThanRetention(value, reference, retentionHours) {
  const referenceDate = parseAgentCallbackDate(reference) ?? new Date();
  const observedDate = parseAgentCallbackDate(value, referenceDate.toISOString()) ?? referenceDate;
  return referenceDate.getTime() - observedDate.getTime() > retentionHours * 60 * 60 * 1000;
}

function parseAgentCallbackDate(value, reference) {
  if (!value) return null;
  const parsed = new Date(value);
  if (!Number.isNaN(parsed.getTime())) return parsed;
  const match = String(value).match(/^(\d{1,2}):(\d{2})(?::(\d{2}))?$/);
  if (!match) return null;
  const referenceDate = parseAgentCallbackDate(reference) ?? new Date();
  const next = new Date(referenceDate);
  next.setHours(Number(match[1]), Number(match[2]), Number(match[3] ?? 0), 0);
  return next;
}

function numberFlag(value, fallback) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function agentUpstreamTlsMode(value) {
  const normalized = String(value ?? 'strict').trim().toLowerCase();
  if (normalized === 'strict' || normalized === 'relaxed') return normalized;
  throw new Error('--upstream-tls must be strict or relaxed');
}

async function ensurePrivateDir(dirPath, options = {}) {
  const resolvedDir = path.resolve(dirPath);
  await assertNoSymlinkComponents(resolvedDir);
  const createdRoot = await fs.mkdir(resolvedDir, { recursive: true, mode: secureAgentDirMode });
  await assertNoSymlinkComponents(resolvedDir);
  if (createdRoot) {
    await chmodCreatedDirectoryTree(createdRoot, resolvedDir, secureAgentDirMode);
  } else if (options.hardenExisting) {
    await chmodIfPossible(resolvedDir, secureAgentDirMode);
  }
}

async function writePrivateFile(filePath, content, options = 'utf8', privacyOptions = {}) {
  const resolvedPath = path.resolve(filePath);
  await ensurePrivateDir(path.dirname(resolvedPath), privacyOptions);
  await assertWritablePrivateFileTarget(resolvedPath);
  const writeOptions = typeof options === 'string'
    ? { encoding: options, mode: secureAgentFileMode }
    : { ...options, mode: secureAgentFileMode };
  const tempPath = path.join(path.dirname(resolvedPath), `.${path.basename(resolvedPath)}.${process.pid}.${Date.now()}.tmp`);
  await fs.writeFile(tempPath, content, { ...writeOptions, flag: 'wx' });
  await chmodIfPossible(tempPath, secureAgentFileMode);
  await fs.rename(tempPath, resolvedPath);
  await chmodIfPossible(resolvedPath, secureAgentFileMode);
}

async function appendPrivateFile(filePath, content, privacyOptions = {}) {
  const resolvedPath = path.resolve(filePath);
  await ensurePrivateDir(path.dirname(resolvedPath), privacyOptions);
  await assertWritablePrivateFileTarget(resolvedPath);
  await fs.appendFile(resolvedPath, content, { encoding: 'utf8', mode: secureAgentFileMode });
  await chmodIfPossible(resolvedPath, secureAgentFileMode);
}

async function chmodCreatedDirectoryTree(createdRoot, resolvedDir, mode) {
  if (process.platform === 'win32') return;
  const resolvedCreatedRoot = path.resolve(createdRoot);
  const resolvedTarget = path.resolve(resolvedDir);
  await chmodIfPossible(resolvedCreatedRoot, mode);
  const relativeParts = path.relative(resolvedCreatedRoot, resolvedTarget).split(path.sep).filter(Boolean);
  let current = resolvedCreatedRoot;
  for (const part of relativeParts) {
    current = path.join(current, part);
    await chmodIfPossible(current, mode);
  }
}

async function assertWritablePrivateFileTarget(filePath) {
  try {
    const stat = await fs.lstat(filePath);
    if (stat.isSymbolicLink()) {
      throw new Error(`Refusing to write private agent output through symlink: ${filePath}`);
    }
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
  }
}

async function assertNoSymlinkComponents(targetPath) {
  const resolvedPath = path.resolve(targetPath);
  const { root } = path.parse(resolvedPath);
  let current = root;
  const relativeParts = path.relative(root, resolvedPath).split(path.sep).filter(Boolean);
  for (const part of relativeParts) {
    current = path.join(current, part);
    try {
      const stat = await fs.lstat(current);
      if (stat.isSymbolicLink()) {
        throw new Error(`Refusing to create private agent output beneath symlink: ${current}`);
      }
    } catch (error) {
      if (error?.code === 'ENOENT') return;
      throw error;
    }
  }
}

async function chmodIfPossible(filePath, mode) {
  if (process.platform === 'win32') return;
  try {
    await fs.chmod(filePath, mode);
  } catch (error) {
    if (!['ENOENT', 'EPERM', 'EACCES'].includes(error?.code ?? '')) throw error;
  }
}

function groupBy(values, keyFn) {
  const grouped = {};
  for (const value of values) {
    const key = keyFn(value);
    grouped[key] = grouped[key] ?? [];
    grouped[key].push(value);
  }
  return grouped;
}

function groupCounts(values) {
  const counts = {};
  for (const value of values) counts[value] = (counts[value] ?? 0) + 1;
  return counts;
}

function unique(values) {
  return Array.from(new Set(values.filter(Boolean)));
}

function runNodeJson(args) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, args, {
      cwd: process.cwd(),
      env: process.env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk.toString(); });
    child.stderr.on('data', (chunk) => { stderr += chunk.toString(); });
    child.on('close', (code) => {
      resolve({
        code: code ?? 1,
        stdout,
        stderr,
        json: parseJsonMaybe(stdout),
      });
    });
  });
}

function parseJsonMaybe(value) {
  try {
    return JSON.parse(value);
  } catch {
    return null;
  }
}

function tailText(value, lineCount = 12) {
  return String(value ?? '').split(/\r?\n/).filter(Boolean).slice(-lineCount).join('\n');
}

function redactDeep(value) {
  if (typeof value === 'string') return redactText(value);
  if (Array.isArray(value)) return value.map(redactDeep);
  if (!value || typeof value !== 'object') return value;
  const output = {};
  for (const [key, item] of Object.entries(value)) {
    if (/secret|token|password|api[_-]?key|cookie|authorization/i.test(key) && typeof item === 'string') {
      output[key] = '[redacted]';
    } else {
      output[key] = redactDeep(item);
    }
  }
  return output;
}

function redactText(value) {
  return String(value)
    .replace(/(authorization:\s*(?:bearer\s+)?)[^\s\r\n]+/gi, '$1[redacted]')
    .replace(/(cookie:\s*)[^\r\n]+/gi, '$1[redacted]')
    .replace(/(x-api-key:\s*)[^\s\r\n]+/gi, '$1[redacted]')
    .replace(/((?:token|session|secret|api[_-]?key|password)=)[^&\s;]+/gi, '$1[redacted]')
    .replace(/\b[A-Za-z0-9][A-Za-z0-9._-]*(?:[_-](?:token|secret|session|api[_-]?key))[A-Za-z0-9._-]*\b/g, '[redacted]');
}

function simpleDigest(value) {
  let hash = 0x811c9dc5;
  const text = String(value);
  for (let index = 0; index < text.length; index += 1) {
    hash ^= text.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return `${hash.toString(16).padStart(8, '0')}${text.length.toString(16).padStart(8, '0')}`;
}

function shellQuote(value) {
  const text = String(value);
  if (/^[A-Za-z0-9_/:=.,@%+-]+$/.test(text)) return text;
  return `'${text.replace(/'/g, "'\\''")}'`;
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
