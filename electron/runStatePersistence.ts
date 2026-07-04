import fs from 'node:fs/promises';
import path from 'node:path';
import {
  ProjectStore,
  type ProjectStoreAiRunInput,
  type ProjectStoreAutomationRunInput,
  type ProjectStoreExtensionRunInput,
  type ProjectStoreIssueInput,
  type ProjectStoreOpenOptions,
  type ProjectStoreStats,
} from './projectStore';

type RuntimeSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';
type RuntimeConfidence = 'certain' | 'firm' | 'tentative';
type RuntimeIssueStatus = 'open' | 'triaged' | 'false-positive' | 'fixed';

export interface RuntimeHttpExchange {
  id: string;
  method: string;
  host: string;
  path: string;
  url: string;
  status: number;
  length: number;
  mime: string;
  risk: RuntimeSeverity;
  timing: number;
  notes: string;
  source: 'proxy' | 'repeater' | 'scanner' | 'crawler' | 'demo' | string;
  time: string;
  requestRaw: string;
  responseRaw: string;
  tags: string[];
}

export interface RuntimeIssue {
  id?: string;
  title: string;
  severity: RuntimeSeverity;
  host: string;
  path: string;
  confidence: RuntimeConfidence;
  status: RuntimeIssueStatus;
  detail: string;
  remediation: string;
}

export interface RuntimeAutomationExecution {
  id: string;
  workflowId: string;
  workflowName: string;
  status: string;
  trigger: string;
  startedAt: string;
  completedAt: string;
  durationMs: number;
  totalRequests: number;
  logs: string[];
  exchange?: RuntimeHttpExchange;
  issue?: RuntimeIssue;
  operationalRawMaterial?: Record<string, unknown>;
  schedulerJobId?: string;
  schedulerLeaseId?: string;
  ciProvider?: string;
  ciConfig?: string;
}

export interface RuntimeAiRunResult {
  id: string;
  providerId: string;
  task: string;
  status: string;
  model: string;
  startedAt: string;
  completedAt: string;
  summary: string;
  output: string;
  evidenceCount: number;
  command?: string;
  providerLabel?: string;
  prompt?: string;
  contextDigest?: string;
  usage?: unknown;
  streamEvents?: unknown[];
  promptEvaluation?: unknown;
  suggestedActions?: unknown[];
}

export interface RuntimeExtensionRun {
  id: string;
  extensionId: string;
  extensionName: string;
  hook: string;
  status: string;
  target: string;
  startedAt: string;
  completedAt: string;
  summary: string;
  logs: string[];
  issue?: RuntimeIssue;
  exchange?: RuntimeHttpExchange;
}

export interface ProjectStoreRunStatePersistResult {
  kind: 'proxyforge-project-run-state-persist-result';
  runType: 'automation' | 'ai' | 'extension';
  id: string;
  stats: ProjectStoreStats;
}

export class ProjectStoreRunStateRecorder {
  private storePromise: Promise<ProjectStore> | null = null;

  constructor(
    readonly rootDir: string,
    private readonly options: ProjectStoreOpenOptions = {},
  ) {}

  async recordAutomationRun(execution: RuntimeAutomationExecution): Promise<ProjectStoreRunStatePersistResult> {
    const store = await this.openStore();
    const input = automationExecutionToProjectStoreInput(execution);
    await store.addAutomationRun(input);
    await store.addAuditEvent({
      actor: 'run-state-recorder',
      action: 'automation.run.persist',
      targetRef: input.id ?? execution.id,
      decision: input.status === 'blocked' ? 'blocked' : 'completed',
      detail: `Persisted automation run ${input.workflowName} with raw executor material preserved until report export.`,
    });
    return { kind: 'proxyforge-project-run-state-persist-result', runType: 'automation', id: input.id ?? execution.id, stats: store.stats() };
  }

  async recordAiRun(result: RuntimeAiRunResult): Promise<ProjectStoreRunStatePersistResult> {
    const store = await this.openStore();
    const input = aiRunResultToProjectStoreInput(result);
    await store.addAiRun(input);
    await store.addAuditEvent({
      actor: 'run-state-recorder',
      action: 'ai.run.persist',
      targetRef: input.id ?? result.id,
      decision: input.status === 'error' ? 'blocked' : 'completed',
      detail: `Persisted ${input.providerId} ${input.task} transcript with report-phase-only redaction boundary.`,
    });
    return { kind: 'proxyforge-project-run-state-persist-result', runType: 'ai', id: input.id ?? result.id, stats: store.stats() };
  }

  async recordExtensionRun(run: RuntimeExtensionRun): Promise<ProjectStoreRunStatePersistResult> {
    const store = await this.openStore();
    const input = extensionRunToProjectStoreInput(run);
    await store.addExtensionRun(input);
    await store.addAuditEvent({
      actor: 'run-state-recorder',
      action: 'extension.run.persist',
      targetRef: input.id ?? run.id,
      decision: input.status === 'blocked' || input.status === 'error' ? 'blocked' : 'completed',
      detail: `Persisted extension hook ${input.extensionName} ${input.hook} with raw evidence links intact.`,
    });
    return { kind: 'proxyforge-project-run-state-persist-result', runType: 'extension', id: input.id ?? run.id, stats: store.stats() };
  }

  async flush() {
    await this.openStore();
  }

  async close() {
    if (!this.storePromise) return;
    const store = await this.storePromise;
    store.close();
    this.storePromise = null;
  }

  private async openStore() {
    if (!this.storePromise) {
      this.storePromise = projectStoreExists(this.rootDir)
        .then((exists) => (exists
          ? ProjectStore.open(this.rootDir)
          : ProjectStore.create(this.rootDir, this.options)));
    }
    return this.storePromise;
  }
}

export function automationExecutionToProjectStoreInput(execution: RuntimeAutomationExecution): ProjectStoreAutomationRunInput {
  const operationalRawMaterial = execution.operationalRawMaterial ?? {
    exchangeId: execution.exchange?.id,
    requestRaw: execution.exchange?.requestRaw,
    responseRaw: execution.exchange?.responseRaw,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
  };
  return {
    id: execution.id,
    workflowId: execution.workflowId,
    workflowName: execution.workflowName,
    status: execution.status,
    trigger: execution.trigger,
    startedAt: execution.startedAt,
    completedAt: execution.completedAt,
    durationMs: execution.durationMs,
    totalRequests: execution.totalRequests,
    logs: execution.logs,
    exchange: execution.exchange as ProjectStoreAutomationRunInput['exchange'],
    issue: execution.issue ? issueToProjectStoreInput(execution.issue, 'automation') : undefined,
    operationalRawMaterial,
    schedulerJobId: execution.schedulerJobId,
    schedulerLeaseId: execution.schedulerLeaseId,
    ciProvider: execution.ciProvider,
    ciConfig: execution.ciConfig,
    tags: ['automation', execution.trigger, execution.status, 'desktop-live-run-state'],
    notes: 'Captured from the live automation execution path; redact only during report/export boundaries.',
  };
}

export function aiRunResultToProjectStoreInput(result: RuntimeAiRunResult): ProjectStoreAiRunInput {
  return {
    id: result.id,
    providerId: result.providerId,
    task: result.task,
    status: result.status,
    model: result.model,
    startedAt: result.startedAt,
    completedAt: result.completedAt,
    summary: result.summary,
    output: result.output,
    prompt: result.prompt,
    evidenceCount: result.evidenceCount,
    command: result.command,
    providerLabel: result.providerLabel,
    contextDigest: result.contextDigest,
    usage: asObjectRecord(result.usage),
    streamEvents: asObjectRecords(result.streamEvents),
    promptEvaluation: asObjectRecord(result.promptEvaluation),
    suggestedActions: asObjectRecords(result.suggestedActions),
    tags: ['ai', result.providerId, result.task, result.status, 'desktop-live-run-state'],
    notes: 'Captured from the live AI provider path; raw prompt/output stay in Project Store until report/export boundaries.',
  };
}

export function extensionRunToProjectStoreInput(run: RuntimeExtensionRun): ProjectStoreExtensionRunInput {
  return {
    id: run.id,
    extensionId: run.extensionId,
    extensionName: run.extensionName,
    hook: run.hook,
    status: run.status,
    target: run.target,
    startedAt: run.startedAt,
    completedAt: run.completedAt,
    summary: run.summary,
    logs: run.logs,
    issue: run.issue ? issueToProjectStoreInput(run.issue, 'extension') : undefined,
    exchange: run.exchange as ProjectStoreExtensionRunInput['exchange'],
    tags: ['extension', run.extensionId, run.hook, run.status, 'desktop-live-run-state'],
    notes: 'Captured from the live extension hook path; raw extension evidence remains intact for executor workflows.',
  };
}

function issueToProjectStoreInput(issue: RuntimeIssue, source: string): ProjectStoreIssueInput {
  return {
    id: issue.id,
    title: issue.title,
    type: source,
    severity: issue.severity,
    confidence: issue.confidence,
    status: issue.status,
    host: issue.host,
    path: issue.path,
    detail: issue.detail,
    remediation: issue.remediation,
    source,
  };
}

async function projectStoreExists(rootDir: string) {
  const candidates = [
    path.join(rootDir, 'manifest.json'),
    path.join(rootDir, 'project.db'),
  ];
  const checks = await Promise.all(candidates.map(async (candidate) => {
    try {
      await fs.access(candidate);
      return true;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return false;
      throw error;
    }
  }));
  return checks.every(Boolean);
}

function asObjectRecord(value: unknown): Record<string, unknown> | undefined {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  return value as Record<string, unknown>;
}

function asObjectRecords(values: unknown[] | undefined): Record<string, unknown>[] | undefined {
  if (!Array.isArray(values)) return undefined;
  return values.filter((value): value is Record<string, unknown> => Boolean(value) && typeof value === 'object' && !Array.isArray(value));
}
