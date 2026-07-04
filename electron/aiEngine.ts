import { spawn } from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';

type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type AiProviderId = 'codex' | 'claude' | 'local';
export type AiTaskKind = 'triage' | 'replay-plan' | 'exploit-review' | 'report-draft';

export interface AiContextExchange {
  method: string;
  host: string;
  path: string;
  status: number;
  risk: string;
  notes: string;
  requestRaw: string;
  responseRaw: string;
  tags: string[];
}

export interface AiContextIssue {
  title: string;
  severity: string;
  host: string;
  path: string;
  detail: string;
  remediation: string;
}

export interface AiContextBundle {
  projectName: string;
  scopeAllowlist: string[];
  taskHint: string;
  exchanges: AiContextExchange[];
  issues: AiContextIssue[];
}

export interface AiProviderConfig {
  id: AiProviderId;
  label: string;
  mode: 'cli' | 'http';
  enabled: boolean;
  model: string;
  command?: string;
  args?: string[];
  endpoint?: string;
  apiKeyEnv?: string;
  timeoutMs: number;
  inputCostPerMillionTokens?: number;
  outputCostPerMillionTokens?: number;
}

export interface AiProviderRuntime extends AiProviderConfig {
  available: boolean;
  secretPresent: boolean;
  status: 'configured' | 'needs-key' | 'offline';
  message: string;
}

export interface AiRunRequest {
  providerId: AiProviderId;
  task: AiTaskKind;
  prompt: string;
  context: AiContextBundle;
}

export interface AiRunUsage {
  promptTokens: number;
  completionTokens: number;
  totalTokens: number;
  estimatedCostUsd: number;
  latencyMs: number;
  source?: 'provider' | 'estimated' | 'browser-preview';
}

export interface AiRunStreamEvent {
  id: string;
  at: string;
  source: 'prompt' | 'stdout' | 'stderr' | 'http' | 'fallback' | 'complete';
  text: string;
}

export interface AiPromptEvaluationCheck {
  label: string;
  status: 'ready' | 'warning' | 'blocked';
  detail: string;
}

export interface AiPromptEvaluation {
  score: number;
  providerId: AiProviderId;
  model: string;
  checks: AiPromptEvaluationCheck[];
  recommendations: string[];
}

export type AiSuggestedActionKind =
  | 'stage-repeater'
  | 'stage-replay-matrix'
  | 'queue-active-scan'
  | 'open-exploit-review'
  | 'record-automation'
  | 'draft-report';

export interface AiSuggestedAction {
  id: string;
  kind: AiSuggestedActionKind;
  label: string;
  detail: string;
  target: string;
  priority: Severity;
}

export interface AiRunResult {
  id: string;
  providerId: AiProviderId;
  task: AiTaskKind;
  status: 'complete' | 'unavailable' | 'error';
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
  usage?: AiRunUsage;
  streamEvents?: AiRunStreamEvent[];
  promptEvaluation?: AiPromptEvaluation;
  suggestedActions?: AiSuggestedAction[];
}

interface ProviderRunResult {
  output: string;
  usage?: Partial<AiRunUsage>;
  streamEvents: AiRunStreamEvent[];
}

const DEFAULT_PROVIDERS: AiProviderConfig[] = [
  {
    id: 'codex',
    label: 'Codex',
    mode: 'cli',
    enabled: true,
    model: 'configured-default',
    command: 'codex',
    args: ['exec', '--skip-git-repo-check', '--ephemeral', '--sandbox', 'read-only', '-'],
    timeoutMs: 90_000,
  },
  {
    id: 'claude',
    label: 'Claude',
    mode: 'cli',
    enabled: true,
    model: 'configured-default',
    command: 'claude',
    args: ['--print', '--no-session-persistence', '--permission-mode', 'dontAsk', '--tools', ''],
    timeoutMs: 90_000,
  },
  {
    id: 'local',
    label: 'OpenAI-compatible Local',
    mode: 'http',
    enabled: false,
    model: 'local-security-model',
    endpoint: 'http://127.0.0.1:11434/v1/chat/completions',
    apiKeyEnv: '',
    timeoutMs: 60_000,
  },
];

export class AiEngine {
  constructor(private readonly configPath: string) {}

  async loadProviders(): Promise<AiProviderRuntime[]> {
    const configs = await this.readConfigs();
    return Promise.all(configs.map((config) => this.runtimeStatus(config)));
  }

  async saveProviders(configs: AiProviderConfig[]): Promise<AiProviderRuntime[]> {
    const sanitized = sanitizeProviderConfigs(configs);
    await fs.mkdir(path.dirname(this.configPath), { recursive: true });
    await fs.writeFile(this.configPath, JSON.stringify({ version: 1, providers: sanitized }, null, 2), 'utf8');
    return Promise.all(sanitized.map((config) => this.runtimeStatus(config)));
  }

  async runTask(request: AiRunRequest): Promise<AiRunResult> {
    const startedAt = new Date();
    const configs = await this.readConfigs();
    const provider = configs.find((config) => config.id === request.providerId) ?? configs[0];
    const evidenceCount = request.context.exchanges.length + request.context.issues.length;
    const prompt = buildAiPrompt(request);

    if (!provider.enabled) {
      return this.fallbackResult(request, provider, startedAt, evidenceCount, `${provider.label} is disabled`);
    }

    try {
      if (provider.mode === 'cli') {
        const command = provider.command ?? '';
        const executable = await resolveExecutable(command);
        if (!executable) {
          return this.fallbackResult(request, provider, startedAt, evidenceCount, `${command || provider.label} was not found on PATH`);
        }
        const run = await runCli(executable, provider.args ?? [], prompt, provider.timeoutMs);
        return completeResult(request, provider, startedAt, evidenceCount, run, `${command} ${(provider.args ?? []).join(' ')}`.trim());
      }

      if (provider.mode === 'http') {
        const endpoint = provider.endpoint ?? '';
        if (!endpoint) return this.fallbackResult(request, provider, startedAt, evidenceCount, 'No local AI endpoint configured');
        const run = await runHttpProvider(provider, prompt);
        return completeResult(request, provider, startedAt, evidenceCount, run, endpoint);
      }

      return this.fallbackResult(request, provider, startedAt, evidenceCount, 'Unsupported provider mode');
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return {
        ...this.fallbackResult(request, provider, startedAt, evidenceCount, message),
        status: 'error',
        summary: `AI task failed: ${message}`,
      };
    }
  }

  private async readConfigs(): Promise<AiProviderConfig[]> {
    try {
      const raw = await fs.readFile(this.configPath, 'utf8');
      const parsed = JSON.parse(raw) as { providers?: AiProviderConfig[] };
      return sanitizeProviderConfigs(parsed.providers ?? DEFAULT_PROVIDERS);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
      return DEFAULT_PROVIDERS;
    }
  }

  private async runtimeStatus(config: AiProviderConfig): Promise<AiProviderRuntime> {
    const available = config.mode === 'cli'
      ? Boolean(await resolveExecutable(config.command ?? ''))
      : Boolean(config.endpoint);
    const secretPresent = config.apiKeyEnv ? Boolean(process.env[config.apiKeyEnv]) : true;
    const status = !config.enabled || !available ? 'offline' : secretPresent ? 'configured' : 'needs-key';
    const message = config.mode === 'cli'
      ? available ? `${config.command} is available on PATH` : `${config.command || config.label} is not available on PATH`
      : config.endpoint ? `Endpoint configured: ${config.endpoint}` : 'No endpoint configured';

    return {
      ...config,
      available,
      secretPresent,
      status,
      message: config.enabled ? message : 'Provider disabled for this project',
    };
  }

  private fallbackResult(request: AiRunRequest, provider: AiProviderConfig, startedAt: Date, evidenceCount: number, reason: string): AiRunResult {
    const output = buildDeterministicAnalysis(request, reason);
    return {
      id: `ai-${Date.now()}-${Math.random().toString(16).slice(2)}`,
      providerId: provider.id,
      task: request.task,
      status: 'unavailable',
      model: provider.model,
      startedAt: startedAt.toISOString(),
      completedAt: new Date().toISOString(),
      summary: `${provider.label} unavailable; generated local planning fallback`,
      output,
      evidenceCount,
      command: provider.mode === 'cli' ? provider.command : provider.endpoint,
      streamEvents: [
        streamEvent('fallback', `Provider fallback: ${reason}`),
        streamEvent('complete', 'Local deterministic plan generated.'),
      ],
      promptEvaluation: evaluateAiPrompt(request, provider),
      suggestedActions: buildSuggestedActions(request),
    };
  }
}

function sanitizeProviderConfigs(configs: AiProviderConfig[]) {
  const byId = new Map<AiProviderId, AiProviderConfig>();
  for (const fallback of DEFAULT_PROVIDERS) byId.set(fallback.id, fallback);

  for (const config of configs) {
    if (!['codex', 'claude', 'local'].includes(config.id)) continue;
    const fallback = byId.get(config.id) ?? DEFAULT_PROVIDERS[0];
    byId.set(config.id, {
      ...fallback,
      ...config,
      label: String(config.label || fallback.label),
      model: String(config.model || fallback.model),
      command: config.command ? String(config.command) : fallback.command,
      args: Array.isArray(config.args) ? config.args.map(String).slice(0, 20) : fallback.args,
      endpoint: config.endpoint ? String(config.endpoint) : fallback.endpoint,
      apiKeyEnv: config.apiKeyEnv ? String(config.apiKeyEnv).replace(/[^A-Z0-9_]/gi, '').slice(0, 80) : '',
      timeoutMs: Math.min(Math.max(Number(config.timeoutMs) || fallback.timeoutMs, 5_000), 180_000),
      inputCostPerMillionTokens: Math.max(Number(config.inputCostPerMillionTokens ?? fallback.inputCostPerMillionTokens ?? 0) || 0, 0),
      outputCostPerMillionTokens: Math.max(Number(config.outputCostPerMillionTokens ?? fallback.outputCostPerMillionTokens ?? 0) || 0, 0),
      mode: config.mode === 'http' ? 'http' : 'cli',
      enabled: Boolean(config.enabled),
    });
  }

  return Array.from(byId.values());
}

function buildAiPrompt(request: AiRunRequest) {
  return [
    'You are ProxyForge AI, assisting an authorized web security assessment.',
    'Stay inside the listed scope. Do not suggest destructive actions unless the operator adds explicit approval.',
    `Task: ${taskLabel(request.task)}`,
    `Operator prompt: ${request.prompt || request.context.taskHint}`,
    '',
    'Context bundle:',
    JSON.stringify(executionContext(request.context), null, 2),
    '',
    'Return concise, actionable output with evidence references, next steps, and safety gates.',
  ].join('\n');
}

function taskLabel(task: AiTaskKind) {
  const labels: Record<AiTaskKind, string> = {
    triage: 'Triage captured traffic and rank likely findings',
    'replay-plan': 'Plan safe Repeater/Intruder validation steps',
    'exploit-review': 'Review PoC assumptions and approval gates',
    'report-draft': 'Draft a report-ready finding narrative',
  };
  return labels[task];
}

function executionContext(context: AiContextBundle): AiContextBundle {
  return {
    ...context,
    exchanges: context.exchanges.slice(0, 8).map((exchange) => ({
      ...exchange,
      requestRaw: exchange.requestRaw.slice(0, 6000),
      responseRaw: exchange.responseRaw.slice(0, 6000),
    })),
    issues: context.issues.slice(0, 12),
  };
}

function buildDeterministicAnalysis(request: AiRunRequest, reason: string) {
  const exchanges = request.context.exchanges;
  const issues = request.context.issues;
  const highRisk = issues.filter((issue) => ['critical', 'high'].includes(issue.severity));
  const authz = exchanges.filter((exchange) => exchange.tags.includes('authz') || /403|permission|role|admin/i.test(`${exchange.status} ${exchange.notes} ${exchange.responseRaw}`));
  const target = exchanges[0];

  return [
    `Provider fallback reason: ${reason}`,
    `Task: ${taskLabel(request.task)}`,
    `Scope: ${request.context.scopeAllowlist.join(', ') || 'none'}`,
    `Evidence reviewed: ${exchanges.length} exchanges, ${issues.length} issues`,
    '',
    'Priority observations:',
    highRisk.length > 0 ? `- High-risk queue: ${highRisk.map((issue) => `${issue.severity} ${issue.title} on ${issue.host}${issue.path}`).join('; ')}` : '- No high-risk issues in the current bundle.',
    authz.length > 0 ? `- Authorization candidates: ${authz.map((exchange) => `${exchange.method} ${exchange.host}${exchange.path} status ${exchange.status}`).join('; ')}` : '- No obvious authorization candidate in the selected bundle.',
    target ? `- Best next evidence anchor: ${target.method} ${target.host}${target.path}` : '- No exchange selected.',
    '',
    'Recommended next steps:',
    '- Reproduce the strongest candidate in Repeater with the current user context.',
    '- Compare allowed versus denied identities before escalating to exploit validation.',
    '- Keep active probes scoped and rate-limited, then attach request/response pairs to the report.',
  ].join('\n');
}

async function resolveExecutable(command: string) {
  if (!command) return null;
  if (command.includes(path.sep) || command.includes('/')) {
    try {
      await fs.access(command);
      return command;
    } catch {
      return null;
    }
  }

  const pathEntries = (process.env.PATH ?? '').split(path.delimiter).filter(Boolean);
  const extensions = process.platform === 'win32'
    ? (process.env.PATHEXT ?? '.EXE;.CMD;.BAT;.COM').split(';')
    : [''];

  for (const directory of pathEntries) {
    for (const extension of extensions) {
      const candidate = path.join(directory, `${command}${extension}`);
      try {
        await fs.access(candidate);
        return candidate;
      } catch {
        // Keep searching PATH.
      }
    }
  }

  return null;
}

function runCli(command: string, args: string[], stdin: string, timeoutMs: number) {
  return new Promise<ProviderRunResult>((resolve, reject) => {
    const child = spawn(command, args, {
      stdio: ['pipe', 'pipe', 'pipe'],
      windowsHide: true,
      env: process.env,
    });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    const streamEvents: AiRunStreamEvent[] = [streamEvent('prompt', `Prompt sent to ${path.basename(command)} (${stdin.length} chars).`)];
    const timer = setTimeout(() => {
      child.kill('SIGTERM');
      reject(new Error(`AI provider timed out after ${timeoutMs} ms`));
    }, timeoutMs);

    child.stdout.on('data', (chunk: Buffer) => {
      stdout.push(chunk);
      const text = chunk.toString('utf8').trim();
      if (text) streamEvents.push(streamEvent('stdout', text.slice(0, 2000)));
    });
    child.stderr.on('data', (chunk: Buffer) => {
      stderr.push(chunk);
      const text = chunk.toString('utf8').trim();
      if (text) streamEvents.push(streamEvent('stderr', text.slice(0, 2000)));
    });
    child.on('error', (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      const out = Buffer.concat(stdout).toString('utf8').trim();
      const err = Buffer.concat(stderr).toString('utf8').trim();
      if (code === 0 && out) {
        streamEvents.push(streamEvent('complete', `CLI provider completed with ${out.length} output chars.`));
        resolve({ output: out, streamEvents });
        return;
      }
      reject(new Error(err || `AI provider exited with code ${code ?? 'unknown'}`));
    });
    child.stdin.end(stdin);
  });
}

async function runHttpProvider(provider: AiProviderConfig, prompt: string) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), provider.timeoutMs);
  const streamEvents: AiRunStreamEvent[] = [streamEvent('prompt', `HTTP prompt prepared for ${provider.model} (${prompt.length} chars).`)];
  try {
    const response = await fetch(provider.endpoint ?? '', {
      method: 'POST',
      signal: controller.signal,
      headers: {
        'content-type': 'application/json',
        ...(provider.apiKeyEnv && process.env[provider.apiKeyEnv] ? { authorization: `Bearer ${process.env[provider.apiKeyEnv]}` } : {}),
      },
      body: JSON.stringify({
        model: provider.model,
        messages: [
          { role: 'system', content: 'You are ProxyForge AI for authorized web security testing.' },
          { role: 'user', content: prompt },
        ],
        temperature: 0.2,
      }),
    });
    if (!response.ok) throw new Error(`HTTP provider returned ${response.status}`);
    streamEvents.push(streamEvent('http', `HTTP provider returned ${response.status}.`));
    const data = await response.json() as {
      choices?: Array<{ message?: { content?: string }; text?: string }>;
      output?: string;
      usage?: {
        prompt_tokens?: number;
        completion_tokens?: number;
        total_tokens?: number;
        input_tokens?: number;
        output_tokens?: number;
      };
    };
    const output = data.choices?.[0]?.message?.content ?? data.choices?.[0]?.text ?? data.output ?? JSON.stringify(data, null, 2);
    streamEvents.push(streamEvent('complete', `HTTP provider completed with ${output.length} output chars.`));
    return {
      output,
      usage: providerUsageFromResponse(data.usage),
      streamEvents,
    };
  } finally {
    clearTimeout(timeout);
  }
}

function completeResult(
  request: AiRunRequest,
  provider: AiProviderConfig,
  startedAt: Date,
  evidenceCount: number,
  run: ProviderRunResult,
  command: string,
): AiRunResult {
  const completedAt = new Date();
  const estimatedUsage = estimateAiUsage(buildAiPrompt(request), run.output, startedAt, completedAt, provider);
  return {
    id: `ai-${Date.now()}-${Math.random().toString(16).slice(2)}`,
    providerId: provider.id,
    task: request.task,
    status: 'complete',
    model: provider.model,
    startedAt: startedAt.toISOString(),
    completedAt: completedAt.toISOString(),
    summary: `${provider.label} completed ${taskLabel(request.task)}`,
    output: run.output,
    evidenceCount,
    command,
    usage: {
      promptTokens: run.usage?.promptTokens ?? estimatedUsage.promptTokens,
      completionTokens: run.usage?.completionTokens ?? estimatedUsage.completionTokens,
      totalTokens: run.usage?.totalTokens ?? estimatedUsage.totalTokens,
      estimatedCostUsd: estimatedUsage.estimatedCostUsd,
      latencyMs: estimatedUsage.latencyMs,
      source: run.usage?.source ?? 'estimated',
    },
    streamEvents: run.streamEvents,
    promptEvaluation: evaluateAiPrompt(request, provider),
    suggestedActions: buildSuggestedActions(request),
  };
}

function streamEvent(source: AiRunStreamEvent['source'], text: string): AiRunStreamEvent {
  return {
    id: `ai-stream-${Date.now()}-${Math.random().toString(16).slice(2)}`,
    at: new Date().toISOString(),
    source,
    text,
  };
}

function providerUsageFromResponse(usage: { prompt_tokens?: number; completion_tokens?: number; total_tokens?: number; input_tokens?: number; output_tokens?: number } | undefined): Partial<AiRunUsage> | undefined {
  if (!usage) return undefined;
  const promptTokens = Number(usage.prompt_tokens ?? usage.input_tokens ?? 0);
  const completionTokens = Number(usage.completion_tokens ?? usage.output_tokens ?? 0);
  const totalTokens = Number(usage.total_tokens ?? promptTokens + completionTokens);
  if (!promptTokens && !completionTokens && !totalTokens) return undefined;
  return {
    promptTokens,
    completionTokens,
    totalTokens,
    source: 'provider',
  };
}

function estimateAiUsage(prompt: string, output: string, startedAt: Date, completedAt: Date, provider: AiProviderConfig): AiRunUsage {
  const promptTokens = estimateTokenCount(prompt);
  const completionTokens = estimateTokenCount(output);
  const inputRate = provider.inputCostPerMillionTokens ?? 0;
  const outputRate = provider.outputCostPerMillionTokens ?? 0;
  return {
    promptTokens,
    completionTokens,
    totalTokens: promptTokens + completionTokens,
    estimatedCostUsd: (promptTokens / 1_000_000) * inputRate + (completionTokens / 1_000_000) * outputRate,
    latencyMs: Math.max(0, completedAt.getTime() - startedAt.getTime()),
    source: 'estimated',
  };
}

function estimateTokenCount(value: string) {
  return Math.max(1, Math.ceil(value.trim().split(/\s+/).filter(Boolean).length * 1.25));
}

function evaluateAiPrompt(request: AiRunRequest, provider: AiProviderConfig): AiPromptEvaluation {
  const prompt = request.prompt || request.context.taskHint;
  const checks: AiPromptEvaluationCheck[] = [];
  const recommendations: string[] = [];
  const addCheck = (label: string, ready: boolean, detail: string, warningDetail: string) => {
    checks.push({ label, status: ready ? 'ready' : 'warning', detail: ready ? detail : warningDetail });
    if (!ready) recommendations.push(warningDetail);
  };

  addCheck('Scope boundary', /scope|authorized|allowlist|engagement/i.test(prompt), 'Prompt references authorization or scope.', 'Add explicit scope and authorization boundaries.');
  addCheck('Evidence request', /evidence|request|response|finding|issue/i.test(prompt), 'Prompt asks the model to anchor on evidence.', 'Ask for evidence-linked reasoning and request/response references.');
  addCheck('Safety gates', /safe|non-destructive|approval|rate|throttle|stop/i.test(prompt), 'Prompt includes safety or stop-condition language.', 'Add stop conditions, approval gates, or throttling expectations.');
  addCheck('Actionable output', /plan|step|draft|prioritize|remediation|next/i.test(prompt), 'Prompt asks for actionable output.', 'Ask for concrete next steps or report-ready remediation.');

  if (provider.id === 'claude') {
    addCheck('Claude structure', /xml|section|bullet|assumption/i.test(prompt), 'Prompt gives Claude structure or assumption handling.', 'Claude prompts work better with sections and explicit assumptions.');
  } else if (provider.id === 'codex') {
    addCheck('Codex execution shape', /file|command|test|diff|implement|verify/i.test(prompt), 'Prompt gives Codex implementation or verification shape.', 'Codex prompts work better with files, commands, expected diffs, or verification gates.');
  } else {
    addCheck('Local model brevity', prompt.length < 2400, 'Prompt is compact enough for smaller local models.', 'Shorten local-model prompts or reduce context to the decisive evidence.');
  }

  const ready = checks.filter((check) => check.status === 'ready').length;
  return {
    score: Math.round((ready / checks.length) * 100),
    providerId: provider.id,
    model: provider.model,
    checks,
    recommendations: recommendations.slice(0, 5),
  };
}

function buildSuggestedActions(request: AiRunRequest): AiSuggestedAction[] {
  const selected = request.context.exchanges[0];
  const target = selected ? `${selected.method} ${selected.host}${selected.path}` : request.context.projectName;
  const issue = request.context.issues.find((candidate) => ['critical', 'high'].includes(candidate.severity)) ?? request.context.issues[0];
  const authzCandidate = Boolean(selected && (selected.tags.includes('authz') || selected.status === 403 || /permission|role|admin/i.test(`${selected.notes} ${selected.responseRaw}`)));
  const graphqlCandidate = Boolean(selected && /graphql/i.test(`${selected.path} ${selected.requestRaw}`));
  const actions: AiSuggestedAction[] = [];

  if (selected) {
    actions.push({
      id: 'ai-action-stage-repeater',
      kind: 'stage-repeater',
      label: 'Stage in Repeater',
      detail: 'Load the selected evidence into Repeater for manual, scoped validation.',
      target,
      priority: selected.risk as Severity,
    });
  }

  if (authzCandidate || request.task === 'replay-plan') {
    actions.push({
      id: 'ai-action-replay-matrix',
      kind: 'stage-replay-matrix',
      label: 'Stage replay matrix',
      detail: 'Prepare an identity comparison matrix without sending traffic automatically.',
      target,
      priority: 'high',
    });
  }

  if (selected && request.task !== 'report-draft') {
    actions.push({
      id: 'ai-action-active-scan',
      kind: 'queue-active-scan',
      label: 'Queue active scan',
      detail: 'Move the selected evidence to the scanner audit queue for throttled, scoped probes.',
      target,
      priority: selected.risk as Severity,
    });
  }

  if (request.task === 'exploit-review' || authzCandidate || graphqlCandidate || issue) {
    actions.push({
      id: 'ai-action-exploit-review',
      kind: 'open-exploit-review',
      label: 'Open exploit review',
      detail: 'Select the closest non-destructive Exploit Lab template and keep approval gates visible.',
      target: issue ? `${issue.host}${issue.path}` : target,
      priority: issue?.severity as Severity ?? 'medium',
    });
  }

  actions.push({
    id: 'ai-action-automation',
    kind: 'record-automation',
    label: 'Record automation',
    detail: 'Capture the selected request as a scoped macro workflow for repeatable validation.',
    target,
    priority: 'low',
  });

  actions.push({
    id: 'ai-action-report',
    kind: 'draft-report',
    label: 'Draft report',
    detail: 'Open report drafting with the current findings and evidence bundle in context.',
    target: request.context.projectName,
    priority: issue?.severity as Severity ?? 'info',
  });

  return actions.slice(0, 6);
}
