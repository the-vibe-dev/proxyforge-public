// Generic external automation API — JSON command/event protocol.
// Any external orchestrator (CI job, shell script, AI agent) can drive
// ProxyForge without coupling via this stable protocol.
// No external dependencies.

// ---------------------------------------------------------------------------
// Command types
// ---------------------------------------------------------------------------

export type AgentOpCode =
  | 'project.create'
  | 'project.open'
  | 'proxy.start'
  | 'proxy.stop'
  | 'browser.launch'
  | 'history.query'
  | 'repeater.send'
  | 'scanner.run'
  | 'scanner.matrix.fetch'
  | 'oast.payload.create'
  | 'oast.interactions.poll'
  | 'exploit.template.run'
  | 'playbook.run'
  | 'issue.promote'
  | 'report.export'
  | 'extension.invoke';

export interface AgentCommand {
  op: AgentOpCode;
  requestId?: string;
  [key: string]: unknown;
}

export interface AgentResponse {
  op: AgentOpCode;
  requestId?: string;
  ok: boolean;
  error?: string;
  data?: unknown;
}

// ---------------------------------------------------------------------------
// Event types
// ---------------------------------------------------------------------------

export type AgentEventType =
  | 'proxy.exchange.captured'
  | 'scanner.probe.classified'
  | 'scanner.finding.created'
  | 'oast.callback.received'
  | 'issue.created'
  | 'report.exported'
  | 'playbook.step.completed';

export interface AgentEvent {
  event: AgentEventType;
  timestamp: string;
  [key: string]: unknown;
}

// ---------------------------------------------------------------------------
// Command serialization
// ---------------------------------------------------------------------------

export function parseCommand(json: string): AgentCommand {
  const obj = JSON.parse(json);
  if (typeof obj.op !== 'string') throw new Error('AgentCommand missing "op" field');
  return obj as AgentCommand;
}

export function serializeResponse(response: AgentResponse): string {
  return JSON.stringify(response);
}

export function serializeEvent(event: AgentEvent): string {
  return JSON.stringify(event);
}

export function buildErrorResponse(op: AgentOpCode, error: string, requestId?: string): AgentResponse {
  return { op, requestId, ok: false, error };
}

export function buildSuccessResponse(op: AgentOpCode, data: unknown, requestId?: string): AgentResponse {
  return { op, requestId, ok: true, data };
}

// ---------------------------------------------------------------------------
// Schema validation
// ---------------------------------------------------------------------------

const REQUIRED_FIELDS: Partial<Record<AgentOpCode, string[]>> = {
  'project.create': ['name'],
  'project.open': ['path'],
  'proxy.start': ['projectId', 'listen'],
  'proxy.stop': ['projectId'],
  'browser.launch': [],
  'history.query': ['projectId'],
  'repeater.send': ['projectId', 'request'],
  'scanner.run': ['projectId', 'exchangeId'],
  'scanner.matrix.fetch': ['projectId', 'matrixId'],
  'oast.payload.create': ['projectId', 'purpose'],
  'oast.interactions.poll': ['projectId'],
  'exploit.template.run': ['projectId', 'templateId'],
  'playbook.run': ['projectId', 'recipeId'],
  'issue.promote': ['projectId', 'evidenceIds'],
  'report.export': ['projectId', 'format'],
  'extension.invoke': ['projectId', 'extensionId', 'hook'],
};

export function validateCommand(cmd: AgentCommand): { valid: boolean; errors: string[] } {
  const required = REQUIRED_FIELDS[cmd.op] ?? [];
  const missing = required.filter((f) => cmd[f] === undefined || cmd[f] === null);
  return { valid: missing.length === 0, errors: missing.map((f) => `Missing required field: ${f}`) };
}

export function isValidOpCode(op: string): op is AgentOpCode {
  return op in REQUIRED_FIELDS;
}
