import type { IpcMainInvokeEvent } from 'electron';

export type IpcCapability =
  | 'project.lifecycle'
  | 'project.backup'
  | 'ai.provider-config'
  | 'ai.external-run'
  | 'active.repeater'
  | 'active.intruder'
  | 'active.scanner'
  | 'oast.listener'
  | 'run-state.automation'
  | 'run-state.extension';

export type IpcDangerLevel =
  | 'none'
  | 'file-write'
  | 'external-ai'
  | 'credential'
  | 'active-workflow';

export interface IpcChannelContract<T> {
  channel: string;
  capability: IpcCapability;
  dangerLevel: IpcDangerLevel;
  validate(value: unknown): T;
}

export interface IpcGuardAuditEvent {
  channel: string;
  capability: IpcCapability;
  dangerLevel: IpcDangerLevel;
  decision: 'blocked' | 'completed' | 'updated';
  detail: string;
}

export const IPC_LIMITS = {
  shortTextBytes: 512,
  mediumTextBytes: 8 * 1024,
  rawTextBytes: 10 * 1024 * 1024,
  jsonMaterialBytes: 10 * 1024 * 1024,
  payloadItems: 5000,
  insertionPoints: 5000,
  aiContextExchanges: 12,
  aiContextIssues: 24,
  listItems: 200,
};

export class IpcValidationError extends Error {
  readonly channel: string;
  readonly capability: IpcCapability;
  readonly dangerLevel: IpcDangerLevel;
  readonly details: string[];

  constructor(contract: Pick<IpcChannelContract<unknown>, 'channel' | 'capability' | 'dangerLevel'>, details: string[]) {
    super(`IPC request rejected for ${contract.channel}: ${details.join('; ')}`);
    this.name = 'IpcValidationError';
    this.channel = contract.channel;
    this.capability = contract.capability;
    this.dangerLevel = contract.dangerLevel;
    this.details = details;
  }
}

export function guardedIpcHandler<T, R>(
  contract: IpcChannelContract<unknown>,
  handler: (request: T, event: IpcMainInvokeEvent) => Promise<R> | R,
  audit?: (event: IpcGuardAuditEvent) => Promise<void> | void,
) {
  return async (event: IpcMainInvokeEvent, value: unknown): Promise<R> => {
    try {
      const request = contract.validate(value) as T;
      return await handler(request, event);
    } catch (error) {
      if (error instanceof IpcValidationError) {
        await audit?.({
          channel: contract.channel,
          capability: contract.capability,
          dangerLevel: contract.dangerLevel,
          decision: 'blocked',
          detail: error.details.join('; '),
        });
      }
      throw error;
    }
  };
}

export const ipcContracts = {
  projectCreate: contract('project:create', 'project.lifecycle', 'file-write', validateProjectCreateRequest),
  projectOpen: contract('project:open', 'project.lifecycle', 'file-write', validateProjectOpenRequest),
  projectClose: contract('project:close', 'project.lifecycle', 'file-write', validateProjectCloseRequest),
  projectBackup: contract('project:backup', 'project.backup', 'file-write', validateProjectBackupRequest),
  aiProvidersSet: contract('ai:providers:set', 'ai.provider-config', 'credential', validateAiProviderConfigs),
  aiRun: contract('ai:run', 'ai.external-run', 'external-ai', validateAiRunRequest),
  repeaterSend: contract('repeater:send', 'active.repeater', 'active-workflow', validateReplayRequest),
  intruderRun: contract('intruder:run', 'active.intruder', 'active-workflow', validateIntruderAttackRequest),
  scannerRunActive: contract('scanner:run-active', 'active.scanner', 'active-workflow', validateActiveScanRequest),
  scannerRunCrawlAudit: contract('scanner:run-crawl-audit', 'active.scanner', 'active-workflow', validateCrawlAuditRequest),
  callbackListenerStart: contract('callback-listener:start', 'oast.listener', 'active-workflow', validateCallbackListenerStartRequest),
  callbackListenerPoll: contract('callback-listener:poll', 'oast.listener', 'active-workflow', validateCallbackListenerPollRequest),
  automationRunState: contract('run-state:automation', 'run-state.automation', 'active-workflow', validateAutomationExecution),
  extensionRunState: contract('run-state:extension', 'run-state.extension', 'active-workflow', validateExtensionRun),
};

function contract<T>(
  channel: string,
  capability: IpcCapability,
  dangerLevel: IpcDangerLevel,
  validator: (value: unknown, contract: IpcChannelContract<T>) => T,
): IpcChannelContract<T> {
  const built: IpcChannelContract<T> = {
    channel,
    capability,
    dangerLevel,
    validate(value: unknown): T {
      return validator(value, built);
    },
  };
  return built;
}

function validateProjectCreateRequest(value: unknown, ipc: IpcChannelContract<unknown>) {
  const record = objectOrDefault(value, {}, ipc, '$');
  assertKnownKeys(record, ['projectName', 'projectId', 'rootDir', 'operator', 'allowExternalRoot'], ipc, '$');
  return stripUndefined({
    projectName: optionalBoundedString(record.projectName, 'projectName', IPC_LIMITS.mediumTextBytes, ipc),
    projectId: optionalProjectId(record.projectId, 'projectId', ipc),
    rootDir: optionalProjectRoot(record.rootDir, 'rootDir', ipc),
    operator: optionalBoundedString(record.operator, 'operator', IPC_LIMITS.shortTextBytes, ipc),
    allowExternalRoot: optionalBoolean(record.allowExternalRoot, 'allowExternalRoot', ipc),
  });
}

function validateProjectOpenRequest(value: unknown, ipc: IpcChannelContract<unknown>) {
  const record = requiredObject(value, ipc, '$');
  assertKnownKeys(record, ['rootDir', 'operator', 'recover', 'allowExternalRoot'], ipc, '$');
  return stripUndefined({
    rootDir: requiredProjectRoot(record.rootDir, 'rootDir', ipc),
    operator: optionalBoundedString(record.operator, 'operator', IPC_LIMITS.shortTextBytes, ipc),
    recover: optionalBoolean(record.recover, 'recover', ipc),
    allowExternalRoot: optionalBoolean(record.allowExternalRoot, 'allowExternalRoot', ipc),
  });
}

function validateProjectCloseRequest(value: unknown, ipc: IpcChannelContract<unknown>) {
  const record = objectOrDefault(value, {}, ipc, '$');
  assertKnownKeys(record, ['operator'], ipc, '$');
  return stripUndefined({
    operator: optionalBoundedString(record.operator, 'operator', IPC_LIMITS.shortTextBytes, ipc),
  });
}

function validateProjectBackupRequest(value: unknown, ipc: IpcChannelContract<unknown>) {
  const record = objectOrDefault(value, {}, ipc, '$');
  assertKnownKeys(record, ['backupRootDir', 'label', 'operator', 'allowExternalRoot'], ipc, '$');
  return stripUndefined({
    backupRootDir: optionalProjectRoot(record.backupRootDir, 'backupRootDir', ipc, false),
    label: optionalBoundedString(record.label, 'label', IPC_LIMITS.mediumTextBytes, ipc),
    operator: optionalBoundedString(record.operator, 'operator', IPC_LIMITS.shortTextBytes, ipc),
    allowExternalRoot: optionalBoolean(record.allowExternalRoot, 'allowExternalRoot', ipc),
  });
}

function validateAiProviderConfigs(value: unknown, ipc: IpcChannelContract<unknown>) {
  const configs = requiredArray(value, 'providers', IPC_LIMITS.listItems, ipc);
  return configs.map((config, index) => {
    const record = requiredObject(config, ipc, `providers[${index}]`);
    assertKnownKeys(record, [
      'id',
      'label',
      'mode',
      'enabled',
      'model',
      'command',
      'args',
      'endpoint',
      'apiKeyEnv',
      'timeoutMs',
      'inputCostPerMillionTokens',
      'outputCostPerMillionTokens',
    ], ipc, `providers[${index}]`);
    const mode = requiredEnum(record.mode, ['cli', 'http'], `providers[${index}].mode`, ipc);
    const command = optionalCommand(record.command, `providers[${index}].command`, ipc);
    const endpoint = optionalHttpEndpoint(record.endpoint, `providers[${index}].endpoint`, ipc);
    return stripUndefined({
      id: requiredEnum(record.id, ['codex', 'claude', 'local'], `providers[${index}].id`, ipc),
      label: requiredBoundedString(record.label, `providers[${index}].label`, IPC_LIMITS.shortTextBytes, ipc),
      mode,
      enabled: requiredBoolean(record.enabled, `providers[${index}].enabled`, ipc),
      model: requiredBoundedString(record.model, `providers[${index}].model`, IPC_LIMITS.shortTextBytes, ipc),
      command,
      args: optionalStringArray(record.args, `providers[${index}].args`, 20, IPC_LIMITS.mediumTextBytes, ipc),
      endpoint,
      apiKeyEnv: optionalEnvName(record.apiKeyEnv, `providers[${index}].apiKeyEnv`, ipc),
      timeoutMs: optionalInteger(record.timeoutMs, `providers[${index}].timeoutMs`, 5_000, 180_000, ipc),
      inputCostPerMillionTokens: optionalNumber(record.inputCostPerMillionTokens, `providers[${index}].inputCostPerMillionTokens`, 0, 10000, ipc),
      outputCostPerMillionTokens: optionalNumber(record.outputCostPerMillionTokens, `providers[${index}].outputCostPerMillionTokens`, 0, 10000, ipc),
    });
  });
}

function validateAiRunRequest(value: unknown, ipc: IpcChannelContract<unknown>) {
  const record = requiredObject(value, ipc, '$');
  assertKnownKeys(record, ['providerId', 'task', 'prompt', 'context'], ipc, '$');
  return {
    providerId: requiredEnum(record.providerId, ['codex', 'claude', 'local'], 'providerId', ipc),
    task: requiredEnum(record.task, ['triage', 'replay-plan', 'exploit-review', 'report-draft'], 'task', ipc),
    prompt: requiredBoundedString(record.prompt, 'prompt', IPC_LIMITS.rawTextBytes, ipc),
    context: validateAiContext(record.context, ipc),
  };
}

function validateReplayRequest(value: unknown, ipc: IpcChannelContract<unknown>) {
  const record = requiredObject(value, ipc, '$');
  assertKnownKeys(record, [
    'rawRequest',
    'targetUrl',
    'scopeAllowlist',
    'settings',
    'sessionProfile',
    'sessionOptions',
    'oastPayloads',
    'repeaterTabId',
    'repeaterTabName',
    'repeaterTabGroup',
    'repeaterSendId',
    'sourceExchangeId',
    'operator',
    'tags',
    'notes',
  ], ipc, '$');
  return stripUndefined({
    rawRequest: requiredBoundedString(record.rawRequest, 'rawRequest', IPC_LIMITS.rawTextBytes, ipc),
    targetUrl: requiredHttpUrl(record.targetUrl, 'targetUrl', ipc),
    scopeAllowlist: requiredScopeAllowlist(record.scopeAllowlist, 'scopeAllowlist', ipc),
    settings: record.settings === undefined ? undefined : validateReplaySettings(record.settings, ipc, 'settings'),
    sessionProfile: record.sessionProfile === undefined ? undefined : boundedJsonRecord(record.sessionProfile, 'sessionProfile', IPC_LIMITS.jsonMaterialBytes, ipc),
    sessionOptions: record.sessionOptions === undefined ? undefined : boundedJsonRecord(record.sessionOptions, 'sessionOptions', IPC_LIMITS.jsonMaterialBytes, ipc),
    oastPayloads: optionalOastPayloadReferences(record.oastPayloads, 'oastPayloads', ipc),
    repeaterTabId: optionalBoundedString(record.repeaterTabId, 'repeaterTabId', IPC_LIMITS.shortTextBytes, ipc),
    repeaterTabName: optionalBoundedString(record.repeaterTabName, 'repeaterTabName', IPC_LIMITS.mediumTextBytes, ipc),
    repeaterTabGroup: optionalBoundedString(record.repeaterTabGroup, 'repeaterTabGroup', IPC_LIMITS.mediumTextBytes, ipc),
    repeaterSendId: optionalBoundedString(record.repeaterSendId, 'repeaterSendId', IPC_LIMITS.shortTextBytes, ipc),
    sourceExchangeId: optionalBoundedString(record.sourceExchangeId, 'sourceExchangeId', IPC_LIMITS.shortTextBytes, ipc),
    operator: optionalBoundedString(record.operator, 'operator', IPC_LIMITS.shortTextBytes, ipc),
    tags: optionalStringArray(record.tags, 'tags', 100, IPC_LIMITS.shortTextBytes, ipc),
    notes: optionalBoundedString(record.notes, 'notes', IPC_LIMITS.rawTextBytes, ipc),
  });
}

function validateIntruderAttackRequest(value: unknown, ipc: IpcChannelContract<unknown>) {
  const record = requiredObject(value, ipc, '$');
  assertKnownKeys(record, [
    'rawRequest',
    'targetUrl',
    'payloads',
    'payloadSets',
    'attackMode',
    'payloadProcessors',
    'payloadRules',
    'scopeAllowlist',
    'throttleMs',
    'grepTerms',
    'extractRegexes',
    'startOffset',
    'maxPayloadRequests',
    'resourcePoolName',
    'resourcePoolMaxConcurrent',
    'streamChunkSize',
    'resultWindowSize',
    'memoryBudgetBytes',
    'sessionProfile',
    'sessionOptions',
    'oastPayloads',
  ], ipc, '$');
  return stripUndefined({
    rawRequest: requiredBoundedString(record.rawRequest, 'rawRequest', IPC_LIMITS.rawTextBytes, ipc),
    targetUrl: requiredHttpUrl(record.targetUrl, 'targetUrl', ipc),
    payloads: requiredStringArray(record.payloads, 'payloads', IPC_LIMITS.payloadItems, IPC_LIMITS.rawTextBytes, ipc),
    payloadSets: optionalNestedStringArray(record.payloadSets, 'payloadSets', 20, IPC_LIMITS.payloadItems, IPC_LIMITS.rawTextBytes, ipc),
    attackMode: record.attackMode === undefined ? undefined : requiredEnum(record.attackMode, ['sniper', 'battering-ram', 'pitchfork', 'cluster-bomb'], 'attackMode', ipc),
    payloadProcessors: optionalEnumArray(record.payloadProcessors, 'payloadProcessors', ['url-encode', 'double-url-encode', 'base64', 'html-encode', 'json-escape', 'hex-encode', 'uppercase', 'lowercase'], 50, ipc),
    payloadRules: optionalEnumArray(record.payloadRules, 'payloadRules', ['case-variants', 'url-recursive', 'path-depth', 'delimiter-variants', 'extension-bypass', 'null-byte'], 50, ipc),
    scopeAllowlist: requiredScopeAllowlist(record.scopeAllowlist, 'scopeAllowlist', ipc),
    throttleMs: requiredInteger(record.throttleMs, 'throttleMs', 0, 60_000, ipc),
    grepTerms: requiredStringArray(record.grepTerms, 'grepTerms', 100, IPC_LIMITS.mediumTextBytes, ipc),
    extractRegexes: optionalStringArray(record.extractRegexes, 'extractRegexes', 100, IPC_LIMITS.mediumTextBytes, ipc),
    startOffset: optionalInteger(record.startOffset, 'startOffset', 0, Number.MAX_SAFE_INTEGER, ipc),
    maxPayloadRequests: optionalInteger(record.maxPayloadRequests, 'maxPayloadRequests', 1, IPC_LIMITS.payloadItems, ipc),
    resourcePoolName: optionalBoundedString(record.resourcePoolName, 'resourcePoolName', IPC_LIMITS.mediumTextBytes, ipc),
    resourcePoolMaxConcurrent: optionalInteger(record.resourcePoolMaxConcurrent, 'resourcePoolMaxConcurrent', 1, 100, ipc),
    streamChunkSize: optionalInteger(record.streamChunkSize, 'streamChunkSize', 1, 1000, ipc),
    resultWindowSize: optionalInteger(record.resultWindowSize, 'resultWindowSize', 1, IPC_LIMITS.payloadItems, ipc),
    memoryBudgetBytes: optionalInteger(record.memoryBudgetBytes, 'memoryBudgetBytes', 1024 * 1024, 4 * 1024 * 1024 * 1024, ipc),
    sessionProfile: record.sessionProfile === undefined ? undefined : boundedJsonRecord(record.sessionProfile, 'sessionProfile', IPC_LIMITS.jsonMaterialBytes, ipc),
    sessionOptions: record.sessionOptions === undefined ? undefined : boundedJsonRecord(record.sessionOptions, 'sessionOptions', IPC_LIMITS.jsonMaterialBytes, ipc),
    oastPayloads: optionalOastPayloadReferences(record.oastPayloads, 'oastPayloads', ipc),
  });
}

function validateActiveScanRequest(value: unknown, ipc: IpcChannelContract<unknown>) {
  const record = requiredObject(value, ipc, '$');
  assertKnownKeys(record, [
    'rawRequest',
    'targetUrl',
    'scopeAllowlist',
    'checks',
    'throttleMs',
    'maxRequests',
    'sessionProfile',
    'sessionOptions',
    'oastPayloadUrl',
    'oastPayloadToken',
    'oastPayloadId',
  ], ipc, '$');
  return stripUndefined({
    rawRequest: requiredBoundedString(record.rawRequest, 'rawRequest', IPC_LIMITS.rawTextBytes, ipc),
    targetUrl: requiredHttpUrl(record.targetUrl, 'targetUrl', ipc),
    scopeAllowlist: requiredScopeAllowlist(record.scopeAllowlist, 'scopeAllowlist', ipc),
    checks: requiredEnumArray(record.checks, 'checks', activeScanCheckIds, 100, ipc),
    throttleMs: requiredInteger(record.throttleMs, 'throttleMs', 0, 60_000, ipc),
    maxRequests: requiredInteger(record.maxRequests, 'maxRequests', 1, 100_000, ipc),
    sessionProfile: record.sessionProfile === undefined ? undefined : boundedJsonRecord(record.sessionProfile, 'sessionProfile', IPC_LIMITS.jsonMaterialBytes, ipc),
    sessionOptions: record.sessionOptions === undefined ? undefined : boundedJsonRecord(record.sessionOptions, 'sessionOptions', IPC_LIMITS.jsonMaterialBytes, ipc),
    oastPayloadUrl: optionalHttpEndpoint(record.oastPayloadUrl, 'oastPayloadUrl', ipc),
    oastPayloadToken: optionalBoundedString(record.oastPayloadToken, 'oastPayloadToken', IPC_LIMITS.mediumTextBytes, ipc),
    oastPayloadId: optionalBoundedString(record.oastPayloadId, 'oastPayloadId', IPC_LIMITS.shortTextBytes, ipc),
  });
}

function validateCrawlAuditRequest(value: unknown, ipc: IpcChannelContract<unknown>) {
  const record = requiredObject(value, ipc, '$');
  assertKnownKeys(record, ['scopeAllowlist', 'checks', 'insertionPoints', 'sessionHeaders', 'throttleMs', 'maxInsertionPoints'], ipc, '$');
  return stripUndefined({
    scopeAllowlist: requiredScopeAllowlist(record.scopeAllowlist, 'scopeAllowlist', ipc),
    checks: requiredEnumArray(record.checks, 'checks', activeScanCheckIds, 100, ipc),
    insertionPoints: requiredArray(record.insertionPoints, 'insertionPoints', IPC_LIMITS.insertionPoints, ipc)
      .map((point, index) => validateCrawlAuditInsertionPoint(point, ipc, `insertionPoints[${index}]`)),
    sessionHeaders: record.sessionHeaders === undefined ? undefined : validateStringRecord(record.sessionHeaders, 'sessionHeaders', ipc),
    throttleMs: requiredInteger(record.throttleMs, 'throttleMs', 0, 60_000, ipc),
    maxInsertionPoints: requiredInteger(record.maxInsertionPoints, 'maxInsertionPoints', 1, IPC_LIMITS.insertionPoints, ipc),
  });
}

function validateCallbackListenerStartRequest(value: unknown, ipc: IpcChannelContract<unknown>) {
  const record = requiredObject(value, ipc, '$');
  assertKnownKeys(record, ['profile', 'payloads'], ipc, '$');
  return {
    profile: validateCallbackListenerProfile(record.profile, ipc, 'profile'),
    payloads: record.payloads === undefined ? [] : validateCallbackPayloads(record.payloads, ipc, 'payloads'),
  };
}

function validateCallbackListenerPollRequest(value: unknown, ipc: IpcChannelContract<unknown>) {
  const record = requiredObject(value, ipc, '$');
  assertKnownKeys(record, ['profileId', 'payloads'], ipc, '$');
  return {
    profileId: requiredBoundedString(record.profileId, 'profileId', IPC_LIMITS.shortTextBytes, ipc),
    payloads: record.payloads === undefined ? [] : validateCallbackPayloads(record.payloads, ipc, 'payloads'),
  };
}

function validateAutomationExecution(value: unknown, ipc: IpcChannelContract<unknown>) {
  const record = requiredObject(value, ipc, '$');
  assertKnownKeys(record, [
    'id',
    'workflowId',
    'workflowName',
    'status',
    'trigger',
    'startedAt',
    'completedAt',
    'durationMs',
    'totalRequests',
    'logs',
    'exchange',
    'issue',
    'operationalRawMaterial',
    'schedulerJobId',
    'schedulerLeaseId',
    'ciProvider',
    'ciConfig',
  ], ipc, '$');
  return stripUndefined({
    id: requiredBoundedString(record.id, 'id', IPC_LIMITS.shortTextBytes, ipc),
    workflowId: requiredBoundedString(record.workflowId, 'workflowId', IPC_LIMITS.shortTextBytes, ipc),
    workflowName: requiredBoundedString(record.workflowName, 'workflowName', IPC_LIMITS.mediumTextBytes, ipc),
    status: requiredBoundedString(record.status, 'status', IPC_LIMITS.shortTextBytes, ipc),
    trigger: requiredBoundedString(record.trigger, 'trigger', IPC_LIMITS.shortTextBytes, ipc),
    startedAt: requiredIsoLike(record.startedAt, 'startedAt', ipc),
    completedAt: requiredIsoLike(record.completedAt, 'completedAt', ipc),
    durationMs: requiredInteger(record.durationMs, 'durationMs', 0, Number.MAX_SAFE_INTEGER, ipc),
    totalRequests: requiredInteger(record.totalRequests, 'totalRequests', 0, Number.MAX_SAFE_INTEGER, ipc),
    logs: requiredStringArray(record.logs, 'logs', IPC_LIMITS.listItems, IPC_LIMITS.rawTextBytes, ipc),
    exchange: record.exchange === undefined ? undefined : validateRuntimeExchange(record.exchange, ipc, 'exchange'),
    issue: record.issue === undefined ? undefined : validateRuntimeIssue(record.issue, ipc, 'issue'),
    operationalRawMaterial: record.operationalRawMaterial === undefined ? undefined : boundedJsonRecord(record.operationalRawMaterial, 'operationalRawMaterial', IPC_LIMITS.jsonMaterialBytes, ipc),
    schedulerJobId: optionalBoundedString(record.schedulerJobId, 'schedulerJobId', IPC_LIMITS.shortTextBytes, ipc),
    schedulerLeaseId: optionalBoundedString(record.schedulerLeaseId, 'schedulerLeaseId', IPC_LIMITS.shortTextBytes, ipc),
    ciProvider: optionalBoundedString(record.ciProvider, 'ciProvider', IPC_LIMITS.shortTextBytes, ipc),
    ciConfig: optionalBoundedString(record.ciConfig, 'ciConfig', IPC_LIMITS.rawTextBytes, ipc),
  });
}

function validateExtensionRun(value: unknown, ipc: IpcChannelContract<unknown>) {
  const record = requiredObject(value, ipc, '$');
  assertKnownKeys(record, [
    'id',
    'extensionId',
    'extensionName',
    'hook',
    'status',
    'target',
    'startedAt',
    'completedAt',
    'summary',
    'logs',
    'issue',
    'exchange',
  ], ipc, '$');
  return stripUndefined({
    id: requiredBoundedString(record.id, 'id', IPC_LIMITS.shortTextBytes, ipc),
    extensionId: requiredBoundedString(record.extensionId, 'extensionId', IPC_LIMITS.shortTextBytes, ipc),
    extensionName: requiredBoundedString(record.extensionName, 'extensionName', IPC_LIMITS.mediumTextBytes, ipc),
    hook: requiredBoundedString(record.hook, 'hook', IPC_LIMITS.shortTextBytes, ipc),
    status: requiredBoundedString(record.status, 'status', IPC_LIMITS.shortTextBytes, ipc),
    target: requiredBoundedString(record.target, 'target', IPC_LIMITS.mediumTextBytes, ipc),
    startedAt: requiredIsoLike(record.startedAt, 'startedAt', ipc),
    completedAt: requiredIsoLike(record.completedAt, 'completedAt', ipc),
    summary: requiredBoundedString(record.summary, 'summary', IPC_LIMITS.rawTextBytes, ipc),
    logs: requiredStringArray(record.logs, 'logs', IPC_LIMITS.listItems, IPC_LIMITS.rawTextBytes, ipc),
    issue: record.issue === undefined ? undefined : validateRuntimeIssue(record.issue, ipc, 'issue'),
    exchange: record.exchange === undefined ? undefined : validateRuntimeExchange(record.exchange, ipc, 'exchange'),
  });
}

function validateAiContext(value: unknown, ipc: IpcChannelContract<unknown>) {
  const record = requiredObject(value, ipc, 'context');
  assertKnownKeys(record, ['projectName', 'scopeAllowlist', 'taskHint', 'exchanges', 'issues'], ipc, 'context');
  return {
    projectName: requiredBoundedString(record.projectName, 'context.projectName', IPC_LIMITS.mediumTextBytes, ipc),
    scopeAllowlist: requiredStringArray(record.scopeAllowlist, 'context.scopeAllowlist', 100, IPC_LIMITS.mediumTextBytes, ipc),
    taskHint: requiredBoundedString(record.taskHint, 'context.taskHint', IPC_LIMITS.mediumTextBytes, ipc),
    exchanges: requiredArray(record.exchanges, 'context.exchanges', IPC_LIMITS.aiContextExchanges, ipc)
      .map((exchange, index) => validateAiContextExchange(exchange, ipc, `context.exchanges[${index}]`)),
    issues: requiredArray(record.issues, 'context.issues', IPC_LIMITS.aiContextIssues, ipc)
      .map((issue, index) => validateAiContextIssue(issue, ipc, `context.issues[${index}]`)),
  };
}

function validateAiContextExchange(value: unknown, ipc: IpcChannelContract<unknown>, label: string) {
  const record = requiredObject(value, ipc, label);
  assertKnownKeys(record, ['method', 'host', 'path', 'status', 'risk', 'notes', 'requestRaw', 'responseRaw', 'tags'], ipc, label);
  return {
    method: requiredBoundedString(record.method, `${label}.method`, IPC_LIMITS.shortTextBytes, ipc),
    host: requiredHost(record.host, `${label}.host`, ipc),
    path: requiredPath(record.path, `${label}.path`, ipc),
    status: requiredInteger(record.status, `${label}.status`, 0, 999, ipc),
    risk: requiredBoundedString(record.risk, `${label}.risk`, IPC_LIMITS.shortTextBytes, ipc),
    notes: requiredBoundedString(record.notes, `${label}.notes`, IPC_LIMITS.rawTextBytes, ipc),
    requestRaw: requiredBoundedString(record.requestRaw, `${label}.requestRaw`, IPC_LIMITS.rawTextBytes, ipc),
    responseRaw: requiredBoundedString(record.responseRaw, `${label}.responseRaw`, IPC_LIMITS.rawTextBytes, ipc),
    tags: requiredStringArray(record.tags, `${label}.tags`, 100, IPC_LIMITS.shortTextBytes, ipc),
  };
}

function validateAiContextIssue(value: unknown, ipc: IpcChannelContract<unknown>, label: string) {
  const record = requiredObject(value, ipc, label);
  assertKnownKeys(record, ['title', 'severity', 'host', 'path', 'detail', 'remediation'], ipc, label);
  return {
    title: requiredBoundedString(record.title, `${label}.title`, IPC_LIMITS.mediumTextBytes, ipc),
    severity: requiredBoundedString(record.severity, `${label}.severity`, IPC_LIMITS.shortTextBytes, ipc),
    host: requiredHost(record.host, `${label}.host`, ipc),
    path: requiredPath(record.path, `${label}.path`, ipc),
    detail: requiredBoundedString(record.detail, `${label}.detail`, IPC_LIMITS.rawTextBytes, ipc),
    remediation: requiredBoundedString(record.remediation, `${label}.remediation`, IPC_LIMITS.rawTextBytes, ipc),
  };
}

function validateRuntimeExchange(value: unknown, ipc: IpcChannelContract<unknown>, label: string) {
  const record = requiredObject(value, ipc, label);
  assertKnownKeys(record, ['id', 'method', 'host', 'path', 'url', 'status', 'length', 'mime', 'risk', 'timing', 'notes', 'source', 'time', 'requestRaw', 'responseRaw', 'tags'], ipc, label);
  return {
    id: requiredBoundedString(record.id, `${label}.id`, IPC_LIMITS.shortTextBytes, ipc),
    method: requiredBoundedString(record.method, `${label}.method`, IPC_LIMITS.shortTextBytes, ipc),
    host: requiredHost(record.host, `${label}.host`, ipc),
    path: requiredPath(record.path, `${label}.path`, ipc),
    url: requiredHttpUrl(record.url, `${label}.url`, ipc),
    status: requiredInteger(record.status, `${label}.status`, 0, 999, ipc),
    length: requiredInteger(record.length, `${label}.length`, 0, Number.MAX_SAFE_INTEGER, ipc),
    mime: requiredBoundedString(record.mime, `${label}.mime`, IPC_LIMITS.shortTextBytes, ipc),
    risk: requiredEnum(record.risk, ['critical', 'high', 'medium', 'low', 'info'], `${label}.risk`, ipc),
    timing: requiredInteger(record.timing, `${label}.timing`, 0, Number.MAX_SAFE_INTEGER, ipc),
    notes: requiredBoundedString(record.notes, `${label}.notes`, IPC_LIMITS.rawTextBytes, ipc),
    source: requiredBoundedString(record.source, `${label}.source`, IPC_LIMITS.shortTextBytes, ipc),
    time: requiredBoundedString(record.time, `${label}.time`, IPC_LIMITS.shortTextBytes, ipc),
    requestRaw: requiredBoundedString(record.requestRaw, `${label}.requestRaw`, IPC_LIMITS.rawTextBytes, ipc),
    responseRaw: requiredBoundedString(record.responseRaw, `${label}.responseRaw`, IPC_LIMITS.rawTextBytes, ipc),
    tags: requiredStringArray(record.tags, `${label}.tags`, 100, IPC_LIMITS.shortTextBytes, ipc),
  };
}

function validateRuntimeIssue(value: unknown, ipc: IpcChannelContract<unknown>, label: string) {
  const record = requiredObject(value, ipc, label);
  assertKnownKeys(record, ['id', 'title', 'severity', 'host', 'path', 'confidence', 'status', 'detail', 'remediation'], ipc, label);
  return stripUndefined({
    id: optionalBoundedString(record.id, `${label}.id`, IPC_LIMITS.shortTextBytes, ipc),
    title: requiredBoundedString(record.title, `${label}.title`, IPC_LIMITS.mediumTextBytes, ipc),
    severity: requiredEnum(record.severity, ['critical', 'high', 'medium', 'low', 'info'], `${label}.severity`, ipc),
    host: requiredHost(record.host, `${label}.host`, ipc),
    path: requiredPath(record.path, `${label}.path`, ipc),
    confidence: requiredEnum(record.confidence, ['certain', 'firm', 'tentative'], `${label}.confidence`, ipc),
    status: requiredEnum(record.status, ['open', 'triaged', 'false-positive', 'fixed'], `${label}.status`, ipc),
    detail: requiredBoundedString(record.detail, `${label}.detail`, IPC_LIMITS.rawTextBytes, ipc),
    remediation: requiredBoundedString(record.remediation, `${label}.remediation`, IPC_LIMITS.rawTextBytes, ipc),
  });
}

const activeScanCheckIds = [
  'security-headers',
  'cors-origin',
  'cache-key',
  'method-options',
  'authz-diff',
  'jwt-claims',
  'graphql-introspection',
  'oast-ssrf',
  'reflected-xss',
  'sql-injection',
  'path-traversal',
  'open-redirect',
  'command-injection',
] as const;

function validateReplaySettings(value: unknown, ipc: IpcChannelContract<unknown>, label: string) {
  const record = requiredObject(value, ipc, label);
  assertKnownKeys(record, ['redirectMode', 'maxRedirects', 'connectionMode', 'timeoutMs'], ipc, label);
  return {
    redirectMode: requiredEnum(record.redirectMode, ['manual', 'follow'], `${label}.redirectMode`, ipc),
    maxRedirects: requiredInteger(record.maxRedirects, `${label}.maxRedirects`, 0, 20, ipc),
    connectionMode: requiredEnum(record.connectionMode, ['default', 'close', 'keep-alive'], `${label}.connectionMode`, ipc),
    timeoutMs: requiredInteger(record.timeoutMs, `${label}.timeoutMs`, 100, 300_000, ipc),
  };
}

function validateCrawlAuditInsertionPoint(value: unknown, ipc: IpcChannelContract<unknown>, label: string) {
  const record = requiredObject(value, ipc, label);
  assertKnownKeys(record, ['id', 'routeId', 'type', 'name', 'method', 'url', 'evidence'], ipc, label);
  return {
    id: requiredBoundedString(record.id, `${label}.id`, IPC_LIMITS.shortTextBytes, ipc),
    routeId: requiredBoundedString(record.routeId, `${label}.routeId`, IPC_LIMITS.shortTextBytes, ipc),
    type: requiredEnum(record.type, ['query', 'form', 'path', 'cookie', 'header', 'body', 'json', 'xml', 'multipart', 'graphql'], `${label}.type`, ipc),
    name: requiredBoundedString(record.name, `${label}.name`, IPC_LIMITS.mediumTextBytes, ipc),
    method: requiredBoundedString(record.method, `${label}.method`, IPC_LIMITS.shortTextBytes, ipc),
    url: requiredHttpUrl(record.url, `${label}.url`, ipc),
    evidence: requiredBoundedString(record.evidence, `${label}.evidence`, IPC_LIMITS.rawTextBytes, ipc),
  };
}

function validateCallbackListenerProfile(value: unknown, ipc: IpcChannelContract<unknown>, label: string) {
  const record = requiredObject(value, ipc, label);
  assertKnownKeys(record, [
    'id',
    'name',
    'createdAt',
    'mode',
    'status',
    'host',
    'publicBaseUrl',
    'protocols',
    'httpPort',
    'dnsPort',
    'smtpPort',
    'pollIntervalSeconds',
    'retentionHours',
    'signingKeyId',
    'ciCommand',
    'healthChecks',
    'summary',
    'content',
  ], ipc, label);
  return {
    id: requiredBoundedString(record.id, `${label}.id`, IPC_LIMITS.shortTextBytes, ipc),
    name: requiredBoundedString(record.name, `${label}.name`, IPC_LIMITS.mediumTextBytes, ipc),
    createdAt: requiredIsoLike(record.createdAt, `${label}.createdAt`, ipc),
    mode: requiredEnum(record.mode, ['browser-preview', 'local-http', 'local-dns', 'local-smtp', 'hybrid-local'], `${label}.mode`, ipc),
    status: requiredEnum(record.status, ['planned', 'running', 'stopped', 'blocked'], `${label}.status`, ipc),
    host: requiredBindHost(record.host, `${label}.host`, ipc),
    publicBaseUrl: requiredHttpUrl(record.publicBaseUrl, `${label}.publicBaseUrl`, ipc),
    protocols: requiredEnumArray(record.protocols, `${label}.protocols`, ['dns', 'http', 'smtp'], 3, ipc),
    httpPort: requiredInteger(record.httpPort, `${label}.httpPort`, 0, 65535, ipc),
    dnsPort: requiredInteger(record.dnsPort, `${label}.dnsPort`, 0, 65535, ipc),
    smtpPort: requiredInteger(record.smtpPort, `${label}.smtpPort`, 0, 65535, ipc),
    pollIntervalSeconds: requiredInteger(record.pollIntervalSeconds, `${label}.pollIntervalSeconds`, 1, 86_400, ipc),
    retentionHours: requiredInteger(record.retentionHours, `${label}.retentionHours`, 1, 8760, ipc),
    signingKeyId: requiredBoundedString(record.signingKeyId, `${label}.signingKeyId`, IPC_LIMITS.mediumTextBytes, ipc),
    ciCommand: requiredBoundedString(record.ciCommand, `${label}.ciCommand`, IPC_LIMITS.rawTextBytes, ipc),
    healthChecks: requiredStringArray(record.healthChecks, `${label}.healthChecks`, 100, IPC_LIMITS.mediumTextBytes, ipc),
    summary: requiredBoundedString(record.summary, `${label}.summary`, IPC_LIMITS.rawTextBytes, ipc),
    content: requiredBoundedString(record.content, `${label}.content`, IPC_LIMITS.rawTextBytes, ipc),
  };
}

function validateCallbackPayloads(value: unknown, ipc: IpcChannelContract<unknown>, label: string) {
  return requiredArray(value, label, IPC_LIMITS.payloadItems, ipc).map((payload, index) => {
    const record = requiredObject(payload, ipc, `${label}[${index}]`);
    assertKnownKeys(record, ['id', 'token', 'label', 'protocol', 'endpoint', 'createdAt', 'status', 'sourceExchangeId', 'sourceHost', 'sourcePath', 'lastInteractionAt', 'notes'], ipc, `${label}[${index}]`);
    return stripUndefined({
      id: requiredBoundedString(record.id, `${label}[${index}].id`, IPC_LIMITS.shortTextBytes, ipc),
      token: requiredBoundedString(record.token, `${label}[${index}].token`, IPC_LIMITS.mediumTextBytes, ipc),
      label: requiredBoundedString(record.label, `${label}[${index}].label`, IPC_LIMITS.mediumTextBytes, ipc),
      protocol: requiredEnum(record.protocol, ['dns', 'http', 'smtp'], `${label}[${index}].protocol`, ipc),
      endpoint: requiredBoundedString(record.endpoint, `${label}[${index}].endpoint`, IPC_LIMITS.rawTextBytes, ipc),
      createdAt: requiredIsoLike(record.createdAt, `${label}[${index}].createdAt`, ipc),
      status: requiredEnum(record.status, ['waiting', 'observed', 'archived'], `${label}[${index}].status`, ipc),
      sourceExchangeId: optionalBoundedString(record.sourceExchangeId, `${label}[${index}].sourceExchangeId`, IPC_LIMITS.shortTextBytes, ipc),
      sourceHost: record.sourceHost === undefined ? undefined : requiredHost(record.sourceHost, `${label}[${index}].sourceHost`, ipc),
      sourcePath: record.sourcePath === undefined ? undefined : requiredPath(record.sourcePath, `${label}[${index}].sourcePath`, ipc),
      lastInteractionAt: record.lastInteractionAt === undefined ? undefined : requiredIsoLike(record.lastInteractionAt, `${label}[${index}].lastInteractionAt`, ipc),
      notes: requiredBoundedString(record.notes, `${label}[${index}].notes`, IPC_LIMITS.rawTextBytes, ipc),
    });
  });
}

function optionalOastPayloadReferences(value: unknown, label: string, ipc: IpcChannelContract<unknown>) {
  if (value === undefined) return undefined;
  return requiredArray(value, label, IPC_LIMITS.payloadItems, ipc).map((payload, index) => {
    const record = requiredObject(payload, ipc, `${label}[${index}]`);
    assertKnownKeys(record, ['id', 'token', 'endpoint', 'label', 'protocol'], ipc, `${label}[${index}]`);
    return stripUndefined({
      id: requiredBoundedString(record.id, `${label}[${index}].id`, IPC_LIMITS.shortTextBytes, ipc),
      token: requiredBoundedString(record.token, `${label}[${index}].token`, IPC_LIMITS.mediumTextBytes, ipc),
      endpoint: requiredBoundedString(record.endpoint, `${label}[${index}].endpoint`, IPC_LIMITS.rawTextBytes, ipc),
      label: optionalBoundedString(record.label, `${label}[${index}].label`, IPC_LIMITS.mediumTextBytes, ipc),
      protocol: record.protocol === undefined ? undefined : requiredEnum(record.protocol, ['http', 'dns', 'smtp'], `${label}[${index}].protocol`, ipc),
    });
  });
}

function validateStringRecord(value: unknown, label: string, ipc: IpcChannelContract<unknown>) {
  const record = boundedJsonRecord(value, label, IPC_LIMITS.jsonMaterialBytes, ipc);
  const entries = Object.entries(record);
  if (entries.length > 200) throw validation(ipc, `${label} must contain 200 entries or fewer`);
  return Object.fromEntries(entries.map(([key, item]) => [
    requiredBoundedString(key, `${label}.key`, IPC_LIMITS.mediumTextBytes, ipc),
    requiredBoundedString(item, `${label}.${key}`, IPC_LIMITS.rawTextBytes, ipc),
  ]));
}

function requiredObject(value: unknown, ipc: IpcChannelContract<unknown>, label: string): Record<string, unknown> {
  if (!isRecord(value)) throw validation(ipc, `${label} must be an object`);
  return value;
}

function objectOrDefault(value: unknown, fallback: Record<string, unknown>, ipc: IpcChannelContract<unknown>, label: string) {
  if (value === undefined || value === null) return fallback;
  return requiredObject(value, ipc, label);
}

function requiredArray(value: unknown, label: string, maxItems: number, ipc: IpcChannelContract<unknown>) {
  if (!Array.isArray(value)) throw validation(ipc, `${label} must be an array`);
  if (value.length > maxItems) throw validation(ipc, `${label} must contain ${maxItems} item(s) or fewer`);
  return value;
}

function assertKnownKeys(record: Record<string, unknown>, keys: string[], ipc: IpcChannelContract<unknown>, label: string) {
  const allowed = new Set(keys);
  const unknown = Object.keys(record).filter((key) => !allowed.has(key));
  if (unknown.length > 0) throw validation(ipc, `${label} contains unsupported field(s): ${unknown.join(', ')}`);
}

function requiredBoundedString(value: unknown, label: string, maxBytes: number, ipc: IpcChannelContract<unknown>) {
  if (typeof value !== 'string') throw validation(ipc, `${label} must be a string`);
  if (Buffer.byteLength(value, 'utf8') > maxBytes) throw validation(ipc, `${label} exceeds ${maxBytes} byte limit`);
  if (value.includes('\0')) throw validation(ipc, `${label} must not contain NUL bytes`);
  return value;
}

function optionalBoundedString(value: unknown, label: string, maxBytes: number, ipc: IpcChannelContract<unknown>) {
  if (value === undefined) return undefined;
  return requiredBoundedString(value, label, maxBytes, ipc);
}

function requiredStringArray(value: unknown, label: string, maxItems: number, maxItemBytes: number, ipc: IpcChannelContract<unknown>) {
  return requiredArray(value, label, maxItems, ipc).map((item, index) => requiredBoundedString(item, `${label}[${index}]`, maxItemBytes, ipc));
}

function optionalStringArray(value: unknown, label: string, maxItems: number, maxItemBytes: number, ipc: IpcChannelContract<unknown>) {
  if (value === undefined) return undefined;
  return requiredStringArray(value, label, maxItems, maxItemBytes, ipc);
}

function requiredScopeAllowlist(value: unknown, label: string, ipc: IpcChannelContract<unknown>) {
  const scopes = requiredStringArray(value, label, 200, IPC_LIMITS.mediumTextBytes, ipc).map((scope) => scope.trim()).filter(Boolean);
  if (scopes.length === 0) throw validation(ipc, `${label} must include at least one scope entry`);
  return scopes;
}

function optionalNestedStringArray(value: unknown, label: string, maxSets: number, maxItems: number, maxItemBytes: number, ipc: IpcChannelContract<unknown>) {
  if (value === undefined) return undefined;
  return requiredArray(value, label, maxSets, ipc).map((set, index) => requiredStringArray(set, `${label}[${index}]`, maxItems, maxItemBytes, ipc));
}

function requiredEnumArray<const T extends string>(value: unknown, label: string, allowed: readonly T[], maxItems: number, ipc: IpcChannelContract<unknown>) {
  return requiredArray(value, label, maxItems, ipc).map((item, index) => requiredEnum(item, allowed, `${label}[${index}]`, ipc));
}

function optionalEnumArray<const T extends string>(value: unknown, label: string, allowed: readonly T[], maxItems: number, ipc: IpcChannelContract<unknown>) {
  if (value === undefined) return undefined;
  return requiredEnumArray(value, label, allowed, maxItems, ipc);
}

function requiredBoolean(value: unknown, label: string, ipc: IpcChannelContract<unknown>) {
  if (typeof value !== 'boolean') throw validation(ipc, `${label} must be a boolean`);
  return value;
}

function optionalBoolean(value: unknown, label: string, ipc: IpcChannelContract<unknown>) {
  if (value === undefined) return undefined;
  return requiredBoolean(value, label, ipc);
}

function requiredInteger(value: unknown, label: string, min: number, max: number, ipc: IpcChannelContract<unknown>): number {
  if (!Number.isInteger(value)) throw validation(ipc, `${label} must be an integer`);
  const numeric = Number(value);
  if (numeric < min || numeric > max) throw validation(ipc, `${label} must be between ${min} and ${max}`);
  return numeric;
}

function optionalInteger(value: unknown, label: string, min: number, max: number, ipc: IpcChannelContract<unknown>): number | undefined {
  if (value === undefined) return undefined;
  return requiredInteger(value, label, min, max, ipc);
}

function optionalNumber(value: unknown, label: string, min: number, max: number, ipc: IpcChannelContract<unknown>): number | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== 'number' || !Number.isFinite(value)) throw validation(ipc, `${label} must be a finite number`);
  if (value < min || value > max) throw validation(ipc, `${label} must be between ${min} and ${max}`);
  return value;
}

function requiredEnum<const T extends string>(value: unknown, allowed: readonly T[], label: string, ipc: IpcChannelContract<unknown>): T {
  if (typeof value !== 'string' || !allowed.includes(value as T)) throw validation(ipc, `${label} must be one of ${allowed.join(', ')}`);
  return value as T;
}

function requiredIsoLike(value: unknown, label: string, ipc: IpcChannelContract<unknown>) {
  const text = requiredBoundedString(value, label, IPC_LIMITS.shortTextBytes, ipc);
  if (Number.isNaN(Date.parse(text))) throw validation(ipc, `${label} must be a parseable timestamp`);
  return text;
}

function requiredHost(value: unknown, label: string, ipc: IpcChannelContract<unknown>) {
  const text = requiredBoundedString(value, label, IPC_LIMITS.mediumTextBytes, ipc).trim();
  if (!text || /[\s/\\]/.test(text)) throw validation(ipc, `${label} must be a host name or address`);
  return text;
}

function requiredBindHost(value: unknown, label: string, ipc: IpcChannelContract<unknown>) {
  const text = requiredHost(value, label, ipc);
  if (!/^(localhost|127(?:\.\d{1,3}){3}|::1|\[::1\])$/i.test(text)) {
    throw validation(ipc, `${label} must bind to a loopback interface`);
  }
  return text;
}

function requiredPath(value: unknown, label: string, ipc: IpcChannelContract<unknown>) {
  const text = requiredBoundedString(value, label, IPC_LIMITS.rawTextBytes, ipc);
  if (!text.startsWith('/')) throw validation(ipc, `${label} must start with /`);
  if (text.includes('\0')) throw validation(ipc, `${label} must not contain NUL bytes`);
  return text;
}

function requiredHttpUrl(value: unknown, label: string, ipc: IpcChannelContract<unknown>) {
  const text = requiredBoundedString(value, label, IPC_LIMITS.rawTextBytes, ipc);
  try {
    const url = new URL(text);
    if (!['http:', 'https:'].includes(url.protocol)) throw new Error('unsupported protocol');
  } catch {
    throw validation(ipc, `${label} must be an http(s) URL`);
  }
  return text;
}

function optionalHttpEndpoint(value: unknown, label: string, ipc: IpcChannelContract<unknown>) {
  if (value === undefined || value === '') return undefined;
  const text = requiredBoundedString(value, label, IPC_LIMITS.rawTextBytes, ipc);
  try {
    const url = new URL(text);
    if (!['http:', 'https:'].includes(url.protocol)) throw new Error('unsupported protocol');
  } catch {
    throw validation(ipc, `${label} must be an http(s) URL`);
  }
  return text;
}

function optionalCommand(value: unknown, label: string, ipc: IpcChannelContract<unknown>) {
  if (value === undefined || value === '') return undefined;
  const text = requiredBoundedString(value, label, IPC_LIMITS.mediumTextBytes, ipc).trim();
  if (!text || /[;&|<>`$]/.test(text)) throw validation(ipc, `${label} must be an executable path or name, not a shell expression`);
  return text;
}

function optionalEnvName(value: unknown, label: string, ipc: IpcChannelContract<unknown>) {
  if (value === undefined || value === '') return undefined;
  const text = requiredBoundedString(value, label, IPC_LIMITS.shortTextBytes, ipc);
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(text)) throw validation(ipc, `${label} must be an environment variable name`);
  return text;
}

function optionalProjectId(value: unknown, label: string, ipc: IpcChannelContract<unknown>) {
  if (value === undefined) return undefined;
  const text = requiredBoundedString(value, label, IPC_LIMITS.shortTextBytes, ipc);
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$/.test(text)) throw validation(ipc, `${label} contains unsupported characters`);
  return text;
}

function requiredProjectRoot(value: unknown, label: string, ipc: IpcChannelContract<unknown>) {
  const text = requiredBoundedString(value, label, IPC_LIMITS.rawTextBytes, ipc).trim();
  validateProjectRootText(text, label, ipc, true);
  return text;
}

function optionalProjectRoot(value: unknown, label: string, ipc: IpcChannelContract<unknown>, requireSuffix = true) {
  if (value === undefined || value === '') return undefined;
  const text = requiredBoundedString(value, label, IPC_LIMITS.rawTextBytes, ipc).trim();
  validateProjectRootText(text, label, ipc, requireSuffix);
  return text;
}

function validateProjectRootText(text: string, label: string, ipc: IpcChannelContract<unknown>, requireSuffix: boolean) {
  if (!text) throw validation(ipc, `${label} is required`);
  if (text.includes('\0')) throw validation(ipc, `${label} must not contain NUL bytes`);
  if (text.split(/[\\/]+/).includes('..')) throw validation(ipc, `${label} must not contain path traversal segments`);
  if (requireSuffix && !/\.proxyforge(?:-backup)?$/i.test(text)) throw validation(ipc, `${label} must end with .proxyforge`);
}

function boundedJsonRecord(value: unknown, label: string, maxBytes: number, ipc: IpcChannelContract<unknown>) {
  if (!isRecord(value)) throw validation(ipc, `${label} must be an object`);
  const serialized = JSON.stringify(value);
  if (Buffer.byteLength(serialized, 'utf8') > maxBytes) throw validation(ipc, `${label} exceeds ${maxBytes} byte limit`);
  return value;
}

function stripUndefined<T extends Record<string, unknown>>(record: T): T {
  return Object.fromEntries(Object.entries(record).filter(([, value]) => value !== undefined)) as T;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function validation(ipc: Pick<IpcChannelContract<unknown>, 'channel' | 'capability' | 'dangerLevel'>, detail: string) {
  return new IpcValidationError(ipc, [detail]);
}
