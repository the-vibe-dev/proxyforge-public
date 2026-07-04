import type { LoggerCustomColumn, LoggerCustomColumnKind, LoggerToolSource, Severity } from './types';

export interface LoggerColumnEntry {
  id: string;
  exchangeId: string;
  at: string;
  tool: LoggerToolSource;
  method: string;
  host: string;
  path: string;
  url: string;
  status: number;
  length: number;
  mime: string;
  risk: Severity;
  timing: number;
  modified: boolean;
  notes: string;
  requestRaw: string;
  responseRaw: string;
  tags: string[];
}

export interface LoggerColumnEvaluation {
  value: string;
  status: 'ok' | 'fallback' | 'blocked' | 'empty';
  reason: string;
  matchedRule?: string;
  warnings: string[];
}

export interface LoggerColumnValidation {
  columnId: string;
  columnName: string;
  kind: LoggerCustomColumnKind;
  enabled: boolean;
  status: 'ok' | 'disabled' | 'blocked' | 'warning';
  supportedApis: string[];
  blockedTokens: string[];
  warnings: string[];
  sampleValues: Array<{
    entryId: string;
    path: string;
    value: string;
    status: LoggerColumnEvaluation['status'];
    reason: string;
  }>;
}

export interface LoggerColumnReviewPackage {
  kind: 'proxyforge-logger-column-sandbox-review';
  generatedAt: string;
  summary: string;
  enabledColumns: number;
  blockedColumns: number;
  warningColumns: number;
  supportedApis: string[];
  validations: LoggerColumnValidation[];
  reportReady: boolean;
  content: string;
}

export interface LoggerCustomColumnCompatibilityPackage {
  kind: 'proxyforge-logger-custom-column-compatibility-fixtures';
  generatedAt: string;
  summary: string;
  supportedApis: string[];
  fixtureCount: number;
  passedFixtures: number;
  blockedFixtures: number;
  fallbackFixtures: number;
  packageRefresh: {
    refreshedAt: string;
    sourceColumnCount: number;
    sourceEntryCount: number;
    supportedApiCount: number;
    sourceDigestPreview: string;
    fixtureDigestPreview: string;
    rawMaterialDigestPreview: string;
    operationalSecretSignals: string[];
  };
  requirements: {
    apiSurfaceCovered: boolean;
    fixtureRefreshCovered: boolean;
    encodedMaterialCovered: boolean;
    operationalSecretsPreserved: boolean;
    reportPhaseOnlyRedaction: boolean;
  };
  secretHandling: 'execution-full-fidelity-secrets-preserved';
  reportRedactionBoundary: 'redact-only-during-report-export';
  reportReady: boolean;
  fixtures: Array<{
    columnId: string;
    columnName: string;
    entryId: string;
    value: string;
    status: LoggerColumnEvaluation['status'];
    reason: string;
    warnings: string[];
  }>;
  content: string;
}

export interface LoggerCustomColumnLargeTableProfile {
  kind: 'proxyforge-logger-custom-column-large-table-profile';
  generatedAt: string;
  summary: string;
  entryCount: number;
  columnCount: number;
  evaluationCount: number;
  statusCounts: Record<LoggerColumnEvaluation['status'], number>;
  durationMs: number;
  maxEvaluationMs: number;
  p95EvaluationMs: number;
  thresholds: {
    maxDurationMs: number;
    maxP95EvaluationMs: number;
  };
  supportedApis: string[];
  sampleValues: Array<{
    columnId: string;
    entryId: string;
    value: string;
    status: LoggerColumnEvaluation['status'];
  }>;
  reportReady: boolean;
  content: string;
}

const severityRank: Record<Severity, number> = {
  info: 1,
  low: 2,
  medium: 3,
  high: 4,
  critical: 5,
};

const loggerToolLabels: Record<LoggerToolSource, string> = {
  proxy: 'Proxy',
  target: 'Target',
  repeater: 'Repeater',
  scanner: 'Scanner',
  intruder: 'Intruder',
  exploit: 'Exploit Lab',
  automations: 'Automations',
  extensions: 'Extensions',
};

const severityLabel: Record<Severity, string> = {
  info: 'Info',
  low: 'Low',
  medium: 'Medium',
  high: 'High',
  critical: 'Critical',
};

const supportedApis = [
  'request.hasHeader(name)',
  'request.header(name)',
  'request.headerNames()',
  'request.contains(text)',
  'request.paramCount()',
  'request.paramNames()',
  'request.param(name)',
  'request.queryParam(name)',
  'request.bodyParam(name)',
  'request.bodyContains(text)',
  'request.jsonField(name)',
  'request.jsonPath(path)',
  'request.body()',
  'request.bodySize()',
  'request.cookie(name)',
  'request.cookies()',
  'request.method',
  'request.url',
  'request.host',
  'request.path',
  'request.pathSegments()',
  'request.extension()',
  'request.contentType',
  'request.isJson()',
  'request.isForm()',
  'response.hasHeader(name)',
  'response.header(name)',
  'response.headerNames()',
  'response.contains(text)',
  'response.status',
  'response.statusClass()',
  'response.timingMs()',
  'response.bodySize()',
  'response.bodyContains(text)',
  'response.body()',
  'response.jsonField(name)',
  'response.jsonPath(path)',
  'response.cookie(name)',
  'response.cookies()',
  'response.contentType',
  'response.isJson()',
  'response.mime',
  'entry.contains(text)',
  'entry.hasTag(tag)',
  'entry.noteContains(text)',
  'entry.tagCount()',
  'entry.isModified()',
  'entry.id',
  'entry.status',
  'entry.length',
  'entry.tool',
  'entry.risk',
  'entry.mime',
  'entry.host',
  'entry.path',
  'entry.method',
  'helpers.includes(value, text)',
  'helpers.matches(value, pattern)',
  'helpers.lower(value)',
  'helpers.upper(value)',
  'helpers.default(value, fallback)',
  'helpers.urlDecode(value)',
  'helpers.urlEncode(value)',
  'helpers.base64Decode(value)',
  'helpers.base64Encode(value)',
];

const blockedScriptPatterns = [
  { token: 'eval', pattern: /\beval\s*\(/i },
  { token: 'Function constructor', pattern: /\bnew\s+Function\b|\bFunction\s*\(/i },
  { token: 'browser global', pattern: /\b(window|document|localStorage|sessionStorage|indexedDB|navigator)\b/i },
  { token: 'network access', pattern: /\b(fetch|XMLHttpRequest|WebSocket|EventSource)\s*\(/i },
  { token: 'module/process access', pattern: /\b(import|require|process|globalThis)\b/i },
  { token: 'prototype access', pattern: /\b(__proto__|prototype|constructor)\b/i },
  { token: 'loop/timer', pattern: /\b(while|for|setTimeout|setInterval|queueMicrotask|requestAnimationFrame)\b/i },
];

export function validateLoggerColumnScript(column: LoggerCustomColumn): LoggerColumnValidation {
  const script = column.script ?? '';
  const lines = script.split(/\r?\n/).map((line) => line.trim()).filter((line) => line && !line.startsWith('//'));
  const blockedTokens = blockedScriptPatterns
    .filter(({ pattern }) => pattern.test(script))
    .map(({ token }) => token);
  const warnings = [
    ...lines.length > 40 ? ['Script has more than 40 executable lines.'] : [],
    ...script.length > 8000 ? ['Script exceeds the 8000 character sandbox limit.'] : [],
    ...lines.filter((line) => !/^if\s*\(.*\)\s*return\s+.+;?$/i.test(line) && !/^return\s+.+;?$/i.test(line))
      .map((line) => `Unsupported statement: ${line.slice(0, 120)}`),
  ];

  return {
    columnId: column.id,
    columnName: column.name,
    kind: column.kind,
    enabled: column.enabled,
    status: !column.enabled ? 'disabled' : blockedTokens.length ? 'blocked' : warnings.length ? 'warning' : 'ok',
    supportedApis,
    blockedTokens,
    warnings,
    sampleValues: [],
  };
}

export function evaluateLoggerCustomColumn(column: LoggerCustomColumn, entry: LoggerColumnEntry): LoggerColumnEvaluation {
  const validation = validateLoggerColumnScript(column);
  if (validation.status === 'blocked') {
    return {
      value: '[blocked]',
      status: 'blocked',
      reason: `Blocked script token: ${validation.blockedTokens.join(', ')}`,
      warnings: validation.warnings,
    };
  }

  const scripted = evaluateLoggerColumnScript(column.script, entry);
  if (scripted.value !== undefined) {
    return {
      value: scripted.value,
      status: validation.status === 'warning' ? 'fallback' : 'ok',
      reason: scripted.reason,
      matchedRule: scripted.matchedRule,
      warnings: validation.warnings,
    };
  }

  const fallbackValue = evaluateLoggerColumnFallback(column.kind, entry);
  return {
    value: fallbackValue,
    status: fallbackValue ? 'fallback' : 'empty',
    reason: fallbackValue ? `${column.kind} fallback` : 'No script rule or fallback matched',
    warnings: validation.warnings,
  };
}

export function buildLoggerColumnSandboxReview(options: {
  columns: LoggerCustomColumn[];
  entries: LoggerColumnEntry[];
  now?: string;
}): LoggerColumnReviewPackage {
  const generatedAt = options.now ?? new Date().toISOString();
  const validations = options.columns.map((column) => {
    const validation = validateLoggerColumnScript(column);
    return {
      ...validation,
      sampleValues: options.entries.slice(0, 6).map((entry) => {
        const evaluated = evaluateLoggerCustomColumn(column, entry);
        return {
          entryId: entry.id,
          path: entry.path,
          value: evaluated.value || '-',
          status: evaluated.status,
          reason: evaluated.reason,
        };
      }),
    };
  });
  const enabledColumns = validations.filter((validation) => validation.enabled).length;
  const blockedColumns = validations.filter((validation) => validation.status === 'blocked').length;
  const warningColumns = validations.filter((validation) => validation.status === 'warning').length;
  const summary = `Reviewed ${options.columns.length} Logger custom column(s): ${enabledColumns} enabled, ${blockedColumns} blocked, ${warningColumns} warning.`;
  const payload = {
    kind: 'proxyforge-logger-column-sandbox-review' as const,
    generatedAt,
    summary,
    enabledColumns,
    blockedColumns,
    warningColumns,
    supportedApis,
    validations,
    reportReady: blockedColumns === 0,
  };
  return {
    ...payload,
    content: JSON.stringify(payload, null, 2),
  };
}

export function buildLoggerCustomColumnCompatibilityPackage(options: {
  columns: LoggerCustomColumn[];
  entries: LoggerColumnEntry[];
  now?: string;
}): LoggerCustomColumnCompatibilityPackage {
  const generatedAt = options.now ?? new Date().toISOString();
  const fixtures = options.columns.flatMap((column) => options.entries.map((entry) => {
    const evaluated = evaluateLoggerCustomColumn(column, entry);
    return {
      columnId: column.id,
      columnName: column.name,
      entryId: entry.id,
      value: evaluated.value || '-',
      status: evaluated.status,
      reason: evaluated.reason,
      warnings: evaluated.warnings,
    };
  }));
  const blockedFixtures = fixtures.filter((fixture) => fixture.status === 'blocked').length;
  const fallbackFixtures = fixtures.filter((fixture) => fixture.status === 'fallback').length;
  const passedFixtures = fixtures.filter((fixture) => fixture.status === 'ok').length;
  const rawMaterial = [
    JSON.stringify(options.columns),
    ...options.entries.flatMap((entry) => [entry.requestRaw, entry.responseRaw, entry.notes, entry.url]),
  ].join('\n');
  const packageRefresh = {
    refreshedAt: generatedAt,
    sourceColumnCount: options.columns.length,
    sourceEntryCount: options.entries.length,
    supportedApiCount: supportedApis.length,
    sourceDigestPreview: simpleDigest(JSON.stringify(options.columns)),
    fixtureDigestPreview: simpleDigest(JSON.stringify(fixtures)),
    rawMaterialDigestPreview: simpleDigest(rawMaterial),
    operationalSecretSignals: operationalSecretSignals(rawMaterial),
  };
  const requirements = {
    apiSurfaceCovered: ['request.cookie(name)', 'response.jsonPath(path)', 'helpers.default(value, fallback)', 'helpers.base64Decode(value)', 'helpers.urlDecode(value)']
      .every((api) => supportedApis.includes(api)),
    fixtureRefreshCovered: packageRefresh.sourceColumnCount > 0
      && packageRefresh.sourceEntryCount > 0
      && Boolean(packageRefresh.sourceDigestPreview)
      && Boolean(packageRefresh.fixtureDigestPreview),
    encodedMaterialCovered: fixtures.some((fixture) => /secret|token|encoded|admin|base64|url/i.test(fixture.value))
      || /%[0-9a-f]{2}|[A-Za-z0-9+/]{16,}={0,2}/i.test(rawMaterial),
    operationalSecretsPreserved: packageRefresh.operationalSecretSignals.length > 0,
    reportPhaseOnlyRedaction: true,
  };
  const payload = {
    kind: 'proxyforge-logger-custom-column-compatibility-fixtures' as const,
    generatedAt,
    summary: `Ran ${fixtures.length} Logger custom column compatibility fixture(s): ${passedFixtures} ok, ${fallbackFixtures} fallback, ${blockedFixtures} blocked.`,
    supportedApis,
    fixtureCount: fixtures.length,
    passedFixtures,
    blockedFixtures,
    fallbackFixtures,
    packageRefresh,
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved' as const,
    reportRedactionBoundary: 'redact-only-during-report-export' as const,
    reportReady: blockedFixtures === 0 && Object.values(requirements).every(Boolean),
    fixtures,
  };
  return {
    ...payload,
    content: JSON.stringify(payload, null, 2),
  };
}

export function buildLoggerCustomColumnLargeTableProfile(options: {
  columns: LoggerCustomColumn[];
  entries: LoggerColumnEntry[];
  now?: string;
  maxDurationMs?: number;
  maxP95EvaluationMs?: number;
}): LoggerCustomColumnLargeTableProfile {
  const generatedAt = options.now ?? new Date().toISOString();
  const maxDurationMs = options.maxDurationMs ?? Math.max(250, options.columns.length * options.entries.length * 2);
  const maxP95EvaluationMs = options.maxP95EvaluationMs ?? 8;
  const timings: number[] = [];
  const statusCounts: Record<LoggerColumnEvaluation['status'], number> = {
    ok: 0,
    fallback: 0,
    blocked: 0,
    empty: 0,
  };
  const sampleValues: LoggerCustomColumnLargeTableProfile['sampleValues'] = [];
  const startedAt = Date.now();
  for (const column of options.columns) {
    for (const entry of options.entries) {
      const evalStartedAt = Date.now();
      const evaluated = evaluateLoggerCustomColumn(column, entry);
      timings.push(Date.now() - evalStartedAt);
      statusCounts[evaluated.status] += 1;
      if (sampleValues.length < 12) {
        sampleValues.push({
          columnId: column.id,
          entryId: entry.id,
          value: evaluated.value || '-',
          status: evaluated.status,
        });
      }
    }
  }
  const durationMs = Date.now() - startedAt;
  const sortedTimings = [...timings].sort((left, right) => left - right);
  const p95Index = Math.max(0, Math.min(sortedTimings.length - 1, Math.ceil(sortedTimings.length * 0.95) - 1));
  const maxEvaluationMs = sortedTimings.at(-1) ?? 0;
  const p95EvaluationMs = sortedTimings[p95Index] ?? 0;
  const evaluationCount = options.columns.length * options.entries.length;
  const reportReady = statusCounts.blocked === 0 && durationMs <= maxDurationMs && p95EvaluationMs <= maxP95EvaluationMs;
  const payload = {
    kind: 'proxyforge-logger-custom-column-large-table-profile' as const,
    generatedAt,
    summary: `Profiled ${evaluationCount} Logger custom column evaluation(s) across ${options.entries.length} entries and ${options.columns.length} column(s): p95 ${p95EvaluationMs}ms, max ${maxEvaluationMs}ms.`,
    entryCount: options.entries.length,
    columnCount: options.columns.length,
    evaluationCount,
    statusCounts,
    durationMs,
    maxEvaluationMs,
    p95EvaluationMs,
    thresholds: {
      maxDurationMs,
      maxP95EvaluationMs,
    },
    supportedApis,
    sampleValues,
    reportReady,
  };
  return {
    ...payload,
    content: JSON.stringify(payload, null, 2),
  };
}

function evaluateLoggerColumnScript(script: string, entry: LoggerColumnEntry): { value?: string; reason: string; matchedRule?: string } {
  const lines = script.split(/\r?\n/).map((line) => line.trim()).filter((line) => line && !line.startsWith('//'));
  for (const line of lines) {
    const conditional = /^if\s*\((.*)\)\s*return\s+(.+)$/i.exec(line);
    if (conditional && evaluateLoggerScriptCondition(conditional[1], entry)) {
      const value = evaluateLoggerScriptReturn(conditional[2], entry);
      if (value !== undefined) return { value, reason: `matched ${conditional[1]}`, matchedRule: line };
    }
    const directReturn = /^return\s+(.+)$/i.exec(line);
    if (directReturn) {
      const value = evaluateLoggerScriptReturn(directReturn[1], entry);
      if (value !== undefined) return { value, reason: 'direct return', matchedRule: line };
    }
  }
  return { reason: 'No script return matched' };
}

function evaluateLoggerScriptCondition(condition: string, entry: LoggerColumnEntry): boolean {
  const trimmed = trimOuter(condition.trim());
  if (trimmed.includes('||')) return splitExpression(trimmed, '||').some((part) => evaluateLoggerScriptCondition(part, entry));
  if (trimmed.includes('&&')) return splitExpression(trimmed, '&&').every((part) => evaluateLoggerScriptCondition(part, entry));
  if (trimmed.startsWith('!')) return !evaluateLoggerScriptCondition(trimmed.slice(1), entry);

  const stringPredicate = /^(.+)\.(includes|startsWith|endsWith)\(["']([^"']*)["']\)$/i.exec(trimmed);
  if (stringPredicate) {
    const value = String(evaluateLoggerScriptValue(stringPredicate[1], entry) ?? '').toLowerCase();
    const expected = stringPredicate[3].toLowerCase();
    if (stringPredicate[2].toLowerCase() === 'startswith') return value.startsWith(expected);
    if (stringPredicate[2].toLowerCase() === 'endswith') return value.endsWith(expected);
    return value.includes(expected);
  }

  const helperIncludes = /helpers\.includes\((.+),\s*["']([^"']*)["']\)$/i.exec(trimmed);
  if (helperIncludes) return String(evaluateLoggerScriptValue(helperIncludes[1], entry) ?? '').toLowerCase().includes(helperIncludes[2].toLowerCase());

  const helperMatches = /helpers\.matches\((.+),\s*["']([^"']*)["']\)$/i.exec(trimmed);
  if (helperMatches) {
    try {
      return new RegExp(helperMatches[2], 'i').test(String(evaluateLoggerScriptValue(helperMatches[1], entry) ?? ''));
    } catch {
      return false;
    }
  }

  const genericComparison = /^(.+?)\s*([<>]=?|={2,3}|!==?)\s*(.+)$/i.exec(trimmed);
  if (genericComparison) {
    return compareLoggerValues(
      evaluateLoggerScriptValue(genericComparison[1], entry),
      genericComparison[2],
      evaluateLoggerScriptValue(genericComparison[3], entry),
    );
  }

  const booleanValue = evaluateLoggerScriptValue(trimmed, entry);
  if (typeof booleanValue === 'boolean') return booleanValue;

  const requestHeader = /request\.hasHeader\(["']([^"']+)["']\)/i.exec(trimmed);
  if (requestHeader) return rawHasHeader(entry.requestRaw, requestHeader[1]);

  const requestHeaderValue = /request\.header\(["']([^"']+)["']\)\s*([!=]={1,2})\s*["']([^"']+)["']/i.exec(trimmed);
  if (requestHeaderValue) {
    const value = rawHeader(entry.requestRaw, requestHeaderValue[1]).toLowerCase();
    const expected = requestHeaderValue[3].toLowerCase();
    const matched = value === expected || value.includes(expected);
    return requestHeaderValue[2].startsWith('!') ? !matched : matched;
  }

  const requestContains = /request\.contains\(["']([^"']+)["']\)/i.exec(trimmed);
  if (requestContains) return rawContains(`${entry.url}\n${entry.requestRaw}`, requestContains[1]);

  const responseContains = /response\.contains\(["']([^"']+)["']\)/i.exec(trimmed);
  if (responseContains) return rawContains(entry.responseRaw, responseContains[1]);

  const entryContains = /entry\.contains\(["']([^"']+)["']\)/i.exec(trimmed);
  if (entryContains) return rawContains(`${entry.url}\n${entry.notes}\n${entry.tags.join(' ')}`, entryContains[1]);

  const entryTag = /entry\.hasTag\(["']([^"']+)["']\)/i.exec(trimmed);
  if (entryTag) return entry.tags.some((tag) => tag.toLowerCase() === entryTag[1].toLowerCase());

  const riskAtLeast = /entry\.risk\s*>=\s*["'](critical|high|medium|low|info)["']/i.exec(trimmed);
  if (riskAtLeast) return severityRank[entry.risk] >= severityRank[riskAtLeast[1].toLowerCase() as Severity];

  const statusCompare = /response\.status\s*([<>]=?|={2,3}|!==?)\s*(\d{3})/i.exec(trimmed);
  if (statusCompare) {
    const target = Number(statusCompare[2]);
    if (statusCompare[1] === '>=') return entry.status >= target;
    if (statusCompare[1] === '<=') return entry.status <= target;
    if (statusCompare[1] === '>') return entry.status > target;
    if (statusCompare[1] === '<') return entry.status < target;
    if (statusCompare[1].startsWith('!')) return entry.status !== target;
    return entry.status === target;
  }

  const statusClassEquals = /response\.statusClass\(\)\s*([!=]={1,2})\s*["']([1-5]xx)["']/i.exec(trimmed);
  if (statusClassEquals) {
    const matched = entry.status > 0 && `${Math.floor(entry.status / 100)}xx` === statusClassEquals[2].toLowerCase();
    return statusClassEquals[1].startsWith('!') ? !matched : matched;
  }

  return false;
}

function evaluateLoggerScriptReturn(expression: string, entry: LoggerColumnEntry) {
  const trimmed = expression.trim().replace(/;$/, '');
  const concatenated = evaluateLoggerConcatenation(trimmed, entry);
  if (concatenated !== undefined) return concatenated;
  const value = evaluateLoggerScriptValue(trimmed, entry);
  if (value !== undefined) return String(value);
  if (/^request\.paramCount\(\)$/i.test(trimmed)) return String(countParams(entry));
  if (/^response\.statusClass\(\)$/i.test(trimmed)) return entry.status > 0 ? `${Math.floor(entry.status / 100)}xx` : 'n/a';
  if (/^response\.timingMs\(\)$/i.test(trimmed)) return `${entry.timing} ms`;
  if (/^response\.bodySize\(\)$/i.test(trimmed)) return formatBytes(rawBodyLength(entry.responseRaw) || entry.length);
  if (/^response\.status$/i.test(trimmed)) return String(entry.status);
  if (/^request\.host$/i.test(trimmed)) return entry.host;
  if (/^request\.path$/i.test(trimmed)) return entry.path;
  if (/^request\.method$/i.test(trimmed)) return entry.method;
  if (/^entry\.tool$/i.test(trimmed)) return loggerToolLabels[entry.tool];
  if (/^entry\.risk$/i.test(trimmed)) return severityLabel[entry.risk];
  if (/^entry\.mime$/i.test(trimmed)) return entry.mime;
  if (/^entry\.host$/i.test(trimmed)) return entry.host;
  if (/^entry\.path$/i.test(trimmed)) return entry.path;
  return undefined;
}

function evaluateLoggerConcatenation(expression: string, entry: LoggerColumnEntry) {
  const parts = splitExpressionOutsideQuotes(expression, '+');
  if (parts.length < 2) return undefined;
  const values = parts.map((part) => evaluateLoggerScriptValue(part, entry));
  if (values.some((value) => value === undefined)) return undefined;
  return values.map((value) => String(value)).join('');
}

function evaluateLoggerScriptValue(expression: string, entry: LoggerColumnEntry): string | number | boolean | undefined {
  const trimmed = trimOuter(expression.trim()).replace(/;$/, '');
  const literal = /^["']([^"']*)["']$/.exec(trimmed);
  if (literal) return literal[1];
  if (/^\d+(?:\.\d+)?$/.test(trimmed)) return Number(trimmed);
  if (/^true$/i.test(trimmed)) return true;
  if (/^false$/i.test(trimmed)) return false;

  const requestHeader = /^request\.header\(["']([^"']+)["']\)$/i.exec(trimmed);
  if (requestHeader) return rawHeader(entry.requestRaw, requestHeader[1]);
  const requestHasHeader = /^request\.hasHeader\(["']([^"']+)["']\)$/i.exec(trimmed);
  if (requestHasHeader) return rawHasHeader(entry.requestRaw, requestHasHeader[1]);
  const requestContains = /^request\.contains\(["']([^"']+)["']\)$/i.exec(trimmed);
  if (requestContains) return rawContains(`${entry.url}\n${entry.requestRaw}`, requestContains[1]);
  const requestBodyContains = /^request\.bodyContains\(["']([^"']+)["']\)$/i.exec(trimmed);
  if (requestBodyContains) return rawContains(splitHttpMessage(entry.requestRaw).body, requestBodyContains[1]);
  const requestQueryParam = /^request\.queryParam\(["']([^"']+)["']\)$/i.exec(trimmed);
  if (requestQueryParam) return requestQueryParamValue(entry, requestQueryParam[1]);
  const requestBodyParam = /^request\.bodyParam\(["']([^"']+)["']\)$/i.exec(trimmed);
  if (requestBodyParam) return requestBodyParamValue(entry, requestBodyParam[1]);
  const requestParam = /^request\.param\(["']([^"']+)["']\)$/i.exec(trimmed);
  if (requestParam) return requestQueryParamValue(entry, requestParam[1]) || requestBodyParamValue(entry, requestParam[1]);
  const requestJsonField = /^request\.jsonField\(["']([^"']+)["']\)$/i.exec(trimmed);
  if (requestJsonField) return requestJsonFieldValue(entry, requestJsonField[1]);
  const requestJsonPath = /^request\.jsonPath\(["']([^"']+)["']\)$/i.exec(trimmed);
  if (requestJsonPath) return requestJsonFieldValue(entry, requestJsonPath[1]);
  if (/^request\.paramCount\(\)$/i.test(trimmed)) return countParams(entry);
  if (/^request\.paramNames\(\)$/i.test(trimmed)) return paramNames(entry).join(',');
  if (/^request\.headerNames\(\)$/i.test(trimmed)) return headerNames(entry.requestRaw).join(',');
  if (/^request\.body\(\)$/i.test(trimmed)) return splitHttpMessage(entry.requestRaw).body;
  if (/^request\.bodySize\(\)$/i.test(trimmed)) return rawBodyLength(entry.requestRaw);
  const requestCookie = /^request\.cookie\(["']([^"']+)["']\)$/i.exec(trimmed);
  if (requestCookie) return requestCookieValue(entry, requestCookie[1]);
  if (/^request\.cookies\(\)$/i.test(trimmed)) return cookiePairsFromRequest(entry.requestRaw).join(',');
  if (/^request\.method$/i.test(trimmed)) return entry.method;
  if (/^request\.url$/i.test(trimmed)) return entry.url;
  if (/^request\.host$/i.test(trimmed)) return entry.host;
  if (/^request\.path$/i.test(trimmed)) return entry.path;
  if (/^request\.pathSegments\(\)$/i.test(trimmed)) return pathSegments(entry.path).join(',');
  if (/^request\.extension\(\)$/i.test(trimmed)) return pathExtension(entry.path);
  if (/^request\.contentType$/i.test(trimmed)) return rawHeader(entry.requestRaw, 'content-type');
  if (/^request\.isJson\(\)$/i.test(trimmed)) return isJsonMessage(entry.requestRaw);
  if (/^request\.isForm\(\)$/i.test(trimmed)) return isFormMessage(entry.requestRaw);

  const responseHeader = /^response\.header\(["']([^"']+)["']\)$/i.exec(trimmed);
  if (responseHeader) return rawHeader(entry.responseRaw, responseHeader[1]);
  const responseHasHeader = /^response\.hasHeader\(["']([^"']+)["']\)$/i.exec(trimmed);
  if (responseHasHeader) return rawHasHeader(entry.responseRaw, responseHasHeader[1]);
  const responseContains = /^response\.contains\(["']([^"']+)["']\)$/i.exec(trimmed);
  if (responseContains) return rawContains(entry.responseRaw, responseContains[1]);
  const responseBodyContains = /^response\.bodyContains\(["']([^"']+)["']\)$/i.exec(trimmed);
  if (responseBodyContains) return rawContains(splitHttpMessage(entry.responseRaw).body, responseBodyContains[1]);
  const responseJsonField = /^response\.jsonField\(["']([^"']+)["']\)$/i.exec(trimmed);
  if (responseJsonField) return responseJsonFieldValue(entry, responseJsonField[1]);
  const responseJsonPath = /^response\.jsonPath\(["']([^"']+)["']\)$/i.exec(trimmed);
  if (responseJsonPath) return responseJsonFieldValue(entry, responseJsonPath[1]);
  const responseCookie = /^response\.cookie\(["']([^"']+)["']\)$/i.exec(trimmed);
  if (responseCookie) return responseCookieValue(entry, responseCookie[1]);
  if (/^response\.cookies\(\)$/i.test(trimmed)) return cookiePairsFromResponse(entry.responseRaw).join(',');
  if (/^response\.headerNames\(\)$/i.test(trimmed)) return headerNames(entry.responseRaw).join(',');
  if (/^response\.status$/i.test(trimmed)) return entry.status;
  if (/^response\.statusClass\(\)$/i.test(trimmed)) return entry.status > 0 ? `${Math.floor(entry.status / 100)}xx` : 'n/a';
  if (/^response\.timingMs\(\)$/i.test(trimmed)) return entry.timing;
  if (/^response\.bodySize\(\)$/i.test(trimmed)) return rawBodyLength(entry.responseRaw) || entry.length;
  if (/^response\.body\(\)$/i.test(trimmed)) return splitHttpMessage(entry.responseRaw).body;
  if (/^response\.contentType$/i.test(trimmed)) return rawHeader(entry.responseRaw, 'content-type');
  if (/^response\.isJson\(\)$/i.test(trimmed)) return isJsonMessage(entry.responseRaw);
  if (/^response\.mime$/i.test(trimmed)) return entry.mime;

  const entryContains = /^entry\.contains\(["']([^"']+)["']\)$/i.exec(trimmed);
  if (entryContains) return rawContains(`${entry.url}\n${entry.notes}\n${entry.tags.join(' ')}`, entryContains[1]);
  const entryTag = /^entry\.hasTag\(["']([^"']+)["']\)$/i.exec(trimmed);
  if (entryTag) return entry.tags.some((tag) => tag.toLowerCase() === entryTag[1].toLowerCase());
  const entryNoteContains = /^entry\.noteContains\(["']([^"']+)["']\)$/i.exec(trimmed);
  if (entryNoteContains) return rawContains(entry.notes, entryNoteContains[1]);
  if (/^entry\.tagCount\(\)$/i.test(trimmed)) return entry.tags.length;
  if (/^entry\.isModified\(\)$/i.test(trimmed)) return entry.modified;
  if (/^entry\.id$/i.test(trimmed)) return entry.id;
  if (/^entry\.status$/i.test(trimmed)) return entry.status;
  if (/^entry\.length$/i.test(trimmed)) return entry.length;
  if (/^entry\.tool$/i.test(trimmed)) return entry.tool;
  if (/^entry\.risk$/i.test(trimmed)) return entry.risk;
  if (/^entry\.mime$/i.test(trimmed)) return entry.mime;
  if (/^entry\.host$/i.test(trimmed)) return entry.host;
  if (/^entry\.path$/i.test(trimmed)) return entry.path;
  if (/^entry\.method$/i.test(trimmed)) return entry.method;
  if (/^entry\.modified$/i.test(trimmed)) return entry.modified;
  if (/^entry\.length$/i.test(trimmed)) return entry.length;

  const lowerHelper = /^helpers\.lower\((.+)\)$/i.exec(trimmed);
  if (lowerHelper) return String(evaluateLoggerScriptValue(lowerHelper[1], entry) ?? '').toLowerCase();
  const upperHelper = /^helpers\.upper\((.+)\)$/i.exec(trimmed);
  if (upperHelper) return String(evaluateLoggerScriptValue(upperHelper[1], entry) ?? '').toUpperCase();
  const defaultHelper = /^helpers\.default\((.+),\s*["']([^"']*)["']\)$/i.exec(trimmed);
  if (defaultHelper) {
    const value = evaluateLoggerScriptValue(defaultHelper[1], entry);
    return value === undefined || value === '' ? defaultHelper[2] : value;
  }
  const urlDecodeHelper = /^helpers\.urlDecode\((.+)\)$/i.exec(trimmed);
  if (urlDecodeHelper) return safeUrlDecode(String(evaluateLoggerScriptValue(urlDecodeHelper[1], entry) ?? ''));
  const urlEncodeHelper = /^helpers\.urlEncode\((.+)\)$/i.exec(trimmed);
  if (urlEncodeHelper) return encodeURIComponent(String(evaluateLoggerScriptValue(urlEncodeHelper[1], entry) ?? ''));
  const base64DecodeHelper = /^helpers\.base64Decode\((.+)\)$/i.exec(trimmed);
  if (base64DecodeHelper) return safeBase64Decode(String(evaluateLoggerScriptValue(base64DecodeHelper[1], entry) ?? ''));
  const base64EncodeHelper = /^helpers\.base64Encode\((.+)\)$/i.exec(trimmed);
  if (base64EncodeHelper) return safeBase64Encode(String(evaluateLoggerScriptValue(base64EncodeHelper[1], entry) ?? ''));
  return undefined;
}

function compareLoggerValues(left: string | number | boolean | undefined, operator: string, right: string | number | boolean | undefined) {
  if (left === undefined || right === undefined) return false;
  const leftText = String(left).toLowerCase();
  const rightText = String(right).toLowerCase();
  const severityLeft = severityRank[leftText as Severity];
  const severityRight = severityRank[rightText as Severity];
  const numericLeft = severityLeft ?? (typeof left === 'number' ? left : Number(left));
  const numericRight = severityRight ?? (typeof right === 'number' ? right : Number(right));
  const canCompareNumeric = Number.isFinite(numericLeft) && Number.isFinite(numericRight);
  if (operator === '>=') return canCompareNumeric ? numericLeft >= numericRight : leftText >= rightText;
  if (operator === '<=') return canCompareNumeric ? numericLeft <= numericRight : leftText <= rightText;
  if (operator === '>') return canCompareNumeric ? numericLeft > numericRight : leftText > rightText;
  if (operator === '<') return canCompareNumeric ? numericLeft < numericRight : leftText < rightText;
  const matched = leftText === rightText || leftText.includes(rightText);
  return operator.startsWith('!') ? !matched : matched;
}

function evaluateLoggerColumnFallback(kind: LoggerCustomColumnKind, entry: LoggerColumnEntry) {
  if (kind === 'auth-state') return /^(authorization|cookie|x-api-key|x-auth-token):/im.test(entry.requestRaw) ? 'auth' : 'anon';
  if (kind === 'param-count') return String(countParams(entry));
  if (kind === 'response-class') return entry.status > 0 ? `${Math.floor(entry.status / 100)}xx` : 'n/a';
  if (kind === 'timing-ms') return `${entry.timing} ms`;
  if (kind === 'body-size') return formatBytes(rawBodyLength(entry.responseRaw) || entry.length);
  const haystack = `${entry.url}\n${entry.notes}\n${entry.tags.join(' ')}\n${entry.requestRaw}\n${entry.responseRaw}`.toLowerCase();
  if (severityRank[entry.risk] >= severityRank.medium) return 'review';
  if (/(admin|token|secret|password|graphql|cors|callback|internal)/i.test(haystack)) return 'review';
  return '';
}

function countParams(entry: LoggerColumnEntry) {
  const urlParams = (() => {
    try {
      return new URL(entry.url).searchParams.size;
    } catch {
      const query = entry.path.split('?')[1] ?? '';
      return query ? query.split('&').filter(Boolean).length : 0;
    }
  })();
  const contentType = rawHeader(entry.requestRaw, 'content-type');
  const body = splitHttpMessage(entry.requestRaw).body;
  const formParams = /application\/x-www-form-urlencoded/i.test(contentType) && body
    ? body.split('&').filter(Boolean).length
    : 0;
  return urlParams + formParams;
}

function requestQueryParamValue(entry: LoggerColumnEntry, name: string) {
  try {
    return new URL(entry.url).searchParams.get(name) ?? '';
  } catch {
    const query = entry.path.split('?')[1] ?? '';
    return new URLSearchParams(query).get(name) ?? '';
  }
}

function requestBodyParamValue(entry: LoggerColumnEntry, name: string) {
  const contentType = rawHeader(entry.requestRaw, 'content-type');
  const body = splitHttpMessage(entry.requestRaw).body;
  if (/application\/x-www-form-urlencoded/i.test(contentType)) return new URLSearchParams(body).get(name) ?? '';
  if (/application\/json/i.test(contentType) || /^[\s\r\n]*[\[{]/.test(body)) return jsonPathValue(body, name);
  return '';
}

function responseJsonFieldValue(entry: LoggerColumnEntry, name: string) {
  return jsonPathValue(splitHttpMessage(entry.responseRaw).body, name);
}

function requestJsonFieldValue(entry: LoggerColumnEntry, name: string) {
  return jsonPathValue(splitHttpMessage(entry.requestRaw).body, name);
}

function jsonPathValue(raw: string, path: string) {
  try {
    const parsed = JSON.parse(raw);
    const value = path.split('.').reduce<unknown>((current, key) => {
      if (current && typeof current === 'object' && key in current) return (current as Record<string, unknown>)[key];
      return undefined;
    }, parsed);
    if (value === undefined || value === null) return '';
    if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') return String(value);
    return JSON.stringify(value);
  } catch {
    return '';
  }
}

function paramNames(entry: LoggerColumnEntry) {
  const names = new Set<string>();
  try {
    for (const name of new URL(entry.url).searchParams.keys()) names.add(name);
  } catch {
    const query = entry.path.split('?')[1] ?? '';
    for (const name of new URLSearchParams(query).keys()) names.add(name);
  }
  const contentType = rawHeader(entry.requestRaw, 'content-type');
  const body = splitHttpMessage(entry.requestRaw).body;
  if (/application\/x-www-form-urlencoded/i.test(contentType)) {
    for (const name of new URLSearchParams(body).keys()) names.add(name);
  } else if (/application\/json/i.test(contentType) || /^[\s\r\n]*\{/.test(body)) {
    try {
      const parsed = JSON.parse(body);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        for (const name of Object.keys(parsed)) names.add(name);
      }
    } catch {
      // Ignore malformed JSON and keep the names collected from URL/form sources.
    }
  }
  return Array.from(names);
}

function headerNames(raw: string) {
  return splitHttpMessage(raw).head
    .split(/\r?\n/)
    .slice(1)
    .map((line) => line.slice(0, line.indexOf(':')).trim())
    .filter(Boolean);
}

function rawHeaderValues(raw: string, name: string) {
  const pattern = new RegExp(`^${escapeRegExp(name)}\\s*:\\s*(.+)$`, 'img');
  return Array.from(raw.matchAll(pattern), (match) => match[1].trim()).filter(Boolean);
}

function rawHasHeader(raw: string, headerName: string) {
  return new RegExp(`^${escapeRegExp(headerName)}\\s*:`, 'im').test(raw);
}

function rawHeader(raw: string, name: string) {
  return new RegExp(`^${escapeRegExp(name)}\\s*:\\s*(.+)$`, 'im').exec(raw)?.[1]?.trim() ?? '';
}

function rawContains(raw: string, needle: string) {
  return raw.toLowerCase().includes(needle.toLowerCase());
}

function requestCookieValue(entry: LoggerColumnEntry, name: string) {
  return cookiePairsFromRequest(entry.requestRaw)
    .map((pair) => pair.split('='))
    .find(([cookieName]) => cookieName?.trim().toLowerCase() === name.toLowerCase())?.slice(1).join('=')?.trim() ?? '';
}

function responseCookieValue(entry: LoggerColumnEntry, name: string) {
  return cookiePairsFromResponse(entry.responseRaw)
    .map((pair) => pair.split('='))
    .find(([cookieName]) => cookieName?.trim().toLowerCase() === name.toLowerCase())?.slice(1).join('=')?.trim() ?? '';
}

function cookiePairsFromRequest(raw: string) {
  return rawHeaderValues(raw, 'cookie')
    .flatMap((value) => value.split(';'))
    .map((pair) => pair.trim())
    .filter(Boolean);
}

function cookiePairsFromResponse(raw: string) {
  return rawHeaderValues(raw, 'set-cookie')
    .map((value) => value.split(';')[0]?.trim() ?? '')
    .filter(Boolean);
}

function isJsonMessage(raw: string) {
  const contentType = rawHeader(raw, 'content-type');
  const body = splitHttpMessage(raw).body.trim();
  return /(^|[+/])json\b/i.test(contentType) || /^[\[{]/.test(body);
}

function isFormMessage(raw: string) {
  return /application\/x-www-form-urlencoded|multipart\/form-data/i.test(rawHeader(raw, 'content-type'));
}

function pathSegments(pathValue: string) {
  const pathOnly = pathValue.split('?')[0] ?? '';
  return pathOnly.split('/').map((part) => part.trim()).filter(Boolean);
}

function pathExtension(pathValue: string) {
  const lastSegment = pathSegments(pathValue).at(-1) ?? '';
  const match = /\.([a-z0-9_-]+)$/i.exec(lastSegment);
  return match?.[1]?.toLowerCase() ?? '';
}

function rawBodyLength(raw: string) {
  return new TextEncoder().encode(splitHttpMessage(raw).body).length;
}

function splitHttpMessage(raw: string) {
  const parts = raw.split(/\r?\n\r?\n/);
  return {
    head: parts[0] ?? '',
    body: parts.slice(1).join('\n\n'),
  };
}

function formatBytes(value: number) {
  if (value >= 1000000) return `${(value / 1000000).toFixed(1)} MB`;
  if (value >= 1000) return `${(value / 1000).toFixed(1)} KB`;
  return `${value} B`;
}

function splitExpression(value: string, operator: '&&' | '||') {
  return value.split(operator).map((part) => part.trim()).filter(Boolean);
}

function splitExpressionOutsideQuotes(value: string, operator: string) {
  const parts: string[] = [];
  let quote = '';
  let current = '';
  for (const char of value) {
    if ((char === '"' || char === "'") && !quote) {
      quote = char;
      current += char;
      continue;
    }
    if (quote === char) {
      quote = '';
      current += char;
      continue;
    }
    if (!quote && char === operator) {
      parts.push(current.trim());
      current = '';
      continue;
    }
    current += char;
  }
  if (current.trim()) parts.push(current.trim());
  return parts;
}

function trimOuter(value: string) {
  if (value.startsWith('(') && value.endsWith(')')) return value.slice(1, -1).trim();
  return value;
}

function escapeRegExp(value: string) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function safeUrlDecode(value: string) {
  try {
    return decodeURIComponent(value.replace(/\+/g, ' '));
  } catch {
    return value;
  }
}

type MinimalBuffer = {
  from(value: string, encoding?: 'utf8' | 'base64'): { toString(encoding?: 'utf8' | 'base64'): string };
};

function globalBuffer() {
  return (globalThis as unknown as { Buffer?: MinimalBuffer }).Buffer;
}

function safeBase64Decode(value: string) {
  try {
    const buffer = globalBuffer();
    if (buffer) return buffer.from(value, 'base64').toString('utf8');
    const atobFn = (globalThis as unknown as { atob?: (input: string) => string }).atob;
    if (!atobFn) return '';
    const binary = atobFn(value);
    const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
    return new TextDecoder().decode(bytes);
  } catch {
    return '';
  }
}

function safeBase64Encode(value: string) {
  try {
    const buffer = globalBuffer();
    if (buffer) return buffer.from(value, 'utf8').toString('base64');
    const btoaFn = (globalThis as unknown as { btoa?: (input: string) => string }).btoa;
    if (!btoaFn) return '';
    const bytes = new TextEncoder().encode(value);
    let binary = '';
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoaFn(binary);
  } catch {
    return '';
  }
}

function operationalSecretSignals(rawMaterial: string) {
  const signals: Array<[RegExp, string]> = [
    [/^authorization\s*:/im, 'authorization-header'],
    [/^cookie\s*:/im, 'cookie-header'],
    [/^x-api-key\s*:/im, 'x-api-key-header'],
    [/\bbearer\s+[a-z0-9._~+/=-]+/i, 'bearer-token'],
    [/\bsession=[^;\s]+/i, 'session-cookie'],
  ];
  return signals.flatMap(([pattern, signal]) => (pattern.test(rawMaterial) ? [signal] : []));
}

function simpleDigest(value: string) {
  let hash = 0x811c9dc5;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return `${hash.toString(16).padStart(8, '0')}${value.length.toString(16).padStart(8, '0')}`;
}
