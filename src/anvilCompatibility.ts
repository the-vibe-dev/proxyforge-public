export interface AnvilEvaluationInput {
  requestRaw?: string;
  responseRaw?: string;
  targetUrl?: string;
}

export interface AnvilEvaluationResult {
  matched: boolean;
  conditionCount: number;
  passedCount: number;
  failedCount: number;
  evidence: string[];
  fields: string[];
  operators: string[];
  mode: 'compatibility' | 'no-conditions';
}

interface AnvilCondition {
  raw: string;
  joiner: 'and' | 'or';
  side: 'request' | 'response';
  field: string;
  operator: 'contains' | 'matches' | '==' | '!=' | '>=' | '<=' | '>' | '<';
  expected: string;
  regexFlags: string;
  negated: boolean;
}

const conditionPattern = /\b(and|or)?\s*(not\s+)?\{latest\.(request|response)\.([^}]+)\}\s+(not\s+contains|contains|matches|==|!=|>=|<=|>|<)\s+("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|\/(?:\\.|[^/\\])*\/[gimsuy]*|[^\s,)]+)/gi;

export function evaluateAnvilSource(source: string, input: AnvilEvaluationInput): AnvilEvaluationResult {
  const conditions = parseAnvilConditions(source);
  if (!conditions.length) {
    return {
      matched: false,
      conditionCount: 0,
      passedCount: 0,
      failedCount: 0,
      evidence: ['No compatibility conditions found in Anvil source.'],
      fields: [],
      operators: [],
      mode: 'no-conditions',
    };
  }

  const results = conditions.map((condition) => {
    const passed = evaluateAnvilCondition(condition, input);
    return {
      condition,
      passed,
      evidence: `${formatAnvilField(condition.side, condition.field)} ${condition.negated ? 'not ' : ''}${condition.operator} ${previewValue(condition.expected)}: ${passed ? 'pass' : 'fail'}`,
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
    fields: unique(results.map((result) => formatAnvilField(result.condition.side, result.condition.field))),
    operators: unique(results.map((result) => `${result.condition.negated ? 'not ' : ''}${result.condition.operator}`)),
    mode: 'compatibility',
  };
}

function parseAnvilConditions(source: string): AnvilCondition[] {
  const substituted = substituteAnvilDefinitions(source);
  const conditions: AnvilCondition[] = [];
  for (const rawLine of substituted.split(/\r?\n/)) {
    const line = rawLine.replace(/#.*/, '').trim();
    if (!line || !line.includes('{latest.')) continue;
    conditionPattern.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = conditionPattern.exec(line))) {
      const operatorText = match[5].toLowerCase();
      const parsedExpected = parseExpectedToken(match[6]);
      conditions.push({
        raw: line,
        joiner: (match[1]?.toLowerCase() === 'or' ? 'or' : 'and'),
        side: match[3].toLowerCase() === 'request' ? 'request' : 'response',
        field: match[4].trim(),
        operator: operatorText.includes('contains') ? 'contains' : operatorText as AnvilCondition['operator'],
        expected: parsedExpected.value,
        regexFlags: parsedExpected.flags,
        negated: Boolean(match[2]) || operatorText.startsWith('not '),
      });
    }
  }
  return conditions;
}

function substituteAnvilDefinitions(source: string) {
  const definitions = extractAnvilDefinitions(source);
  return Object.entries(definitions).reduce((current, [key, value]) => {
    return current
      .replace(new RegExp(`\\$\\{${escapeRegExp(key)}\\}`, 'g'), () => value)
      .replace(new RegExp(`\\{\\{\\s*${escapeRegExp(key)}\\s*\\}\\}`, 'g'), () => value)
      .replace(new RegExp(`\\{${escapeRegExp(key)}\\}`, 'g'), () => value);
  }, source);
}

function extractAnvilDefinitions(source: string) {
  const definitions: Record<string, string> = {};
  let inDefineBlock = false;
  for (const line of source.split(/\r?\n/)) {
    if (/^\s*define\s*:?\s*$/i.test(line)) {
      inDefineBlock = true;
      continue;
    }
    if (/^\s*(given|metadata|report issue|end if)\b/i.test(line)) inDefineBlock = false;
    const match = line.match(/^\s*([A-Za-z_][\w.-]*)\s*=\s*("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|.+?)\s*$/);
    if (!match || !inDefineBlock) continue;
    definitions[match[1]] = parseExpectedToken(match[2]).value;
  }
  return definitions;
}

function evaluateAnvilCondition(condition: AnvilCondition, input: AnvilEvaluationInput) {
  const actual = anvilFieldValue(condition, input);
  const expected = condition.expected;
  let result = false;
  if (condition.operator === 'contains') {
    result = String(actual).toLowerCase().includes(expected.toLowerCase());
  } else if (condition.operator === 'matches') {
    result = anvilRegexMatches(String(actual), expected, condition.regexFlags);
  } else {
    result = compareAnvilValues(actual, expected, condition.operator);
  }
  return condition.negated ? !result : result;
}

function anvilFieldValue(condition: AnvilCondition, input: AnvilEvaluationInput): string | number {
  const raw = condition.side === 'response' ? input.responseRaw ?? '' : input.requestRaw ?? '';
  const field = condition.field.trim();
  const normalized = field.toLowerCase();
  const headerName = field.match(/^headers?\s*\[\s*["']([^"']+)["']\s*\]$/i)?.[1];
  if (headerName) return rawHttpHeader(raw, headerName);
  if (normalized === 'headers') return rawHttpHeaders(raw);
  if (normalized === 'body') return splitHttpMessage(raw).body;
  if (normalized === 'raw') return raw;
  if (condition.side === 'response' && (normalized === 'status_code' || normalized === 'status')) {
    return responseStatusFromRaw(raw);
  }
  if (condition.side === 'request' && normalized === 'method') {
    return methodFromRawRequest(raw);
  }
  if (condition.side === 'request' && normalized === 'url') {
    return input.targetUrl || urlFromRawRequest(raw);
  }
  if (condition.side === 'request' && normalized === 'path') {
    return pathFromRawRequest(raw, input.targetUrl);
  }
  if (condition.side === 'request' && normalized === 'host') {
    return rawHttpHeader(raw, 'Host') || hostFromUrl(input.targetUrl || urlFromRawRequest(raw));
  }
  return raw;
}

function parseExpectedToken(token: string) {
  const trimmed = token.trim().replace(/\s+then$/i, '');
  const regexLiteral = trimmed.match(/^\/((?:\\.|[^/\\])*)\/([gimsuy]*)$/);
  if (regexLiteral) return { value: regexLiteral[1].replace(/\\\//g, '/'), flags: regexLiteral[2] ?? '' };
  if ((trimmed.startsWith('"') && trimmed.endsWith('"')) || (trimmed.startsWith("'") && trimmed.endsWith("'"))) {
    return { value: unescapeAnvilString(trimmed.slice(1, -1)), flags: '' };
  }
  return { value: trimmed, flags: '' };
}

function compareAnvilValues(actual: string | number, expected: string, operator: AnvilCondition['operator']) {
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
  if (operator === '==') return String(actual) === expected;
  if (operator === '!=') return String(actual) !== expected;
  return false;
}

function anvilRegexMatches(actual: string, pattern: string, flags: string) {
  let source = pattern;
  let normalizedFlags = flags;
  if (source.startsWith('(?i)')) {
    source = source.slice(4);
    normalizedFlags += 'i';
  }
  try {
    return new RegExp(source, unique(normalizedFlags.split('')).join('')).test(actual);
  } catch {
    return false;
  }
}

function splitHttpMessage(raw: string) {
  const [head, ...rest] = String(raw ?? '').split(/\r?\n\r?\n/);
  return { head: head ?? '', body: rest.join('\n\n') };
}

function rawHttpHeader(raw: string, name: string) {
  return splitHttpMessage(raw).head
    .split(/\r?\n/)
    .slice(1)
    .find((line) => new RegExp(`^${escapeRegExp(name)}\\s*:`, 'i').test(line))
    ?.replace(new RegExp(`^${escapeRegExp(name)}\\s*:\\s*`, 'i'), '')
    .trim() ?? '';
}

function rawHttpHeaders(raw: string) {
  return splitHttpMessage(raw).head.split(/\r?\n/).slice(1).join('\n');
}

function responseStatusFromRaw(raw: string) {
  return Number(/^HTTP\/\S+\s+(\d{3})/im.exec(String(raw ?? ''))?.[1] ?? 0);
}

function methodFromRawRequest(raw: string) {
  return String(raw ?? '').split(/\s+/, 1)[0] || '';
}

function urlFromRawRequest(raw: string) {
  const { head } = splitHttpMessage(raw);
  const [requestLine = ''] = head.split(/\r?\n/);
  const [, requestTarget = ''] = requestLine.match(/^\S+\s+(\S+)/) ?? [];
  if (/^https?:\/\//i.test(requestTarget)) return requestTarget;
  const host = rawHttpHeader(raw, 'Host');
  return host ? `https://${host}${requestTarget.startsWith('/') ? requestTarget : `/${requestTarget}`}` : '';
}

function pathFromRawRequest(raw: string, targetUrl?: string) {
  const candidate = targetUrl || urlFromRawRequest(raw);
  try {
    const parsed = new URL(candidate);
    return `${parsed.pathname}${parsed.search}` || '/';
  } catch {
    const { head } = splitHttpMessage(raw);
    const [requestLine = ''] = head.split(/\r?\n/);
    return requestLine.match(/^\S+\s+(\S+)/)?.[1] ?? '';
  }
}

function hostFromUrl(value: string) {
  try {
    return new URL(value).host;
  } catch {
    return '';
  }
}

function formatAnvilField(side: string, field: string) {
  return `${side}.${field.trim()}`;
}

function previewValue(value: string) {
  return value.length > 48 ? `${value.slice(0, 45)}...` : value;
}

function unescapeAnvilString(value: string) {
  return value
    .replace(/\\n/g, '\n')
    .replace(/\\r/g, '\r')
    .replace(/\\t/g, '\t')
    .replace(/\\"/g, '"')
    .replace(/\\'/g, "'")
    .replace(/\\\\/g, '\\');
}

function unique<T>(values: T[]) {
  return Array.from(new Set(values.filter(Boolean)));
}

function escapeRegExp(value: string) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
