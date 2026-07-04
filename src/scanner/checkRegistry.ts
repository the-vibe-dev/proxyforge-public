// Check registry: maps check IDs to their family metadata and variant generators.

import type { FamilyMetadata, PayloadFamily, ProbeContext, PayloadVariant } from './types';
import { generatePayloadVariants } from './payloadMutationEngine';

export interface CheckDefinition {
  id: string;
  family: PayloadFamily;
  metadata: FamilyMetadata;
  variants(ctx: ProbeContext): PayloadVariant[];
}

const REGISTRY = new Map<string, CheckDefinition>();

function define(id: string, family: PayloadFamily, meta: Omit<FamilyMetadata, 'id' | 'family'>): CheckDefinition {
  const def: CheckDefinition = {
    id,
    family,
    metadata: { id, family, ...meta },
    variants: (ctx: ProbeContext) => generatePayloadVariants({ ...ctx, family }),
  };
  REGISTRY.set(id, def);
  return def;
}

// ─── Core injection checks ────────────────────────────────────────────────────

define('sql-injection', 'sql-injection', {
  title: 'SQL injection',
  severity: 'high',
  destructiveRisk: 'none',
  requiresOast: false,
  requiresBrowser: false,
  insertionPointKinds: ['query', 'body', 'json', 'form', 'cookie', 'header'],
  expectedSignals: ['sql-error', 'timing-delta', 'union-data'],
  cwe: [89],
});

define('xss-reflected', 'xss-reflected', {
  title: 'Reflected XSS',
  severity: 'medium',
  destructiveRisk: 'none',
  requiresOast: false,
  requiresBrowser: false,
  insertionPointKinds: ['query', 'body', 'form', 'json', 'cookie', 'header', 'path'],
  expectedSignals: ['xss-reflection', 'script-tag', 'event-handler'],
  cwe: [79],
});

define('xss-oracle', 'xss-oracle', {
  title: 'XSS oracle-confirmed',
  severity: 'medium',
  destructiveRisk: 'none',
  requiresOast: false,
  requiresBrowser: true,
  insertionPointKinds: ['query', 'body', 'form', 'json'],
  expectedSignals: ['xss-reflection', 'browser-alert'],
  cwe: [79],
});

define('ssti', 'ssti', {
  title: 'Server-side template injection',
  severity: 'critical',
  destructiveRisk: 'low',
  requiresOast: false,
  requiresBrowser: false,
  insertionPointKinds: ['query', 'body', 'json', 'form', 'cookie', 'header'],
  expectedSignals: ['ssti-reflection', 'math-eval'],
  cwe: [94],
});

define('lfi-traversal', 'lfi-traversal', {
  title: 'Local file inclusion / path traversal',
  severity: 'high',
  destructiveRisk: 'none',
  requiresOast: false,
  requiresBrowser: false,
  insertionPointKinds: ['query', 'body', 'json', 'form', 'path'],
  expectedSignals: ['file-content', 'passwd-pattern'],
  cwe: [22],
});

define('command-injection', 'command-injection', {
  title: 'OS command injection',
  severity: 'critical',
  destructiveRisk: 'medium',
  requiresOast: false,
  requiresBrowser: false,
  insertionPointKinds: ['query', 'body', 'json', 'form', 'header'],
  expectedSignals: ['command-output', 'uid-pattern', 'timing-delta'],
  cwe: [78],
});

define('ssrf', 'ssrf', {
  title: 'Server-side request forgery',
  severity: 'high',
  destructiveRisk: 'none',
  requiresOast: false,
  requiresBrowser: false,
  insertionPointKinds: ['query', 'body', 'json', 'form', 'header'],
  expectedSignals: ['ssrf-response', 'metadata-content'],
  cwe: [918],
});

define('ssrf-oast', 'ssrf-oast', {
  title: 'SSRF (OAST-confirmed)',
  severity: 'high',
  destructiveRisk: 'none',
  requiresOast: true,
  requiresBrowser: false,
  insertionPointKinds: ['query', 'body', 'json', 'form', 'header'],
  expectedSignals: ['oast-callback-confirmed'],
  cwe: [918],
});

define('open-redirect', 'open-redirect', {
  title: 'Open redirect',
  severity: 'medium',
  destructiveRisk: 'none',
  requiresOast: false,
  requiresBrowser: false,
  insertionPointKinds: ['query', 'body', 'json', 'form'],
  expectedSignals: ['redirect-location', 'cross-origin'],
  cwe: [601],
});

define('xxe-file', 'xxe', {
  title: 'XML external entity injection (file read)',
  severity: 'high',
  destructiveRisk: 'none',
  requiresOast: false,
  requiresBrowser: false,
  insertionPointKinds: ['xml', 'body'],
  expectedSignals: ['file-content', 'xxe-reflection'],
  cwe: [611],
});

define('xxe-oast', 'xxe-oast', {
  title: 'XXE (OAST-confirmed)',
  severity: 'high',
  destructiveRisk: 'none',
  requiresOast: true,
  requiresBrowser: false,
  insertionPointKinds: ['xml', 'body'],
  expectedSignals: ['oast-callback-confirmed'],
  cwe: [611],
});

define('nosql-injection', 'nosql-injection', {
  title: 'NoSQL injection',
  severity: 'high',
  destructiveRisk: 'none',
  requiresOast: false,
  requiresBrowser: false,
  insertionPointKinds: ['query', 'body', 'json'],
  expectedSignals: ['nosql-auth-bypass', 'array-response'],
  cwe: [943],
});

define('xpath-injection', 'xpath-injection', {
  title: 'XPath injection',
  severity: 'high',
  destructiveRisk: 'none',
  requiresOast: false,
  requiresBrowser: false,
  insertionPointKinds: ['query', 'body', 'form'],
  expectedSignals: ['xpath-error', 'xml-data'],
  cwe: [643],
});

define('ldap-injection', 'ldap-injection', {
  title: 'LDAP injection',
  severity: 'high',
  destructiveRisk: 'none',
  requiresOast: false,
  requiresBrowser: false,
  insertionPointKinds: ['query', 'body', 'form'],
  expectedSignals: ['ldap-error', 'all-records'],
  cwe: [90],
});

define('expression-language-injection', 'expression-language-injection', {
  title: 'Expression language injection',
  severity: 'critical',
  destructiveRisk: 'medium',
  requiresOast: false,
  requiresBrowser: false,
  insertionPointKinds: ['query', 'body', 'json', 'form'],
  expectedSignals: ['ssti-reflection', 'math-eval'],
  cwe: [917],
});

define('csv-formula-injection', 'csv-formula-injection', {
  title: 'CSV formula injection',
  severity: 'low',
  destructiveRisk: 'none',
  requiresOast: false,
  requiresBrowser: false,
  insertionPointKinds: ['query', 'body', 'form', 'json'],
  expectedSignals: ['csv-formula-echo'],
  cwe: [1236],
});

// Auth/session checks
define('jwt-none-algorithm', 'jwt-attack', {
  title: 'JWT none algorithm accepted',
  severity: 'high',
  destructiveRisk: 'none',
  requiresOast: false,
  requiresBrowser: false,
  insertionPointKinds: ['header', 'cookie', 'query'],
  expectedSignals: ['auth-bypass', 'status-200'],
  cwe: [327],
});

define('jwt-weak-secret', 'jwt-attack', {
  title: 'JWT weak secret',
  severity: 'high',
  destructiveRisk: 'none',
  requiresOast: false,
  requiresBrowser: false,
  insertionPointKinds: ['header', 'cookie'],
  expectedSignals: ['auth-bypass'],
  cwe: [327],
});

define('session-fixation', 'session-fixation', {
  title: 'Session fixation',
  severity: 'medium',
  destructiveRisk: 'none',
  requiresOast: false,
  requiresBrowser: false,
  insertionPointKinds: ['cookie', 'query'],
  expectedSignals: ['session-accepted'],
  cwe: [384],
});

define('csrf-heuristic', 'csrf', {
  title: 'CSRF heuristic',
  severity: 'medium',
  destructiveRisk: 'none',
  requiresOast: false,
  requiresBrowser: false,
  insertionPointKinds: ['header', 'body', 'form'],
  expectedSignals: ['csrf-token-missing', 'origin-not-checked'],
  cwe: [352],
});

define('clickjacking', 'clickjacking', {
  title: 'Clickjacking',
  severity: 'low',
  destructiveRisk: 'none',
  requiresOast: false,
  requiresBrowser: false,
  insertionPointKinds: ['header'],
  expectedSignals: ['x-frame-options-missing', 'csp-frame-ancestors-missing'],
  cwe: [1021],
});

define('host-header-injection', 'host-header', {
  title: 'Host header injection',
  severity: 'medium',
  destructiveRisk: 'none',
  requiresOast: false,
  requiresBrowser: false,
  insertionPointKinds: ['header'],
  expectedSignals: ['host-reflected', 'redirect-location'],
  cwe: [20],
});

define('crlf-header-injection', 'crlf-injection', {
  title: 'CRLF header injection',
  severity: 'medium',
  destructiveRisk: 'none',
  requiresOast: false,
  requiresBrowser: false,
  insertionPointKinds: ['query', 'header', 'path'],
  expectedSignals: ['crlf-in-response', 'injected-header'],
  cwe: [113],
});

// CVE / named families
define('shell-shock', 'cve-named', {
  title: 'ShellShock (CVE-2014-6271)',
  severity: 'critical',
  destructiveRisk: 'none',
  requiresOast: false,
  requiresBrowser: false,
  insertionPointKinds: ['header'],
  expectedSignals: ['command-output', 'uid-pattern'],
  cwe: [78],
});

define('log4-shell', 'cve-named', {
  title: 'Log4Shell (CVE-2021-44228)',
  severity: 'critical',
  destructiveRisk: 'none',
  requiresOast: true,
  requiresBrowser: false,
  insertionPointKinds: ['header', 'query', 'body', 'json'],
  expectedSignals: ['oast-callback-confirmed'],
  cwe: [917],
});

define('spring4-shell', 'cve-named', {
  title: 'Spring4Shell (CVE-2022-22965)',
  severity: 'critical',
  destructiveRisk: 'none',
  requiresOast: false,
  requiresBrowser: false,
  insertionPointKinds: ['query', 'body', 'form'],
  expectedSignals: ['rce-indicator', 'webshell-response'],
  cwe: [94],
});

define('env-file-exposure', 'lfi-traversal', {
  title: '.env file exposure',
  severity: 'high',
  destructiveRisk: 'none',
  requiresOast: false,
  requiresBrowser: false,
  insertionPointKinds: ['path', 'query'],
  expectedSignals: ['file-content', 'env-vars'],
  cwe: [538],
});

define('source-code-disclosure-git', 'lfi-traversal', {
  title: 'Git source code disclosure',
  severity: 'medium',
  destructiveRisk: 'none',
  requiresOast: false,
  requiresBrowser: false,
  insertionPointKinds: ['path'],
  expectedSignals: ['git-refs', 'git-head'],
  cwe: [538],
});

// ─── API ─────────────────────────────────────────────────────────────────────

export function getCheck(id: string): CheckDefinition | undefined {
  return REGISTRY.get(id);
}

export function getAllCheckIds(): string[] {
  return Array.from(REGISTRY.keys());
}

export function getAllChecks(): CheckDefinition[] {
  return Array.from(REGISTRY.values());
}

export function getCheckCount(): number {
  return REGISTRY.size;
}
