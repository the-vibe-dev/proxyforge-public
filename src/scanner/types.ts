// Adapted from source-reference/vantix/secops/skills/ design patterns
// (snapshot 2026-05-26). Rewritten in TypeScript with Proxy Forge naming, types,
// and storage model. No runtime dependency on the vendored source.

export type PayloadFamily =
  | 'sql-injection'
  | 'xss-reflected'
  | 'xss-oracle'
  | 'ssti'
  | 'ssti-blind-time'
  | 'lfi-traversal'
  | 'command-injection'
  | 'command-injection-blind-time'
  | 'command-injection-blind-oast'
  | 'ssrf'
  | 'ssrf-oast'
  | 'open-redirect'
  | 'crlf-injection'
  | 'host-header'
  | 'cache-poisoning'
  | 'xxe'
  | 'xxe-oast'
  | 'nosql-injection'
  | 'xpath-injection'
  | 'ldap-injection'
  | 'expression-language-injection'
  | 'csv-formula-injection'
  | 'jwt-attack'
  | 'deserialization'
  | 'request-smuggling'
  | 'prototype-pollution-client'
  | 'prototype-pollution-server'
  | 'dom-xss'
  | 'graphql-attack'
  | 'mass-assignment'
  | 'idor'
  | 'cors-misconfig'
  | 'clickjacking'
  | 'csrf'
  | 'session-fixation'
  | 'cache-deception'
  | 'cve-named'
  | 'csrf-heuristic'
  | 'postMessage-misconfig';

export type InsertionPointKind =
  | 'query'
  | 'body'
  | 'form'
  | 'header'
  | 'path'
  | 'json'
  | 'xml'
  | 'graphql'
  | 'cookie'
  | 'multipart';

export interface MutationContext {
  family: PayloadFamily;
  baseValue: string;
  insertionPointKind: InsertionPointKind;
  contentType?: string;
  blockedChars?: string[];
  observedErrors?: string[];
  maxVariants?: number;
  oastBaseUrl?: string;
  oastToken?: string;
}

export interface PayloadVariant {
  id: string;
  family: PayloadFamily;
  value: string;
  encoding: 'raw' | 'url' | 'double-url' | 'json-string' | 'html' | 'header-safe';
  intent: string;
  requiresOast?: boolean;
  requiresBrowser?: boolean;
  destructiveRisk: 'none' | 'low' | 'medium' | 'high';
  expectedSignals: string[];
}

export type OracleResponseClass =
  | 'expected-proof'
  | 'verifier-type-error'
  | 'wrong-observed-value'
  | 'observed-value'
  | 'tag-stripped-or-ignored'
  | 'neutral-or-not-parsed'
  | 'reflected-inert'
  | 'method-or-parser-rejected'
  | 'parser-error'
  | 'timing-delta'
  | 'length-delta'
  | 'status-delta'
  | 'oast-callback-confirmed'
  | 'unknown';

export interface ResponseFingerprint {
  statusCode: number;
  contentType: string;
  bodyLength: number;
  bodyHash: string;
  responseTimeMs: number;
}

export interface OracleObservation {
  payloadVariantId: string;
  payload: string;
  statusCode?: number;
  contentType?: string;
  responseTextPreview: string;
  responseHeaders?: Record<string, string>;
  baseline?: ResponseFingerprint;
  timingMs?: number;
}

export interface OracleClassification {
  payloadVariantId: string;
  responseClass: OracleResponseClass;
  confidence: number;
  observedValue?: string;
  reflectedValue?: string;
  evidence: string[];
  nextAction: 'continue' | 'mutate' | 'confirm' | 'stop-negative' | 'promote-finding';
}

export interface ScanProbeMatrix {
  id: string;
  projectId: string;
  sourceExchangeId: string;
  checkId: string;
  insertionPointId: string;
  baselineExchangeId?: string;
  variants: PayloadVariant[];
  classifications: OracleClassification[];
  oastPayloadIds: string[];
  finalState: 'running' | 'finding' | 'negative' | 'inconclusive' | 'stopped';
  confidence: number;
  createdAt: string;
  updatedAt: string;
}

export interface EvidenceConclusion {
  state: 'finding' | 'negative' | 'inconclusive';
  confidence: number;
  summary: string;
  evidenceIds: string[];
}

export type FamilyMetadata = {
  id: string;
  family: PayloadFamily;
  title: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  destructiveRisk: 'none' | 'low' | 'medium' | 'high';
  requiresOast: boolean;
  requiresBrowser: boolean;
  insertionPointKinds: InsertionPointKind[];
  expectedSignals: string[];
  cwe?: number[];
};

export interface ProbeContext {
  exchangeId: string;
  projectId: string;
  insertionPointKind: InsertionPointKind;
  insertionPointName: string;
  baseValue: string;
  contentType?: string;
  oastBaseUrl?: string;
  oastToken?: string;
  maxVariants?: number;
  blockedChars?: string[];
}

export interface ScannerResponseInput {
  statusCode: number;
  headers: Record<string, string>;
  bodyText: string;
  responseTimeMs: number;
}

export interface SafetyBudget {
  maxRequests: number;
  maxVariantsPerInsertionPoint: number;
  throttleMs: number;
  allowDestructive: boolean;
  allowOast: boolean;
}
