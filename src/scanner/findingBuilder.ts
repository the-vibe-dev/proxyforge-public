// Builds ActiveScanFinding and Issue objects from oracle-classified evidence.

import type { ActiveScanFinding, Issue, Severity } from '../types';
import type { EvidenceConclusion, OracleClassification, PayloadVariant } from './types';

function severityFromFamily(family: string): Severity {
  if (/command-injection|xxe|deserialization|log4|spring4/i.test(family)) return 'critical';
  if (/sql-injection|ssrf|lfi-traversal|nosql|xpath|ldap|prototype-pollution/i.test(family)) return 'high';
  if (/xss|ssti|open-redirect|csrf|jwt|session-fixation|cache-poisoning/i.test(family)) return 'medium';
  if (/crlf|host-header|csv-formula|clickjacking/i.test(family)) return 'low';
  return 'medium';
}

function titleFromFamily(family: string, checkId: string): string {
  const map: Record<string, string> = {
    'sql-injection': 'SQL injection detected',
    'xss-reflected': 'Reflected XSS detected',
    'xss-oracle': 'XSS confirmed by oracle',
    'ssti': 'Server-side template injection detected',
    'lfi-traversal': 'Local file inclusion / path traversal detected',
    'command-injection': 'OS command injection detected',
    'ssrf': 'Server-side request forgery detected',
    'ssrf-oast': 'SSRF confirmed by out-of-band callback',
    'open-redirect': 'Open redirect detected',
    'xxe': 'XML external entity injection detected',
    'xxe-oast': 'XXE confirmed by out-of-band callback',
    'nosql-injection': 'NoSQL injection detected',
    'xpath-injection': 'XPath injection detected',
    'ldap-injection': 'LDAP injection detected',
  };
  return map[family] ?? map[checkId] ?? `Security finding: ${checkId}`;
}

function remediationFromFamily(family: string): string {
  const map: Record<string, string> = {
    'sql-injection': 'Use parameterised queries or prepared statements. Never concatenate user input into SQL.',
    'xss-reflected': 'HTML-encode all user-supplied data before rendering. Implement a strict CSP.',
    'ssti': 'Sandbox template engines. Never render untrusted template strings.',
    'lfi-traversal': 'Validate and canonicalise file paths. Restrict file access to a whitelist of permitted directories.',
    'command-injection': 'Avoid shell invocation with user input. Use library APIs or parameterised subprocess calls.',
    'ssrf': 'Validate and restrict outbound URLs. Use an allowlist of permitted destinations. Block RFC-1918 ranges.',
    'open-redirect': 'Validate redirect targets against an allowlist of permitted domains.',
    'xxe': 'Disable XML external entity processing in your XML parser. Use a hardened parser configuration.',
    'nosql-injection': 'Use parameterised query APIs. Never build queries from user-supplied objects.',
  };
  return map[family] ?? 'Review the affected endpoint, sanitise and validate inputs, and retest after remediation.';
}

export function buildFinding(
  checkId: string,
  family: string,
  host: string,
  path: string,
  insertionPointId: string,
  conclusion: EvidenceConclusion,
  bestClassification: OracleClassification,
  variant: PayloadVariant,
  exchangeId?: string,
): ActiveScanFinding {
  const id = `finding-${checkId}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
  const confidence: ActiveScanFinding['confidence'] =
    conclusion.confidence >= 0.85 ? 'certain' :
    conclusion.confidence >= 0.6 ? 'firm' :
    'tentative';

  return {
    id,
    checkId: checkId as ActiveScanFinding['checkId'],
    title: titleFromFamily(family, checkId),
    severity: severityFromFamily(family),
    confidence,
    host,
    path,
    detail: [
      conclusion.summary,
      bestClassification.evidence.join(' '),
      `Payload: ${variant.value.slice(0, 120)}`,
      `Insertion point: ${insertionPointId}`,
    ].filter(Boolean).join(' | '),
    remediation: remediationFromFamily(family),
    evidenceExchangeId: exchangeId,
    dedupeKey: `${checkId}:${host}:${path}:${insertionPointId}`,
    confidenceReason: bestClassification.evidence[0] ?? conclusion.summary,
  };
}

export function buildIssueFromFinding(finding: ActiveScanFinding): Issue {
  return {
    id: `issue-${finding.id}`,
    title: finding.title,
    severity: finding.severity,
    host: finding.host,
    path: finding.path,
    confidence: finding.confidence,
    status: 'triaged',
    detail: finding.detail,
    remediation: finding.remediation,
    triageNote: `Promoted from active scanner finding ${finding.id}. Confidence: ${finding.confidence}.`,
    lastTriagedAt: new Date().toISOString(),
  };
}
