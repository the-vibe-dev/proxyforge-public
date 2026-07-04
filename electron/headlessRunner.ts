#!/usr/bin/env node
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { CertificateAuthorityManager } from './certManager';
import { CrawlEngine, type CrawlRequest, type CrawlSummary } from './crawlEngine';
import { ProxyEngine, type ActiveScanCheckId, type ActiveScanFinding, type ActiveScanSummary, type ActiveScanSuppressedFinding, type ActiveScanTuningMetadata, type CrawlAuditSummary } from './proxyEngine';
import { ReportEngine, type ReportArtifact, type ReportExportRequest, type ReportFormat, type ReportIssue, type ReportSection, type ReportTemplateId } from './reportEngine';

type Severity = ReportIssue['severity'];
export type HeadlessCiOutputFormat = 'sarif' | 'junit';

export interface HeadlessCiArtifact {
  format: HeadlessCiOutputFormat;
  fileName: string;
  path: string;
  generatedAt: string;
  findingCount: number;
  content: string;
}

export interface HeadlessSessionProfile {
  headers?: Record<string, string>;
  cookies?: string | string[] | Record<string, string>;
}

export interface HeadlessScanConfig {
  projectName?: string;
  targetUrl?: string;
  projectFile?: string;
  projectExchangeId?: string;
  scopeAllowlist?: string[];
  outDir?: string;
  failOnSeverity?: Severity | 'none';
  session?: HeadlessSessionProfile;
  crawl?: Partial<Pick<CrawlRequest, 'maxDepth' | 'maxPages' | 'throttleMs' | 'userAgent' | 'includeForms'>> & { enabled?: boolean };
  activeScan?: {
    enabled?: boolean;
    checks?: ActiveScanCheckId[];
    throttleMs?: number;
    maxRequests?: number;
  };
  crawlAudit?: {
    enabled?: boolean;
    checks?: ActiveScanCheckId[];
    throttleMs?: number;
    maxInsertionPoints?: number;
  };
  report?: {
    formats?: ReportFormat[];
    sections?: ReportSection[];
    templateId?: ReportTemplateId;
    brandName?: string;
    preparedFor?: string;
    engagementId?: string;
    signEvidenceBundle?: boolean;
    signerName?: string;
    signingKeyId?: string;
    signingSecret?: string;
  };
  ci?: {
    outputs?: HeadlessCiOutputFormat[];
  };
}

export interface HeadlessScanSummary {
  id: string;
  projectName: string;
  targetUrl: string;
  scopeAllowlist: string[];
  projectFilePath?: string;
  projectExchangeCount: number;
  seedExchangeId?: string;
  sessionHeaderCount: number;
  sessionCookieCount: number;
  startedAt: string;
  completedAt: string;
  durationMs: number;
  blocked: boolean;
  exitCode: number;
  failOnSeverity: Severity | 'none';
  highestSeverity: Severity | 'none';
  routeCount: number;
  insertionPointCount: number;
  totalRequests: number;
  findingCount: number;
  suppressedFindingCount: number;
  exchangeCount: number;
  reportCount: number;
  ciArtifactCount: number;
  outDir: string;
  summaryPath: string;
  logs: string[];
  suppressedFindings: ActiveScanSuppressedFinding[];
  scannerTuning: ActiveScanTuningMetadata[];
  findings: ReportIssue[];
  reports: ReportArtifact[];
  ciArtifacts: HeadlessCiArtifact[];
}

interface HeadlessProjectSnapshot {
  version: 1;
  savedAt?: string;
  projectName: string;
  scopeAllowlist: string[];
  exchanges: ReportExportRequest['exchanges'];
  importedBundleIssues?: unknown[];
  intruderPromotedIssues?: unknown[];
  webSocketPromotedIssues?: unknown[];
}

const defaultChecks: ActiveScanCheckId[] = ['security-headers', 'cors-origin', 'cache-key', 'method-options'];
const severityRank: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

export async function runHeadlessScan(input: HeadlessScanConfig): Promise<HeadlessScanSummary> {
  const startedAt = new Date();
  const projectFilePath = input.projectFile ? path.resolve(input.projectFile) : undefined;
  const projectSnapshot = projectFilePath ? await loadProjectSnapshotFile(projectFilePath) : null;
  const projectExchanges = normalizeProjectExchanges(projectSnapshot);
  const seedExchange = selectProjectExchange(projectExchanges, input.projectExchangeId, Boolean(input.targetUrl));
  const target = parseTargetUrl(input.targetUrl ?? seedExchange?.url);
  const scopeAllowlist = normalizeScope(input.scopeAllowlist ?? projectSnapshot?.scopeAllowlist, target);
  const projectName = input.projectName?.trim() || projectSnapshot?.projectName?.trim() || `${target.hostname} Headless Scan`;
  const outDir = path.resolve(input.outDir || path.join(process.cwd(), 'proxyforge-headless-artifacts'));
  const session = normalizeSessionProfile(input.session);
  const logs: string[] = [];
  const exchanges: ReportExportRequest['exchanges'] = [...projectExchanges];
  const findings: ActiveScanFinding[] = [];
  const suppressedFindings: ActiveScanSuppressedFinding[] = [];
  const scannerTuning: ActiveScanTuningMetadata[] = [];
  let routeCount = 0;
  let insertionPointCount = 0;
  let blocked = false;

  await fs.mkdir(outDir, { recursive: true });
  logs.push(`Target: ${target.toString()}`);
  logs.push(`Scope: ${scopeAllowlist.join(', ')}`);
  if (projectSnapshot && projectFilePath) {
    logs.push(`Loaded project file ${projectFilePath} with ${projectExchanges.length} exchange${projectExchanges.length === 1 ? '' : 's'}.`);
  }
  if (seedExchange) {
    logs.push(`Selected project exchange ${seedExchange.id}: ${seedExchange.method} ${seedExchange.url}`);
  }
  if (session.headerCount > 0 || session.cookieCount > 0) {
    logs.push(`Session profile applied: ${session.headerCount} header${session.headerCount === 1 ? '' : 's'} and ${session.cookieCount} cookie value${session.cookieCount === 1 ? '' : 's'}.`);
  }

  const crawler = new CrawlEngine();
  const proxy = new ProxyEngine(
    (exchange) => exchanges.push(exchange),
    new CertificateAuthorityManager(path.join(outDir, '.certs')),
  );

  let crawlSummary: CrawlSummary | null = null;
  if (input.crawl?.enabled !== false) {
    crawlSummary = await crawler.runCrawl({
      startUrl: target.toString(),
      scopeAllowlist,
      maxDepth: input.crawl?.maxDepth ?? 1,
      maxPages: input.crawl?.maxPages ?? 8,
      throttleMs: input.crawl?.throttleMs ?? 0,
      userAgent: input.crawl?.userAgent || 'ProxyForge Headless Crawler',
      includeForms: input.crawl?.includeForms ?? true,
      headers: session.headers,
    });
    blocked = blocked || crawlSummary.blocked;
    routeCount = crawlSummary.routes.length;
    insertionPointCount = crawlSummary.insertionPoints.length;
    exchanges.push(...crawlSummary.exchanges);
    logs.push(crawlSummary.message);
  } else {
    logs.push('Crawler skipped by configuration.');
  }

  if (input.activeScan?.enabled !== false) {
    const rawRequest = applySessionToRawRequest(seedExchange?.requestRaw || renderRawRequest(target), target, session.headers);
    const active = await proxy.runActiveScan({
      rawRequest,
      targetUrl: target.toString(),
      scopeAllowlist,
      checks: input.activeScan?.checks?.length ? input.activeScan.checks : defaultChecks,
      throttleMs: input.activeScan?.throttleMs ?? 0,
      maxRequests: input.activeScan?.maxRequests ?? 4,
    });
    appendScanSummary(active, findings, suppressedFindings, scannerTuning, exchanges, logs);
    blocked = blocked || active.blocked;
  } else {
    logs.push('Active scanner skipped by configuration.');
  }

  if (input.crawlAudit?.enabled && crawlSummary?.insertionPoints.length) {
    const audit = await proxy.runCrawlAudit({
      scopeAllowlist,
      checks: input.crawlAudit.checks?.length ? input.crawlAudit.checks : defaultChecks,
      insertionPoints: crawlSummary.insertionPoints,
      sessionHeaders: session.headers,
      throttleMs: input.crawlAudit.throttleMs ?? 0,
      maxInsertionPoints: input.crawlAudit.maxInsertionPoints ?? 6,
    });
    appendScanSummary(audit, findings, suppressedFindings, scannerTuning, exchanges, logs);
    blocked = blocked || audit.blocked;
  } else if (input.crawlAudit?.enabled) {
    logs.push('Crawl audit skipped because no insertion points were discovered.');
  }

  const reportIssues = mergeReportIssues([
    ...normalizeProjectIssues(projectSnapshot),
    ...normalizeFindings(findings),
  ]);
  const reportEngine = new ReportEngine(outDir);
  const reports: ReportArtifact[] = [];
  const formats: ReportFormat[] = input.report?.formats?.length ? input.report.formats : ['json'];
  for (const format of formats) {
    reports.push(await reportEngine.exportReport({
      projectName,
      scopeAllowlist,
      issues: reportIssues,
      exchanges,
      format,
      sections: input.report?.sections?.length ? input.report.sections : ['executive', 'technical', 'evidence'],
      templateId: input.report?.templateId ?? (format === 'bundle' ? 'evidence-bundle' : 'technical-remediation'),
      brandName: input.report?.brandName ?? 'ProxyForge Headless',
      preparedFor: input.report?.preparedFor ?? 'CI Pipeline',
      engagementId: input.report?.engagementId ?? `CI-${startedAt.toISOString().slice(0, 10)}`,
      signEvidenceBundle: input.report?.signEvidenceBundle ?? format === 'bundle',
      signerName: input.report?.signerName ?? 'ProxyForge CI',
      signingKeyId: input.report?.signingKeyId ?? 'proxyforge-ci',
      signingSecret: input.report?.signingSecret ?? '',
    }));
  }
  const ciArtifacts = await exportCiArtifacts({
    outDir,
    outputs: input.ci?.outputs ?? [],
    projectName,
    target,
    scopeAllowlist,
    findings: reportIssues,
    startedAt,
  });

  const highestSeverity = highestFindingSeverity(reportIssues);
  const failOnSeverity = input.failOnSeverity ?? 'none';
  const exitCode = blocked
    ? 1
    : failOnSeverity !== 'none' && highestSeverity !== 'none' && severityRank[highestSeverity] >= severityRank[failOnSeverity]
      ? 2
      : 0;
  const completedAt = new Date();
  const summaryPath = path.join(outDir, 'proxyforge-headless-summary.json');
  const summary: HeadlessScanSummary = {
    id: `headless-${startedAt.getTime()}-${Math.random().toString(16).slice(2)}`,
    projectName,
    targetUrl: target.toString(),
    scopeAllowlist,
    projectFilePath,
    projectExchangeCount: projectExchanges.length,
    seedExchangeId: seedExchange?.id,
    sessionHeaderCount: session.headerCount,
    sessionCookieCount: session.cookieCount,
    startedAt: startedAt.toISOString(),
    completedAt: completedAt.toISOString(),
    durationMs: completedAt.getTime() - startedAt.getTime(),
    blocked,
    exitCode,
    failOnSeverity,
    highestSeverity,
    routeCount,
    insertionPointCount,
    totalRequests: exchanges.length,
    findingCount: reportIssues.length,
    suppressedFindingCount: suppressedFindings.length,
    exchangeCount: exchanges.length,
    reportCount: reports.length,
    ciArtifactCount: ciArtifacts.length,
    outDir,
    summaryPath,
    logs,
    suppressedFindings,
    scannerTuning,
    findings: reportIssues,
    reports,
    ciArtifacts,
  };
  await fs.writeFile(summaryPath, JSON.stringify(redactSummaryContent(summary), null, 2), 'utf8');
  return summary;
}

function appendScanSummary(
  summary: ActiveScanSummary | CrawlAuditSummary,
  findings: ActiveScanFinding[],
  suppressedFindings: ActiveScanSuppressedFinding[],
  scannerTuning: ActiveScanTuningMetadata[],
  exchanges: ReportExportRequest['exchanges'],
  logs: string[],
) {
  findings.push(...summary.findings);
  suppressedFindings.push(...summary.suppressedFindings);
  scannerTuning.push(summary.tuning);
  exchanges.push(...summary.exchanges);
  logs.push(summary.message);
  if (summary.tuning.suppressedFindingCount > 0) {
    logs.push(`Scanner tuning ${summary.tuning.profile}: ${summary.tuning.suppressedFindingCount} noisy signal${summary.tuning.suppressedFindingCount === 1 ? '' : 's'} suppressed before issue promotion.`);
  }
}

async function loadProjectSnapshotFile(projectFilePath: string): Promise<HeadlessProjectSnapshot> {
  const raw = await fs.readFile(projectFilePath, 'utf8');
  const parsed = JSON.parse(raw) as Partial<HeadlessProjectSnapshot>;
  if (parsed.version !== 1 || typeof parsed.projectName !== 'string' || !Array.isArray(parsed.exchanges)) {
    throw new Error('Project file is not a valid ProxyForge v1 project snapshot.');
  }
  return {
    version: 1,
    savedAt: parsed.savedAt,
    projectName: parsed.projectName,
    scopeAllowlist: Array.isArray(parsed.scopeAllowlist) ? parsed.scopeAllowlist.filter((item): item is string => typeof item === 'string') : [],
    exchanges: parsed.exchanges,
    importedBundleIssues: parsed.importedBundleIssues,
    intruderPromotedIssues: parsed.intruderPromotedIssues,
    webSocketPromotedIssues: parsed.webSocketPromotedIssues,
  };
}

function normalizeProjectExchanges(project: HeadlessProjectSnapshot | null): ReportExportRequest['exchanges'] {
  if (!project) return [];
  return project.exchanges
    .filter(isReportExchangeLike)
    .slice(0, 500)
    .map((exchange) => ({ ...exchange, tags: Array.from(new Set([...exchange.tags, 'project-file'])) }));
}

function isReportExchangeLike(value: unknown): value is ReportExportRequest['exchanges'][number] {
  const candidate = value as Partial<ReportExportRequest['exchanges'][number]> | undefined;
  return Boolean(
    candidate
    && typeof candidate.id === 'string'
    && typeof candidate.method === 'string'
    && typeof candidate.host === 'string'
    && typeof candidate.path === 'string'
    && typeof candidate.url === 'string'
    && typeof candidate.status === 'number'
    && typeof candidate.requestRaw === 'string'
    && typeof candidate.responseRaw === 'string'
    && Array.isArray(candidate.tags),
  );
}

function selectProjectExchange(
  exchanges: ReportExportRequest['exchanges'],
  exchangeId: string | undefined,
  explicitTargetProvided: boolean,
) {
  if (exchangeId) {
    return exchanges.find((exchange) => exchange.id === exchangeId)
      ?? exchanges.find((exchange) => `${exchange.method} ${exchange.url}` === exchangeId);
  }
  if (explicitTargetProvided) return undefined;
  return exchanges.find((exchange) => exchange.requestRaw.trim() && isHttpUrl(exchange.url))
    ?? exchanges[0];
}

function normalizeProjectIssues(project: HeadlessProjectSnapshot | null): ReportIssue[] {
  if (!project) return [];
  const candidates = [
    ...(project.importedBundleIssues ?? []),
    ...(project.intruderPromotedIssues ?? []),
    ...(project.webSocketPromotedIssues ?? []),
  ];
  return candidates.filter(isReportIssueLike).map((issue) => ({
    id: issue.id,
    title: issue.title,
    severity: issue.severity,
    host: issue.host,
    path: issue.path,
    confidence: issue.confidence,
    status: issue.status,
    detail: issue.detail,
    remediation: issue.remediation,
  }));
}

function isReportIssueLike(value: unknown): value is ReportIssue {
  const candidate = value as Partial<ReportIssue> | undefined;
  return Boolean(
    candidate
    && typeof candidate.id === 'string'
    && typeof candidate.title === 'string'
    && typeof candidate.host === 'string'
    && typeof candidate.path === 'string'
    && typeof candidate.detail === 'string'
    && typeof candidate.remediation === 'string'
    && candidate.severity
    && candidate.confidence
    && candidate.status,
  );
}

function normalizeFindings(findings: ActiveScanFinding[]): ReportIssue[] {
  const byKey = new Map<string, ReportIssue>();
  for (const finding of findings) {
    const key = finding.dedupeKey ?? `${finding.title}|${finding.host}|${finding.path}`;
    const existing = byKey.get(key);
    if (existing && severityRank[existing.severity] >= severityRank[finding.severity]) continue;
    byKey.set(key, {
      id: finding.id,
      title: finding.title,
      severity: finding.severity,
      host: finding.host,
      path: finding.path,
      confidence: finding.confidence,
      status: 'open',
      detail: finding.confidenceReason ? `${finding.detail} ${finding.confidenceReason}` : finding.detail,
      remediation: finding.remediation,
    });
  }
  return Array.from(byKey.values()).sort((a, b) => severityRank[b.severity] - severityRank[a.severity]);
}

function mergeReportIssues(issues: ReportIssue[]) {
  const byKey = new Map<string, ReportIssue>();
  for (const issue of issues) {
    const key = `${issue.title}|${issue.host}|${issue.path}`.toLowerCase();
    const existing = byKey.get(key);
    if (!existing || severityRank[issue.severity] > severityRank[existing.severity]) {
      byKey.set(key, issue);
    }
  }
  return Array.from(byKey.values()).sort((a, b) => severityRank[b.severity] - severityRank[a.severity]);
}

interface NormalizedSessionProfile {
  headers: Record<string, string>;
  headerCount: number;
  cookieCount: number;
}

function normalizeSessionProfile(profile: HeadlessSessionProfile | undefined): NormalizedSessionProfile {
  const headerEntries = new Map<string, { name: string; value: string }>();
  for (const [name, value] of Object.entries(profile?.headers ?? {})) {
    addSessionHeader(headerEntries, name, value);
  }

  const cookieHeader = renderCookieHeader(profile?.cookies);
  if (cookieHeader) {
    const existing = headerEntries.get('cookie')?.value;
    addSessionHeader(headerEntries, 'Cookie', existing ? `${existing}; ${cookieHeader}` : cookieHeader);
  }

  const headers = Object.fromEntries(Array.from(headerEntries.values()).map((entry) => [entry.name, entry.value]));
  return {
    headers,
    headerCount: Object.keys(headers).length,
    cookieCount: countCookieValues(headers.Cookie ?? headers.cookie ?? ''),
  };
}

function addSessionHeader(target: Map<string, { name: string; value: string }>, name: string, value: unknown) {
  const normalizedName = normalizeHeaderName(name);
  const normalizedValue = normalizeHeaderValue(value);
  if (!normalizedName || !normalizedValue || isForbiddenSessionHeader(normalizedName)) return;
  target.set(normalizedName.toLowerCase(), { name: normalizedName, value: normalizedValue });
}

function normalizeHeaderName(name: string) {
  const trimmed = name.trim();
  if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(trimmed)) return '';
  return trimmed;
}

function normalizeHeaderValue(value: unknown) {
  const text = String(value ?? '').trim();
  if (!text || /[\r\n]/.test(text)) return '';
  return text;
}

function isForbiddenSessionHeader(name: string) {
  return /^(host|content-length|transfer-encoding|connection|proxy-connection|proxy-authorization)$/i.test(name);
}

function renderCookieHeader(cookies: HeadlessSessionProfile['cookies']) {
  if (!cookies) return '';
  if (typeof cookies === 'string') return normalizeCookieHeader(cookies);
  if (Array.isArray(cookies)) return cookies.map(normalizeCookieHeader).filter(Boolean).join('; ');
  return Object.entries(cookies)
    .map(([name, value]) => {
      const cookieName = name.trim();
      const cookieValue = String(value ?? '').trim();
      if (!cookieName || /[;=\r\n]/.test(cookieName) || /[\r\n]/.test(cookieValue)) return '';
      return `${cookieName}=${cookieValue}`;
    })
    .filter(Boolean)
    .join('; ');
}

function normalizeCookieHeader(value: string) {
  return value
    .replace(/^cookie:\s*/i, '')
    .split(';')
    .map((item) => item.trim())
    .filter(Boolean)
    .join('; ');
}

function countCookieValues(cookieHeader: string) {
  if (!cookieHeader.trim()) return 0;
  return cookieHeader.split(';').map((item) => item.trim()).filter(Boolean).length;
}

function applySessionToRawRequest(rawRequest: string, target: URL, headers: Record<string, string>) {
  if (!Object.keys(headers).length) return rawRequest;

  const normalized = rawRequest.replace(/\r\n/g, '\n');
  const [head, ...bodyParts] = normalized.split('\n\n');
  const lines = head.split('\n').filter((line) => line.trim());
  const requestLine = lines.shift() || `GET ${target.pathname || '/'}${target.search} HTTP/1.1`;
  const rawHeaders = new Map<string, { name: string; value: string }>();

  for (const line of lines) {
    const separator = line.indexOf(':');
    if (separator === -1) continue;
    const name = normalizeHeaderName(line.slice(0, separator));
    const value = normalizeHeaderValue(line.slice(separator + 1));
    if (!name || !value || isForbiddenSessionHeader(name)) continue;
    rawHeaders.set(name.toLowerCase(), { name, value });
  }

  rawHeaders.set('host', { name: 'Host', value: target.host });
  for (const [name, value] of Object.entries(headers)) {
    const existing = rawHeaders.get(name.toLowerCase());
    const nextValue = /^cookie$/i.test(name) && existing?.value ? `${existing.value}; ${value}` : value;
    rawHeaders.set(name.toLowerCase(), { name, value: nextValue });
  }

  return [
    requestLine,
    ...Array.from(rawHeaders.values()).map((entry) => `${entry.name}: ${entry.value}`),
    '',
    bodyParts.join('\n\n'),
  ].join('\n');
}

function renderRawRequest(target: URL) {
  return [
    `GET ${target.pathname || '/'}${target.search} HTTP/1.1`,
    `Host: ${target.host}`,
    'User-Agent: ProxyForge Headless Scanner',
    'Accept: text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8',
    '',
    '',
  ].join('\n');
}

function parseTargetUrl(value: string | undefined) {
  if (!value) throw new Error('Headless scan requires --target or a config targetUrl.');
  const target = new URL(value);
  if (target.protocol !== 'http:' && target.protocol !== 'https:') {
    throw new Error('Headless target must be an http or https URL.');
  }
  return target;
}

function isHttpUrl(value: string) {
  try {
    const parsed = new URL(value);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch {
    return false;
  }
}

function normalizeScope(scope: string[] | undefined, target: URL) {
  const normalized = (scope ?? []).map((item) => item.trim()).filter(Boolean);
  return normalized.length ? normalized : [target.hostname];
}

function highestFindingSeverity(findings: ReportIssue[]): Severity | 'none' {
  return findings.reduce<Severity | 'none'>((highest, finding) => (
    highest === 'none' || severityRank[finding.severity] > severityRank[highest] ? finding.severity : highest
  ), 'none');
}

async function exportCiArtifacts(request: {
  outDir: string;
  outputs: HeadlessCiOutputFormat[];
  projectName: string;
  target: URL;
  scopeAllowlist: string[];
  findings: ReportIssue[];
  startedAt: Date;
}): Promise<HeadlessCiArtifact[]> {
  const outputs = Array.from(new Set(request.outputs));
  const generatedAt = new Date().toISOString();
  const artifacts: HeadlessCiArtifact[] = [];
  for (const output of outputs) {
    const fileName = output === 'sarif' ? 'proxyforge-results.sarif' : 'proxyforge-junit.xml';
    const content = output === 'sarif'
      ? renderSarif(request.projectName, request.target, request.scopeAllowlist, request.findings, request.startedAt, generatedAt)
      : renderJunit(request.projectName, request.target, request.findings, request.startedAt, generatedAt);
    const artifactPath = path.join(request.outDir, fileName);
    await fs.writeFile(artifactPath, content, 'utf8');
    artifacts.push({
      format: output,
      fileName,
      path: artifactPath,
      generatedAt,
      findingCount: request.findings.length,
      content,
    });
  }
  return artifacts;
}

function renderSarif(
  projectName: string,
  target: URL,
  scopeAllowlist: string[],
  findings: ReportIssue[],
  startedAt: Date,
  generatedAt: string,
) {
  const rules = Array.from(new Map(findings.map((finding) => [sarifRuleId(finding), finding])).entries())
    .map(([ruleId, finding]) => ({
      id: ruleId,
      name: finding.title,
      shortDescription: { text: finding.title },
      fullDescription: { text: finding.detail },
      help: { text: finding.remediation },
      properties: {
        severity: finding.severity,
        confidence: finding.confidence,
        tags: ['proxyforge', 'web-security', finding.severity],
      },
    }));

  return JSON.stringify({
    version: '2.1.0',
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: [
      {
        tool: {
          driver: {
            name: 'ProxyForge',
            informationUri: 'https://example.invalid/proxyforge',
            rules,
          },
        },
        automationDetails: {
          id: `${projectName.replace(/[^A-Za-z0-9_.-]+/g, '-') || 'proxyforge-headless'}/headless`,
        },
        invocations: [
          {
            executionSuccessful: true,
            startTimeUtc: startedAt.toISOString(),
            endTimeUtc: generatedAt,
            workingDirectory: {
              uri: process.cwd(),
            },
            properties: {
              targetUrl: target.toString(),
              scopeAllowlist,
            },
          },
        ],
        results: findings.map((finding) => ({
          ruleId: sarifRuleId(finding),
          level: sarifLevel(finding.severity),
          message: {
            text: `${finding.title}: ${finding.detail}`,
          },
          locations: [
            {
              physicalLocation: {
                artifactLocation: {
                  uri: findingUrl(target, finding),
                },
                region: {
                  startLine: 1,
                },
              },
              logicalLocations: [
                {
                  name: `${finding.host}${finding.path}`,
                  kind: 'function',
                },
              ],
            },
          ],
          properties: {
            severity: finding.severity,
            confidence: finding.confidence,
            status: finding.status,
            host: finding.host,
            path: finding.path,
            remediation: finding.remediation,
          },
        })),
      },
    ],
  }, null, 2);
}

function renderJunit(projectName: string, target: URL, findings: ReportIssue[], startedAt: Date, generatedAt: string) {
  const elapsedSeconds = Math.max(0, (Date.parse(generatedAt) - startedAt.getTime()) / 1000).toFixed(3);
  const testCases = findings.length
    ? findings.map((finding) => [
        `    <testcase classname="ProxyForge.${xmlEscape(finding.severity)}" name="${xmlEscape(finding.title)}" time="0">`,
        `      <failure type="${xmlEscape(finding.severity)}" message="${xmlEscape(`${finding.host}${finding.path}`)}">${xmlEscape(`${finding.detail}\n\nRemediation: ${finding.remediation}`)}</failure>`,
        '    </testcase>',
      ].join(os.EOL))
    : [
        '    <testcase classname="ProxyForge" name="No findings" time="0" />',
      ];
  const tests = Math.max(1, findings.length);
  return [
    '<?xml version="1.0" encoding="UTF-8"?>',
    `<testsuites name="ProxyForge Headless" tests="${tests}" failures="${findings.length}" errors="0" time="${elapsedSeconds}">`,
    `  <testsuite name="${xmlEscape(projectName)}" tests="${tests}" failures="${findings.length}" errors="0" skipped="0" time="${elapsedSeconds}" timestamp="${xmlEscape(generatedAt)}">`,
    `    <properties><property name="target" value="${xmlEscape(target.toString())}" /></properties>`,
    ...testCases,
    '  </testsuite>',
    '</testsuites>',
    '',
  ].join(os.EOL);
}

function sarifRuleId(finding: ReportIssue) {
  return `PF-${finding.title.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 80) || 'finding'}`;
}

function sarifLevel(severity: Severity) {
  if (severity === 'critical' || severity === 'high') return 'error';
  if (severity === 'medium' || severity === 'low') return 'warning';
  return 'note';
}

function findingUrl(target: URL, finding: ReportIssue) {
  const protocol = target.protocol || 'https:';
  return `${protocol}//${finding.host}${finding.path || '/'}`;
}

function xmlEscape(value: string) {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

function redactSummaryContent(summary: HeadlessScanSummary): HeadlessScanSummary {
  return {
    ...summary,
    reports: summary.reports.map((artifact) => ({
      ...artifact,
      content: artifact.format === 'bundle' || artifact.format === 'json'
        ? artifact.content
        : artifact.content.slice(0, 4000),
    })),
  };
}

async function loadConfig(configPath: string | undefined): Promise<Partial<HeadlessScanConfig>> {
  if (!configPath) return {};
  const raw = await fs.readFile(path.resolve(configPath), 'utf8');
  return JSON.parse(raw) as Partial<HeadlessScanConfig>;
}

function parseCliArgs(argv: string[]): { configPath?: string; overrides: Partial<HeadlessScanConfig> } {
  const args = argv[0] === 'headless' ? argv.slice(1) : argv.slice();
  const overrides: Partial<HeadlessScanConfig> = {};
  let configPath: string | undefined;

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    const value = args[index + 1];
    if (arg === '--config') {
      configPath = requireValue(arg, value);
      index += 1;
    } else if (arg === '--project-file') {
      overrides.projectFile = requireValue(arg, value);
      index += 1;
    } else if (arg === '--project-exchange') {
      overrides.projectExchangeId = requireValue(arg, value);
      index += 1;
    } else if (arg === '--target') {
      overrides.targetUrl = requireValue(arg, value);
      index += 1;
    } else if (arg === '--project') {
      overrides.projectName = requireValue(arg, value);
      index += 1;
    } else if (arg === '--scope') {
      overrides.scopeAllowlist = splitList(requireValue(arg, value));
      index += 1;
    } else if (arg === '--out-dir') {
      overrides.outDir = requireValue(arg, value);
      index += 1;
    } else if (arg === '--header') {
      const parsed = parseHeaderArgument(requireValue(arg, value), arg);
      overrides.session = mergeSessionProfiles(overrides.session, { headers: { [parsed.name]: parsed.value } });
      index += 1;
    } else if (arg === '--cookie') {
      overrides.session = mergeSessionProfiles(overrides.session, { cookies: requireValue(arg, value) });
      index += 1;
    } else if (arg === '--report') {
      overrides.report = { ...overrides.report, formats: splitList(requireValue(arg, value)) as ReportFormat[] };
      index += 1;
    } else if (arg === '--ci-output') {
      overrides.ci = { ...overrides.ci, outputs: splitList(requireValue(arg, value)) as HeadlessCiOutputFormat[] };
      index += 1;
    } else if (arg === '--sarif') {
      overrides.ci = { ...overrides.ci, outputs: mergeOutputs(overrides.ci?.outputs, ['sarif']) };
    } else if (arg === '--junit') {
      overrides.ci = { ...overrides.ci, outputs: mergeOutputs(overrides.ci?.outputs, ['junit']) };
    } else if (arg === '--checks') {
      overrides.activeScan = { ...overrides.activeScan, checks: splitList(requireValue(arg, value)) as ActiveScanCheckId[] };
      index += 1;
    } else if (arg === '--max-active-requests') {
      overrides.activeScan = { ...overrides.activeScan, maxRequests: parsePositiveInteger(requireValue(arg, value), arg) };
      index += 1;
    } else if (arg === '--crawl-depth') {
      overrides.crawl = { ...overrides.crawl, maxDepth: parsePositiveInteger(requireValue(arg, value), arg) };
      index += 1;
    } else if (arg === '--crawl-pages') {
      overrides.crawl = { ...overrides.crawl, maxPages: parsePositiveInteger(requireValue(arg, value), arg) };
      index += 1;
    } else if (arg === '--throttle') {
      const throttleMs = parsePositiveInteger(requireValue(arg, value), arg);
      overrides.crawl = { ...overrides.crawl, throttleMs };
      overrides.activeScan = { ...overrides.activeScan, throttleMs };
      overrides.crawlAudit = { ...overrides.crawlAudit, throttleMs };
      index += 1;
    } else if (arg === '--crawl-audit') {
      overrides.crawlAudit = { ...overrides.crawlAudit, enabled: true };
    } else if (arg === '--no-crawl') {
      overrides.crawl = { ...overrides.crawl, enabled: false };
    } else if (arg === '--no-active-scan') {
      overrides.activeScan = { ...overrides.activeScan, enabled: false };
    } else if (arg === '--fail-on') {
      overrides.failOnSeverity = requireValue(arg, value) as Severity | 'none';
      index += 1;
    } else if (arg === '--sign-bundle') {
      overrides.report = { ...overrides.report, signEvidenceBundle: true };
    } else if (arg === '--signing-secret') {
      overrides.report = { ...overrides.report, signingSecret: requireValue(arg, value) };
      index += 1;
    } else if (arg === '--help' || arg === '-h') {
      throw new CliHelp();
    } else if (arg === '--workflow') {
      index += 1;
    } else {
      throw new Error(`Unknown headless option: ${arg}`);
    }
  }

  return { configPath, overrides };
}

function mergeConfig(base: Partial<HeadlessScanConfig>, overrides: Partial<HeadlessScanConfig>): HeadlessScanConfig {
  const ciOutputs = mergeOutputs(base.ci?.outputs, overrides.ci?.outputs ?? []);
  const environment = loadEnvironmentConfig();
  return {
    ...base,
    ...environment,
    ...overrides,
    session: mergeSessionProfiles(base.session, environment.session, overrides.session),
    crawl: { ...base.crawl, ...environment.crawl, ...overrides.crawl },
    activeScan: { ...base.activeScan, ...environment.activeScan, ...overrides.activeScan },
    crawlAudit: { ...base.crawlAudit, ...environment.crawlAudit, ...overrides.crawlAudit },
    report: { ...base.report, ...environment.report, ...overrides.report },
    ci: { ...base.ci, ...environment.ci, ...overrides.ci, outputs: ciOutputs },
  } as HeadlessScanConfig;
}

function loadEnvironmentConfig(): Partial<HeadlessScanConfig> {
  const session: HeadlessSessionProfile = {};
  const headers: Record<string, string> = {};
  const authorization = process.env.PROXYFORGE_AUTHORIZATION?.trim();
  const bearerToken = process.env.PROXYFORGE_BEARER_TOKEN?.trim();
  const apiKey = process.env.PROXYFORGE_API_KEY?.trim();
  const headerBlock = process.env.PROXYFORGE_SESSION_HEADERS?.trim();
  const cookie = process.env.PROXYFORGE_COOKIE?.trim();

  if (headerBlock) Object.assign(headers, parseHeaderBlock(headerBlock));
  if (authorization) headers.Authorization = authorization;
  if (!authorization && bearerToken) headers.Authorization = `Bearer ${bearerToken}`;
  if (apiKey) headers['X-API-Key'] = apiKey;
  if (Object.keys(headers).length) session.headers = headers;
  if (cookie) session.cookies = cookie;
  return Object.keys(headers).length || cookie ? { session } : {};
}

function mergeSessionProfiles(...profiles: Array<HeadlessSessionProfile | undefined>): HeadlessSessionProfile | undefined {
  const headers: Record<string, string> = {};
  const cookies: string[] = [];
  for (const profile of profiles) {
    if (!profile) continue;
    for (const [name, value] of Object.entries(profile.headers ?? {})) {
      const normalizedName = normalizeHeaderName(name);
      const normalizedValue = normalizeHeaderValue(value);
      if (!normalizedName || !normalizedValue || isForbiddenSessionHeader(normalizedName)) continue;
      headers[normalizedName] = normalizedValue;
    }
    const cookieHeader = renderCookieHeader(profile.cookies);
    if (cookieHeader) cookies.push(cookieHeader);
  }
  const mergedCookies = cookies.join('; ');
  if (!Object.keys(headers).length && !mergedCookies) return undefined;
  return {
    ...(Object.keys(headers).length ? { headers } : {}),
    ...(mergedCookies ? { cookies: mergedCookies } : {}),
  };
}

function parseHeaderBlock(value: string) {
  if (value.trim().startsWith('{')) {
    const parsed = JSON.parse(value) as Record<string, unknown>;
    return Object.fromEntries(
      Object.entries(parsed)
        .map(([name, headerValue]) => [normalizeHeaderName(name), normalizeHeaderValue(headerValue)] as const)
        .filter(([name, headerValue]) => Boolean(name && headerValue && !isForbiddenSessionHeader(name))),
    );
  }
  return Object.fromEntries(
    value
      .split(/\n+/)
      .map((line) => line.trim())
      .filter(Boolean)
      .map((line) => {
        const parsed = parseHeaderArgument(line, 'PROXYFORGE_SESSION_HEADERS');
        return [parsed.name, parsed.value] as const;
      }),
  );
}

function parseHeaderArgument(value: string, flag: string) {
  const separator = value.indexOf(':');
  const alternateSeparator = value.indexOf('=');
  const splitAt = separator === -1 || (alternateSeparator !== -1 && alternateSeparator < separator)
    ? alternateSeparator
    : separator;
  if (splitAt <= 0) throw new Error(`${flag} requires a header in "Name: value" form.`);
  const name = normalizeHeaderName(value.slice(0, splitAt));
  const headerValue = normalizeHeaderValue(value.slice(splitAt + 1));
  if (!name || !headerValue || isForbiddenSessionHeader(name)) throw new Error(`${flag} includes an invalid or unsafe header.`);
  return { name, value: headerValue };
}

function splitList(value: string) {
  return value.split(',').map((item) => item.trim()).filter(Boolean);
}

function mergeOutputs(current: HeadlessCiOutputFormat[] | undefined, next: HeadlessCiOutputFormat[]) {
  return Array.from(new Set([...(current ?? []), ...next]));
}

function requireValue(flag: string, value: string | undefined) {
  if (!value || value.startsWith('--')) throw new Error(`${flag} requires a value.`);
  return value;
}

function parsePositiveInteger(value: string, flag: string) {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed) || parsed < 0) throw new Error(`${flag} requires a positive integer.`);
  return parsed;
}

class CliHelp extends Error {}

function usage() {
  return [
    'ProxyForge headless scanner',
    '',
    'Usage:',
    '  proxyforge headless --target https://app.example.test --scope app.example.test --report json,markdown',
    '  node dist-electron/headlessRunner.js --config proxyforge-headless.json',
    '',
    'Options:',
    '  --config <file>               Load a JSON headless scan config.',
    '  --project-file <file>         Load a .proxyforge.json project snapshot.',
    '  --project-exchange <id>       Replay/scan from a saved project exchange.',
    '  --target <url>                Target URL to crawl and scan.',
    '  --scope <hosts>               Comma-separated host allowlist.',
    '  --out-dir <dir>               Artifact output directory.',
    '  --header <name:value>         Add an authenticated session header; repeatable.',
    '  --cookie <cookie>             Add Cookie header values for authenticated scans.',
    '  --report <formats>            Comma-separated json,markdown,html,pdf,bundle.',
    '  --ci-output <formats>         Comma-separated sarif,junit.',
    '  --sarif                       Write proxyforge-results.sarif.',
    '  --junit                       Write proxyforge-junit.xml.',
    '  --checks <ids>                Comma-separated active scanner check IDs.',
    '  --crawl-audit                 Audit crawler insertion points.',
    '  --fail-on <severity|none>     Return exit code 2 at or above severity.',
    '  --no-crawl                    Skip crawler.',
    '  --no-active-scan              Skip active scanner.',
  ].join(os.EOL);
}

async function main() {
  try {
    const { configPath, overrides } = parseCliArgs(process.argv.slice(2));
    const config = mergeConfig(await loadConfig(configPath), overrides);
    const summary = await runHeadlessScan(config);
    process.stdout.write(`${JSON.stringify(redactSummaryContent(summary), null, 2)}${os.EOL}`);
    process.exitCode = summary.exitCode;
  } catch (error) {
    if (error instanceof CliHelp) {
      process.stdout.write(`${usage()}${os.EOL}`);
      process.exitCode = 0;
      return;
    }
    process.stderr.write(`${error instanceof Error ? error.message : 'Headless scan failed'}${os.EOL}`);
    process.exitCode = 1;
  }
}

if (require.main === module) {
  void main();
}
