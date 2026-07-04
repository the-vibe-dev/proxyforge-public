import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import path from 'node:path';

const require = createRequire(import.meta.url);
const {
  ProjectStore,
  ProjectStoreReportRecorder,
} = require('../dist-electron/projectStore.js');
const {
  ReportEngine,
  verifyEvidenceBundleText,
} = require('../dist-electron/reportEngine.js');

const artifactRoot = path.resolve('.gitignored/test-artifacts/project-store-issue-report-workflow', `${Date.now()}-${process.pid}`);
const projectDir = path.join(artifactRoot, 'issue-report-workflow.proxyforge');
const reportsDir = path.join(artifactRoot, 'reports');
await fs.mkdir(artifactRoot, { recursive: true });

let seedStore;
let reopened;
let restored;

const requestRaw = [
  'POST /api/profile?token=issue-report-query-secret HTTP/1.1',
  'Host: app.issue-report.local',
  'Authorization: Bearer issue-report-bearer-secret',
  'X-API-Key: issue-report-api-key-secret',
  'Cookie: pf_session=issue-report-cookie-secret',
  'Content-Type: application/json',
  '',
  '{"api_key":"issue-report-json-key","role":"admin"}',
].join('\r\n');

const responseRaw = [
  'HTTP/1.1 200 OK',
  'Content-Type: application/json',
  'Set-Cookie: pf_session=issue-report-response-cookie',
  '',
  '{"token":"issue-report-response-token","role":"support_admin"}',
].join('\r\n');

const exchange = {
  id: 'hx-issue-report-profile',
  method: 'POST',
  url: 'https://app.issue-report.local/api/profile?token=issue-report-query-secret',
  host: 'app.issue-report.local',
  path: '/api/profile?token=issue-report-query-secret',
  protocol: 'https',
  status: 200,
  mime: 'application/json',
  timingMs: 42,
  source: 'proxy',
  tags: ['issue-report', 'full-fidelity'],
  notes: 'Captured with raw Authorization, Cookie, and API key material for execution.',
  requestRaw,
  responseRaw,
};

const reportExchange = {
  id: exchange.id,
  method: exchange.method,
  host: exchange.host,
  path: exchange.path,
  url: exchange.url,
  status: exchange.status,
  length: Buffer.byteLength(responseRaw),
  mime: exchange.mime,
  risk: 'high',
  timing: exchange.timingMs,
  notes: 'Evidence notes include token=issue-report-note-secret before export redaction.',
  source: 'proxy',
  time: '14:22:10',
  requestRaw,
  responseRaw,
  tags: exchange.tags,
};

const issue = {
  id: 'issue-report-manual-1',
  title: 'Profile response leaks role material token=issue-report-title-secret',
  severity: 'high',
  host: exchange.host,
  path: exchange.path,
  confidence: 'firm',
  status: 'open',
  detail: 'Manual triage preserved Bearer issue-detail-secret and api_key=issue-detail-api-key until report export.',
  remediation: 'Remove the role leak and rotate secret=issue-remediation-secret after validating the fix.',
  assignee: 'Identity Platform',
  triageNote: 'Keep session=issue-triage-session for executor replay only.',
};

const request = {
  projectName: 'Project Store Issue Report Workflow',
  scopeAllowlist: ['app.issue-report.local'],
  format: 'bundle',
  sections: ['executive', 'technical', 'remediation', 'evidence', 'appendix'],
  templateId: 'evidence-bundle',
  preparedFor: 'Authorized QA',
  engagementId: 'PF-ISSUE-REPORT',
  signEvidenceBundle: true,
  signingKeyId: 'project-store-issue-report-key',
  signingSecret: 'project-store-issue-report-signing-secret',
  signerName: 'Project Store Test Signer',
  issues: [issue],
  exchanges: [reportExchange],
  crossToolEvidenceAttachments: [
    {
      id: 'send-issue-report-profile',
      title: 'Repeater send with linked raw proof',
      fileName: 'send-issue-report-profile.json',
      path: 'evidence/repeater/send-issue-report-profile.json',
      createdAt: '2026-05-26T12:00:00.000Z',
      reportReady: true,
      issueId: issue.id,
      summary: 'Repeater send points at the same profile proof.',
      content: '{"Authorization":"Bearer cross-tool-secret","session":"cross-tool-session"}',
      tool: 'repeater',
      kind: 'repeater-send',
      signatureStatus: 'ready-on-export',
      sha256: 'f'.repeat(64),
    },
  ],
};

try {
  seedStore = await ProjectStore.create(projectDir, {
    projectName: request.projectName,
    projectId: 'project-store-issue-report-workflow',
  });
  await seedStore.addHttpExchange(exchange);
  await seedStore.addRepeaterSend({
    id: 'send-issue-report-profile',
    tabId: 'rt-issue-report-profile',
    exchangeId: exchange.id,
    targetUrl: exchange.url,
    rawRequest: requestRaw,
    responseRaw,
    status: exchange.status,
    mime: exchange.mime,
    timingMs: exchange.timingMs,
    sourceExchangeId: exchange.id,
    tags: ['issue-report'],
    notes: 'Repeater send keeps raw token material before report export.',
  });
  seedStore.close();
  seedStore = null;

  const engine = new ReportEngine(reportsDir);
  const artifact = await engine.exportReport(request);
  assert.equal(artifact.format, 'bundle');
  assert.equal(artifact.issueCount, 1);
  assert.equal(artifact.exchangeCount, 1);

  const reportSecrets = [
    'issue-report-bearer-secret',
    'issue-report-api-key-secret',
    'issue-report-cookie-secret',
    'issue-report-json-key',
    'issue-report-response-token',
    'issue-detail-secret',
    'issue-detail-api-key',
    'issue-remediation-secret',
    'issue-triage-session',
    'cross-tool-secret',
    'cross-tool-session',
  ];
  for (const secret of reportSecrets) {
    assert(!artifact.content.includes(secret), `report export leaked ${secret}`);
  }
  assert.match(artifact.content, /\[redacted\]/);

  const verification = verifyEvidenceBundleText(artifact.content, request.signingSecret);
  assert.equal(verification.status, 'valid');

  const recorder = new ProjectStoreReportRecorder(projectDir, {
    projectName: request.projectName,
    projectId: 'project-store-issue-report-workflow',
  });
  await recorder.recordExport(request, artifact);
  assert.equal(recorder.stats().failedCount, 0);
  assert.equal(recorder.stats().persistedIssueCount, 1);
  assert.equal(recorder.stats().persistedReportCount, 1);
  await recorder.close();

  reopened = await ProjectStore.open(projectDir);
  const stats = reopened.stats();
  assert.equal(stats.exchangeCount, 1);
  assert.equal(stats.repeaterSendCount, 1);
  assert.equal(stats.issueCount, 1);
  assert.equal(stats.reportExportCount, 1);
  assert(stats.reportBytes > 0);
  assert(stats.blobCount >= 3);

  const storedIssue = reopened.getIssue(issue.id);
  assert(storedIssue);
  assert.match(storedIssue.detail, /Bearer issue-detail-secret/);
  assert.match(storedIssue.remediation, /secret=issue-remediation-secret/);
  assert.match(storedIssue.triageNote, /session=issue-triage-session/);
  assert(storedIssue.evidenceRefs.some((ref) => ref.kind === 'http-exchange' && ref.id === exchange.id));
  assert(storedIssue.evidenceRefs.some((ref) => ref.kind === 'repeater-send' && ref.id === 'send-issue-report-profile'));

  const storedExchange = reopened.getHttpExchange(exchange.id);
  assert(storedExchange);
  assert.match(storedExchange.requestRaw.toString('utf8'), /Authorization: Bearer issue-report-bearer-secret/);
  assert.match(storedExchange.responseRaw.toString('utf8'), /issue-report-response-token/);

  const storedReport = reopened.getReportExport(artifact.id);
  assert(storedReport);
  assert.equal(storedReport.signatureStatus, 'signed');
  assert.equal(storedReport.signerName, request.signerName);
  assert.equal(storedReport.keyId, request.signingKeyId);
  assert.equal(storedReport.redacted, true);
  assert.equal(storedReport.issueIds[0], issue.id);
  assert.equal(storedReport.exchangeIds[0], exchange.id);
  const storedReportText = storedReport.content.toString('utf8');
  assert.equal(verifyEvidenceBundleText(storedReportText, request.signingSecret).status, 'valid');
  for (const secret of reportSecrets) {
    assert(!storedReportText.includes(secret), `stored report export leaked ${secret}`);
  }
  assert.match(storedReportText, /\[redacted\]/);

  const auditEvents = reopened.listAuditEvents({ action: 'report.exported', limit: 10 });
  assert.equal(auditEvents.length, 1);

  const backup = await reopened.createBackup(path.join(artifactRoot, 'backups'), { label: 'issue-report' });
  assert.equal(backup.stats.issueCount, 1);
  assert.equal(backup.stats.reportExportCount, 1);
  reopened.close();
  reopened = null;

  restored = await ProjectStore.open(backup.backupDir);
  assert.equal(restored.stats().issueCount, 1);
  assert.equal(restored.stats().reportExportCount, 1);
  assert.match(restored.getIssue(issue.id).detail, /issue-detail-secret/);
  assert.equal(verifyEvidenceBundleText(restored.getReportExport(artifact.id).content.toString('utf8'), request.signingSecret).status, 'valid');

  console.log(`project-store-issue-report-workflow: persisted issue/report workflow, raw project evidence, report-only redaction, signature verification, and backup restore from ${projectDir}`);
} finally {
  restored?.close();
  reopened?.close();
  seedStore?.close();
}
