import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

const require = createRequire(import.meta.url);
const {
  ReportEngine,
  buildPdfRenderQaMetadata,
  buildReportExternalBundleDiversityPackage,
  buildReportParityEvidencePackage,
  buildReportProductionReadinessPackage,
  buildReportTemplateLibraryInteropPackage,
  renderReport,
  verifyEvidenceBundleText,
} = require('../dist-electron/reportEngine.js');

const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'proxyforge-report-'));

const request = {
  projectName: 'Retail API Assessment',
  scopeAllowlist: ['*.shop.local'],
  format: 'markdown',
  sections: ['executive', 'technical', 'remediation', 'evidence', 'appendix'],
  issues: [
    {
      id: 'issue-1',
      title: 'Role hint exposed in profile response',
      severity: 'medium',
      host: 'app.shop.local',
      path: '/api/account/profile',
      confidence: 'firm',
      status: 'open',
      detail: 'Profile response exposes internal role labels and pf_live_validation_secret.',
      remediation: 'Avoid returning internal role labels unless required by the current workflow.',
      assignee: 'Identity Platform',
      triageNote: 'Needs retest against the user profile role boundary.',
      evidence: [
        {
          exchangeId: 'hx-1',
          summary: 'Evidence has pf_live_validation_token and pf_live_validation_secret.',
        },
      ],
    },
  ],
  exchanges: [
    {
      id: 'hx-1',
      method: 'GET',
      host: 'app.shop.local',
      path: '/api/account/profile',
      url: 'https://app.shop.local/api/account/profile',
      status: 200,
      length: 1842,
      mime: 'application/json',
      risk: 'medium',
      timing: 128,
      notes: 'Session object exposes role hints',
      source: 'proxy',
      time: '13:18:42',
      requestRaw: 'GET /api/account/profile HTTP/2\nHost: app.shop.local\nAuthorization: Bearer SECRET_TOKEN\nCookie: session=abc123\n\n',
      responseRaw: 'HTTP/2 200 OK\nContent-Type: application/json\nX-Live-Header: pf_live_validation_token\n\n{"api_key":"SECRET_API_KEY","role":"support_admin","secret":"pf_live_validation_secret"}',
      requestHeaders: {
        Authorization: 'Bearer pf_live_validation_token',
        Cookie: 'session=pf_live_validation_secret',
      },
      responseHeaders: {
        'Set-Cookie': 'session=pf_live_validation_secret; HttpOnly',
        'X-Live-Header': 'pf_live_validation_token',
      },
      requestBody: '{"secret":"pf_live_validation_secret","token":"pf_live_validation_token"}',
      responseBody: '{"echoedSecret":"pf_live_validation_secret","echoedToken":"pf_live_validation_token"}',
      tags: ['in-scope', 'auth'],
    },
  ],
  loggerImportJobs: [
    {
      id: 'logger-job-1',
      importedAt: '2026-05-23T12:00:00.000Z',
      format: 'har',
      mappingPresetName: 'Partner HAR replay',
      normalization: 'replay-proof',
      notes: 'Batch replayed from partner HAR import job.',
      addedEntries: 1,
      changedEntries: 2,
      duplicateEntries: 0,
      sourceHosts: ['app.shop.local'],
      replayCount: 1,
      replayedAt: '2026-05-23T12:02:00.000Z',
      exchangeCount: 3,
    },
  ],
  targetSiteMapEvidenceAttachments: [
    {
      id: 'target-site-map-1',
      title: 'Target site-map comparison',
      fileName: 'target-site-map-comparison.json',
      path: 'reports/target-site-map-comparison.json',
      createdAt: '2026-05-23T12:03:00.000Z',
      reportReady: true,
      issueId: 'issue-1',
      summary: 'Target comparison linked role-sensitive route drift to the profile finding.',
      content: '{"kind":"proxyforge-target-map-comparison","Authorization":"Bearer TARGET_ATTACHMENT_TOKEN","Cookie":"session=target-attachment-session"}',
    },
  ],
  proxyHistoryEvidenceAttachments: [
    {
      id: 'proxy-history-1',
      title: 'Proxy handoff package',
      fileName: 'proxy-history-handoff.json',
      path: 'reports/proxy-history-handoff.json',
      createdAt: '2026-05-23T12:04:00.000Z',
      reportReady: true,
      issueId: 'issue-1',
      summary: 'Proxy handoff preserved selected raw requests and Reports fingerprints.',
      content: '{"kind":"proxyforge-proxy-cross-tool-handoff-package","X-API-Key":"PROXY_ATTACHMENT_KEY","token":"PROXY_ATTACHMENT_TOKEN"}',
    },
  ],
  scannerActiveScanEvidencePackages: [
    {
      id: 'scanner-active-1',
      title: 'Scanner active scan package',
      fileName: 'scanner-active-scan-evidence.json',
      path: 'reports/scanner-active-scan-evidence.json',
      createdAt: '2026-05-23T12:05:00.000Z',
      planId: 'scanner-plan-1',
      insertionPointReviewId: 'insertion-review-1',
      authenticatedStateMatrixId: 'auth-state-1',
      replayCheckPackageId: 'replay-check-1',
      activeScanSummaryId: 'active-summary-1',
      findingCount: 1,
      exchangeIds: ['hx-1'],
      ciCommand: 'proxyforge --scan --report',
      reportReady: true,
      summary: 'Scanner active scan evidence linked authenticated state and replay-derived checks.',
      content: '{"kind":"proxyforge-scanner-active-scan-evidence-package","Authorization":"Bearer SCANNER_ATTACHMENT_TOKEN","api_key":"SCANNER_ATTACHMENT_KEY"}',
    },
  ],
  crossToolEvidenceAttachments: [
    {
      id: 'callback-package-1',
      title: 'Callback signed poll batch',
      fileName: 'callback-signed-poll.json',
      path: 'reports/callback-signed-poll.json',
      createdAt: '2026-05-23T12:06:00.000Z',
      reportReady: true,
      issueId: 'issue-1',
      summary: 'Callback package linked OAST interaction evidence.',
      content: '{"kind":"proxyforge-callback-evidence-package","secret":"CALLBACK_ATTACHMENT_SECRET"}',
      tool: 'callback',
      kind: 'proxyforge-callback-evidence-package',
      signatureStatus: 'signed',
      sha256: 'a'.repeat(64),
    },
    {
      id: 'extension-handoff-1',
      title: 'Extension evidence handoff',
      fileName: 'extension-evidence-handoff.json',
      path: 'reports/extension-evidence-handoff.json',
      createdAt: '2026-05-23T12:07:00.000Z',
      reportReady: true,
      issueId: 'issue-1',
      summary: 'Extension package preserved listener mutation evidence.',
      content: '{"kind":"proxyforge-extension-evidence-handoff","x-api-key":"EXTENSION_ATTACHMENT_KEY"}',
      tool: 'extensions',
      kind: 'proxyforge-extension-evidence-handoff',
      signatureStatus: 'valid',
      sha256: 'b'.repeat(64),
    },
    {
      id: 'exploit-package-1',
      title: 'Exploit package review',
      fileName: 'exploit-package-review.json',
      path: 'reports/exploit-package-review.json',
      createdAt: '2026-05-23T12:08:00.000Z',
      reportReady: true,
      issueId: 'issue-1',
      summary: 'Exploit package preserved non-destructive validation context.',
      content: '{"kind":"proxyforge-exploit-package","session":"EXPLOIT_ATTACHMENT_SESSION"}',
      tool: 'exploit',
      kind: 'proxyforge-exploit-package',
      signatureStatus: 'ready-on-export',
      sha256: 'c'.repeat(64),
    },
  ],
};

function readPdfRenderQaMetadata(html) {
  const match = html.match(/<script type="application\/json" id="proxyforge-pdf-render-qa">([\s\S]*?)<\/script>/);
  assert(match, 'expected embedded PDF render QA metadata');
  return JSON.parse(match[1]);
}

try {
  const engine = new ReportEngine(tempDir, async (html) => {
    assert.match(html, /Retail API Assessment Security Assessment/);
    assert.match(html, /printToPDF|Security Assessment PDF|ProxyForge/);
    const metadata = readPdfRenderQaMetadata(html);
    assert.equal(metadata.renderer, 'electron-printToPDF');
    assert.equal(metadata.validation.passed, true);
    assert.match(metadata.visualQa.deterministicContentHash, /^[a-f0-9]{64}$/);
    return Buffer.from('%PDF-1.4\n% ProxyForge test PDF\n', 'utf8');
  });
  const artifact = await engine.exportReport(request);
  const content = await fs.readFile(artifact.path, 'utf8');
  if (process.platform !== 'win32') {
    assert.equal((await fs.stat(tempDir)).mode & 0o777, 0o700, 'report directory should be private');
    assert.equal((await fs.stat(artifact.path)).mode & 0o777, 0o600, 'report file should be private');
  }

  assert.equal(artifact.format, 'markdown');
  assert.equal(artifact.issueCount, 1);
  assert.equal(artifact.exchangeCount, 1);
  assert.match(artifact.fileName, /^retail-api-assessment-.*\.md$/);
  assert.match(content, /Executive Summary/);
  assert.match(content, /Technical Findings/);
  assert.match(content, /Remediation Plan/);
  assert.match(content, /Identity Platform/);
  assert.match(content, /Replay linked evidence after the fix/);
  assert.match(content, /Role hint exposed in profile response/);
  assert.match(content, /Logger Import Jobs/);
  assert.match(content, /Partner HAR replay/);
  assert.match(content, /Batch replayed from partner HAR import job/);
  assert.match(content, /Target Site Map Evidence/);
  assert.match(content, /Proxy History Evidence/);
  assert.match(content, /Scanner Active Scan Evidence Packages/);
  assert.match(content, /Cross-Tool Evidence Attachments/);
  assert.match(content, /Authorization: \[redacted\]/i);
  assert.match(content, /Cookie: \[redacted\]/i);
  assert.match(content, /api_key":"\[redacted\]/i);
  assert(!content.includes('SECRET_TOKEN'));
  assert(!content.includes('session=abc123'));
  assert(!content.includes('SECRET_API_KEY'));
  assert(!content.includes('pf_live_validation_token'));
  assert(!content.includes('pf_live_validation_secret'));
  assert(!content.includes('TARGET_ATTACHMENT_TOKEN'));
  assert(!content.includes('PROXY_ATTACHMENT_KEY'));
  assert(!content.includes('SCANNER_ATTACHMENT_TOKEN'));
  assert(!content.includes('CALLBACK_ATTACHMENT_SECRET'));
  assert(!content.includes('EXTENSION_ATTACHMENT_KEY'));
  assert(!content.includes('EXPLOIT_ATTACHMENT_SESSION'));

  const json = renderReport({ ...request, format: 'json', sections: ['executive', 'technical', 'remediation'] }, new Date('2026-05-23T12:00:00.000Z'));
  const parsed = JSON.parse(json);
  assert.equal(parsed.summary.totalIssues, 1);
  assert.equal(parsed.summary.loggerImportJobs, 1);
  assert.equal(parsed.summary.targetSiteMapEvidence, 1);
  assert.equal(parsed.summary.proxyHistoryEvidence, 1);
  assert.equal(parsed.summary.scannerActiveScanEvidencePackages, 1);
  assert.equal(parsed.summary.crossToolEvidence, 3);
  assert.equal(parsed.remediationPlan.length, 1);
  assert.equal(parsed.remediationPlan[0].owner, 'Identity Platform');
  assert.equal(parsed.remediationPlan[0].evidenceCount, 1);
  assert.equal(parsed.exchanges.length, 0);
  assert.equal(parsed.loggerImportJobs.length, 0);
  const parsedJsonText = JSON.stringify(parsed);
  assert(!parsedJsonText.includes('pf_live_validation_token'));
  assert(!parsedJsonText.includes('pf_live_validation_secret'));

  const jsonWithEvidence = renderReport({ ...request, format: 'json', sections: ['executive', 'technical', 'evidence'] }, new Date('2026-05-23T12:00:00.000Z'));
  const parsedJsonWithEvidence = JSON.parse(jsonWithEvidence);
  assert.match(jsonWithEvidence, /Bearer \[redacted\]/);
  assert.match(jsonWithEvidence, /session=\[redacted\]/);
  assert.equal(parsedJsonWithEvidence.exchanges[0].requestBody, '{"secret":"[redacted]","token":"[redacted]"}');
  assert.equal(parsedJsonWithEvidence.exchanges[0].responseBody, '{"echoedSecret":"[redacted]","echoedToken":"[redacted]"}');
  assert(!jsonWithEvidence.includes('pf_live_validation_token'));
  assert(!jsonWithEvidence.includes('pf_live_validation_secret'));

  const html = renderReport({ ...request, format: 'html', sections: ['executive'] }, new Date('2026-05-23T12:00:00.000Z'));
  assert.match(html, /<!doctype html>/);
  assert.match(html, /Retail API Assessment Security Assessment/);
  assert.match(html, /ProxyForge/);

  const pdfHtml = renderReport({ ...request, format: 'pdf', sections: ['executive', 'technical', 'remediation'] }, new Date('2026-05-23T12:00:00.000Z'));
  assert.match(pdfHtml, /Security Assessment PDF/);
  assert.match(pdfHtml, /@page/);
  assert.match(pdfHtml, /id="proxyforge-pdf-render-qa"/);
  assert.match(pdfHtml, /data-pdf-section="technical"/);
  assert.match(pdfHtml, /break-before:page/);
  assert.match(pdfHtml, /Role hint exposed in profile response/);
  assert.match(pdfHtml, /Remediation Plan/);
  const pdfQaMetadata = readPdfRenderQaMetadata(pdfHtml);
  assert.equal(pdfQaMetadata.validation.passed, true);
  assert.deepEqual(pdfQaMetadata.sectionOrder, ['executive', 'technical', 'remediation']);
  assert.equal(pdfQaMetadata.pageBreaks.length, 3);
  assert.equal(pdfQaMetadata.pageBreaks[1].section, 'technical');
  assert.equal(pdfQaMetadata.summary.estimatedPageCount >= 4, true);
  assert.equal(pdfQaMetadata.visualQa.avoidBreakSelectors.includes('.pdf-evidence-block'), true);
  assert.match(pdfQaMetadata.visualQa.deterministicContentHash, /^[a-f0-9]{64}$/);

  const directPdfQaMetadata = buildPdfRenderQaMetadata({
    ...request,
    format: 'pdf',
    sections: ['executive', 'technical', 'remediation', 'evidence', 'appendix'],
  }, new Date('2026-05-23T12:00:00.000Z'));
  assert.equal(directPdfQaMetadata.summary.sectionCount, 5);
  assert.equal(directPdfQaMetadata.pageBreaks.length, 5);
  assert.equal(directPdfQaMetadata.pageBreaks[0].estimatedStartPage, 2);
  assert.equal(directPdfQaMetadata.pageBreaks.every((pageBreak, index, pageBreaks) => index === 0 || pageBreak.estimatedStartPage > pageBreaks[index - 1].estimatedStartPage), true);
  assert.equal(directPdfQaMetadata.validation.checks.includes('forced-section-breaks:5/5'), true);

  const pdfArtifact = await engine.exportReport({ ...request, format: 'pdf', sections: ['executive', 'technical', 'evidence'] });
  const pdfContent = await fs.readFile(pdfArtifact.path);
  if (process.platform !== 'win32') {
    assert.equal((await fs.stat(pdfArtifact.path)).mode & 0o777, 0o600, 'PDF report file should be private');
  }
  assert.equal(pdfArtifact.format, 'pdf');
  assert.match(pdfArtifact.fileName, /^retail-api-assessment-.*\.pdf$/);
  assert.match(pdfContent.toString('utf8'), /^%PDF-1\.4/);
  assert.match(pdfArtifact.content, /PDF report package/);
  assert.match(pdfArtifact.content, /Electron printToPDF/);
  assert.match(pdfArtifact.content, /PDF render QA metadata/);
  assert.match(pdfArtifact.content, /Forced page breaks: executive@2, technical@3, evidence@4/);
  assert.match(pdfArtifact.content, /Content hash: [a-f0-9]{64}/);

  const customMarkdown = renderReport({
    ...request,
    format: 'markdown',
    sections: ['executive', 'technical', 'remediation', 'evidence', 'appendix'],
    templateId: 'custom',
    brandName: 'Acme Security',
    preparedFor: 'Retail Board',
    engagementId: 'ENG-CUSTOM',
    customTemplateName: 'Operator narrative',
    customTemplateBody: [
      '# {{projectName}} Custom Narrative',
      '',
      'For {{preparedFor}} by {{brandName}}',
      'Template: {{templateName}}',
      'Findings: {{summary.totalIssues}}',
      'Evidence: {{summary.evidenceItems}}',
      '',
      '{{findingsMarkdown}}',
      '',
      '{{remediationMarkdown}}',
      '',
      '{{evidenceMarkdown}}',
    ].join('\n'),
  }, new Date('2026-05-23T12:00:00.000Z'));
  assert.match(customMarkdown, /Retail API Assessment Custom Narrative/);
  assert.match(customMarkdown, /Template: Operator narrative/);
  assert.match(customMarkdown, /Findings: 1/);
  assert.match(customMarkdown, /Evidence: 1/);
  assert.match(customMarkdown, /Role hint exposed in profile response/);
  assert.match(customMarkdown, /Remediation Plan/);
  assert.match(customMarkdown, /Logger Import Jobs/);
  assert.match(customMarkdown, /Authorization: \[redacted\]/i);
  assert(!customMarkdown.includes('SECRET_TOKEN'));
  assert(!customMarkdown.includes('SECRET_API_KEY'));

  const customHtml = renderReport({
    ...request,
    format: 'html',
    templateId: 'custom',
    customTemplateName: 'Operator narrative',
    customTemplateBody: '# {{projectName}} Custom HTML\n\n{{executiveMarkdown}}',
  }, new Date('2026-05-23T12:00:00.000Z'));
  assert.match(customHtml, /<!doctype html>/);
  assert.match(customHtml, /Custom HTML/);

  const bundle = renderReport({
    ...request,
    format: 'bundle',
    sections: ['executive', 'technical', 'remediation', 'evidence', 'appendix'],
    templateId: 'evidence-bundle',
    brandName: 'Acme Security',
    preparedFor: 'Retail Board',
    engagementId: 'ENG-42',
    signEvidenceBundle: true,
    signerName: 'Report Operator',
    signingKeyId: 'acme-q2-key',
    signingSecret: 'super-secret-bundle-key',
  }, new Date('2026-05-23T12:00:00.000Z'));
  const parsedBundle = JSON.parse(bundle);
  assert.equal(parsedBundle.manifest.kind, 'proxyforge-evidence-bundle');
  assert.equal(parsedBundle.manifest.brandName, 'Acme Security');
  assert.equal(parsedBundle.manifest.preparedFor, 'Retail Board');
  assert.equal(parsedBundle.manifest.engagementId, 'ENG-42');
  assert.equal(parsedBundle.signature.status, 'signed');
  assert.equal(parsedBundle.signature.algorithm, 'HMAC-SHA256');
  assert.equal(parsedBundle.signature.signerName, 'Report Operator');
  assert.equal(parsedBundle.signature.keyId, 'acme-q2-key');
  assert.match(parsedBundle.signature.bundleDigestSha256, /^[a-f0-9]{64}$/);
  assert.match(parsedBundle.signature.signature, /^[a-f0-9]{64}$/);
  assert.equal(parsedBundle.evidence.length, 1);
  assert.equal(parsedBundle.loggerImportJobs.length, 1);
  assert.equal(parsedBundle.manifest.summary.loggerImportJobs, 1);
  assert.equal(parsedBundle.remediationPlan.length, 1);
  assert.equal(parsedBundle.signature.covers.includes('loggerImportJobs'), true);
  assert.equal(parsedBundle.signature.covers.includes('remediationPlan'), true);
  assert.equal(parsedBundle.signature.covers.includes('crossToolEvidenceAttachments'), true);
  assert.equal(parsedBundle.crossToolEvidenceAttachments.length, 3);
  assert.match(parsedBundle.reportMarkdown, /Branded evidence bundle/);
  assert(!bundle.includes('SECRET_TOKEN'));
  assert(!bundle.includes('session=abc123'));
  assert(!bundle.includes('SECRET_API_KEY'));
  assert(!bundle.includes('super-secret-bundle-key'));

  const bundleVerification = verifyEvidenceBundleText(bundle, 'super-secret-bundle-key');
  assert.equal(bundleVerification.status, 'valid');
  assert.equal(bundleVerification.digestMatches, true);
  assert.equal(bundleVerification.signatureMatches, true);
  assert.equal(bundleVerification.findings, 1);
  assert.equal(bundleVerification.evidence, 1);
  const tamperedVerification = verifyEvidenceBundleText(bundle.replace('Retail API Assessment', 'Tampered Retail API Assessment'), 'super-secret-bundle-key');
  assert.equal(tamperedVerification.status, 'invalid');

  const parityPackage = buildReportParityEvidencePackage({
    ...request,
    format: 'markdown',
    sections: ['executive', 'technical', 'remediation', 'evidence', 'appendix'],
    templateId: 'custom',
    brandName: 'Acme Security',
    preparedFor: 'Retail Board',
    engagementId: 'ENG-PARITY',
    customTemplateName: 'Parity operator narrative',
    customTemplateBody: [
      '# {{projectName}} Parity Report',
      '',
      'Template: {{templateName}}',
      'Findings: {{summary.totalIssues}}',
      'Cross-tool evidence: {{summary.crossToolEvidence}}',
      '',
      '{{executiveMarkdown}}',
      '{{findingsMarkdown}}',
      '{{remediationMarkdown}}',
      '{{evidenceMarkdown}}',
      '{{appendixMarkdown}}',
    ].join('\n'),
    signEvidenceBundle: true,
    signerName: 'Report Operator',
    signingKeyId: 'acme-q2-key',
    signingSecret: 'super-secret-bundle-key',
  }, new Date('2026-05-23T12:00:00.000Z'));
  assert.equal(parityPackage.kind, 'proxyforge-report-parity-evidence-package');
  assert.equal(parityPackage.requirements.allSubmissionFormatsCovered, true);
  assert.equal(parityPackage.requirements.signedBundleVerificationCovered, true);
  assert.equal(parityPackage.requirements.tamperRejectionCovered, true);
  assert.equal(parityPackage.requirements.executiveTechnicalRemediationAppendicesCovered, true);
  assert.equal(parityPackage.requirements.customTemplateCovered, true);
  assert.equal(parityPackage.requirements.crossToolEvidenceAttachmentsCovered, true);
  assert.equal(parityPackage.requirements.pdfRenderQaCovered, true);
  assert.equal(parityPackage.requirements.reportExportsRedacted, true);
  assert.equal(parityPackage.requirements.operationalSecretsDetectedBeforeRedaction, true);
  assert.equal(parityPackage.reportRedactionBoundary, 'redact-only-during-report-export');
  assert.equal(parityPackage.formats.length, 5);
  assert(parityPackage.formats.every((format) => /^[a-f0-9]{64}$/.test(format.sha256)));
  assert.equal(parityPackage.attachmentCoverage.crossToolEvidence, 3);
  assert(parityPackage.attachmentCoverage.crossToolKinds.includes('callback:proxyforge-callback-evidence-package'));
  assert.equal(parityPackage.bundleVerification.validStatus, 'valid');
  assert.equal(parityPackage.bundleVerification.tamperStatus, 'invalid');
  assert(parityPackage.bundleVerification.signatureCovers.includes('crossToolEvidenceAttachments'));
  assert.equal(parityPackage.pdfQa.validationPassed, true);
  assert(parityPackage.operationalSecretSignals.includes('authorization-header'));
  assert(!parityPackage.content.includes('SECRET_TOKEN'));
  assert(!parityPackage.content.includes('TARGET_ATTACHMENT_TOKEN'));
  assert(!parityPackage.content.includes('super-secret-bundle-key'));

  const artifactDir = path.resolve('.gitignored/test-artifacts/report-engine');
  await fs.mkdir(artifactDir, { recursive: true });
  await fs.writeFile(path.join(artifactDir, 'report-parity-evidence-package.json'), JSON.stringify(parityPackage, null, 2), 'utf8');

  const productionReadinessPackage = buildReportProductionReadinessPackage(
    buildLargeReportProductionRequest(),
    new Date('2026-05-23T12:30:00.000Z'),
  );
  assertReportProductionReadinessPackage(productionReadinessPackage);
  await fs.writeFile(path.join(artifactDir, 'report-production-readiness-package.json'), JSON.stringify(productionReadinessPackage, null, 2), 'utf8');

  const externalBundleDiversityPackage = buildReportExternalBundleDiversityPackage(
    buildLargeReportProductionRequest(),
    new Date('2026-05-23T12:45:00.000Z'),
  );
  assertReportExternalBundleDiversityPackage(externalBundleDiversityPackage);
  await fs.writeFile(path.join(artifactDir, 'report-external-bundle-diversity-package.json'), JSON.stringify(externalBundleDiversityPackage, null, 2), 'utf8');

  const templateLibraryInteropPackage = buildReportTemplateLibraryInteropPackage(
    buildLargeReportProductionRequest(),
    new Date('2026-05-23T13:00:00.000Z'),
  );
  assertReportTemplateLibraryInteropPackage(templateLibraryInteropPackage);
  await fs.writeFile(path.join(artifactDir, 'report-template-library-interop-package.json'), JSON.stringify(templateLibraryInteropPackage, null, 2), 'utf8');
} finally {
  await fs.rm(tempDir, { recursive: true, force: true });
}

function buildLargeReportProductionRequest() {
  const issueCount = 16;
  const exchanges = Array.from({ length: 240 }, (_item, index) => {
    const host = `api-${index % 12}.shop.local`;
    const route = `/api/orders/${index % 48}`;
    const method = index % 5 === 0 ? 'POST' : 'GET';
    return {
      id: `prod-hx-${String(index).padStart(3, '0')}`,
      method,
      host,
      path: route,
      url: `https://${host}${route}`,
      status: index % 11 === 0 ? 403 : index % 7 === 0 ? 500 : 200,
      length: 1600 + index,
      mime: 'application/json',
      risk: index % 11 === 0 ? 'high' : index % 7 === 0 ? 'medium' : 'low',
      timing: 80 + (index % 120),
      notes: `Large report production evidence row ${index}`,
      source: index % 3 === 0 ? 'proxy' : index % 3 === 1 ? 'repeater' : 'scanner',
      time: `14:${String(index % 60).padStart(2, '0')}:00`,
      requestRaw: [
        `${method} ${route} HTTP/2`,
        `Host: ${host}`,
        `Authorization: Bearer PROD_TOKEN_${index}`,
        `Cookie: session=prod-session-${index}`,
        `X-API-Key: PROD_X_API_KEY_${index}`,
        'Content-Type: application/json',
        '',
        JSON.stringify({ orderId: `ord-${index}`, token: `request-body-token-${index}` }),
      ].join('\n'),
      responseRaw: [
        'HTTP/2 200 OK',
        'Content-Type: application/json',
        '',
        JSON.stringify({ ok: true, api_key: `PROD_API_KEY_${index}`, session: `response-session-${index}` }),
      ].join('\n'),
      tags: ['production-report', index % 2 ? 'authz' : 'evidence-scale'],
    };
  });
  const issues = Array.from({ length: issueCount }, (_item, index) => ({
    id: `prod-issue-${index + 1}`,
    title: `Production report finding ${index + 1}`,
    severity: index % 5 === 0 ? 'critical' : index % 3 === 0 ? 'high' : index % 2 === 0 ? 'medium' : 'low',
    host: `api-${index % 12}.shop.local`,
    path: `/api/orders/${index % 48}`,
    confidence: index % 2 === 0 ? 'firm' : 'certain',
    status: index % 4 === 0 ? 'triaged' : 'open',
    detail: `Finding ${index + 1} is included to exercise long report pagination and remediation scale.`,
    remediation: `Fix authorization and evidence handling for production report finding ${index + 1}.`,
    assignee: index % 2 === 0 ? 'API Platform' : 'Identity Platform',
    triageNote: `Report production readiness triage note ${index + 1}.`,
  }));
  const reportAttachment = (prefix, index) => ({
    id: `${prefix}-${index}`,
    title: `${prefix} attachment ${index}`,
    fileName: `${prefix}-${index}.json`,
    path: `reports/${prefix}-${index}.json`,
    createdAt: '2026-05-23T12:20:00.000Z',
    reportReady: true,
    issueId: `prod-issue-${(index % issueCount) + 1}`,
    summary: `${prefix} production attachment ${index} with full-fidelity executor material before report export.`,
    content: JSON.stringify({
      kind: `proxyforge-${prefix}-production-attachment`,
      authorization: `Bearer ${prefix.toUpperCase()}_ATTACHMENT_TOKEN_${index}`,
      cookie: `session=${prefix}-attachment-session-${index}`,
      api_key: `${prefix.toUpperCase()}_ATTACHMENT_KEY_${index}`,
      reportRedactionBoundary: 'redact-only-during-report-export',
    }),
  });
  const scannerPackage = (index) => ({
    ...reportAttachment('scanner-active', index),
    planId: `scanner-plan-${index}`,
    insertionPointReviewId: `insertion-review-${index}`,
    authenticatedStateMatrixId: `auth-state-${index}`,
    replayCheckPackageId: `replay-check-${index}`,
    activeScanSummaryId: `active-summary-${index}`,
    findingCount: 1 + (index % 4),
    exchangeIds: [`prod-hx-${String(index % 200).padStart(3, '0')}`],
    ciCommand: 'proxyforge --scan --report --production-profile',
  });
  const crossTool = (index) => ({
    ...reportAttachment(`cross-tool-${index % 6}`, index),
    tool: ['callback', 'extensions', 'exploit', 'proxy', 'scanner', 'repeater'][index % 6],
    kind: [
      'proxyforge-callback-report-roundtrip-package',
      'proxyforge-extension-evidence-handoff',
      'proxyforge-exploit-package',
      'proxyforge-proxy-edge-profile-package',
      'proxyforge-scanner-live-target-profile-package',
      'proxyforge-repeater-race-evidence-package',
    ][index % 6],
    signatureStatus: index % 2 === 0 ? 'signed' : 'valid',
    sha256: `${(index % 16).toString(16)}`.repeat(64).slice(0, 64),
  });

  return {
    ...request,
    projectName: 'Retail API Production Report',
    format: 'markdown',
    sections: ['executive', 'technical', 'remediation', 'evidence', 'appendix'],
    issues,
    exchanges,
    loggerImportJobs: Array.from({ length: 24 }, (_item, index) => ({
      id: `prod-logger-job-${index}`,
      importedAt: '2026-05-23T12:10:00.000Z',
      format: 'har',
      mappingPresetName: `Production HAR batch ${index}`,
      normalization: 'report-evidence',
      notes: `Large production report import job ${index}.`,
      addedEntries: 10 + index,
      changedEntries: index % 3,
      duplicateEntries: index % 2,
      sourceHosts: [`api-${index % 12}.shop.local`],
      replayCount: index % 5,
      exchangeCount: 20 + index,
    })),
    targetSiteMapEvidenceAttachments: Array.from({ length: 45 }, (_item, index) => reportAttachment('target-map', index)),
    proxyHistoryEvidenceAttachments: Array.from({ length: 45 }, (_item, index) => reportAttachment('proxy-history', index)),
    scannerActiveScanEvidencePackages: Array.from({ length: 45 }, (_item, index) => scannerPackage(index)),
    crossToolEvidenceAttachments: Array.from({ length: 90 }, (_item, index) => crossTool(index)),
    signEvidenceBundle: true,
    signerName: 'Report Production Operator',
    signingKeyId: 'report-production-key',
    signingSecret: 'report-production-secret-value',
  };
}

function assertReportProductionReadinessPackage(result) {
  const serialized = stringify(result);
  const failedRequirements = Object.entries(result.requirements)
    .filter(([, passed]) => !passed)
    .map(([name]) => name);
  assert.equal(result.kind, 'proxyforge-report-production-readiness-package');
  assert.equal(result.reportReady, true, `Report production readiness should be report-ready; failed: ${failedRequirements.join(', ') || 'none'}`);
  assert.deepEqual(failedRequirements, [], 'Report production readiness should satisfy every requirement');
  assert.equal(result.rendererComparison.length >= 7, true);
  assert(result.rendererComparison.some((item) => item.renderer === 'fallback-pdf' && item.byteLength > 0));
  assert(result.rendererComparison.some((item) => item.renderer === 'pdf-render-qa-metadata' && item.redacted));
  assert.equal(result.signedBundleInterop.localValidStatus, 'valid');
  assert.equal(result.signedBundleInterop.externalValidStatus, 'valid');
  assert.equal(result.signedBundleInterop.externalNoSecretStatus, 'unverified');
  assert.equal(result.signedBundleInterop.externalTamperStatus, 'invalid');
  assert(result.signedBundleInterop.signatureCovers.includes('crossToolEvidenceAttachments'));
  assert.equal(result.accessibilityReview.passed, true);
  assert.equal(result.accessibilityReview.htmlLanguageDeclared, true);
  assert.equal(result.accessibilityReview.mainLandmarkPresent, true);
  assert.equal(result.accessibilityReview.taggedPdfReadiness, true);
  assert.equal(result.scaleProfile.normalizedExchangeCount, 200);
  assert.equal(result.scaleProfile.cappedAtExchangeLimit, true);
  assert.equal(result.scaleProfile.totalAttachmentCount >= 180, true);
  assert.equal(result.scaleProfile.estimatedPdfPageCount >= 40, true);
  assert(result.pdfQa.warnings.some((warning) => /Large report/i.test(warning)));
  assert(result.pdfQa.warnings.some((warning) => /capped at 200 exchanges/i.test(warning)));
  assert(result.operationalSecretSignals.includes('authorization-header'));
  assert(result.operationalSecretSignals.includes('cookie-header'));
  assert(result.operationalSecretSignals.includes('api-key-header'));
  assert.match(serialized, /rendererComparison|signedBundleInterop|accessibilityReview|scaleProfile|redact-only-during-report-export/i);
  assert(!serialized.includes('PROD_TOKEN_1'));
  assert(!serialized.includes('prod-session-1'));
  assert(!serialized.includes('PROD_API_KEY_1'));
  assert(!serialized.includes('report-production-secret-value'));
}

function assertReportExternalBundleDiversityPackage(result) {
  const serialized = stringify(result);
  const failedRequirements = Object.entries(result.requirements)
    .filter(([, passed]) => !passed)
    .map(([name]) => name);
  assert.equal(result.kind, 'proxyforge-report-external-bundle-diversity-package');
  assert.equal(result.reportReady, true, `Report external bundle diversity should be report-ready; failed: ${failedRequirements.join(', ') || 'none'}`);
  assert.deepEqual(failedRequirements, [], 'Report external bundle diversity should satisfy every requirement');
  assert.equal(result.bundleProfiles.length, 4);
  assert.equal(result.diversity.shareChannelCount, 4);
  assert.equal(result.diversity.recipientCount, 4);
  assert.equal(result.diversity.signerCount, 4);
  assert.equal(result.diversity.keyIdCount, 4);
  assert.equal(result.diversity.templateCount, 4);
  assert.equal(result.diversity.crossToolKindCount >= 5, true);
  assert.equal(result.diversity.attachmentKindCount >= 8, true);
  assert.equal(result.diversity.canonicalDigestCount, 4);
  assert.equal(result.templateLibraryInterop.length, 4);
  assert(result.templateLibraryInterop.some((item) => item.templateId === 'custom'));
  assert(result.bundleProfiles.every((profile) => profile.verificationStatus === 'valid'));
  assert(result.bundleProfiles.every((profile) => profile.noSecretStatus === 'unverified' && profile.noSecretDigestMatches));
  assert(result.bundleProfiles.every((profile) => profile.tamperStatus === 'invalid'));
  assert(result.bundleProfiles.every((profile) => profile.canonicalRoundTripStatus === 'valid'));
  assert(result.bundleProfiles.every((profile) => profile.signatureCovers.includes('crossToolEvidenceAttachments')));
  assert(result.bundleProfiles.every((profile) => profile.redacted && profile.secretMarkerLeaks === 0));
  assert(result.operationalSecretSignals.includes('authorization-header'));
  assert(result.operationalSecretSignals.includes('cookie-header'));
  assert(result.operationalSecretSignals.includes('api-key-header'));
  assert.match(serialized, /externalSharedBundleDiversityCovered|canonicalRoundTripCovered|crossToolAttachmentDiversityCovered|redact-only-during-report-export/i);
  assert(!serialized.includes('PROD_TOKEN_1'));
  assert(!serialized.includes('prod-session-1'));
  assert(!serialized.includes('PROD_API_KEY_1'));
  assert(!serialized.includes('report-production-secret-value'));
  assert(!serialized.includes('external-profile'));
}

function assertReportTemplateLibraryInteropPackage(result) {
  const serialized = stringify(result);
  const failedRequirements = Object.entries(result.requirements)
    .filter(([, passed]) => !passed)
    .map(([name]) => name);
  assert.equal(result.kind, 'proxyforge-report-template-library-interop-package');
  assert.equal(result.reportReady, true, `Report template library interop should be report-ready; failed: ${failedRequirements.join(', ') || 'none'}`);
  assert.deepEqual(failedRequirements, [], 'Report template library interop should satisfy every requirement');
  assert.equal(result.exportedLibrary.kind, 'proxyforge-report-template-library');
  assert.equal(result.exportedLibrary.templateCount, 4);
  assert.match(result.exportedLibrary.sha256, /^[a-f0-9]{64}$/);
  assert.equal(result.importReview.existingTemplateCount, 1);
  assert.equal(result.importReview.incomingTemplateCount, 4);
  assert.equal(result.importReview.acceptedTemplateCount, 4);
  assert.equal(result.importReview.conflictCount, 1);
  assert.equal(result.importReview.conflicts[0].resolution, 'renamed-import');
  assert.match(result.importReview.conflicts[0].importedId, /executive-board-summary-imported/);
  assert.equal(result.renderProofs.length, 4);
  assert(result.renderProofs.some((proof) => proof.reportTemplateId === 'executive-board'));
  assert(result.renderProofs.some((proof) => proof.reportTemplateId === 'technical-remediation'));
  assert(result.renderProofs.some((proof) => proof.reportTemplateId === 'evidence-bundle'));
  assert(result.renderProofs.some((proof) => proof.reportTemplateId === 'custom' && proof.variables.includes('findingsMarkdown')));
  assert(result.renderProofs.every((proof) => proof.unresolvedTokenCount === 0));
  assert(result.renderProofs.every((proof) => proof.redacted));
  assert(result.renderProofs.every((proof) => /^[a-f0-9]{64}$/.test(proof.markdownSha256)));
  assert(result.renderProofs.every((proof) => /^[a-f0-9]{64}$/.test(proof.htmlSha256)));
  assert(result.renderProofs.every((proof) => /^[a-f0-9]{64}$/.test(proof.bundleSha256)));
  assert(result.operationalSecretSignals.includes('authorization-header'));
  assert(result.operationalSecretSignals.includes('cookie-header'));
  assert(result.operationalSecretSignals.includes('api-key-header'));
  assert.match(serialized, /templateLibraryExportCovered|duplicateConflictReviewCovered|templateVariablesResolved|redact-only-during-report-export/i);
  assert(!serialized.includes('PROD_TOKEN_1'));
  assert(!serialized.includes('prod-session-1'));
  assert(!serialized.includes('PROD_API_KEY_1'));
  assert(!serialized.includes('report-production-secret-value'));
}

function stringify(value) {
  return typeof value === 'string' ? value : JSON.stringify(value);
}
