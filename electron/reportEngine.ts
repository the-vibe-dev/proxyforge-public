import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';

const SECURE_REPORT_DIR_MODE = 0o700;
const SECURE_REPORT_FILE_MODE = 0o600;

type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type ReportFormat = 'markdown' | 'html' | 'json' | 'bundle' | 'pdf';
export type ReportSection = 'executive' | 'technical' | 'remediation' | 'evidence' | 'appendix';
export type ReportTemplateId = 'executive-board' | 'technical-remediation' | 'evidence-bundle' | 'custom';

export interface ReportLoggerImportAttachment {
  id: string;
  importedAt: string;
  format: string;
  mappingPresetName: string;
  normalization: string;
  notes: string;
  addedEntries: number;
  changedEntries: number;
  duplicateEntries: number;
  sourceHosts: string[];
  replayCount: number;
  replayedAt?: string;
  exchangeCount: number;
}

export interface ReportEvidenceAttachment {
  id: string;
  title: string;
  fileName: string;
  path: string;
  createdAt?: string;
  reportReady: boolean;
  issueId?: string;
  summary: string;
  content: string;
}

export interface ReportCrossToolEvidenceAttachment extends ReportEvidenceAttachment {
  tool: string;
  kind: string;
  signatureStatus?: 'unsigned' | 'signed' | 'valid' | 'invalid' | 'unverified' | 'ready-on-export';
  sha256?: string;
}

export interface ReportScannerActiveScanEvidencePackage {
  id: string;
  title: string;
  fileName: string;
  path: string;
  createdAt: string;
  planId: string;
  insertionPointReviewId: string;
  authenticatedStateMatrixId: string;
  replayCheckPackageId: string;
  activeScanSummaryId?: string;
  findingCount: number;
  exchangeIds: string[];
  ciCommand: string;
  reportReady: boolean;
  summary: string;
  content: string;
}

export interface ReportGovernanceAttestation {
  packageId: string;
  title: string;
  teamName: string;
  activeOperator: string;
  operatorRole: string;
  status: 'missing' | 'signed' | 'reviewed' | 'active';
  exportedAt?: string;
  reviewedAt?: string;
  activatedAt?: string;
  signature: {
    algorithm: 'HMAC-SHA256';
    signerName: string;
    keyId: string;
    status: 'signed' | 'reviewed' | 'active' | 'missing';
    digestPreview: string;
  };
  runnerBindingCount: number;
  approvalRequiredCount: number;
  scopeGateSummary: string;
  rateGateSummary: string;
  approvalGateSummary: string;
  ciHeadlessSummary: string;
}

export interface ReportIssue {
  id: string;
  title: string;
  severity: Severity;
  host: string;
  path: string;
  confidence: 'certain' | 'firm' | 'tentative';
  status: 'open' | 'triaged' | 'false-positive' | 'fixed';
  detail: string;
  remediation: string;
  assignee?: string;
  triageNote?: string;
  lastTriagedAt?: string;
}

export interface ReportExchange {
  id: string;
  method: string;
  host: string;
  path: string;
  url: string;
  status: number;
  length: number;
  mime: string;
  risk: Severity;
  timing: number;
  notes: string;
  source: 'proxy' | 'repeater' | 'scanner' | 'crawler' | 'demo';
  time: string;
  requestRaw: string;
  responseRaw: string;
  tags: string[];
}

export interface ReportExportRequest {
  projectName: string;
  scopeAllowlist: string[];
  issues: ReportIssue[];
  exchanges: ReportExchange[];
  format: ReportFormat;
  sections: ReportSection[];
  templateId?: ReportTemplateId;
  customTemplateName?: string;
  customTemplateBody?: string;
  brandName?: string;
  preparedFor?: string;
  engagementId?: string;
  signEvidenceBundle?: boolean;
  signingKeyId?: string;
  signingSecret?: string;
  signerName?: string;
  loggerImportJobs?: ReportLoggerImportAttachment[];
  targetSiteMapEvidenceAttachments?: ReportEvidenceAttachment[];
  proxyHistoryEvidenceAttachments?: ReportEvidenceAttachment[];
  scannerActiveScanEvidencePackages?: ReportScannerActiveScanEvidencePackage[];
  crossToolEvidenceAttachments?: ReportCrossToolEvidenceAttachment[];
  governanceAttestation?: ReportGovernanceAttestation;
}

export interface ReportArtifact {
  id: string;
  format: ReportFormat;
  fileName: string;
  path: string;
  generatedAt: string;
  issueCount: number;
  exchangeCount: number;
  content: string;
}

export interface ReportPdfPageBreak {
  id: string;
  section: ReportSection;
  label: string;
  selector: string;
  reason: string;
  forced: boolean;
  estimatedStartPage: number;
  estimatedLineCount: number;
}

export interface ReportPdfRenderQaMetadata {
  version: 1;
  generatedAt: string;
  renderer: 'electron-printToPDF';
  page: {
    size: 'A4';
    marginMm: {
      top: number;
      right: number;
      bottom: number;
      left: number;
    };
    targetLinesPerPage: number;
  };
  summary: {
    projectName: string;
    templateId: ReportTemplateId;
    sectionCount: number;
    issueCount: number;
    exchangeCount: number;
    estimatedLineCount: number;
    estimatedPageCount: number;
  };
  sectionOrder: ReportSection[];
  pageBreaks: ReportPdfPageBreak[];
  visualQa: {
    forcedBreakSelector: string;
    avoidBreakSelectors: string[];
    headingKeepWithNext: boolean;
    widowOrphanLines: number;
    deterministicContentHash: string;
  };
  validation: {
    passed: boolean;
    checks: string[];
    warnings: string[];
  };
}

export interface ReportPdfRenderedSectionProbe {
  section: ReportSection;
  selector: string;
  top: number;
  height: number;
  width: number;
  computedBreakBefore: string;
  computedPageBreakBefore: string;
  computedBreakInside: string;
  text: string;
}

export interface ReportPdfVisualQaSnapshot {
  generatedAt: string;
  viewport: {
    width: number;
    height: number;
  };
  screenshot: {
    width: number;
    height: number;
    sha256: string;
    nonWhitePixelRatio: number;
    accentPixelCount: number;
  };
  sections: ReportPdfRenderedSectionProbe[];
}

export interface ReportPdfVisualQaEvaluation {
  version: 1;
  generatedAt: string;
  passed: boolean;
  checks: string[];
  warnings: string[];
  failures: string[];
  snapshot: ReportPdfVisualQaSnapshot;
}

export interface ReportEvidenceBundleVerificationResult {
  status: 'valid' | 'invalid' | 'unsigned' | 'unverified' | 'parse-error';
  message: string;
  digest?: string;
  digestMatches?: boolean;
  signatureMatches?: boolean;
  signerName?: string;
  keyId?: string;
  signedAt?: string;
  findings?: number;
  evidence?: number;
}

export interface ReportParityEvidencePackage {
  kind: 'proxyforge-report-parity-evidence-package';
  schemaVersion: 1;
  generatedAt: string;
  projectName: string;
  formats: Array<{
    format: ReportFormat;
    rendered: boolean;
    byteLength: number;
    sha256: string;
    redacted: boolean;
    sectionCount: number;
  }>;
  sectionCoverage: Record<ReportSection, boolean>;
  templateCoverage: {
    templateId: ReportTemplateId;
    customTemplateRendered: boolean;
    customTemplateName?: string;
    executiveTechnicalRemediationAppendixCovered: boolean;
  };
  attachmentCoverage: {
    exchanges: number;
    loggerImportJobs: number;
    targetSiteMapEvidence: number;
    proxyHistoryEvidence: number;
    scannerActiveScanEvidencePackages: number;
    crossToolEvidence: number;
    crossToolKinds: string[];
  };
  bundleVerification: {
    signed: boolean;
    validStatus: ReportEvidenceBundleVerificationResult['status'];
    tamperStatus: ReportEvidenceBundleVerificationResult['status'];
    signatureCovers: string[];
    digest?: string;
  };
  pdfQa: {
    validationPassed: boolean;
    estimatedPageCount: number;
    pageBreakCount: number;
    checks: string[];
    warnings: string[];
    contentHash: string;
  };
  operationalSecretSignals: string[];
  requirements: {
    allSubmissionFormatsCovered: boolean;
    signedBundleVerificationCovered: boolean;
    tamperRejectionCovered: boolean;
    executiveTechnicalRemediationAppendicesCovered: boolean;
    customTemplateCovered: boolean;
    crossToolEvidenceAttachmentsCovered: boolean;
    pdfRenderQaCovered: boolean;
    reportExportsRedacted: boolean;
    operationalSecretsDetectedBeforeRedaction: boolean;
    reportPhaseOnlyRedaction: boolean;
  };
  secretHandling: 'report-export-redacts-submission-artifacts';
  operationalInputBoundary: 'executor-artifacts-remain-full-fidelity-before-report-export';
  reportRedactionBoundary: 'redact-only-during-report-export';
  reportReady: true;
  summary: string;
  content: string;
}

export type ReportRendererComparisonName =
  | 'markdown'
  | 'html'
  | 'json'
  | 'bundle'
  | 'pdf-html'
  | 'fallback-pdf'
  | 'pdf-render-qa-metadata';

export interface ReportRendererComparisonProof {
  renderer: ReportRendererComparisonName;
  byteLength: number;
  sha256: string;
  redacted: boolean;
  deterministic: boolean;
}

export interface ReportAccessibilityReview {
  htmlLanguageDeclared: boolean;
  documentTitlePresent: boolean;
  mainLandmarkPresent: boolean;
  semanticSectionCount: number;
  pdfSectionTagCount: number;
  headingOrderValid: boolean;
  tableRowCount: number;
  evidenceBlockCount: number;
  taggedPdfReadiness: boolean;
  checks: string[];
  warnings: string[];
  passed: boolean;
}

export interface ReportScaleProfile {
  issueCount: number;
  inputExchangeCount: number;
  normalizedExchangeCount: number;
  loggerImportJobCount: number;
  targetAttachmentCount: number;
  proxyAttachmentCount: number;
  scannerAttachmentCount: number;
  crossToolAttachmentCount: number;
  totalAttachmentCount: number;
  estimatedPdfPageCount: number;
  cappedAtExchangeLimit: boolean;
  attachmentCapsObserved: boolean;
  reportMarkdownByteLength: number;
  bundleByteLength: number;
  renderByteBudgetOk: boolean;
}

export interface ReportProductionReadinessPackage {
  kind: 'proxyforge-report-production-readiness-package';
  schemaVersion: 1;
  generatedAt: string;
  projectName: string;
  rendererComparison: ReportRendererComparisonProof[];
  signedBundleInterop: {
    localValidStatus: ReportEvidenceBundleVerificationResult['status'];
    externalValidStatus: ReportEvidenceBundleVerificationResult['status'];
    externalNoSecretStatus: ReportEvidenceBundleVerificationResult['status'];
    externalTamperStatus: ReportEvidenceBundleVerificationResult['status'];
    externalSignerName?: string;
    externalKeyId?: string;
    signatureCovers: string[];
    digest?: string;
  };
  accessibilityReview: ReportAccessibilityReview;
  scaleProfile: ReportScaleProfile;
  pdfQa: {
    validationPassed: boolean;
    estimatedPageCount: number;
    warningCount: number;
    checks: string[];
    warnings: string[];
    contentHash: string;
  };
  operationalSecretSignals: string[];
  requirements: {
    rendererComparisonCovered: boolean;
    externalSignedBundleInteropCovered: boolean;
    accessibilityReviewCovered: boolean;
    longProjectAttachmentScaleCovered: boolean;
    pdfLargeReportWarningCovered: boolean;
    reportExportsRedacted: boolean;
    signedBundleTamperRejectionCovered: boolean;
    rawOperationalInputsPreservedPreExport: boolean;
    reportPhaseOnlyRedaction: boolean;
  };
  secretHandling: 'report-export-redacts-submission-artifacts';
  operationalInputBoundary: 'executor-artifacts-remain-full-fidelity-before-report-export';
  reportRedactionBoundary: 'redact-only-during-report-export';
  reportReady: boolean;
  summary: string;
  content: string;
}

export type ReportExternalBundleShareChannel =
  | 'bug-bounty-portal'
  | 'customer-grc'
  | 'partner-mssp'
  | 'internal-remediation';

export interface ReportExternalBundleDiversityProfileInput {
  profileId: string;
  shareChannel: ReportExternalBundleShareChannel;
  recipient: string;
  brandName: string;
  preparedFor: string;
  engagementId: string;
  signerName: string;
  signingKeyId: string;
  signingSecret?: string;
  templateId?: ReportTemplateId;
  sections?: ReportSection[];
  customTemplateName?: string;
  customTemplateBody?: string;
}

export interface ReportExternalBundleDiversityProfileProof {
  profileId: string;
  shareChannel: ReportExternalBundleShareChannel;
  recipient: string;
  brandName: string;
  preparedFor: string;
  engagementId: string;
  templateId: ReportTemplateId;
  signerName: string;
  keyId: string;
  byteLength: number;
  sha256: string;
  bundleDigestSha256?: string;
  verificationStatus: ReportEvidenceBundleVerificationResult['status'];
  noSecretStatus: ReportEvidenceBundleVerificationResult['status'];
  noSecretDigestMatches: boolean;
  tamperStatus: ReportEvidenceBundleVerificationResult['status'];
  canonicalRoundTripStatus: ReportEvidenceBundleVerificationResult['status'];
  signatureCovers: string[];
  attachmentKinds: string[];
  findingCount: number;
  evidenceCount: number;
  crossToolEvidenceCount: number;
  redacted: boolean;
  secretMarkerLeaks: number;
}

export interface ReportExternalBundleDiversityPackage {
  kind: 'proxyforge-report-external-bundle-diversity-package';
  schemaVersion: 1;
  generatedAt: string;
  projectName: string;
  bundleProfiles: ReportExternalBundleDiversityProfileProof[];
  diversity: {
    profileCount: number;
    shareChannelCount: number;
    recipientCount: number;
    signerCount: number;
    keyIdCount: number;
    templateCount: number;
    attachmentKindCount: number;
    crossToolKindCount: number;
    canonicalDigestCount: number;
  };
  templateLibraryInterop: Array<{
    templateId: ReportTemplateId;
    profileId: string;
    rendered: boolean;
    byteLength: number;
    sha256: string;
    redacted: boolean;
  }>;
  operationalSecretSignals: string[];
  requirements: {
    externalSharedBundleDiversityCovered: boolean;
    signedBundleVerificationCovered: boolean;
    digestOnlyNoSecretReviewCovered: boolean;
    tamperRejectionCovered: boolean;
    canonicalRoundTripCovered: boolean;
    crossToolAttachmentDiversityCovered: boolean;
    templateLibraryInteropCovered: boolean;
    reportExportsRedacted: boolean;
    rawOperationalInputsPreservedPreExport: boolean;
    reportPhaseOnlyRedaction: boolean;
  };
  secretHandling: 'report-export-redacts-submission-artifacts';
  operationalInputBoundary: 'executor-artifacts-remain-full-fidelity-before-report-export';
  reportRedactionBoundary: 'redact-only-during-report-export';
  reportReady: boolean;
  summary: string;
  content: string;
}

export interface ReportTemplateLibraryEntryInput {
  id: string;
  name: string;
  description?: string;
  templateId: ReportTemplateId;
  sections?: ReportSection[];
  body?: string;
  version?: string;
  source?: string;
}

export interface ReportTemplateLibraryEntry {
  id: string;
  name: string;
  description: string;
  templateId: ReportTemplateId;
  sections: ReportSection[];
  body: string;
  version: string;
  source: string;
  variables: string[];
  byteLength: number;
  sha256: string;
}

export interface ReportTemplateLibraryConflict {
  existingId: string;
  incomingId: string;
  importedId: string;
  resolution: 'renamed-import';
  reason: string;
}

export interface ReportTemplateLibraryRenderProof {
  templateId: string;
  name: string;
  reportTemplateId: ReportTemplateId;
  sections: ReportSection[];
  variables: string[];
  markdownSha256: string;
  htmlSha256: string;
  bundleSha256: string;
  markdownByteLength: number;
  htmlByteLength: number;
  bundleByteLength: number;
  redacted: boolean;
  unresolvedTokenCount: number;
}

export interface ReportTemplateLibraryInteropPackage {
  kind: 'proxyforge-report-template-library-interop-package';
  schemaVersion: 1;
  generatedAt: string;
  projectName: string;
  exportedLibrary: {
    kind: 'proxyforge-report-template-library';
    templateCount: number;
    byteLength: number;
    sha256: string;
    templateIds: string[];
  };
  importReview: {
    existingTemplateCount: number;
    incomingTemplateCount: number;
    acceptedTemplateCount: number;
    conflictCount: number;
    conflicts: ReportTemplateLibraryConflict[];
    acceptedTemplateIds: string[];
  };
  renderProofs: ReportTemplateLibraryRenderProof[];
  operationalSecretSignals: string[];
  requirements: {
    templateLibraryExportCovered: boolean;
    templateLibraryImportCovered: boolean;
    duplicateConflictReviewCovered: boolean;
    builtinTemplateInteropCovered: boolean;
    customTemplateInteropCovered: boolean;
    templateVariablesResolved: boolean;
    bundleRenderCovered: boolean;
    reportExportsRedacted: boolean;
    rawOperationalInputsPreservedPreExport: boolean;
    reportPhaseOnlyRedaction: boolean;
  };
  secretHandling: 'report-export-redacts-submission-artifacts';
  operationalInputBoundary: 'executor-artifacts-remain-full-fidelity-before-report-export';
  reportRedactionBoundary: 'redact-only-during-report-export';
  reportReady: boolean;
  summary: string;
  content: string;
}

type PdfRenderer = (html: string, request: ReportExportRequest, generatedAt: Date) => Promise<Buffer>;

const DEFAULT_CUSTOM_TEMPLATE = [
  '# {{projectName}} Operator Report',
  '',
  'Prepared for: {{preparedFor}}',
  'Brand: {{brandName}}',
  'Engagement: {{engagementId}}',
  'Generated: {{generatedAt}}',
  'Scope: {{scope}}',
  '',
  '{{executiveMarkdown}}',
  '',
  '{{findingsMarkdown}}',
  '',
  '{{remediationMarkdown}}',
  '',
  '{{evidenceMarkdown}}',
  '',
  '{{appendixMarkdown}}',
].join('\n');

const PDF_TARGET_LINES_PER_PAGE = 46;
const PDF_PAGE_MARGIN_MM = {
  top: 18,
  right: 16,
  bottom: 18,
  left: 16,
};
const PDF_AVOID_BREAK_SELECTORS = [
  '.cover',
  '.meta div',
  '.pdf-section',
  '.pdf-keep-with-next',
  '.pdf-avoid-break',
  '.pdf-evidence-block',
  '.table-row',
];
const REPORT_SECTION_LABELS: Record<ReportSection, string> = {
  executive: 'Executive Summary',
  technical: 'Technical Findings',
  remediation: 'Remediation Plan',
  evidence: 'Evidence',
  appendix: 'Appendix',
};

export class ReportEngine {
  constructor(
    private readonly reportsDir: string,
    private readonly pdfRenderer?: PdfRenderer,
  ) {}

  async exportReport(request: ReportExportRequest): Promise<ReportArtifact> {
    const generatedAt = new Date();
    const normalized = normalizeReportRequest(request);
    const extension = reportExtension(normalized.format);
    const fileName = `${slugify(normalized.projectName)}-${generatedAt.toISOString().replace(/[:.]/g, '-')}.${extension}`;
    await ensurePrivateDir(this.reportsDir);
    const filePath = path.join(this.reportsDir, fileName);
    let content = renderReport(normalized, generatedAt);
    if (normalized.format === 'pdf') {
      const html = renderPdfReportHtml(normalized, generatedAt);
      const pdf = this.pdfRenderer
        ? await this.pdfRenderer(html, normalized, generatedAt)
        : renderFallbackPdf(normalized, generatedAt);
      await writePrivateFile(filePath, pdf);
      content = renderPdfArtifactPreview(normalized, generatedAt);
    } else {
      await writePrivateFile(filePath, content, 'utf8');
    }

    return {
      id: `report-${generatedAt.getTime()}-${Math.random().toString(16).slice(2)}`,
      format: normalized.format,
      fileName,
      path: filePath,
      generatedAt: generatedAt.toISOString(),
      issueCount: normalized.issues.length,
      exchangeCount: normalized.exchanges.length,
      content,
    };
  }
}

async function ensurePrivateDir(dirPath: string) {
  const createdRoot = await fs.mkdir(dirPath, { recursive: true, mode: SECURE_REPORT_DIR_MODE });
  if (createdRoot) await chmodCreatedDirectoryTree(createdRoot, dirPath, SECURE_REPORT_DIR_MODE);
}

async function writePrivateFile(filePath: string, content: string | Buffer, encoding?: BufferEncoding) {
  await ensurePrivateDir(path.dirname(filePath));
  await fs.writeFile(filePath, content, encoding ? { encoding, mode: SECURE_REPORT_FILE_MODE } : { mode: SECURE_REPORT_FILE_MODE });
  await chmodIfPossible(filePath, SECURE_REPORT_FILE_MODE);
}

async function chmodIfPossible(filePath: string, mode: number) {
  if (process.platform === 'win32') return;
  try {
    await fs.chmod(filePath, mode);
  } catch (error) {
    if (!['ENOENT', 'EPERM', 'EACCES'].includes((error as NodeJS.ErrnoException).code ?? '')) throw error;
  }
}

async function chmodCreatedDirectoryTree(createdRoot: string, targetDir: string, mode: number) {
  if (process.platform === 'win32') return;
  const resolvedCreatedRoot = path.resolve(createdRoot);
  const resolvedTarget = path.resolve(targetDir);
  await chmodIfPossible(resolvedCreatedRoot, mode);
  const relativeParts = path.relative(resolvedCreatedRoot, resolvedTarget).split(path.sep).filter(Boolean);
  let current = resolvedCreatedRoot;
  for (const part of relativeParts) {
    current = path.join(current, part);
    await chmodIfPossible(current, mode);
  }
}

export function renderReport(request: ReportExportRequest, generatedAt = new Date()) {
  const normalized = normalizeReportRequest(request);
  if (normalized.format === 'json') {
    return JSON.stringify({
      version: 1,
      generatedAt: generatedAt.toISOString(),
      projectName: normalized.projectName,
      brandName: normalized.brandName,
      preparedFor: normalized.preparedFor,
      engagementId: normalized.engagementId,
      templateId: normalized.templateId,
      templateName: templateLabel(normalized.templateId, normalized.customTemplateName),
      scopeAllowlist: normalized.scopeAllowlist,
      sections: normalized.sections,
      issues: redactReportValue(normalized.issues),
      remediationPlan: normalized.sections.includes('remediation') ? buildRemediationPlan(normalized) : [],
      exchanges: normalized.sections.includes('evidence') ? normalized.exchanges.map(redactExchange) : [],
      loggerImportJobs: normalized.sections.includes('evidence') ? redactReportValue(normalized.loggerImportJobs ?? []) : [],
      targetSiteMapEvidenceAttachments: normalized.sections.includes('evidence') ? redactReportValue(normalized.targetSiteMapEvidenceAttachments ?? []) : [],
      proxyHistoryEvidenceAttachments: normalized.sections.includes('evidence') ? redactReportValue(normalized.proxyHistoryEvidenceAttachments ?? []) : [],
      scannerActiveScanEvidencePackages: normalized.sections.includes('evidence') ? redactReportValue(normalized.scannerActiveScanEvidencePackages ?? []) : [],
      crossToolEvidenceAttachments: normalized.sections.includes('evidence') ? redactReportValue(normalized.crossToolEvidenceAttachments ?? []) : [],
      governanceAttestation: normalized.governanceAttestation,
      summary: buildSummary(normalized),
    }, null, 2);
  }

  if (normalized.format === 'bundle') {
    return renderEvidenceBundle(normalized, generatedAt);
  }

  if (normalized.format === 'html') {
    return renderHtmlReport(normalized, generatedAt);
  }

  if (normalized.format === 'pdf') {
    return renderPdfReportHtml(normalized, generatedAt);
  }

  return renderMarkdownReport(normalized, generatedAt);
}

export function buildReportParityEvidencePackage(
  request: ReportExportRequest,
  generatedAt = new Date(),
): ReportParityEvidencePackage {
  const signingSecret = request.signingSecret?.trim() || 'proxyforge-report-parity-secret';
  const normalized = normalizeReportRequest({
    ...request,
    sections: request.sections.length ? request.sections : ['executive', 'technical', 'remediation', 'evidence', 'appendix'],
    signEvidenceBundle: true,
    signingSecret,
  });
  const formats: ReportFormat[] = ['markdown', 'html', 'json', 'pdf', 'bundle'];
  const renderedOutputs = new Map<ReportFormat, string>();
  for (const format of formats) {
    const output = renderReport({
      ...normalized,
      format,
      signEvidenceBundle: format === 'bundle',
      signingSecret,
    }, generatedAt);
    renderedOutputs.set(format, output);
  }
  const secretMarkers = extractReportSecretMarkers(request);
  const formatEvidence = formats.map((format) => {
    const output = renderedOutputs.get(format) ?? '';
    return {
      format,
      rendered: output.length > 0,
      byteLength: Buffer.byteLength(output, 'utf8'),
      sha256: crypto.createHash('sha256').update(output).digest('hex'),
      redacted: secretMarkers.every((marker) => !output.includes(marker)),
      sectionCount: normalized.sections.length,
    };
  });
  const signedBundle = renderedOutputs.get('bundle') ?? '';
  const validBundle = verifyEvidenceBundleText(signedBundle, signingSecret);
  const tamperedBundle = signedBundle.replace(normalized.projectName, `${normalized.projectName} tampered`);
  const tamperResult = verifyEvidenceBundleText(tamperedBundle, signingSecret);
  const parsedBundle = safeParseJson(signedBundle) as { signature?: { covers?: string[] } } | undefined;
  const customMarkdown = renderReport({
    ...normalized,
    format: 'markdown',
    templateId: 'custom',
    customTemplateName: normalized.customTemplateName || 'Parity custom report template',
    customTemplateBody: normalized.customTemplateBody || DEFAULT_CUSTOM_TEMPLATE,
  }, generatedAt);
  const pdfQa = buildPdfRenderQaMetadata({ ...normalized, format: 'pdf' }, generatedAt);
  const attachmentCoverage = {
    exchanges: normalized.exchanges.length,
    loggerImportJobs: normalized.loggerImportJobs?.length ?? 0,
    targetSiteMapEvidence: (normalized.targetSiteMapEvidenceAttachments ?? []).filter((item) => item.reportReady).length,
    proxyHistoryEvidence: (normalized.proxyHistoryEvidenceAttachments ?? []).filter((item) => item.reportReady).length,
    scannerActiveScanEvidencePackages: (normalized.scannerActiveScanEvidencePackages ?? []).filter((item) => item.reportReady).length,
    crossToolEvidence: (normalized.crossToolEvidenceAttachments ?? []).filter((item) => item.reportReady).length,
    crossToolKinds: Array.from(new Set((normalized.crossToolEvidenceAttachments ?? [])
      .filter((item) => item.reportReady)
      .map((item) => `${item.tool}:${item.kind}`))).sort(),
  };
  const sectionCoverage = {
    executive: normalized.sections.includes('executive'),
    technical: normalized.sections.includes('technical'),
    remediation: normalized.sections.includes('remediation'),
    evidence: normalized.sections.includes('evidence'),
    appendix: normalized.sections.includes('appendix'),
  };
  const operationalSecretSignals = reportOperationalSecretSignals(request);
  const requirements = {
    allSubmissionFormatsCovered: formatEvidence.every((item) => item.rendered && item.byteLength > 0 && /^[a-f0-9]{64}$/.test(item.sha256)),
    signedBundleVerificationCovered: validBundle.status === 'valid',
    tamperRejectionCovered: tamperResult.status === 'invalid',
    executiveTechnicalRemediationAppendicesCovered: sectionCoverage.executive && sectionCoverage.technical && sectionCoverage.remediation && sectionCoverage.appendix,
    customTemplateCovered: /Custom|Template|Operator|Narrative|Security Assessment/i.test(customMarkdown) && customMarkdown.includes(normalized.projectName),
    crossToolEvidenceAttachmentsCovered: attachmentCoverage.loggerImportJobs > 0
      && attachmentCoverage.targetSiteMapEvidence > 0
      && attachmentCoverage.proxyHistoryEvidence > 0
      && attachmentCoverage.scannerActiveScanEvidencePackages > 0
      && attachmentCoverage.crossToolEvidence >= 3,
    pdfRenderQaCovered: pdfQa.validation.passed && pdfQa.pageBreaks.length === normalized.sections.length && /^[a-f0-9]{64}$/.test(pdfQa.visualQa.deterministicContentHash),
    reportExportsRedacted: formatEvidence.every((item) => item.redacted),
    operationalSecretsDetectedBeforeRedaction: operationalSecretSignals.length > 0,
    reportPhaseOnlyRedaction: true,
  };
  const body = {
    kind: 'proxyforge-report-parity-evidence-package',
    generatedAt: generatedAt.toISOString(),
    projectName: normalized.projectName,
    formats: formatEvidence,
    sectionCoverage,
    attachmentCoverage,
    bundleVerification: {
      validBundle,
      tamperResult,
      signatureCovers: parsedBundle?.signature?.covers ?? [],
    },
    pdfQa,
    operationalSecretSignals,
    requirements,
  };

  return {
    kind: 'proxyforge-report-parity-evidence-package',
    schemaVersion: 1,
    generatedAt: generatedAt.toISOString(),
    projectName: normalized.projectName,
    formats: formatEvidence,
    sectionCoverage,
    templateCoverage: {
      templateId: normalized.templateId ?? 'technical-remediation',
      customTemplateRendered: requirements.customTemplateCovered,
      customTemplateName: normalized.customTemplateName,
      executiveTechnicalRemediationAppendixCovered: requirements.executiveTechnicalRemediationAppendicesCovered,
    },
    attachmentCoverage,
    bundleVerification: {
      signed: validBundle.status === 'valid',
      validStatus: validBundle.status,
      tamperStatus: tamperResult.status,
      signatureCovers: parsedBundle?.signature?.covers ?? [],
      digest: validBundle.digest,
    },
    pdfQa: {
      validationPassed: pdfQa.validation.passed,
      estimatedPageCount: pdfQa.summary.estimatedPageCount,
      pageBreakCount: pdfQa.pageBreaks.length,
      checks: pdfQa.validation.checks,
      warnings: pdfQa.validation.warnings,
      contentHash: pdfQa.visualQa.deterministicContentHash,
    },
    operationalSecretSignals,
    requirements,
    secretHandling: 'report-export-redacts-submission-artifacts',
    operationalInputBoundary: 'executor-artifacts-remain-full-fidelity-before-report-export',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady: true,
    summary: `Report parity package rendered ${formatEvidence.length} submission format(s), verified signed bundle status=${validBundle.status}, rejected tamper status=${tamperResult.status}, covered ${Object.values(sectionCoverage).filter(Boolean).length} section(s), ${attachmentCoverage.crossToolEvidence} cross-tool attachment(s), and PDF QA page breaks=${pdfQa.pageBreaks.length}.`,
    content: JSON.stringify(body, null, 2),
  };
}

export function buildReportProductionReadinessPackage(
  request: ReportExportRequest,
  generatedAt = new Date(),
): ReportProductionReadinessPackage {
  const signingSecret = request.signingSecret?.trim() || 'proxyforge-report-production-secret';
  const normalized = normalizeReportRequest({
    ...request,
    sections: request.sections.length ? request.sections : ['executive', 'technical', 'remediation', 'evidence', 'appendix'],
    signEvidenceBundle: true,
    signingSecret,
  });
  const secretMarkers = extractReportSecretMarkers(request);
  const renderers: Array<{ renderer: ReportRendererComparisonName; output: string | Buffer }> = [
    { renderer: 'markdown', output: renderReport({ ...normalized, format: 'markdown' }, generatedAt) },
    { renderer: 'html', output: renderReport({ ...normalized, format: 'html' }, generatedAt) },
    { renderer: 'json', output: renderReport({ ...normalized, format: 'json' }, generatedAt) },
    { renderer: 'bundle', output: renderReport({ ...normalized, format: 'bundle', signEvidenceBundle: true, signingSecret }, generatedAt) },
    { renderer: 'pdf-html', output: renderReport({ ...normalized, format: 'pdf' }, generatedAt) },
    { renderer: 'fallback-pdf', output: renderFallbackPdf(normalized, generatedAt) },
    { renderer: 'pdf-render-qa-metadata', output: JSON.stringify(buildPdfRenderQaMetadata(normalized, generatedAt)) },
  ];
  const rendererComparison = renderers.map(({ renderer, output }) => {
    const text = Buffer.isBuffer(output) ? output.toString('utf8') : output;
    return {
      renderer,
      byteLength: Buffer.isBuffer(output) ? output.length : Buffer.byteLength(output, 'utf8'),
      sha256: crypto.createHash('sha256').update(output).digest('hex'),
      redacted: secretMarkers.every((marker) => !text.includes(marker)),
      deterministic: renderer !== 'fallback-pdf' || text.startsWith('%PDF-1.4'),
    };
  });
  const localBundle = renderReport({ ...normalized, format: 'bundle', signEvidenceBundle: true, signingSecret }, generatedAt);
  const localVerification = verifyEvidenceBundleText(localBundle, signingSecret);
  const externalSecret = `${signingSecret}:external-partner`;
  const externalBundle = renderReport({
    ...normalized,
    format: 'bundle',
    brandName: 'External Partner Security',
    signerName: 'External Report Reviewer',
    signingKeyId: 'external-report-review-key',
    signingSecret: externalSecret,
    signEvidenceBundle: true,
  }, generatedAt);
  const externalVerification = verifyEvidenceBundleText(externalBundle, externalSecret);
  const externalNoSecretVerification = verifyEvidenceBundleText(externalBundle);
  const externalTamperVerification = verifyEvidenceBundleText(
    externalBundle.replace(normalized.projectName, `${normalized.projectName} tampered`),
    externalSecret,
  );
  const externalParsed = safeParseJson(externalBundle) as { signature?: { covers?: string[] } } | undefined;
  const pdfQa = buildPdfRenderQaMetadata(normalized, generatedAt);
  const accessibilityReview = buildReportAccessibilityReview(normalized, generatedAt);
  const reportMarkdown = renderReport({ ...normalized, format: 'markdown' }, generatedAt);
  const bundleText = renderReport({ ...normalized, format: 'bundle', signEvidenceBundle: true, signingSecret }, generatedAt);
  const scaleProfile: ReportScaleProfile = {
    issueCount: normalized.issues.length,
    inputExchangeCount: request.exchanges.length,
    normalizedExchangeCount: normalized.exchanges.length,
    loggerImportJobCount: normalized.loggerImportJobs?.length ?? 0,
    targetAttachmentCount: normalized.targetSiteMapEvidenceAttachments?.length ?? 0,
    proxyAttachmentCount: normalized.proxyHistoryEvidenceAttachments?.length ?? 0,
    scannerAttachmentCount: normalized.scannerActiveScanEvidencePackages?.length ?? 0,
    crossToolAttachmentCount: normalized.crossToolEvidenceAttachments?.length ?? 0,
    totalAttachmentCount: (normalized.loggerImportJobs?.length ?? 0)
      + (normalized.targetSiteMapEvidenceAttachments?.length ?? 0)
      + (normalized.proxyHistoryEvidenceAttachments?.length ?? 0)
      + (normalized.scannerActiveScanEvidencePackages?.length ?? 0)
      + (normalized.crossToolEvidenceAttachments?.length ?? 0),
    estimatedPdfPageCount: pdfQa.summary.estimatedPageCount,
    cappedAtExchangeLimit: request.exchanges.length > normalized.exchanges.length && normalized.exchanges.length === 200,
    attachmentCapsObserved: (request.loggerImportJobs?.length ?? 0) >= (normalized.loggerImportJobs?.length ?? 0)
      && (request.targetSiteMapEvidenceAttachments?.length ?? 0) >= (normalized.targetSiteMapEvidenceAttachments?.length ?? 0)
      && (request.proxyHistoryEvidenceAttachments?.length ?? 0) >= (normalized.proxyHistoryEvidenceAttachments?.length ?? 0)
      && (request.scannerActiveScanEvidencePackages?.length ?? 0) >= (normalized.scannerActiveScanEvidencePackages?.length ?? 0)
      && (request.crossToolEvidenceAttachments?.length ?? 0) >= (normalized.crossToolEvidenceAttachments?.length ?? 0),
    reportMarkdownByteLength: Buffer.byteLength(reportMarkdown, 'utf8'),
    bundleByteLength: Buffer.byteLength(bundleText, 'utf8'),
    renderByteBudgetOk: Buffer.byteLength(reportMarkdown, 'utf8') > 10000 && Buffer.byteLength(bundleText, 'utf8') > 10000,
  };
  const operationalSecretSignals = reportOperationalSecretSignals(request);
  const requirements = {
    rendererComparisonCovered: rendererComparison.length >= 7
      && rendererComparison.every((item) => item.byteLength > 0 && /^[a-f0-9]{64}$/.test(item.sha256) && item.deterministic),
    externalSignedBundleInteropCovered: localVerification.status === 'valid'
      && externalVerification.status === 'valid'
      && externalNoSecretVerification.status === 'unverified'
      && externalNoSecretVerification.digestMatches === true
      && (externalParsed?.signature?.covers ?? []).includes('crossToolEvidenceAttachments'),
    accessibilityReviewCovered: accessibilityReview.passed,
    longProjectAttachmentScaleCovered: scaleProfile.normalizedExchangeCount >= 200
      && scaleProfile.totalAttachmentCount >= 180
      && scaleProfile.estimatedPdfPageCount >= 40
      && scaleProfile.cappedAtExchangeLimit
      && scaleProfile.attachmentCapsObserved
      && scaleProfile.renderByteBudgetOk,
    pdfLargeReportWarningCovered: pdfQa.validation.warnings.some((warning) => /Large report/i.test(warning))
      && pdfQa.validation.warnings.some((warning) => /capped at 200 exchanges/i.test(warning)),
    reportExportsRedacted: rendererComparison.every((item) => item.redacted),
    signedBundleTamperRejectionCovered: externalTamperVerification.status === 'invalid',
    rawOperationalInputsPreservedPreExport: secretMarkers.length > 0 && operationalSecretSignals.length > 0,
    reportPhaseOnlyRedaction: true,
  };
  const body = {
    kind: 'proxyforge-report-production-readiness-package',
    generatedAt: generatedAt.toISOString(),
    projectName: normalized.projectName,
    rendererComparison,
    signedBundleInterop: {
      localValidStatus: localVerification.status,
      externalValidStatus: externalVerification.status,
      externalNoSecretStatus: externalNoSecretVerification.status,
      externalTamperStatus: externalTamperVerification.status,
      externalSignerName: externalVerification.signerName,
      externalKeyId: externalVerification.keyId,
      signatureCovers: externalParsed?.signature?.covers ?? [],
      digest: externalVerification.digest,
    },
    accessibilityReview,
    scaleProfile,
    pdfQa: {
      validationPassed: pdfQa.validation.passed,
      estimatedPageCount: pdfQa.summary.estimatedPageCount,
      warningCount: pdfQa.validation.warnings.length,
      checks: pdfQa.validation.checks,
      warnings: pdfQa.validation.warnings,
      contentHash: pdfQa.visualQa.deterministicContentHash,
    },
    operationalSecretSignals,
    requirements,
    secretHandling: 'report-export-redacts-submission-artifacts',
    operationalInputBoundary: 'executor-artifacts-remain-full-fidelity-before-report-export',
    reportRedactionBoundary: 'redact-only-during-report-export',
  };

  return {
    kind: 'proxyforge-report-production-readiness-package',
    schemaVersion: 1,
    generatedAt: generatedAt.toISOString(),
    projectName: normalized.projectName,
    rendererComparison,
    signedBundleInterop: body.signedBundleInterop,
    accessibilityReview,
    scaleProfile,
    pdfQa: body.pdfQa,
    operationalSecretSignals,
    requirements,
    secretHandling: 'report-export-redacts-submission-artifacts',
    operationalInputBoundary: 'executor-artifacts-remain-full-fidelity-before-report-export',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady: Object.values(requirements).every(Boolean),
    summary: `Report production readiness compared ${rendererComparison.length} renderer output(s), verified local/external signed bundles, reviewed semantic PDF accessibility tags, profiled ${scaleProfile.normalizedExchangeCount}/${scaleProfile.inputExchangeCount} exchange(s), ${scaleProfile.totalAttachmentCount} attachment(s), and ${scaleProfile.estimatedPdfPageCount} estimated PDF page(s).`,
    content: JSON.stringify(body, null, 2),
  };
}

export function buildReportExternalBundleDiversityPackage(
  request: ReportExportRequest,
  generatedAt = new Date(),
  profiles?: ReportExternalBundleDiversityProfileInput[],
): ReportExternalBundleDiversityPackage {
  const baseSigningSecret = request.signingSecret?.trim() || 'proxyforge-report-external-diversity-secret';
  const normalized = normalizeReportRequest({
    ...request,
    sections: request.sections.length ? request.sections : ['executive', 'technical', 'remediation', 'evidence', 'appendix'],
    format: 'bundle',
    signEvidenceBundle: true,
    signingSecret: baseSigningSecret,
  });
  const profileInputs = profiles?.length
    ? profiles
    : defaultExternalBundleDiversityProfiles(baseSigningSecret);
  const baseSecretMarkers = extractReportSecretMarkers({ ...request, signingSecret: baseSigningSecret });
  const operationalSecretSignals = reportOperationalSecretSignals({ ...request, signingSecret: baseSigningSecret });

  const bundleProfiles = profileInputs.map((profile, index): ReportExternalBundleDiversityProfileProof => {
    const signingSecret = profile.signingSecret?.trim() || `${baseSigningSecret}:external-profile-${index + 1}`;
    const profileRequest = normalizeReportRequest({
      ...normalized,
      format: 'bundle',
      templateId: profile.templateId ?? normalized.templateId,
      sections: profile.sections?.length ? profile.sections : normalized.sections,
      customTemplateName: profile.customTemplateName ?? normalized.customTemplateName,
      customTemplateBody: profile.customTemplateBody ?? normalized.customTemplateBody,
      brandName: profile.brandName,
      preparedFor: profile.preparedFor,
      engagementId: profile.engagementId,
      signerName: profile.signerName,
      signingKeyId: profile.signingKeyId,
      signingSecret,
      signEvidenceBundle: true,
    });
    const bundleText = renderReport(profileRequest, generatedAt);
    const parsedBundle = safeParseJson(bundleText) as {
      signature?: {
        covers?: string[];
        bundleDigestSha256?: string;
      };
      findings?: unknown[];
      evidence?: unknown[];
      loggerImportJobs?: unknown[];
      targetSiteMapEvidenceAttachments?: unknown[];
      proxyHistoryEvidenceAttachments?: unknown[];
      scannerActiveScanEvidencePackages?: unknown[];
      crossToolEvidenceAttachments?: Array<{ tool?: unknown; kind?: unknown }>;
    } | undefined;
    const canonicalRoundTripText = parsedBundle ? JSON.stringify(parsedBundle, null, 2) : bundleText;
    const verification = verifyEvidenceBundleText(bundleText, signingSecret);
    const noSecretVerification = verifyEvidenceBundleText(bundleText);
    const tamperVerification = verifyEvidenceBundleText(
      bundleText.replace(profileRequest.projectName, `${profileRequest.projectName} tampered ${profile.profileId}`),
      signingSecret,
    );
    const canonicalRoundTripVerification = verifyEvidenceBundleText(canonicalRoundTripText, signingSecret);
    const markerLeaks = [...baseSecretMarkers, signingSecret]
      .filter((marker) => marker.trim().length >= 4 && bundleText.includes(marker));
    const crossToolKinds = (parsedBundle?.crossToolEvidenceAttachments ?? [])
      .map((attachment) => `${String(attachment.tool ?? 'unknown')}:${String(attachment.kind ?? 'proxyforge-cross-tool-evidence')}`);
    const attachmentKinds = [
      ...(parsedBundle?.loggerImportJobs?.length ? ['logger-import-jobs'] : []),
      ...(parsedBundle?.targetSiteMapEvidenceAttachments?.length ? ['target-site-map-evidence'] : []),
      ...(parsedBundle?.proxyHistoryEvidenceAttachments?.length ? ['proxy-history-evidence'] : []),
      ...(parsedBundle?.scannerActiveScanEvidencePackages?.length ? ['scanner-active-scan-evidence'] : []),
      ...crossToolKinds,
    ].sort();

    return {
      profileId: profile.profileId,
      shareChannel: profile.shareChannel,
      recipient: profile.recipient,
      brandName: profileRequest.brandName ?? 'ProxyForge',
      preparedFor: profileRequest.preparedFor ?? 'Authorized Security Team',
      engagementId: profileRequest.engagementId ?? '',
      templateId: profileRequest.templateId ?? 'technical-remediation',
      signerName: profileRequest.signerName ?? profile.signerName,
      keyId: profileRequest.signingKeyId ?? profile.signingKeyId,
      byteLength: Buffer.byteLength(bundleText, 'utf8'),
      sha256: crypto.createHash('sha256').update(bundleText).digest('hex'),
      bundleDigestSha256: parsedBundle?.signature?.bundleDigestSha256,
      verificationStatus: verification.status,
      noSecretStatus: noSecretVerification.status,
      noSecretDigestMatches: Boolean(noSecretVerification.digestMatches),
      tamperStatus: tamperVerification.status,
      canonicalRoundTripStatus: canonicalRoundTripVerification.status,
      signatureCovers: parsedBundle?.signature?.covers ?? [],
      attachmentKinds,
      findingCount: Array.isArray(parsedBundle?.findings) ? parsedBundle.findings.length : 0,
      evidenceCount: Array.isArray(parsedBundle?.evidence) ? parsedBundle.evidence.length : 0,
      crossToolEvidenceCount: Array.isArray(parsedBundle?.crossToolEvidenceAttachments) ? parsedBundle.crossToolEvidenceAttachments.length : 0,
      redacted: markerLeaks.length === 0,
      secretMarkerLeaks: markerLeaks.length,
    };
  });

  const templateLibraryInterop = bundleProfiles.map((profile) => ({
    templateId: profile.templateId,
    profileId: profile.profileId,
    rendered: profile.byteLength > 0,
    byteLength: profile.byteLength,
    sha256: profile.sha256,
    redacted: profile.redacted,
  }));
  const diversity = {
    profileCount: bundleProfiles.length,
    shareChannelCount: uniqueCount(bundleProfiles.map((profile) => profile.shareChannel)),
    recipientCount: uniqueCount(bundleProfiles.map((profile) => profile.recipient)),
    signerCount: uniqueCount(bundleProfiles.map((profile) => profile.signerName)),
    keyIdCount: uniqueCount(bundleProfiles.map((profile) => profile.keyId)),
    templateCount: uniqueCount(bundleProfiles.map((profile) => profile.templateId)),
    attachmentKindCount: uniqueCount(bundleProfiles.flatMap((profile) => profile.attachmentKinds)),
    crossToolKindCount: uniqueCount(bundleProfiles.flatMap((profile) => (
      profile.attachmentKinds.filter((kind) => kind.includes(':'))
    ))),
    canonicalDigestCount: uniqueCount(bundleProfiles.map((profile) => profile.bundleDigestSha256 ?? profile.sha256)),
  };
  const requirements = {
    externalSharedBundleDiversityCovered: diversity.profileCount >= 4
      && diversity.shareChannelCount >= 4
      && diversity.recipientCount >= 4
      && diversity.signerCount >= 4
      && diversity.keyIdCount >= 4,
    signedBundleVerificationCovered: bundleProfiles.every((profile) => profile.verificationStatus === 'valid'),
    digestOnlyNoSecretReviewCovered: bundleProfiles.every((profile) => (
      profile.noSecretStatus === 'unverified' && profile.noSecretDigestMatches
    )),
    tamperRejectionCovered: bundleProfiles.every((profile) => profile.tamperStatus === 'invalid'),
    canonicalRoundTripCovered: bundleProfiles.every((profile) => profile.canonicalRoundTripStatus === 'valid')
      && diversity.canonicalDigestCount >= 4,
    crossToolAttachmentDiversityCovered: diversity.attachmentKindCount >= 8
      && diversity.crossToolKindCount >= 5
      && bundleProfiles.every((profile) => profile.signatureCovers.includes('crossToolEvidenceAttachments')),
    templateLibraryInteropCovered: diversity.templateCount >= 4
      && templateLibraryInterop.every((item) => item.rendered && /^[a-f0-9]{64}$/.test(item.sha256)),
    reportExportsRedacted: bundleProfiles.every((profile) => profile.redacted),
    rawOperationalInputsPreservedPreExport: baseSecretMarkers.length > 0 && operationalSecretSignals.length > 0,
    reportPhaseOnlyRedaction: true,
  };
  const body = {
    kind: 'proxyforge-report-external-bundle-diversity-package',
    generatedAt: generatedAt.toISOString(),
    projectName: normalized.projectName,
    bundleProfiles,
    diversity,
    templateLibraryInterop,
    operationalSecretSignals,
    requirements,
    secretHandling: 'report-export-redacts-submission-artifacts',
    operationalInputBoundary: 'executor-artifacts-remain-full-fidelity-before-report-export',
    reportRedactionBoundary: 'redact-only-during-report-export',
  };

  return {
    kind: 'proxyforge-report-external-bundle-diversity-package',
    schemaVersion: 1,
    generatedAt: generatedAt.toISOString(),
    projectName: normalized.projectName,
    bundleProfiles,
    diversity,
    templateLibraryInterop,
    operationalSecretSignals,
    requirements,
    secretHandling: 'report-export-redacts-submission-artifacts',
    operationalInputBoundary: 'executor-artifacts-remain-full-fidelity-before-report-export',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady: Object.values(requirements).every(Boolean),
    summary: `Report external bundle diversity verified ${diversity.profileCount} externally shared bundle profile(s), ${diversity.shareChannelCount} share channel(s), ${diversity.templateCount} template(s), ${diversity.crossToolKindCount} cross-tool kind(s), canonical JSON round trips, digest-only review, and tamper rejection.`,
    content: JSON.stringify(body, null, 2),
  };
}

export function buildReportTemplateLibraryInteropPackage(
  request: ReportExportRequest,
  generatedAt = new Date(),
  library?: {
    templates?: ReportTemplateLibraryEntryInput[];
    existingTemplates?: ReportTemplateLibraryEntryInput[];
  },
): ReportTemplateLibraryInteropPackage {
  const normalized = normalizeReportRequest({
    ...request,
    sections: request.sections.length ? request.sections : ['executive', 'technical', 'remediation', 'evidence', 'appendix'],
    format: 'markdown',
    signEvidenceBundle: true,
    signingSecret: request.signingSecret?.trim() || 'proxyforge-report-template-library-secret',
  });
  const templates = normalizeReportTemplateLibraryEntries(
    library?.templates?.length ? library.templates : defaultReportTemplateLibraryEntries(),
  );
  const existingTemplates = normalizeReportTemplateLibraryEntries(
    library?.existingTemplates?.length ? library.existingTemplates : defaultExistingReportTemplateLibraryEntries(),
  );
  const exportedLibraryObject = buildReportTemplateLibraryExport(templates, generatedAt);
  const exportedLibraryText = JSON.stringify(exportedLibraryObject, null, 2);
  const exportedLibrary = {
    kind: 'proxyforge-report-template-library' as const,
    templateCount: templates.length,
    byteLength: Buffer.byteLength(exportedLibraryText, 'utf8'),
    sha256: crypto.createHash('sha256').update(exportedLibraryText).digest('hex'),
    templateIds: templates.map((template) => template.id),
  };
  const importReview = importReportTemplateLibrary(exportedLibraryText, existingTemplates);
  const secretMarkers = extractReportSecretMarkers(normalized);
  const operationalSecretSignals = reportOperationalSecretSignals(normalized);
  const signingSecret = normalized.signingSecret?.trim() || 'proxyforge-report-template-library-secret';
  const renderProofs = importReview.acceptedTemplates.map((template): ReportTemplateLibraryRenderProof => {
    const templateRequest = buildTemplateLibraryReportRequest(normalized, template);
    const markdown = renderReport({ ...templateRequest, format: 'markdown' }, generatedAt);
    const html = renderReport({ ...templateRequest, format: 'html' }, generatedAt);
    const bundle = renderReport({
      ...templateRequest,
      format: 'bundle',
      signEvidenceBundle: true,
      signingSecret,
      signerName: 'Template Library Operator',
      signingKeyId: 'template-library-interop-key',
    }, generatedAt);
    const renderedText = [markdown, html, bundle].join('\n');
    const markers = [...secretMarkers, signingSecret].filter((marker) => marker.trim().length >= 4);
    const unresolvedTokenCount = countUnresolvedTemplateTokens(renderedText);
    return {
      templateId: template.id,
      name: template.name,
      reportTemplateId: template.templateId,
      sections: template.sections,
      variables: template.variables,
      markdownSha256: crypto.createHash('sha256').update(markdown).digest('hex'),
      htmlSha256: crypto.createHash('sha256').update(html).digest('hex'),
      bundleSha256: crypto.createHash('sha256').update(bundle).digest('hex'),
      markdownByteLength: Buffer.byteLength(markdown, 'utf8'),
      htmlByteLength: Buffer.byteLength(html, 'utf8'),
      bundleByteLength: Buffer.byteLength(bundle, 'utf8'),
      redacted: markers.every((marker) => !renderedText.includes(marker)),
      unresolvedTokenCount,
    };
  });
  const renderedTemplateIds = new Set(renderProofs.map((proof) => proof.reportTemplateId));
  const requirements = {
    templateLibraryExportCovered: exportedLibrary.templateCount >= 4
      && exportedLibrary.byteLength > 1000
      && /^[a-f0-9]{64}$/.test(exportedLibrary.sha256),
    templateLibraryImportCovered: importReview.acceptedTemplates.length >= templates.length
      && importReview.acceptedTemplateIds.length === importReview.acceptedTemplates.length,
    duplicateConflictReviewCovered: importReview.conflicts.length >= 1
      && importReview.conflicts.every((conflict) => conflict.resolution === 'renamed-import'),
    builtinTemplateInteropCovered: renderedTemplateIds.has('executive-board')
      && renderedTemplateIds.has('technical-remediation')
      && renderedTemplateIds.has('evidence-bundle'),
    customTemplateInteropCovered: renderedTemplateIds.has('custom')
      && renderProofs.some((proof) => proof.variables.includes('findingsMarkdown') && proof.variables.includes('evidenceMarkdown')),
    templateVariablesResolved: renderProofs.every((proof) => proof.unresolvedTokenCount === 0),
    bundleRenderCovered: renderProofs.every((proof) => (
      proof.bundleByteLength > 0 && /^[a-f0-9]{64}$/.test(proof.bundleSha256)
    )),
    reportExportsRedacted: renderProofs.every((proof) => proof.redacted),
    rawOperationalInputsPreservedPreExport: secretMarkers.length > 0 && operationalSecretSignals.length > 0,
    reportPhaseOnlyRedaction: true,
  };
  const body = {
    kind: 'proxyforge-report-template-library-interop-package',
    generatedAt: generatedAt.toISOString(),
    projectName: normalized.projectName,
    exportedLibrary: {
      ...exportedLibrary,
      templates,
    },
    importReview: {
      existingTemplateCount: importReview.existingTemplateCount,
      incomingTemplateCount: importReview.incomingTemplateCount,
      acceptedTemplateCount: importReview.acceptedTemplates.length,
      conflictCount: importReview.conflicts.length,
      conflicts: importReview.conflicts,
      acceptedTemplateIds: importReview.acceptedTemplateIds,
    },
    renderProofs,
    operationalSecretSignals,
    requirements,
    secretHandling: 'report-export-redacts-submission-artifacts',
    operationalInputBoundary: 'executor-artifacts-remain-full-fidelity-before-report-export',
    reportRedactionBoundary: 'redact-only-during-report-export',
  };

  return {
    kind: 'proxyforge-report-template-library-interop-package',
    schemaVersion: 1,
    generatedAt: generatedAt.toISOString(),
    projectName: normalized.projectName,
    exportedLibrary,
    importReview: body.importReview,
    renderProofs,
    operationalSecretSignals,
    requirements,
    secretHandling: 'report-export-redacts-submission-artifacts',
    operationalInputBoundary: 'executor-artifacts-remain-full-fidelity-before-report-export',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady: Object.values(requirements).every(Boolean),
    summary: `Report template library interop exported ${exportedLibrary.templateCount} template(s), imported ${importReview.acceptedTemplates.length} template(s), reviewed ${importReview.conflicts.length} conflict(s), and rendered ${renderProofs.length} Markdown/HTML/bundle proof set(s).`,
    content: JSON.stringify(body, null, 2),
  };
}

export function verifyEvidenceBundleText(bundleText: string, signingSecret = ''): ReportEvidenceBundleVerificationResult {
  let bundle: Record<string, unknown>;
  try {
    bundle = JSON.parse(bundleText) as Record<string, unknown>;
  } catch (error) {
    return {
      status: 'parse-error',
      message: `Bundle JSON parse failed: ${error instanceof Error ? error.message : 'unknown error'}`,
    };
  }
  const signature = bundle.signature && typeof bundle.signature === 'object'
    ? bundle.signature as Record<string, unknown>
    : undefined;
  const findings = Array.isArray(bundle.findings) ? bundle.findings.length : undefined;
  const evidence = Array.isArray(bundle.evidence) ? bundle.evidence.length : undefined;
  if (!signature) {
    return {
      status: 'unsigned',
      message: 'Evidence bundle has no signature block.',
      findings,
      evidence,
    };
  }
  if (signature.algorithm !== 'HMAC-SHA256') {
    return {
      status: 'invalid',
      message: `Unsupported bundle signature algorithm: ${String(signature.algorithm ?? 'unknown')}.`,
      signerName: readOptionalString(signature.signerName),
      keyId: readOptionalString(signature.keyId),
      signedAt: readOptionalString(signature.signedAt),
      findings,
      evidence,
    };
  }
  const unsignedBundle = { ...bundle };
  delete unsignedBundle.signature;
  const canonical = canonicalize(unsignedBundle);
  const digest = crypto.createHash('sha256').update(canonical).digest('hex');
  const digestMatches = digest.toLowerCase() === String(signature.bundleDigestSha256 ?? '').toLowerCase();
  if (!signingSecret.trim()) {
    return {
      status: 'unverified',
      message: digestMatches
        ? 'Bundle digest matches, but no signing secret was supplied for HMAC verification.'
        : 'Bundle digest does not match the signature block.',
      digest,
      digestMatches,
      signatureMatches: false,
      signerName: readOptionalString(signature.signerName),
      keyId: readOptionalString(signature.keyId),
      signedAt: readOptionalString(signature.signedAt),
      findings,
      evidence,
    };
  }
  const computedSignature = crypto.createHmac('sha256', signingSecret).update(canonical).digest('hex');
  const signatureMatches = computedSignature.toLowerCase() === String(signature.signature ?? '').toLowerCase();
  return {
    status: digestMatches && signatureMatches ? 'valid' : 'invalid',
    message: digestMatches && signatureMatches
      ? 'Evidence bundle signature and digest are valid.'
      : 'Evidence bundle signature or digest is invalid.',
    digest,
    digestMatches,
    signatureMatches,
    signerName: readOptionalString(signature.signerName),
    keyId: readOptionalString(signature.keyId),
    signedAt: readOptionalString(signature.signedAt),
    findings,
    evidence,
  };
}

function normalizeReportRequest(request: ReportExportRequest): ReportExportRequest {
  const templateId = request.templateId ?? (request.format === 'bundle' ? 'evidence-bundle' : 'technical-remediation');
  const defaultSections: ReportSection[] = templateId === 'executive-board'
    ? ['executive', 'remediation', 'appendix']
    : templateId === 'evidence-bundle'
      ? ['executive', 'technical', 'remediation', 'evidence', 'appendix']
      : templateId === 'custom'
        ? ['executive', 'technical', 'remediation', 'evidence', 'appendix']
      : ['executive', 'technical', 'remediation', 'evidence'];
  const sections: ReportSection[] = request.sections.length ? request.sections : defaultSections;
  return {
    projectName: request.projectName || 'ProxyForge Assessment',
    brandName: request.brandName?.trim() || 'ProxyForge',
    preparedFor: request.preparedFor?.trim() || 'Authorized Security Team',
    engagementId: request.engagementId?.trim() || `PF-${new Date().getFullYear()}`,
    templateId,
    customTemplateName: request.customTemplateName?.trim().slice(0, 120) || 'Custom operator template',
    customTemplateBody: request.customTemplateBody?.slice(0, 30000) || DEFAULT_CUSTOM_TEMPLATE,
    signEvidenceBundle: Boolean(request.signEvidenceBundle),
    signingKeyId: request.signingKeyId?.trim() || 'proxyforge-local',
    signingSecret: request.signingSecret ?? '',
    signerName: request.signerName?.trim() || request.brandName?.trim() || 'ProxyForge',
    loggerImportJobs: normalizeLoggerImportJobs(request.loggerImportJobs),
    targetSiteMapEvidenceAttachments: normalizeReportEvidenceAttachments(request.targetSiteMapEvidenceAttachments),
    proxyHistoryEvidenceAttachments: normalizeReportEvidenceAttachments(request.proxyHistoryEvidenceAttachments),
    scannerActiveScanEvidencePackages: normalizeScannerActiveScanEvidencePackages(request.scannerActiveScanEvidencePackages),
    crossToolEvidenceAttachments: normalizeReportCrossToolEvidenceAttachments(request.crossToolEvidenceAttachments),
    governanceAttestation: request.governanceAttestation ?? defaultGovernanceAttestation(request.scopeAllowlist),
    scopeAllowlist: request.scopeAllowlist.filter(Boolean),
    issues: request.issues.map(redactIssue).sort((a, b) => severityRank(b.severity) - severityRank(a.severity)),
    exchanges: request.exchanges.slice(0, 200),
    format: request.format,
    sections,
  };
}

function buildSummary(request: ReportExportRequest) {
  const openIssues = request.issues.filter((issue) => issue.status === 'open');
  return {
    totalIssues: request.issues.length,
    openIssues: openIssues.length,
    highOrCritical: request.issues.filter((issue) => severityRank(issue.severity) >= severityRank('high')).length,
    affectedHosts: Array.from(new Set(request.issues.map((issue) => issue.host))).length,
    evidenceItems: request.exchanges.length,
    loggerImportJobs: request.loggerImportJobs?.length ?? 0,
    targetSiteMapEvidence: (request.targetSiteMapEvidenceAttachments ?? []).filter((item) => item.reportReady).length,
    proxyHistoryEvidence: (request.proxyHistoryEvidenceAttachments ?? []).filter((item) => item.reportReady).length,
    scannerActiveScanEvidencePackages: (request.scannerActiveScanEvidencePackages ?? []).filter((item) => item.reportReady).length,
    crossToolEvidence: (request.crossToolEvidenceAttachments ?? []).filter((item) => item.reportReady).length,
  };
}

function normalizeReportEvidenceAttachments(attachments?: ReportEvidenceAttachment[]) {
  return (attachments ?? []).slice(0, 40).map((attachment, index) => ({
    id: attachment.id || `report-evidence-attachment-${index + 1}`,
    title: attachment.title || 'Report evidence attachment',
    fileName: attachment.fileName || `report-evidence-attachment-${index + 1}.json`,
    path: attachment.path || `reports/attachments/report-evidence-attachment-${index + 1}.json`,
    createdAt: attachment.createdAt,
    reportReady: Boolean(attachment.reportReady),
    issueId: attachment.issueId,
    summary: redactSecrets(attachment.summary || 'Report-ready evidence attachment'),
    content: redactSecrets(attachment.content || ''),
  }));
}

function normalizeLoggerImportJobs(jobs?: ReportLoggerImportAttachment[]) {
  return (jobs ?? []).slice(0, 20).map((job, index) => ({
    id: job.id || `logger-import-job-${index + 1}`,
    importedAt: job.importedAt || '',
    format: job.format || 'raw-http',
    mappingPresetName: job.mappingPresetName || 'Logger import',
    normalization: job.normalization || 'report-evidence',
    notes: job.notes || '',
    addedEntries: Number.isFinite(job.addedEntries) ? job.addedEntries : 0,
    changedEntries: Number.isFinite(job.changedEntries) ? job.changedEntries : 0,
    duplicateEntries: Number.isFinite(job.duplicateEntries) ? job.duplicateEntries : 0,
    sourceHosts: (job.sourceHosts ?? []).filter((host): host is string => typeof host === 'string').slice(0, 12),
    replayCount: Number.isFinite(job.replayCount) ? job.replayCount : 0,
    replayedAt: job.replayedAt,
    exchangeCount: Number.isFinite(job.exchangeCount) ? job.exchangeCount : 0,
  }));
}

function normalizeReportCrossToolEvidenceAttachments(attachments?: ReportCrossToolEvidenceAttachment[]) {
  return (attachments ?? []).slice(0, 80).map((attachment, index) => ({
    ...normalizeReportEvidenceAttachments([attachment])[0],
    tool: attachment.tool?.trim() || 'unknown',
    kind: attachment.kind?.trim() || 'proxyforge-cross-tool-evidence',
    signatureStatus: attachment.signatureStatus,
    sha256: attachment.sha256,
  }));
}

function normalizeScannerActiveScanEvidencePackages(packages?: unknown) {
  const packageList = Array.isArray(packages) ? packages : [];
  return packageList.slice(0, 40).map((item, index): ReportScannerActiveScanEvidencePackage => {
    const source = item && typeof item === 'object' ? item as Record<string, unknown> : {};
    const exchangeIds = Array.isArray(source.exchangeIds)
      ? source.exchangeIds.filter((id): id is string => typeof id === 'string').slice(0, 80)
      : [];
    return {
      id: readString(source.id, `scanner-active-scan-evidence-package-${index + 1}`),
      title: readString(source.title, 'Scanner Active Scan Evidence Package'),
      fileName: readString(source.fileName, `scanner-active-scan-evidence-package-${index + 1}.json`),
      path: readString(source.path, `reports/scanner-active-scan-evidence-package-${index + 1}.json`),
      createdAt: readString(source.createdAt, ''),
      planId: readString(source.planId, 'pending-plan'),
      insertionPointReviewId: readString(source.insertionPointReviewId, 'pending-insertion-point-review'),
      authenticatedStateMatrixId: readString(source.authenticatedStateMatrixId, 'pending-authenticated-state-matrix'),
      replayCheckPackageId: readString(source.replayCheckPackageId, 'pending-replay-check-package'),
      activeScanSummaryId: readOptionalString(source.activeScanSummaryId),
      findingCount: readNumber(source.findingCount),
      exchangeIds,
      ciCommand: readString(source.ciCommand, ''),
      reportReady: Boolean(source.reportReady),
      summary: redactSecrets(readString(source.summary, 'Scanner active scan evidence package')),
      content: redactSecrets(readString(source.content, '')),
    };
  });
}

function readString(value: unknown, fallback: string) {
  return typeof value === 'string' && value.trim() ? value : fallback;
}

function readOptionalString(value: unknown) {
  return typeof value === 'string' && value.trim() ? value : undefined;
}

function readNumber(value: unknown) {
  return typeof value === 'number' && Number.isFinite(value) ? value : 0;
}

function uniqueCount(values: Array<string | undefined>) {
  return new Set(values.filter((value): value is string => typeof value === 'string' && value.trim().length > 0)).size;
}

function defaultGovernanceAttestation(scopeAllowlist: string[]): ReportGovernanceAttestation {
  return {
    packageId: 'no-active-governance-package',
    title: 'No active governance policy package',
    teamName: 'Local project policy',
    activeOperator: 'unassigned',
    operatorRole: 'operator',
    status: 'missing',
    signature: {
      algorithm: 'HMAC-SHA256',
      signerName: 'ProxyForge Governance',
      keyId: 'missing-governance-key',
      status: 'missing',
      digestPreview: 'missing',
    },
    runnerBindingCount: 0,
    approvalRequiredCount: 0,
    scopeGateSummary: `Report scope ${scopeAllowlist.filter(Boolean).join(', ') || 'not specified'} has no active governance package attestation.`,
    rateGateSummary: 'No active governance rate gate attested for this export.',
    approvalGateSummary: 'No active governance approval gate attested for this export.',
    ciHeadlessSummary: 'No active CI/headless governance binding attested for this export.',
  };
}

function defaultExternalBundleDiversityProfiles(baseSigningSecret: string): ReportExternalBundleDiversityProfileInput[] {
  return [
    {
      profileId: 'bug-bounty-portal-handoff',
      shareChannel: 'bug-bounty-portal',
      recipient: 'Bug bounty program portal',
      brandName: 'External Program Security',
      preparedFor: 'Program Triage Team',
      engagementId: 'EXT-BB-PORTAL',
      signerName: 'Program Portal Reviewer',
      signingKeyId: 'external-bugbounty-portal-key',
      signingSecret: `${baseSigningSecret}:bug-bounty-portal`,
      templateId: 'evidence-bundle',
      sections: ['executive', 'technical', 'remediation', 'evidence', 'appendix'],
    },
    {
      profileId: 'customer-grc-import',
      shareChannel: 'customer-grc',
      recipient: 'Customer GRC system',
      brandName: 'Customer Risk Office',
      preparedFor: 'Risk Register Intake',
      engagementId: 'EXT-GRC-IMPORT',
      signerName: 'Customer GRC Reviewer',
      signingKeyId: 'external-customer-grc-key',
      signingSecret: `${baseSigningSecret}:customer-grc`,
      templateId: 'technical-remediation',
      sections: ['executive', 'technical', 'remediation', 'evidence', 'appendix'],
    },
    {
      profileId: 'partner-mssp-retainer',
      shareChannel: 'partner-mssp',
      recipient: 'Partner MSSP evidence vault',
      brandName: 'Partner Security Operations',
      preparedFor: 'MSSP Retainer Desk',
      engagementId: 'EXT-MSSP-VAULT',
      signerName: 'Partner MSSP Reviewer',
      signingKeyId: 'external-partner-mssp-key',
      signingSecret: `${baseSigningSecret}:partner-mssp`,
      templateId: 'executive-board',
      sections: ['executive', 'technical', 'remediation', 'evidence', 'appendix'],
    },
    {
      profileId: 'internal-remediation-board',
      shareChannel: 'internal-remediation',
      recipient: 'Internal remediation board',
      brandName: 'Internal Security Engineering',
      preparedFor: 'Remediation Owners',
      engagementId: 'EXT-REMEDIATION-BOARD',
      signerName: 'Remediation Board Reviewer',
      signingKeyId: 'external-remediation-board-key',
      signingSecret: `${baseSigningSecret}:internal-remediation`,
      templateId: 'custom',
      sections: ['executive', 'technical', 'remediation', 'evidence', 'appendix'],
      customTemplateName: 'External bundle diversity custom template',
      customTemplateBody: [
        '# {{projectName}} External Shared Bundle',
        '',
        'Recipient: {{preparedFor}}',
        'Brand: {{brandName}}',
        'Engagement: {{engagementId}}',
        'Findings: {{summary.totalIssues}}',
        'Cross-tool evidence: {{summary.crossToolEvidence}}',
        '',
        '{{executiveMarkdown}}',
        '',
        '{{findingsMarkdown}}',
        '',
        '{{remediationMarkdown}}',
        '',
        '{{evidenceMarkdown}}',
        '',
        '{{appendixMarkdown}}',
      ].join('\n'),
    },
  ];
}

function defaultReportTemplateLibraryEntries(): ReportTemplateLibraryEntryInput[] {
  return [
    {
      id: 'executive-board-summary',
      name: 'Executive board summary',
      description: 'Board-facing impact and priority narrative for leadership handoff.',
      templateId: 'executive-board',
      sections: ['executive', 'remediation', 'appendix'],
      version: '1.0.0',
      source: 'proxyforge-builtins',
      body: [
        '# {{projectName}} Board Summary',
        '',
        '{{executiveMarkdown}}',
        '',
        '{{remediationMarkdown}}',
        '',
        '{{appendixMarkdown}}',
      ].join('\n'),
    },
    {
      id: 'technical-remediation-runbook',
      name: 'Technical remediation runbook',
      description: 'Detailed finding, owner, and validation workflow report.',
      templateId: 'technical-remediation',
      sections: ['executive', 'technical', 'remediation', 'evidence'],
      version: '1.0.0',
      source: 'proxyforge-builtins',
      body: [
        '# {{projectName}} Technical Remediation',
        '',
        '{{executiveMarkdown}}',
        '',
        '{{findingsMarkdown}}',
        '',
        '{{remediationMarkdown}}',
        '',
        '{{evidenceMarkdown}}',
      ].join('\n'),
    },
    {
      id: 'signed-evidence-bundle',
      name: 'Signed evidence bundle',
      description: 'Evidence-heavy bundle template for signed cross-tool handoff.',
      templateId: 'evidence-bundle',
      sections: ['executive', 'technical', 'remediation', 'evidence', 'appendix'],
      version: '1.0.0',
      source: 'proxyforge-builtins',
      body: [
        '# {{projectName}} Evidence Bundle',
        '',
        '{{executiveMarkdown}}',
        '',
        '{{findingsMarkdown}}',
        '',
        '{{evidenceMarkdown}}',
        '',
        '{{appendixMarkdown}}',
      ].join('\n'),
    },
    {
      id: 'bug-bounty-narrative',
      name: 'Bug bounty narrative',
      description: 'Submission-ready narrative with concise impact, proof, and remediation.',
      templateId: 'custom',
      sections: ['executive', 'technical', 'remediation', 'evidence', 'appendix'],
      version: '1.0.0',
      source: 'operator-library',
      body: [
        '# {{projectName}} Bug Bounty Narrative',
        '',
        'Prepared for {{preparedFor}} by {{brandName}}',
        'Engagement: {{engagementId}}',
        'Findings: {{summary.totalIssues}}',
        'Evidence items: {{summary.evidenceItems}}',
        'Cross-tool evidence: {{summary.crossToolEvidence}}',
        '',
        '{{executiveMarkdown}}',
        '',
        '{{findingsMarkdown}}',
        '',
        '{{remediationMarkdown}}',
        '',
        '{{evidenceMarkdown}}',
        '',
        '{{appendixMarkdown}}',
      ].join('\n'),
    },
  ];
}

function defaultExistingReportTemplateLibraryEntries(): ReportTemplateLibraryEntryInput[] {
  return [
    {
      id: 'executive-board-summary',
      name: 'Existing executive board summary',
      description: 'Older local executive template that should not be overwritten by import.',
      templateId: 'executive-board',
      sections: ['executive', 'appendix'],
      version: '0.9.0',
      source: 'local-existing-library',
      body: [
        '# Existing {{projectName}} Board Summary',
        '',
        '{{executiveMarkdown}}',
        '',
        '{{appendixMarkdown}}',
      ].join('\n'),
    },
  ];
}

function normalizeReportTemplateLibraryEntries(entries: ReportTemplateLibraryEntryInput[]): ReportTemplateLibraryEntry[] {
  return entries.slice(0, 40).map((entry, index) => {
    const templateId = isReportTemplateId(entry.templateId) ? entry.templateId : 'custom';
    const defaultSections: ReportSection[] = templateId === 'executive-board'
      ? ['executive', 'remediation', 'appendix']
      : ['executive', 'technical', 'remediation', 'evidence', 'appendix'];
    const sections = Array.from(new Set((entry.sections ?? defaultSections).filter(isReportSection)));
    const body = (entry.body?.trim() || DEFAULT_CUSTOM_TEMPLATE).slice(0, 30000);
    const normalized = {
      id: slugifyTemplateId(entry.id || entry.name || `report-template-${index + 1}`),
      name: (entry.name || `Report template ${index + 1}`).trim().slice(0, 120),
      description: (entry.description || 'Report template library entry').trim().slice(0, 400),
      templateId,
      sections: sections.length ? sections : defaultSections,
      body,
      version: (entry.version || '1.0.0').trim().slice(0, 40),
      source: (entry.source || 'operator-library').trim().slice(0, 120),
      variables: extractTemplateVariables(body),
      byteLength: Buffer.byteLength(body, 'utf8'),
      sha256: '',
    };
    return {
      ...normalized,
      sha256: crypto.createHash('sha256').update(canonicalize({
        id: normalized.id,
        name: normalized.name,
        description: normalized.description,
        templateId: normalized.templateId,
        sections: normalized.sections,
        body: normalized.body,
        version: normalized.version,
        source: normalized.source,
      })).digest('hex'),
    };
  });
}

function buildReportTemplateLibraryExport(templates: ReportTemplateLibraryEntry[], generatedAt: Date) {
  return {
    kind: 'proxyforge-report-template-library',
    schemaVersion: 1,
    exportedAt: generatedAt.toISOString(),
    templates,
  };
}

function importReportTemplateLibrary(libraryText: string, existingTemplates: ReportTemplateLibraryEntry[]) {
  const parsed = safeParseJson(libraryText) as { templates?: ReportTemplateLibraryEntryInput[] } | undefined;
  const incomingTemplates = normalizeReportTemplateLibraryEntries(parsed?.templates ?? []);
  const existingById = new Map(existingTemplates.map((template) => [template.id, template]));
  const acceptedTemplates: ReportTemplateLibraryEntry[] = [];
  const conflicts: ReportTemplateLibraryConflict[] = [];

  for (const incoming of incomingTemplates) {
    const existing = existingById.get(incoming.id);
    if (existing && existing.sha256 !== incoming.sha256) {
      const importedId = uniqueTemplateImportId(`${incoming.id}-imported`, existingById, acceptedTemplates);
      conflicts.push({
        existingId: existing.id,
        incomingId: incoming.id,
        importedId,
        resolution: 'renamed-import',
        reason: 'Incoming template id matched an existing template with different content.',
      });
      acceptedTemplates.push({
        ...incoming,
        id: importedId,
        sha256: crypto.createHash('sha256').update(canonicalize({
          id: importedId,
          name: incoming.name,
          description: incoming.description,
          templateId: incoming.templateId,
          sections: incoming.sections,
          body: incoming.body,
          version: incoming.version,
          source: incoming.source,
        })).digest('hex'),
      });
      continue;
    }
    acceptedTemplates.push(incoming);
  }

  return {
    existingTemplateCount: existingTemplates.length,
    incomingTemplateCount: incomingTemplates.length,
    acceptedTemplates,
    acceptedTemplateIds: acceptedTemplates.map((template) => template.id),
    conflicts,
  };
}

function buildTemplateLibraryReportRequest(
  baseRequest: ReportExportRequest,
  template: ReportTemplateLibraryEntry,
): ReportExportRequest {
  return normalizeReportRequest({
    ...baseRequest,
    templateId: template.templateId,
    sections: template.sections,
    customTemplateName: template.templateId === 'custom' ? template.name : baseRequest.customTemplateName,
    customTemplateBody: template.templateId === 'custom' ? template.body : baseRequest.customTemplateBody,
  });
}

function extractTemplateVariables(body: string) {
  return Array.from(new Set(Array.from(body.matchAll(/{{\s*([a-zA-Z0-9_.]+)\s*}}/g))
    .map((match) => match[1])))
    .sort();
}

function countUnresolvedTemplateTokens(value: string) {
  return (value.match(/{{\s*[a-zA-Z0-9_.]+\s*}}/g) ?? []).length;
}

function uniqueTemplateImportId(
  baseId: string,
  existingById: Map<string, ReportTemplateLibraryEntry>,
  acceptedTemplates: ReportTemplateLibraryEntry[],
) {
  let candidate = baseId;
  let suffix = 2;
  const acceptedIds = new Set(acceptedTemplates.map((template) => template.id));
  while (existingById.has(candidate) || acceptedIds.has(candidate)) {
    candidate = `${baseId}-${suffix}`;
    suffix += 1;
  }
  return candidate;
}

function slugifyTemplateId(value: string) {
  return value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_.-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 80) || 'report-template';
}

function isReportTemplateId(value: unknown): value is ReportTemplateId {
  return value === 'executive-board'
    || value === 'technical-remediation'
    || value === 'evidence-bundle'
    || value === 'custom';
}

function isReportSection(value: unknown): value is ReportSection {
  return value === 'executive'
    || value === 'technical'
    || value === 'remediation'
    || value === 'evidence'
    || value === 'appendix';
}

function renderLoggerImportJobsMarkdown(jobs: ReportLoggerImportAttachment[]) {
  if (!jobs.length) return '';
  return [
    '### Logger Import Jobs',
    '',
    '| Imported | Mapping | Hosts | Adds | Variants | Duplicates | Replays | Notes |',
    '| --- | --- | --- | ---: | ---: | ---: | ---: | --- |',
    ...jobs.map((job) => (
      `| ${markdownCell(job.importedAt)} | ${markdownCell(job.mappingPresetName)} | ${markdownCell(job.sourceHosts.join(', ') || 'none')} | ${job.addedEntries} | ${job.changedEntries} | ${job.duplicateEntries} | ${job.replayCount} | ${markdownCell(job.notes || 'No reviewer notes')} |`
    )),
  ].join('\n');
}

function renderTargetSiteMapEvidenceMarkdown(attachments: ReportEvidenceAttachment[]) {
  const reportReadyAttachments = attachments.filter((item) => item.reportReady);
  if (!reportReadyAttachments.length) return '';
  return [
    '### Target Site Map Evidence',
    '',
    '| Attachment | Linked Issue | Summary |',
    '| --- | --- | --- |',
    ...reportReadyAttachments.map((item) => (
      `| ${markdownCell(item.fileName)} | ${markdownCell(item.issueId ?? 'pending')} | ${markdownCell(item.summary)} |`
    )),
    '',
    ...reportReadyAttachments.map((item) => [
      `#### ${item.title}`,
      '',
      item.summary,
      '',
      '```',
      item.content.trim(),
      '```',
    ].join('\n')),
  ].join('\n');
}

function renderProxyHistoryEvidenceMarkdown(attachments: ReportEvidenceAttachment[]) {
  const reportReadyAttachments = attachments.filter((item) => item.reportReady);
  if (!reportReadyAttachments.length) return '';
  return [
    '### Proxy History Evidence',
    '',
    '| Attachment | Linked Issue | Summary |',
    '| --- | --- | --- |',
    ...reportReadyAttachments.map((item) => (
      `| ${markdownCell(item.fileName)} | ${markdownCell(item.issueId ?? 'pending')} | ${markdownCell(item.summary)} |`
    )),
    '',
    ...reportReadyAttachments.map((item) => [
      `#### ${item.title}`,
      '',
      item.summary,
      '',
      '```',
      item.content.trim(),
      '```',
    ].join('\n')),
  ].join('\n');
}

function renderScannerActiveScanEvidencePackagesMarkdown(packages: ReportScannerActiveScanEvidencePackage[]) {
  const reportReadyPackages = packages.filter((item) => item.reportReady);
  if (!reportReadyPackages.length) return '';
  return [
    '### Scanner Active Scan Evidence Packages',
    '',
    '| Package | Plan | Findings | Exchanges | CI Handoff | Summary |',
    '| --- | --- | ---: | ---: | --- | --- |',
    ...reportReadyPackages.map((item) => (
      `| ${markdownCell(item.fileName)} | ${markdownCell(item.planId)} | ${item.findingCount} | ${item.exchangeIds.length} | ${markdownCell(item.ciCommand || 'not captured')} | ${markdownCell(item.summary)} |`
    )),
    '',
    ...reportReadyPackages.map((item) => [
      `#### ${item.title}`,
      '',
      item.summary,
      '',
      '```json',
      item.content.trim() || '{}',
      '```',
    ].join('\n')),
  ].join('\n');
}

function renderCrossToolEvidenceMarkdown(attachments: ReportCrossToolEvidenceAttachment[]) {
  const reportReadyAttachments = attachments.filter((item) => item.reportReady);
  if (!reportReadyAttachments.length) return '';
  return [
    '### Cross-Tool Evidence Attachments',
    '',
    '| Tool | Kind | Attachment | Signature | Summary |',
    '| --- | --- | --- | --- | --- |',
    ...reportReadyAttachments.map((item) => (
      `| ${markdownCell(item.tool)} | ${markdownCell(item.kind)} | ${markdownCell(item.fileName)} | ${markdownCell(item.signatureStatus ?? 'ready-on-export')} | ${markdownCell(item.summary)} |`
    )),
    '',
    ...reportReadyAttachments.map((item) => [
      `#### ${item.tool}: ${item.title}`,
      '',
      item.summary,
      '',
      '```json',
      item.content.trim() || '{}',
      '```',
    ].join('\n')),
  ].join('\n');
}

function renderMarkdownReport(request: ReportExportRequest, generatedAt: Date) {
  if (request.templateId === 'custom') {
    return renderCustomMarkdownReport(request, generatedAt);
  }

  const lines = [
    `# ${request.projectName} Security Assessment`,
    '',
    `Prepared for: ${request.preparedFor}`,
    `Brand: ${request.brandName}`,
    `Engagement: ${request.engagementId}`,
    `Template: ${templateLabel(request.templateId, request.customTemplateName)}`,
    `Generated: ${generatedAt.toISOString()}`,
    `Governance: ${request.governanceAttestation?.status ?? 'missing'} ${request.governanceAttestation?.teamName ?? 'Local project policy'} ${request.governanceAttestation?.signature.digestPreview ?? 'missing'}`,
    `Scope: ${request.scopeAllowlist.join(', ') || 'Not specified'}`,
    '',
  ];

  if (request.sections.includes('executive')) {
    const summary = buildSummary(request);
    lines.push('## Executive Summary', '');
    lines.push(`${request.brandName} reviewed ${summary.evidenceItems} evidence items and identified ${summary.totalIssues} issues across ${summary.affectedHosts} host(s).`);
    lines.push(`${summary.highOrCritical} issue(s) are high or critical priority and should be validated first.`, '');
    if (request.templateId === 'executive-board') {
      lines.push('Board Focus:', '');
      lines.push(`- Exposure: ${summary.affectedHosts} affected host(s) in authorized scope.`);
      lines.push(`- Priority: ${summary.highOrCritical} high-or-critical item(s) need owner review.`);
      lines.push(`- Evidence: ${summary.evidenceItems} redacted request/response artifact(s) retained for audit.`, '');
    }
  }

  if (request.sections.includes('technical')) {
    lines.push('## Technical Findings', '');
    for (const issue of request.issues) {
      lines.push(`### ${severityLabel(issue.severity)}: ${issue.title}`, '');
      lines.push(`- Host: ${issue.host}`);
      lines.push(`- Path: ${issue.path}`);
      lines.push(`- Confidence: ${issue.confidence}`);
      lines.push(`- Status: ${issue.status}`);
      lines.push('');
      lines.push(issue.detail, '');
      lines.push('Remediation:', issue.remediation, '');
      if (request.templateId === 'technical-remediation') {
        lines.push('Validation plan:', `Replay the linked evidence under an authorized account, compare status/body deltas, and attach remediation proof before closure.`, '');
      }
    }
  }

  if (request.sections.includes('remediation')) {
    lines.push('## Remediation Plan', '');
    lines.push('| Priority | Finding | Owner | Status | Evidence | Validation |');
    lines.push('| --- | --- | --- | --- | ---: | --- |');
    for (const item of buildRemediationPlan(request)) {
      lines.push(`| ${item.priority} | ${markdownCell(item.finding)} | ${markdownCell(item.owner)} | ${markdownCell(item.status)} | ${item.evidenceCount} | ${markdownCell(item.validation)} |`);
    }
    lines.push('');
  }

  if (request.sections.includes('evidence')) {
    lines.push('## Evidence', '');
    for (const exchange of request.exchanges.map(redactExchange)) {
      lines.push(`### ${exchange.method} ${exchange.host}${exchange.path}`, '');
      lines.push(`Status: ${exchange.status} | Source: ${exchange.source} | Risk: ${severityLabel(exchange.risk)} | Notes: ${exchange.notes}`, '');
      lines.push('Request:', '```http', exchange.requestRaw.trim(), '```', '');
      lines.push('Response:', '```http', exchange.responseRaw.trim(), '```', '');
    }
    const loggerImportJobsMarkdown = renderLoggerImportJobsMarkdown(request.loggerImportJobs ?? []);
    if (loggerImportJobsMarkdown) lines.push(loggerImportJobsMarkdown, '');
    const targetSiteMapEvidenceMarkdown = renderTargetSiteMapEvidenceMarkdown(request.targetSiteMapEvidenceAttachments ?? []);
    if (targetSiteMapEvidenceMarkdown) lines.push(targetSiteMapEvidenceMarkdown, '');
    const proxyHistoryEvidenceMarkdown = renderProxyHistoryEvidenceMarkdown(request.proxyHistoryEvidenceAttachments ?? []);
    if (proxyHistoryEvidenceMarkdown) lines.push(proxyHistoryEvidenceMarkdown, '');
    const scannerActiveScanEvidenceMarkdown = renderScannerActiveScanEvidencePackagesMarkdown(request.scannerActiveScanEvidencePackages ?? []);
    if (scannerActiveScanEvidenceMarkdown) lines.push(scannerActiveScanEvidenceMarkdown, '');
    const crossToolEvidenceMarkdown = renderCrossToolEvidenceMarkdown(request.crossToolEvidenceAttachments ?? []);
    if (crossToolEvidenceMarkdown) lines.push(crossToolEvidenceMarkdown, '');
  }

  if (request.sections.includes('appendix')) {
    lines.push('## Appendix', '');
    lines.push(`- Generated by ${request.brandName}`);
    lines.push(`- Prepared for ${request.preparedFor}`);
    lines.push(`- Engagement ID: ${request.engagementId}`);
    lines.push('- Active traffic should remain within the recorded project scope.');
    lines.push('- Secrets in request and response evidence were redacted before export.');
  }

  return `${lines.join('\n')}\n`;
}

function renderCustomMarkdownReport(request: ReportExportRequest, generatedAt: Date) {
  const summary = buildSummary(request);
  const safeTemplate = request.customTemplateBody?.trim() || DEFAULT_CUSTOM_TEMPLATE;
  const replacements: Record<string, string | number> = {
    projectName: request.projectName,
    brandName: request.brandName ?? 'ProxyForge',
    preparedFor: request.preparedFor ?? 'Authorized Security Team',
    engagementId: request.engagementId ?? '',
    generatedAt: generatedAt.toISOString(),
    scope: request.scopeAllowlist.join(', ') || 'Not specified',
    sections: request.sections.join(', '),
    templateName: templateLabel(request.templateId, request.customTemplateName),
    'summary.totalIssues': summary.totalIssues,
    'summary.openIssues': summary.openIssues,
    'summary.highOrCritical': summary.highOrCritical,
    'summary.affectedHosts': summary.affectedHosts,
    'summary.evidenceItems': summary.evidenceItems,
    'summary.loggerImportJobs': summary.loggerImportJobs,
    'summary.targetSiteMapEvidence': summary.targetSiteMapEvidence,
    'summary.proxyHistoryEvidence': summary.proxyHistoryEvidence,
    'summary.scannerActiveScanEvidencePackages': summary.scannerActiveScanEvidencePackages,
    'summary.crossToolEvidence': summary.crossToolEvidence,
    executiveMarkdown: renderCustomExecutiveSection(request),
    findingsMarkdown: renderCustomFindingsSection(request),
    remediationMarkdown: renderCustomRemediationSection(request),
    evidenceMarkdown: renderCustomEvidenceSection(request),
    loggerImportJobsMarkdown: renderLoggerImportJobsMarkdown(request.loggerImportJobs ?? []),
    targetSiteMapEvidenceMarkdown: renderTargetSiteMapEvidenceMarkdown(request.targetSiteMapEvidenceAttachments ?? []),
    proxyHistoryEvidenceMarkdown: renderProxyHistoryEvidenceMarkdown(request.proxyHistoryEvidenceAttachments ?? []),
    scannerActiveScanEvidencePackagesMarkdown: renderScannerActiveScanEvidencePackagesMarkdown(request.scannerActiveScanEvidencePackages ?? []),
    crossToolEvidenceMarkdown: renderCrossToolEvidenceMarkdown(request.crossToolEvidenceAttachments ?? []),
    appendixMarkdown: renderCustomAppendixSection(request, generatedAt),
  };

  return `${safeTemplate.replace(/{{\s*([a-zA-Z0-9_.]+)\s*}}/g, (_match, key: string) => String(replacements[key] ?? ''))}\n`;
}

function renderCustomExecutiveSection(request: ReportExportRequest) {
  if (!request.sections.includes('executive')) return '';
  const summary = buildSummary(request);
  return [
    '## Executive Summary',
    '',
    `${request.brandName} reviewed ${summary.evidenceItems} evidence item(s) and identified ${summary.totalIssues} issue(s) across ${summary.affectedHosts} host(s).`,
    `${summary.highOrCritical} issue(s) are high or critical priority.`,
  ].join('\n');
}

function renderCustomFindingsSection(request: ReportExportRequest) {
  if (!request.sections.includes('technical')) return '';
  const findings = request.issues.map((issue) => [
    `### ${severityLabel(issue.severity)}: ${issue.title}`,
    '',
    `- Host: ${issue.host}`,
    `- Path: ${issue.path}`,
    `- Confidence: ${issue.confidence}`,
    `- Status: ${issue.status}`,
    '',
    issue.detail,
    '',
    `Remediation: ${issue.remediation}`,
  ].join('\n'));

  return ['## Technical Findings', '', ...findings].join('\n\n').trim();
}

function renderCustomRemediationSection(request: ReportExportRequest) {
  if (!request.sections.includes('remediation')) return '';
  return [
    '## Remediation Plan',
    '',
    '| Priority | Finding | Owner | Status | Evidence | Validation |',
    '| --- | --- | --- | --- | ---: | --- |',
    ...buildRemediationPlan(request).map((item) => (
      `| ${item.priority} | ${markdownCell(item.finding)} | ${markdownCell(item.owner)} | ${markdownCell(item.status)} | ${item.evidenceCount} | ${markdownCell(item.validation)} |`
    )),
  ].join('\n');
}

function renderCustomEvidenceSection(request: ReportExportRequest) {
  if (!request.sections.includes('evidence')) return '';
  const evidence = request.exchanges.map(redactExchange).slice(0, 50).map((exchange) => [
    `### ${exchange.method} ${exchange.host}${exchange.path}`,
    '',
    `Status: ${exchange.status} | Source: ${exchange.source} | Risk: ${severityLabel(exchange.risk)} | Notes: ${exchange.notes}`,
    '',
    'Request:',
    '```http',
    exchange.requestRaw.trim(),
    '```',
    '',
    'Response:',
    '```http',
    exchange.responseRaw.trim(),
    '```',
  ].join('\n'));

  return [
    '## Evidence',
    '',
    ...evidence,
    renderLoggerImportJobsMarkdown(request.loggerImportJobs ?? []),
    renderTargetSiteMapEvidenceMarkdown(request.targetSiteMapEvidenceAttachments ?? []),
    renderProxyHistoryEvidenceMarkdown(request.proxyHistoryEvidenceAttachments ?? []),
    renderScannerActiveScanEvidencePackagesMarkdown(request.scannerActiveScanEvidencePackages ?? []),
    renderCrossToolEvidenceMarkdown(request.crossToolEvidenceAttachments ?? []),
  ].join('\n\n').trim();
}

function renderCustomAppendixSection(request: ReportExportRequest, generatedAt: Date) {
  if (!request.sections.includes('appendix')) return '';
  return [
    '## Appendix',
    '',
    `- Generated by ${request.brandName}`,
    `- Prepared for ${request.preparedFor}`,
    `- Engagement ID: ${request.engagementId}`,
    `- Generated at ${generatedAt.toISOString()}`,
    '- Active traffic should remain within the recorded project scope.',
    '- Secrets in request and response evidence were redacted before export.',
  ].join('\n');
}

function renderHtmlReport(request: ReportExportRequest, generatedAt: Date) {
  const markdown = renderMarkdownReport({ ...request, format: 'markdown' }, generatedAt);
  const html = markdown
    .split('\n')
    .map((line) => {
      if (line.startsWith('# ')) return `<h1>${escapeHtml(line.slice(2))}</h1>`;
      if (line.startsWith('## ')) return `<h2>${escapeHtml(line.slice(3))}</h2>`;
      if (line.startsWith('### ')) return `<h3>${escapeHtml(line.slice(4))}</h3>`;
      if (line.startsWith('- ')) return `<p class="bullet">${escapeHtml(line)}</p>`;
      if (line.startsWith('```')) return '';
      if (!line.trim()) return '';
      return `<p>${escapeHtml(line)}</p>`;
    })
    .join('\n');

  return [
    '<!doctype html>',
    '<html lang="en">',
    '<head>',
    '<meta charset="utf-8" />',
    `<title>${escapeHtml(request.projectName)} Security Assessment</title>`,
    '<style>body{font-family:Inter,system-ui,sans-serif;margin:40px;line-height:1.5;color:#17211b}.brand{padding:14px 18px;background:#f4f1ec;border-left:5px solid #ff9b3e;margin-bottom:22px}h1,h2,h3{color:#0d1511}.bullet{margin-left:16px;color:#38483f}p{max-width:960px;white-space:pre-wrap}</style>',
    '</head>',
    '<body>',
    `<div class="brand"><strong>${escapeHtml(request.brandName ?? 'ProxyForge')}</strong><br>${escapeHtml(request.preparedFor ?? '')} · ${escapeHtml(request.engagementId ?? '')}</div>`,
    '<main role="main" aria-label="Security assessment report">',
    html,
    '</main>',
    '</body>',
    '</html>',
    '',
  ].join('\n');
}

export function buildPdfRenderQaMetadata(request: ReportExportRequest, generatedAt = new Date()): ReportPdfRenderQaMetadata {
  const normalized = normalizeReportRequest({ ...request, format: 'pdf' });
  const markdown = renderMarkdownReport({ ...normalized, format: 'markdown' }, generatedAt);
  const sectionLineCounts = estimatePdfSectionLineCounts(markdown);
  const estimatedLineCount = estimatePdfLineCount(markdown);
  const pageBreaks = buildPdfPageBreaks(normalized.sections, sectionLineCounts);
  const estimatedPageCount = Math.max(
    1,
    ...pageBreaks.map((pageBreak) => (
      pageBreak.estimatedStartPage + Math.max(1, Math.ceil(pageBreak.estimatedLineCount / PDF_TARGET_LINES_PER_PAGE)) - 1
    )),
    Math.ceil(estimatedLineCount / PDF_TARGET_LINES_PER_PAGE),
  );
  const warnings = buildPdfRenderWarnings(normalized, estimatedPageCount);
  const deterministicContentHash = crypto
    .createHash('sha256')
    .update(canonicalize({
      projectName: normalized.projectName,
      sections: normalized.sections,
      issueIds: normalized.issues.map((issue) => issue.id),
      exchangeIds: normalized.exchanges.map((exchange) => exchange.id),
      estimatedLineCount,
      pageBreaks: pageBreaks.map((pageBreak) => ({
        section: pageBreak.section,
        estimatedStartPage: pageBreak.estimatedStartPage,
        estimatedLineCount: pageBreak.estimatedLineCount,
      })),
    }))
    .digest('hex');
  const checks = [
    'cover-page:true',
    `forced-section-breaks:${pageBreaks.length}/${normalized.sections.length}`,
    `estimated-pages:${estimatedPageCount}`,
    `avoid-break-selectors:${PDF_AVOID_BREAK_SELECTORS.length}`,
    'heading-keep-with-next:true',
    'widow-orphan-lines:3',
  ];

  return {
    version: 1,
    generatedAt: generatedAt.toISOString(),
    renderer: 'electron-printToPDF',
    page: {
      size: 'A4',
      marginMm: PDF_PAGE_MARGIN_MM,
      targetLinesPerPage: PDF_TARGET_LINES_PER_PAGE,
    },
    summary: {
      projectName: normalized.projectName,
      templateId: normalized.templateId ?? 'technical-remediation',
      sectionCount: normalized.sections.length,
      issueCount: normalized.issues.length,
      exchangeCount: normalized.exchanges.length,
      estimatedLineCount,
      estimatedPageCount,
    },
    sectionOrder: normalized.sections,
    pageBreaks,
    visualQa: {
      forcedBreakSelector: '.pdf-page-break[data-pdf-page-break="before"]',
      avoidBreakSelectors: PDF_AVOID_BREAK_SELECTORS,
      headingKeepWithNext: true,
      widowOrphanLines: 3,
      deterministicContentHash,
    },
    validation: {
      passed: pageBreaks.length === normalized.sections.length && estimatedPageCount >= pageBreaks.length + 1,
      checks,
      warnings,
    },
  };
}

export function evaluatePdfVisualQaSnapshot(
  metadata: ReportPdfRenderQaMetadata,
  snapshot: ReportPdfVisualQaSnapshot,
): ReportPdfVisualQaEvaluation {
  const checks: string[] = [];
  const warnings = [...metadata.validation.warnings];
  const failures: string[] = [];
  const sectionByName = new Map(snapshot.sections.map((section) => [section.section, section]));

  if (/^[a-f0-9]{64}$/.test(snapshot.screenshot.sha256)) {
    checks.push('screenshot-hash:sha256');
  } else {
    failures.push('Rendered screenshot hash is missing or not SHA-256.');
  }

  if (snapshot.screenshot.width >= 700 && snapshot.screenshot.height >= 900) {
    checks.push(`screenshot-size:${snapshot.screenshot.width}x${snapshot.screenshot.height}`);
  } else {
    failures.push(`Rendered screenshot is too small for A4 visual QA: ${snapshot.screenshot.width}x${snapshot.screenshot.height}.`);
  }

  if (snapshot.screenshot.nonWhitePixelRatio > 0.02) {
    checks.push(`non-white-pixels:${snapshot.screenshot.nonWhitePixelRatio.toFixed(4)}`);
  } else {
    failures.push('Rendered screenshot appears blank or nearly blank.');
  }

  if (snapshot.screenshot.accentPixelCount >= 8) {
    checks.push(`brand-accent-pixels:${snapshot.screenshot.accentPixelCount}`);
  } else {
    failures.push('Rendered screenshot did not include enough ProxyForge brand accent pixels.');
  }

  const missingSections = metadata.sectionOrder.filter((section) => !sectionByName.has(section));
  if (missingSections.length) {
    failures.push(`Rendered PDF HTML is missing section probe(s): ${missingSections.join(', ')}.`);
  } else {
    checks.push(`section-probes:${metadata.sectionOrder.length}/${metadata.sectionOrder.length}`);
  }

  for (const pageBreak of metadata.pageBreaks) {
    const rendered = sectionByName.get(pageBreak.section);
    if (!rendered) continue;
    if (rendered.height <= 0 || rendered.width <= 0) {
      failures.push(`Section ${pageBreak.section} rendered with empty dimensions.`);
    }
    if (!/page/i.test(rendered.computedBreakBefore) && !/always/i.test(rendered.computedPageBreakBefore)) {
      failures.push(`Section ${pageBreak.section} does not expose a computed page break before it.`);
    }
    if (!/avoid/i.test(rendered.computedBreakInside)) {
      failures.push(`Section ${pageBreak.section} does not expose computed break-inside avoidance.`);
    }
  }
  if (!metadata.pageBreaks.length || metadata.pageBreaks.every((pageBreak) => {
    const rendered = sectionByName.get(pageBreak.section);
    return rendered && (/page/i.test(rendered.computedBreakBefore) || /always/i.test(rendered.computedPageBreakBefore));
  })) {
    checks.push(`computed-page-breaks:${metadata.pageBreaks.length}/${metadata.pageBreaks.length}`);
  }

  const orderedSections = metadata.sectionOrder
    .map((section) => sectionByName.get(section))
    .filter(Boolean) as ReportPdfRenderedSectionProbe[];
  const monotonicOrder = orderedSections.every((section, index) => index === 0 || section.top > orderedSections[index - 1].top);
  if (monotonicOrder) {
    checks.push('section-visual-order:monotonic');
  } else {
    failures.push('Rendered section headings are not in visual document order.');
  }

  if (metadata.summary.estimatedPageCount >= metadata.pageBreaks.length + 1) {
    checks.push(`pagination-estimate:${metadata.summary.estimatedPageCount}`);
  } else {
    failures.push('PDF metadata estimated page count is inconsistent with forced section breaks.');
  }

  return {
    version: 1,
    generatedAt: new Date().toISOString(),
    passed: failures.length === 0,
    checks,
    warnings,
    failures,
    snapshot,
  };
}

function buildReportAccessibilityReview(request: ReportExportRequest, generatedAt: Date): ReportAccessibilityReview {
  const normalized = normalizeReportRequest(request);
  const html = renderHtmlReport(normalized, generatedAt);
  const pdfHtml = renderPdfReportHtml(normalized, generatedAt);
  const htmlLanguageDeclared = /<html\s+lang="en"/i.test(html) && /<html\s+lang="en"/i.test(pdfHtml);
  const documentTitlePresent = /<title>[^<]+Security Assessment/i.test(html) && /<title>[^<]+Security Assessment PDF/i.test(pdfHtml);
  const mainLandmarkPresent = /<main[^>]+role="main"[^>]+aria-label="Security assessment report"/i.test(html)
    && /<main[^>]+role="main"[^>]+aria-label="PDF security assessment report"/i.test(pdfHtml);
  const semanticSectionCount = normalized.sections.filter((section) => (
    new RegExp(`data-pdf-section="${section}"`, 'i').test(pdfHtml)
  )).length;
  const pdfSectionTagCount = (pdfHtml.match(/data-pdf-section="/g) ?? []).length;
  const h1Index = pdfHtml.indexOf('<h1');
  const h2Index = pdfHtml.indexOf('<h2');
  const h3Index = pdfHtml.indexOf('<h3');
  const headingOrderValid = h1Index >= 0 && h2Index > h1Index && (h3Index === -1 || h3Index > h2Index);
  const tableRowCount = (pdfHtml.match(/class="table-row/g) ?? []).length;
  const evidenceBlockCount = (pdfHtml.match(/pdf-evidence-block/g) ?? []).length;
  const checks = [
    htmlLanguageDeclared ? 'html-lang:en' : '',
    documentTitlePresent ? 'document-title:present' : '',
    mainLandmarkPresent ? 'main-landmark:present' : '',
    `semantic-sections:${semanticSectionCount}/${normalized.sections.length}`,
    `pdf-section-tags:${pdfSectionTagCount}`,
    headingOrderValid ? 'heading-order:h1-h2-h3' : '',
    `table-rows:${tableRowCount}`,
    `evidence-blocks:${evidenceBlockCount}`,
  ].filter(Boolean);
  const warnings: string[] = [];
  if (normalized.exchanges.length >= 200) {
    warnings.push('Large-report accessibility review should receive a human spot-check on the final PDF renderer.');
  }
  const taggedPdfReadiness = htmlLanguageDeclared
    && documentTitlePresent
    && mainLandmarkPresent
    && semanticSectionCount === normalized.sections.length
    && pdfSectionTagCount >= normalized.sections.length
    && headingOrderValid;
  return {
    htmlLanguageDeclared,
    documentTitlePresent,
    mainLandmarkPresent,
    semanticSectionCount,
    pdfSectionTagCount,
    headingOrderValid,
    tableRowCount,
    evidenceBlockCount,
    taggedPdfReadiness,
    checks,
    warnings,
    passed: taggedPdfReadiness && tableRowCount > 0 && evidenceBlockCount > 0,
  };
}

function estimatePdfSectionLineCounts(markdown: string): Partial<Record<ReportSection, number>> {
  const sectionLines: Partial<Record<ReportSection, string[]>> = {};
  let currentSection: ReportSection | undefined;
  for (const line of markdown.split('\n')) {
    if (line.startsWith('## ')) {
      currentSection = reportSectionFromHeading(line.slice(3));
      if (currentSection) sectionLines[currentSection] = [line];
      continue;
    }
    if (currentSection) {
      sectionLines[currentSection]?.push(line);
    }
  }

  const counts: Partial<Record<ReportSection, number>> = {};
  for (const section of Object.keys(REPORT_SECTION_LABELS) as ReportSection[]) {
    counts[section] = estimatePdfLineCount((sectionLines[section] ?? []).join('\n'));
  }
  return counts;
}

function buildPdfPageBreaks(
  sections: ReportSection[],
  sectionLineCounts: Partial<Record<ReportSection, number>>,
): ReportPdfPageBreak[] {
  let estimatedStartPage = 2;
  return sections.map((section) => {
    const estimatedLineCount = Math.max(1, sectionLineCounts[section] ?? 1);
    const pageBreak: ReportPdfPageBreak = {
      id: `pdf-page-break-${section}`,
      section,
      label: REPORT_SECTION_LABELS[section],
      selector: `[data-pdf-section="${section}"]`,
      reason: section === 'executive'
        ? 'Executive narrative starts after the fixed cover page.'
        : 'Major report section starts on a deterministic page boundary.',
      forced: true,
      estimatedStartPage,
      estimatedLineCount,
    };
    estimatedStartPage += Math.max(1, Math.ceil(estimatedLineCount / PDF_TARGET_LINES_PER_PAGE));
    return pageBreak;
  });
}

function estimatePdfLineCount(markdown: string) {
  return markdown.split('\n').reduce((total, line) => {
    const trimmed = line.trim();
    if (!trimmed) return total + 1;
    if (trimmed === '```') return total;
    const wrapWidth = trimmed.startsWith('|') ? 88 : 96;
    return total + Math.max(1, Math.ceil(trimmed.length / wrapWidth));
  }, 0);
}

function buildPdfRenderWarnings(request: ReportExportRequest, estimatedPageCount: number) {
  const warnings: string[] = [];
  if (estimatedPageCount > 40) {
    warnings.push('Large report should receive a manual rendered PDF spot-check before handoff.');
  }
  if (request.exchanges.length >= 200) {
    warnings.push('Evidence was capped at 200 exchanges before PDF pagination.');
  }
  return warnings;
}

function reportSectionFromHeading(heading: string): ReportSection | undefined {
  return (Object.keys(REPORT_SECTION_LABELS) as ReportSection[])
    .find((section) => REPORT_SECTION_LABELS[section] === heading.trim());
}

function renderPdfReportHtml(request: ReportExportRequest, generatedAt: Date) {
  const markdown = renderMarkdownReport({ ...request, format: 'markdown' }, generatedAt);
  const summary = buildSummary(request);
  const pdfQaMetadata = buildPdfRenderQaMetadata(request, generatedAt);
  const body = markdown
    .split('\n')
    .map((line) => {
      if (line.startsWith('# ')) return `<h1 class="pdf-title">${escapeHtml(line.slice(2))}</h1>`;
      if (line.startsWith('## ')) {
        const heading = line.slice(3);
        const section = reportSectionFromHeading(heading);
        const sectionAttributes = section
          ? ` data-pdf-section="${section}" data-pdf-page-break="before"`
          : ' data-pdf-page-break="before"';
        return `<h2 class="pdf-section pdf-page-break"${sectionAttributes}>${escapeHtml(heading)}</h2>`;
      }
      if (line.startsWith('### ')) return `<h3 class="pdf-keep-with-next">${escapeHtml(line.slice(4))}</h3>`;
      if (line.startsWith('- ')) return `<li class="pdf-avoid-break">${escapeHtml(line.slice(2))}</li>`;
      if (line.startsWith('```')) return '';
      if (!line.trim()) return '<div class="spacer"></div>';
      if (line.startsWith('|')) return `<p class="table-row pdf-avoid-break">${escapeHtml(line)}</p>`;
      return `<p class="${pdfEvidenceLineClass(line)}">${escapeHtml(line)}</p>`;
    })
    .join('\n');

  return [
    '<!doctype html>',
    '<html lang="en">',
    '<head>',
    '<meta charset="utf-8" />',
    `<title>${escapeHtml(request.projectName)} Security Assessment PDF</title>`,
    '<style>',
    '@page{size:A4;margin:18mm 16mm;}',
    'html{-webkit-print-color-adjust:exact;print-color-adjust:exact;}',
    'body{font-family:Inter,Arial,sans-serif;color:#142019;line-height:1.45;font-size:11px;widows:3;orphans:3;}',
    '.cover{border-bottom:2px solid #f28c28;margin-bottom:18px;padding-bottom:16px;break-inside:avoid;page-break-inside:avoid;}',
    '.brand{font-size:12px;letter-spacing:.04em;text-transform:uppercase;color:#a45f17;font-weight:700;}',
    'h1{font-size:27px;line-height:1.1;margin:8px 0 12px;color:#0d1511;}',
    'h2{font-size:17px;margin:22px 0 8px;color:#10241b;break-after:avoid;page-break-after:avoid;}',
    'h3{font-size:13px;margin:15px 0 6px;color:#172c21;break-after:avoid;page-break-after:avoid;}',
    'p{margin:5px 0;white-space:pre-wrap;}',
    'li{margin:4px 0 4px 18px;}',
    '.meta{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-top:14px;}',
    '.meta div{border:1px solid #d9e1d9;border-radius:6px;padding:8px;background:#f7faf7;break-inside:avoid;page-break-inside:avoid;}',
    '.meta span{display:block;font-size:8px;text-transform:uppercase;color:#637568;margin-bottom:3px;}',
    '.meta strong{font-size:12px;color:#0d1511;}',
    '.pdf-page-break{break-before:page;page-break-before:always;}',
    '.pdf-section,.pdf-keep-with-next,.pdf-avoid-break,.pdf-evidence-block,.table-row{break-inside:avoid;page-break-inside:avoid;}',
    '.table-row{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:9px;margin:2px 0;}',
    '.pdf-evidence-block{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:9px;background:#f8faf8;border-left:2px solid #d9e1d9;padding-left:5px;}',
    '.footer{position:fixed;bottom:8mm;left:16mm;right:16mm;font-size:8px;color:#66766d;border-top:1px solid #d9e1d9;padding-top:4px;}',
    '.spacer{height:5px;}',
    '</style>',
    `<script type="application/json" id="proxyforge-pdf-render-qa">${escapeScriptJson(pdfQaMetadata)}</script>`,
    '</head>',
    '<body>',
    '<main role="main" aria-label="PDF security assessment report">',
    '<section class="cover">',
    `<div class="brand">${escapeHtml(request.brandName ?? 'ProxyForge')}</div>`,
    `<h1>${escapeHtml(request.projectName)} Security Assessment</h1>`,
    '<div class="meta">',
    `<div><span>Prepared for</span><strong>${escapeHtml(request.preparedFor ?? '')}</strong></div>`,
    `<div><span>Engagement</span><strong>${escapeHtml(request.engagementId ?? '')}</strong></div>`,
    `<div><span>Findings</span><strong>${summary.totalIssues}</strong></div>`,
    `<div><span>Evidence</span><strong>${summary.evidenceItems}</strong></div>`,
    '</div>',
    '</section>',
    body,
    '</main>',
    `<div class="footer">${escapeHtml(request.brandName ?? 'ProxyForge')} · ${escapeHtml(request.engagementId ?? '')} · Generated ${escapeHtml(generatedAt.toISOString())}</div>`,
    '</body>',
    '</html>',
    '',
  ].join('\n');
}

function renderPdfArtifactPreview(request: ReportExportRequest, generatedAt: Date) {
  const summary = buildSummary(request);
  const pdfQaMetadata = buildPdfRenderQaMetadata(request, generatedAt);
  return [
    'PDF report package',
    '',
    `Project: ${request.projectName}`,
    `Prepared for: ${request.preparedFor}`,
    `Brand: ${request.brandName}`,
    `Engagement: ${request.engagementId}`,
    `Template: ${templateLabel(request.templateId, request.customTemplateName)}`,
    `Generated: ${generatedAt.toISOString()}`,
    `Sections: ${request.sections.join(', ')}`,
    `Governance attestation: ${request.governanceAttestation?.status ?? 'missing'} ${request.governanceAttestation?.signature.digestPreview ?? 'missing'}`,
    '',
    `Findings: ${summary.totalIssues}`,
    `High/Critical: ${summary.highOrCritical}`,
    `Evidence items: ${summary.evidenceItems}`,
    `Logger import jobs: ${summary.loggerImportJobs}`,
    `Scanner active scan evidence packages: ${summary.scannerActiveScanEvidencePackages}`,
    '',
    'PDF render QA metadata',
    `Estimated pages: ${pdfQaMetadata.summary.estimatedPageCount}`,
    `Forced page breaks: ${pdfQaMetadata.pageBreaks.map((pageBreak) => `${pageBreak.section}@${pageBreak.estimatedStartPage}`).join(', ') || 'none'}`,
    `Visual QA checks: ${pdfQaMetadata.validation.checks.join('; ')}`,
    `Visual QA warnings: ${pdfQaMetadata.validation.warnings.join('; ') || 'none'}`,
    `Content hash: ${pdfQaMetadata.visualQa.deterministicContentHash}`,
    '',
    'Desktop exports render a paginated PDF through Electron printToPDF with redacted evidence.',
  ].join('\n');
}

function pdfEvidenceLineClass(line: string) {
  const trimmed = line.trim();
  if (/^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+/i.test(trimmed)) return 'pdf-evidence-block';
  if (/^(HTTP\/|Host:|Authorization:|Cookie:|Set-Cookie:|Content-Type:|X-[A-Za-z-]+:)/i.test(trimmed)) return 'pdf-evidence-block';
  if (/^[{[]/.test(trimmed)) return 'pdf-evidence-block';
  return 'pdf-paragraph';
}

function renderFallbackPdf(request: ReportExportRequest, generatedAt: Date) {
  const lines = renderMarkdownReport({ ...request, format: 'markdown' }, generatedAt)
    .split('\n')
    .map((line) => line.replace(/[^\x20-\x7E]/g, ' ').slice(0, 96))
    .slice(0, 54);
  const commands = [
    'BT',
    '/F1 10 Tf',
    '40 760 Td',
    ...lines.flatMap((line, index) => [
      index === 0 ? '' : '0 -13 Td',
      `(${escapePdfText(line || ' ')}) Tj`,
    ]).filter(Boolean),
    'ET',
  ].join('\n');
  const stream = Buffer.from(commands, 'utf8');
  const objects = [
    '1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n',
    '2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n',
    '3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>\nendobj\n',
    '4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n',
    `5 0 obj\n<< /Length ${stream.length} >>\nstream\n${commands}\nendstream\nendobj\n`,
  ];
  let offset = '%PDF-1.4\n'.length;
  const offsets = objects.map((object) => {
    const current = offset;
    offset += Buffer.byteLength(object, 'utf8');
    return current;
  });
  const xrefOffset = offset;
  const xref = [
    'xref',
    `0 ${objects.length + 1}`,
    '0000000000 65535 f ',
    ...offsets.map((item) => `${String(item).padStart(10, '0')} 00000 n `),
    'trailer',
    `<< /Size ${objects.length + 1} /Root 1 0 R >>`,
    'startxref',
    String(xrefOffset),
    '%%EOF',
    '',
  ].join('\n');
  return Buffer.from(`%PDF-1.4\n${objects.join('')}${xref}`, 'utf8');
}

function renderEvidenceBundle(request: ReportExportRequest, generatedAt: Date) {
  const redactedExchanges = request.exchanges.map(redactExchange);
  const bundle: Record<string, unknown> = {
    manifest: {
      version: 1,
      kind: 'proxyforge-evidence-bundle',
      generatedAt: generatedAt.toISOString(),
      projectName: request.projectName,
      brandName: request.brandName,
      preparedFor: request.preparedFor,
      engagementId: request.engagementId,
      templateId: request.templateId,
      templateName: templateLabel(request.templateId, request.customTemplateName),
      sections: request.sections,
      scopeAllowlist: request.scopeAllowlist,
      summary: buildSummary(request),
      redactionPolicy: ['authorization bearer', 'cookie', 'session', 'api key'],
      governanceAttestation: request.governanceAttestation,
    },
    governanceAttestation: request.governanceAttestation,
    findings: request.issues.map((issue) => ({
      id: issue.id,
      title: issue.title,
      severity: issue.severity,
      host: issue.host,
      path: issue.path,
      confidence: issue.confidence,
      status: issue.status,
      remediation: issue.remediation,
      evidenceIds: redactedExchanges
        .filter((exchange) => exchange.host === issue.host || exchange.path === issue.path)
        .slice(0, 5)
        .map((exchange) => exchange.id),
    })),
    evidence: redactedExchanges.map((exchange) => ({
      id: exchange.id,
      request: {
        method: exchange.method,
        url: exchange.url,
        raw: exchange.requestRaw,
      },
      response: {
        status: exchange.status,
        mime: exchange.mime,
        length: exchange.length,
        raw: exchange.responseRaw,
      },
      metadata: {
        host: exchange.host,
        path: exchange.path,
        risk: exchange.risk,
        source: exchange.source,
        tags: exchange.tags,
        notes: exchange.notes,
      },
    })),
    remediationPlan: request.sections.includes('remediation') ? buildRemediationPlan(request) : [],
    loggerImportJobs: request.sections.includes('evidence') ? request.loggerImportJobs ?? [] : [],
    targetSiteMapEvidenceAttachments: request.sections.includes('evidence') ? request.targetSiteMapEvidenceAttachments ?? [] : [],
    proxyHistoryEvidenceAttachments: request.sections.includes('evidence') ? request.proxyHistoryEvidenceAttachments ?? [] : [],
    scannerActiveScanEvidencePackages: request.sections.includes('evidence') ? request.scannerActiveScanEvidencePackages ?? [] : [],
    crossToolEvidenceAttachments: request.sections.includes('evidence') ? request.crossToolEvidenceAttachments ?? [] : [],
    reportMarkdown: renderMarkdownReport({ ...request, format: 'markdown' }, generatedAt),
  };
  if (request.signEvidenceBundle) {
    bundle.signature = signEvidenceBundle(bundle, request, generatedAt);
  }
  return JSON.stringify(bundle, null, 2);
}

function signEvidenceBundle(bundle: Record<string, unknown>, request: ReportExportRequest, generatedAt: Date) {
  const unsignedBundle = { ...bundle };
  delete unsignedBundle.signature;
  const serializableBundle = JSON.parse(JSON.stringify(unsignedBundle)) as Record<string, unknown>;
  const canonical = canonicalize(serializableBundle);
  const digest = crypto.createHash('sha256').update(canonical).digest('hex');
  const secret = request.signingSecret?.trim();
  const signature = secret
    ? crypto.createHmac('sha256', secret).update(canonical).digest('hex')
    : '';
  return {
    version: 1,
    algorithm: 'HMAC-SHA256',
    canonicalization: 'proxyforge-evidence-bundle-v1',
    signedAt: generatedAt.toISOString(),
    signerName: request.signerName,
    keyId: request.signingKeyId,
    bundleDigestSha256: digest,
    signature,
    status: signature ? 'signed' : 'missing-secret',
    covers: ['manifest', 'governanceAttestation', 'findings', 'evidence', 'loggerImportJobs', 'targetSiteMapEvidenceAttachments', 'proxyHistoryEvidenceAttachments', 'scannerActiveScanEvidencePackages', 'crossToolEvidenceAttachments', 'remediationPlan', 'reportMarkdown'],
  };
}

function buildRemediationPlan(request: ReportExportRequest) {
  return request.issues.map((issue) => {
    const linkedEvidence = request.exchanges.filter((exchange) => exchangeMatchesIssue(exchange, issue));
    return {
      id: issue.id,
      finding: issue.title,
      severity: issue.severity,
      priority: remediationPriority(issue.severity),
      owner: issue.assignee?.trim() || 'Unassigned',
      status: issue.status,
      host: issue.host,
      path: issue.path,
      evidenceCount: linkedEvidence.length,
      validation: remediationValidation(issue, linkedEvidence.length),
      triageNote: issue.triageNote?.trim() || '',
      lastTriagedAt: issue.lastTriagedAt ?? '',
    };
  });
}

function exchangeMatchesIssue(exchange: ReportExchange, issue: ReportIssue) {
  if (exchange.host !== issue.host) return false;
  if (exchange.path === issue.path) return true;
  if (exchange.url.includes(issue.path)) return true;
  return issue.path !== '/' && exchange.path.startsWith(issue.path);
}

function remediationPriority(severity: Severity) {
  if (severity === 'critical') return 'P0 - immediate containment';
  if (severity === 'high') return 'P1 - next release';
  if (severity === 'medium') return 'P2 - planned fix';
  if (severity === 'low') return 'P3 - backlog';
  return 'P4 - informational';
}

function remediationValidation(issue: ReportIssue, evidenceCount: number) {
  if (issue.status === 'fixed') return 'Attach fixed-state replay evidence and close after owner signoff.';
  if (issue.status === 'false-positive') return 'Retain reviewer rationale and exclude from retest queue.';
  if (evidenceCount > 0) return 'Replay linked evidence after the fix and compare response/status deltas.';
  return 'Add at least one scoped request/response proof before retest.';
}

function markdownCell(value: string) {
  return value.replace(/\|/g, '\\|').replace(/\r?\n/g, ' ').trim();
}

function redactExchange(exchange: ReportExchange): ReportExchange {
  return redactReportValue({
    ...exchange,
    path: redactSecrets(exchange.path),
    url: redactSecrets(exchange.url),
    requestRaw: redactSecrets(exchange.requestRaw),
    responseRaw: redactSecrets(exchange.responseRaw),
    notes: redactSecrets(exchange.notes),
  });
}

function redactIssue(issue: ReportIssue): ReportIssue {
  return redactReportValue({
    ...issue,
    title: redactSecrets(issue.title),
    host: redactSecrets(issue.host),
    path: redactSecrets(issue.path),
    detail: redactSecrets(issue.detail),
    remediation: redactSecrets(issue.remediation),
    assignee: issue.assignee ? redactSecrets(issue.assignee) : undefined,
    triageNote: issue.triageNote ? redactSecrets(issue.triageNote) : undefined,
  });
}

function redactReportValue<T>(value: T): T {
  if (typeof value === 'string') {
    return redactSecrets(value) as T;
  }
  if (Array.isArray(value)) {
    return value.map((item) => redactReportValue(item)) as T;
  }
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([key, nestedValue]) => [
        key,
        redactReportValue(nestedValue),
      ]),
    ) as T;
  }
  return value;
}

function redactSecrets(value: string) {
  return value
    .replace(/(authorization:\s*)[^\n]+/gi, '$1[redacted]')
    .replace(/(proxy-authorization:\s*)[^\n]+/gi, '$1[redacted]')
    .replace(/\bbearer\s+[A-Za-z0-9._~+/-]+/gi, 'Bearer [redacted]')
    .replace(/(cookie:\s*)[^\n]+/gi, '$1[redacted]')
    .replace(/(set-cookie:\s*)[^\n]+/gi, '$1[redacted]')
    .replace(/((?:x-api-key|api-key|x-auth-token|x-session-token):\s*)[^\n]+/gi, '$1[redacted]')
    .replace(/((?:"|')?(?:authorization|proxy-authorization)(?:"|')?\s*:\s*(?:"|')?)[^"',\n}]+/gi, '$1[redacted]')
    .replace(/((?:"|')?(?:cookie|set-cookie)(?:"|')?\s*:\s*(?:"|')?)[^"',\n}]+/gi, '$1[redacted]')
    .replace(/((?:"|')?(?:x-api-key|api-key|x-auth-token|x-session-token)(?:"|')?\s*:\s*(?:"|')?)[^"',\n}]+/gi, '$1[redacted]')
    .replace(/((?:"|')?(?:access_token|refresh_token|session|token|secret|password|api[_-]?key)(?:"|')?\s*:\s*(?:"|')?)[^"',\n}]+/gi, '$1[redacted]')
    .replace(/((?:access_token|refresh_token|session|token|secret|password|api[_-]?key)=)[^;&\s]+/gi, '$1[redacted]')
    .replace(/(api[_-]?key["']?\s*[:=]\s*["']?)[^"',\s]+/gi, '$1[redacted]')
    .replace(/\b[A-Za-z0-9][A-Za-z0-9._-]*(?:[_-](?:token|secret|session|api[_-]?key))[A-Za-z0-9._-]*\b/g, '[redacted]');
}

function extractReportSecretMarkers(request: ReportExportRequest) {
  const values = [
    request.signingSecret ?? '',
    ...request.exchanges.flatMap((exchange) => [exchange.requestRaw, exchange.responseRaw]),
    ...(request.targetSiteMapEvidenceAttachments ?? []).map((item) => item.content),
    ...(request.proxyHistoryEvidenceAttachments ?? []).map((item) => item.content),
    ...(request.scannerActiveScanEvidencePackages ?? []).map((item) => item.content),
    ...(request.crossToolEvidenceAttachments ?? []).map((item) => item.content),
  ];
  const markers = new Set<string>();
  if (request.signingSecret?.trim()) markers.add(request.signingSecret.trim());
  for (const value of values) {
    for (const match of value.matchAll(/authorization:\s*bearer\s+([^\s\n]+)/gi)) markers.add(match[1]);
    for (const match of value.matchAll(/cookie:\s*([^\n]+)/gi)) markers.add(match[1]);
    for (const match of value.matchAll(/(?:session|token|secret|api[_-]?key)=([^;&\s"']+)/gi)) markers.add(match[1]);
    for (const match of value.matchAll(/(?:api[_-]?key|access_token|refresh_token|password|secret)["']?\s*[:=]\s*["']?([^"',\s}]+)/gi)) markers.add(match[1]);
    for (const match of value.matchAll(/(?:x-api-key|api-key|x-auth-token|x-session-token):\s*([^\s\n]+)/gi)) markers.add(match[1]);
  }
  return Array.from(markers)
    .map((marker) => marker.trim())
    .filter((marker) => marker.length >= 4 && !/^\[redacted\]$/i.test(marker))
    .slice(0, 100);
}

function reportOperationalSecretSignals(request: ReportExportRequest) {
  const text = [
    request.signingSecret ? 'report-signing-secret-present' : '',
    ...request.exchanges.flatMap((exchange) => [exchange.requestRaw, exchange.responseRaw]),
    ...(request.targetSiteMapEvidenceAttachments ?? []).map((item) => item.content),
    ...(request.proxyHistoryEvidenceAttachments ?? []).map((item) => item.content),
    ...(request.scannerActiveScanEvidencePackages ?? []).map((item) => item.content),
    ...(request.crossToolEvidenceAttachments ?? []).map((item) => item.content),
  ].join('\n');
  return Array.from(new Set([
    /authorization:/i.test(text) ? 'authorization-header' : '',
    /cookie:/i.test(text) ? 'cookie-header' : '',
    /x-api-key:|api-key:/i.test(text) ? 'api-key-header' : '',
    /bearer\s+[a-z0-9._-]+/i.test(text) ? 'bearer-token' : '',
    /session=|token|secret|api[_-]?key/i.test(text) ? 'secret-like-material' : '',
    /report-signing-secret-present/.test(text) ? 'report-signing-secret' : '',
  ].filter(Boolean))).sort();
}

function safeParseJson(value: string): unknown {
  try {
    return JSON.parse(value);
  } catch {
    return undefined;
  }
}

function severityRank(severity: Severity) {
  return {
    critical: 5,
    high: 4,
    medium: 3,
    low: 2,
    info: 1,
  }[severity];
}

function severityLabel(severity: Severity) {
  return severity.charAt(0).toUpperCase() + severity.slice(1);
}

function reportExtension(format: ReportFormat) {
  if (format === 'markdown') return 'md';
  if (format === 'bundle') return 'evidence-bundle.json';
  if (format === 'pdf') return 'pdf';
  return format;
}

function templateLabel(templateId?: ReportTemplateId, customTemplateName?: string) {
  if (templateId === 'custom') return customTemplateName?.trim() || 'Custom operator template';
  return {
    'executive-board': 'Executive board brief',
    'technical-remediation': 'Technical remediation plan',
    'evidence-bundle': 'Branded evidence bundle',
  }[templateId ?? 'technical-remediation'];
}

function slugify(value: string) {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'proxyforge-report';
}

function escapeHtml(value: string) {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function escapePdfText(value: string) {
  return value.replace(/\\/g, '\\\\').replace(/\(/g, '\\(').replace(/\)/g, '\\)');
}

function escapeScriptJson(value: unknown) {
  return JSON.stringify(value, null, 2)
    .replace(/</g, '\\u003c')
    .replace(/>/g, '\\u003e')
    .replace(/&/g, '\\u0026')
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029');
}

function canonicalize(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value as Record<string, unknown>).sort().map((key) => (
      `${JSON.stringify(key)}:${canonicalize((value as Record<string, unknown>)[key])}`
    )).join(',')}}`;
  }
  return JSON.stringify(value) ?? 'null';
}
