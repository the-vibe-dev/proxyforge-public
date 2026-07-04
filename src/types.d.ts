export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type ToolId = 'dashboard' | 'target' | 'proxy' | 'repeater' | 'intruder' | 'scanner' | 'exploit' | 'automations' | 'ai' | 'logger' | 'organizer' | 'search' | 'viewer' | 'sequencer' | 'decoder' | 'comparer' | 'collaborator' | 'extensions' | 'reports' | 'settings';
export interface ToolDefinition {
    id: ToolId;
    label: string;
    shortLabel: string;
    description: string;
    status: 'ready' | 'foundation' | 'planned';
    category: 'core' | 'attack' | 'analysis' | 'platform';
    count?: number;
}
export interface HttpExchange {
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
export type OrganizerItemStatus = 'inbox' | 'reviewing' | 'interesting' | 'done';
export type OrganizerHighlight = 'none' | 'yellow' | 'green' | 'red';
export type OrganizerPackageMode = 'plain' | 'passphrase-sealed';
export type OrganizerPackageMergeMode = 'new-only' | 'keep-both' | 'replace-conflicts';
export type OrganizerPackageSignatureStatus = 'unsigned' | 'signed' | 'valid' | 'invalid' | 'unverified';
export type OrganizerPackageTrustDecision = 'trusted' | 'warn' | 'blocked';
export type OrganizerReviewerSlaExportFormat = 'csv' | 'json';
export type OrganizerPackageConflictAuditAction = 'reviewed' | 'merged' | 'skipped' | 'kept-local' | 'accepted-incoming' | 'kept-both' | 'replaced-local';
export interface OrganizerItem {
    id: string;
    exchangeId: string;
    collectionId: string;
    addedAt: string;
    originalTool: ToolId | 'system';
    status: OrganizerItemStatus;
    highlight: OrganizerHighlight;
    reviewerId?: string;
    reviewerName?: string;
    reviewDueAt?: string;
    notes: string;
    method: string;
    host: string;
    path: string;
    url: string;
    statusCode: number;
    length: number;
    mime: string;
    risk: Severity;
    requestRaw: string;
    responseRaw: string;
}
export interface OrganizerCollection {
    id: string;
    name: string;
    description: string;
    createdAt: string;
    updatedAt: string;
    items: OrganizerItem[];
    shareLink?: string;
    lastExportCsv?: string;
    lastPackageDigest?: string;
    lastPackageExportedAt?: string;
}
export interface OrganizerReviewer {
    id: string;
    name: string;
    role: string;
    email: string;
}
export interface OrganizerSignedPackageTrustPolicyPreset {
    id: string;
    name: string;
    description: string;
    pinned: boolean;
    decisionOnUnsigned: OrganizerPackageTrustDecision;
    decisionOnUnverified: OrganizerPackageTrustDecision;
    decisionOnInvalid: OrganizerPackageTrustDecision;
    trustedSignerNames: string[];
    trustedSigningKeyIds: string[];
    allowedPackageModes: OrganizerPackageMode[];
    createdAt: string;
    updatedAt: string;
}
export interface OrganizerPackageTrustEvaluation {
    presetId: string;
    presetName: string;
    decision: OrganizerPackageTrustDecision;
    reasons: string[];
    evaluatedAt: string;
}
export interface OrganizerReviewerSlaExportRow {
    reviewerId: string;
    reviewerName: string;
    reviewerRole: string;
    reviewerEmail: string;
    assigned: number;
    open: number;
    overdue: number;
    dueSoon: number;
    done: number;
    oldestOverdueAt?: string;
    nextDueAt?: string;
}
export interface OrganizerReviewerSlaExportArtifact {
    id: string;
    fileName: string;
    path: string;
    exportedAt: string;
    projectName: string;
    format: OrganizerReviewerSlaExportFormat;
    collectionIds: string[];
    reviewerCount: number;
    assignedCount: number;
    openCount: number;
    overdueCount: number;
    dueSoonCount: number;
    doneCount: number;
    rows: OrganizerReviewerSlaExportRow[];
    content?: string;
}
export interface OrganizerPackageConflictRoute {
    route: string;
    localStatus: OrganizerItemStatus;
    incomingStatus: OrganizerItemStatus;
    localReviewer: string;
    incomingReviewer: string;
    localDueAt?: string;
    incomingDueAt?: string;
}
export interface OrganizerPackageConflictAuditEntry {
    id: string;
    at: string;
    diffId: string;
    packageDigest: string;
    sourceCollectionId: string;
    targetCollectionId: string;
    route: string;
    action: OrganizerPackageConflictAuditAction;
    mergeMode: OrganizerPackageMergeMode;
    actor?: string;
    localItemId?: string;
    incomingItemId?: string;
    localStatus?: OrganizerItemStatus;
    incomingStatus?: OrganizerItemStatus;
    localReviewer?: string;
    incomingReviewer?: string;
    localDueAt?: string;
    incomingDueAt?: string;
    notes?: string;
}
export interface OrganizerCollectionDiff {
    id: string;
    importedAt: string;
    sourceProjectName?: string;
    sourceCollectionId: string;
    sourceCollectionName: string;
    targetCollectionId: string;
    targetCollectionName: string;
    addedItems: number;
    changedItems: number;
    duplicateItems: number;
    reviewerChanges: number;
    statusChanges: number;
    dueDateChanges?: number;
    packageDigest: string;
    packageMode: OrganizerPackageMode;
    signatureStatus?: OrganizerPackageSignatureStatus;
    signerName?: string;
    signingKeyId?: string;
    signedAt?: string;
    trustEvaluation?: OrganizerPackageTrustEvaluation;
    conflictRoutes?: OrganizerPackageConflictRoute[];
    conflictAuditTrail?: OrganizerPackageConflictAuditEntry[];
    collection: OrganizerCollection;
}
export type LoggerCustomColumnKind = 'auth-state' | 'param-count' | 'response-class' | 'interesting-signal' | 'timing-ms' | 'body-size';
export type LoggerToolSource = 'proxy' | 'target' | 'repeater' | 'scanner' | 'intruder' | 'exploit' | 'automations' | 'extensions';
export interface LoggerCustomColumn {
    id: string;
    name: string;
    kind: LoggerCustomColumnKind;
    enabled: boolean;
    script: string;
    createdAt: string;
    updatedAt: string;
}
export interface LoggerCaptureControl {
    tool: LoggerToolSource;
    enabled: boolean;
    updatedAt: string;
}
export interface LoggerCapturePreset {
    id: string;
    name: string;
    description: string;
    pinned: boolean;
    controls: LoggerCaptureControl[];
    createdAt: string;
    updatedAt: string;
}
export type LoggerArchiveImportFormat = 'raw-http' | 'har' | 'legacy-proxy-xml' | 'project' | 'plain-text';
export type LoggerArchiveNormalizationMode = 'preserve' | 'report-evidence' | 'scanner-triage' | 'replay-proof';
export type LoggerArchiveMergeStrategy = 'add-and-variants' | 'add-only' | 'replace-route';
export type LoggerImportJobAttachmentSignatureStatus = 'unsigned' | 'ready-on-export' | 'preview-signed' | 'signed' | 'valid' | 'invalid' | 'missing-secret' | 'unverified';
export type LoggerImportJobRedactionTarget = 'request' | 'request-header' | 'request-body' | 'response' | 'response-header' | 'response-body' | 'url' | 'metadata' | 'notes';
export type LoggerImportJobRedactionAction = 'preserve' | 'mask' | 'remove' | 'hash' | 'truncate';
export interface LoggerArchiveMappingPreset {
    id: string;
    name: string;
    description: string;
    source: HttpExchange['source'];
    normalization: LoggerArchiveNormalizationMode;
    tags: string[];
    pinned: boolean;
    createdAt: string;
    updatedAt: string;
}
export interface LoggerArchiveFieldMappingPreview {
    field: string;
    before: string;
    after: string;
    action: 'preserved' | 'mapped' | 'normalized' | 'redacted';
}
export interface LoggerArchiveConflictDetail {
    id: string;
    kind: 'new-route' | 'route-variant' | 'exact-duplicate';
    importedExchangeId: string;
    existingExchangeId?: string;
    route: string;
    statusDelta: number;
    lengthDelta: number;
    timingDelta: number;
    importedSummary: string;
    existingSummary: string;
    requestPreview: string;
    responsePreview: string;
}
export interface LoggerImportJobAttachmentSignatureMetadata {
    status: LoggerImportJobAttachmentSignatureStatus;
    signerName?: string;
    signingKeyId?: string;
    signedAt?: string;
    algorithm?: string;
    canonicalization?: string;
    manifestDigestSha256?: string;
    signature?: string;
}
export interface LoggerImportJobAttachmentProvenanceManifest {
    id: string;
    version: 1;
    generatedAt: string;
    importJobId: string;
    format: LoggerArchiveImportFormat;
    normalization: LoggerArchiveNormalizationMode;
    exchangeCount: number;
    sourceHosts: string[];
    importedExchangeIds?: string[];
    sourceFileName?: string;
    sourceDigestSha256?: string;
    manifestDigestSha256?: string;
    signature?: LoggerImportJobAttachmentSignatureMetadata;
}
export interface LoggerImportJobRedactionRule {
    id: string;
    target: LoggerImportJobRedactionTarget;
    selector: string;
    action: LoggerImportJobRedactionAction;
    replacement?: string;
    enabled: boolean;
}
export interface LoggerImportJobRedactionControl {
    id: string;
    importJobId: string;
    mode: 'inherit-project' | 'disabled' | 'rules';
    rules: LoggerImportJobRedactionRule[];
    updatedAt: string;
}
export interface LoggerArchiveImportReview {
    id: string;
    importedAt: string;
    format: LoggerArchiveImportFormat;
    mappingPresetId: string;
    mappingPresetName: string;
    normalization: LoggerArchiveNormalizationMode;
    notes: string;
    addedEntries: number;
    duplicateEntries: number;
    changedEntries: number;
    sourceHosts: string[];
    fieldMappings: LoggerArchiveFieldMappingPreview[];
    conflictDetails: LoggerArchiveConflictDetail[];
    replayCount: number;
    replayedAt?: string;
    provenanceManifest?: LoggerImportJobAttachmentProvenanceManifest;
    redactionControl?: LoggerImportJobRedactionControl;
    exchanges: HttpExchange[];
}
export interface ProjectSnapshot {
    version: 1;
    savedAt: string;
    projectName: string;
    scopeAllowlist: string[];
    exchanges: HttpExchange[];
    sessionProfiles?: SessionProfile[];
    selectedSessionProfileId?: string;
    browserLaunches?: BrowserLaunchResult[];
    browserClientAnalyses?: BrowserClientAnalysisRun[];
    selectedBrowserClientAnalysisId?: string;
    browserWebMessageReplays?: BrowserWebMessageReplay[];
    selectedBrowserWebMessageReplayId?: string;
    browserPrototypeScans?: BrowserPrototypeGadgetScan[];
    selectedBrowserPrototypeScanId?: string;
    browserClientEvidencePackages?: BrowserClientEvidencePackage[];
    selectedBrowserClientEvidencePackageId?: string;
    httpsInspectionSettings?: HttpsInspectionSettings;
    safetyPolicy?: ProjectSafetyPolicy;
    auditEvents?: AuditEvent[];
    approvalRecords?: ApprovalRecord[];
    policyOverrides?: PolicyOverride[];
    signedAuditExports?: SignedAuditExport[];
    enterpriseTeamSync?: EnterpriseTeamSync;
    enterpriseSsoProviderConfig?: EnterpriseSsoProviderConfig;
    remotePolicyTransport?: EnterpriseRemotePolicyTransport;
    enterpriseOperatorIdentities?: EnterpriseOperatorIdentity[];
    selectedEnterpriseOperatorId?: string;
    governancePolicyPackages?: GovernancePolicyPackage[];
    selectedGovernancePolicyPackageId?: string;
    governanceApprovalReviews?: GovernanceApprovalReview[];
    remoteAuditRetention?: RemoteAuditRetention;
    organizerCollections?: OrganizerCollection[];
    selectedOrganizerCollectionId?: string;
    selectedOrganizerItemId?: string;
    organizerPackageTrustPolicyPresets?: OrganizerSignedPackageTrustPolicyPreset[];
    selectedOrganizerPackageTrustPolicyPresetId?: string;
    organizerReviewerSlaExports?: OrganizerReviewerSlaExportArtifact[];
    organizerPackageConflictAuditTrail?: OrganizerPackageConflictAuditEntry[];
    loggerCustomColumns?: LoggerCustomColumn[];
    selectedLoggerCustomColumnId?: string;
    loggerCaptureControls?: LoggerCaptureControl[];
    loggerCapturePresets?: LoggerCapturePreset[];
    selectedLoggerCapturePresetId?: string;
    loggerArchiveMappingPresets?: LoggerArchiveMappingPreset[];
    selectedLoggerArchiveMappingPresetId?: string;
    loggerArchiveMergeStrategy?: LoggerArchiveMergeStrategy;
    loggerArchiveImportHistory?: LoggerArchiveImportReview[];
    selectedLoggerArchiveReviewId?: string;
    selectedLoggerArchiveConflictId?: string;
    matchReplaceRules?: MatchReplaceRule[];
    proxyInterceptRuleReviews?: ProxyInterceptRuleReview[];
    selectedProxyInterceptRuleReviewId?: string;
    proxyCapturePresetHandoffs?: ProxyCapturePresetHandoff[];
    selectedProxyCapturePresetHandoffId?: string;
    proxyTrafficComparisonPackages?: ProxyTrafficComparisonPackage[];
    selectedProxyTrafficComparisonPackageId?: string;
    proxyHistoryEvidenceAttachments?: ProxyHistoryEvidenceAttachment[];
    selectedProxyHistoryEvidenceAttachmentId?: string;
    callbackPayloads?: CallbackPayload[];
    callbackInteractions?: CallbackInteraction[];
    callbackWorkspaces?: CallbackWorkspace[];
    selectedCallbackWorkspaceId?: string;
    callbackEvidencePackages?: CallbackEvidencePackage[];
    selectedCallbackEvidencePackageId?: string;
    callbackListenerProfiles?: CallbackListenerProfile[];
    selectedCallbackListenerProfileId?: string;
    callbackSignedPollBatches?: CallbackSignedPollBatch[];
    selectedCallbackSignedPollBatchId?: string;
    callbackCorrelationReplays?: CallbackCorrelationReplayPackage[];
    selectedCallbackCorrelationReplayId?: string;
    callbackReplayExecutionBatches?: CallbackReplayExecutionBatch[];
    selectedCallbackReplayExecutionBatchId?: string;
    callbackLifecycleReviews?: CallbackPayloadLifecycleReview[];
    selectedCallbackLifecycleReviewId?: string;
    callbackCiHandoffPackages?: CallbackCiHandoffPackage[];
    selectedCallbackCiHandoffPackageId?: string;
    callbackPublicRelaySoakPackages?: CallbackPublicRelaySoakPackage[];
    selectedCallbackPublicRelaySoakPackageId?: string;
    installedExtensions?: InstalledExtension[];
    extensionRuns?: ExtensionRun[];
    extensionPackageManifests?: ExtensionPackageManifest[];
    selectedExtensionPackageManifestId?: string;
    extensionRuntimeHealth?: ExtensionRuntimeHealthEntry[];
    extensionPolicyPresets?: ExtensionPolicyPreset[];
    selectedExtensionPolicyPresetId?: string;
    extensionEvidenceHandoffs?: ExtensionEvidenceHandoff[];
    extensionRuntimeApiPolicies?: ExtensionRuntimeApiPolicy[];
    selectedExtensionRuntimeApiPolicyId?: string;
    extensionDependencyReviews?: ExtensionDependencyReview[];
    selectedExtensionDependencyReviewId?: string;
    extensionHeadlessEvidence?: ExtensionHeadlessExecutionEvidence[];
    selectedExtensionHeadlessEvidenceId?: string;
    extensionSignedUpdates?: ExtensionSignedUpdate[];
    selectedExtensionSignedUpdateId?: string;
    extensionCompatibilityFixtures?: ExtensionCompatibilityFixture[];
    selectedExtensionCompatibilityFixtureId?: string;
    extensionRuntimeDiagnostics?: ExtensionRuntimeDiagnosticPackage[];
    selectedExtensionRuntimeDiagnosticId?: string;
    extensionMigrationGuides?: ExtensionMigrationGuide[];
    selectedExtensionMigrationGuideId?: string;
    automationWorkflows?: AutomationWorkflow[];
    automationExecutions?: AutomationExecution[];
    automationSchedulerState?: AutomationSchedulerState;
    exploitRuns?: ExploitRun[];
    exploitChainPlans?: ExploitChainPlan[];
    exploitPackageReviews?: ExploitChainPackageReview[];
    exploitChainComparisons?: ExploitChainComparison[];
    savedIntruderAttacks?: IntruderSavedAttack[];
    intruderPayloadGenerators?: IntruderPayloadGenerator[];
    intruderAttackQueue?: IntruderAttackQueueItem[];
    intruderComparisons?: IntruderResultComparison[];
    intruderPositionDiffs?: IntruderPayloadPositionDiff[];
    intruderResultClusters?: IntruderResultCluster[];
    intruderStatRankings?: IntruderStatisticalRanking[];
    intruderPromotedIssues?: Issue[];
    replayMatrixRuns?: ReplayMatrixRun[];
    replaySessionProfileInjections?: ReplaySessionProfileInjection[];
    replayBulkRuns?: ReplayBulkRun[];
    replayAuthorizationMatrices?: ReplayAuthorizationMatrix[];
    selectedReplayAuthorizationMatrixId?: string;
    desyncProbePlans?: DesyncProbePlan[];
    selectedDesyncProbePlanId?: string;
    desyncConnectionEvidence?: DesyncConnectionEvidence[];
    selectedDesyncConnectionEvidenceId?: string;
    parallelRaceRuns?: ParallelRaceRun[];
    selectedParallelRaceRunId?: string;
    desyncProofBundles?: DesyncProofBundle[];
    selectedDesyncProofBundleId?: string;
    pinnedRepeaterExchangeIds?: string[];
    savedRepeaterRequests?: RepeaterSavedRequest[];
    repeaterTabs?: RepeaterWorkspaceTab[];
    selectedRepeaterTabId?: string;
    repeaterBatchRuns?: RepeaterBatchRun[];
    replayTransportSettings?: ReplayTransportSettings;
    savedWebSocketReplays?: WebSocketSavedReplay[];
    webSocketFrameRewriteRules?: WebSocketFrameRewriteRule[];
    webSocketConnectionNotebooks?: WebSocketConnectionNotebook[];
    webSocketPromotedIssues?: Issue[];
    webSocketConnectionClusterSummaries?: WebSocketConnectionClusterSummary[];
    webSocketFuzzRuns?: WebSocketSequenceFuzzRun[];
    webSocketStateGraphExports?: WebSocketStateGraphExportArtifact[];
    webSocketTranscriptExports?: WebSocketTranscriptExport[];
    webSocketRestoredTranscriptFrames?: WebSocketRestoredTranscriptFrame[];
    viewerEvidencePins?: ViewerEvidencePin[];
    viewerDecodedRawSnapshots?: ViewerDecodedRawSnapshot[];
    viewerReplayComparisonExports?: ViewerReplayComparisonExport[];
    selectedViewerEvidencePinId?: string;
    selectedViewerDecodedRawSnapshotId?: string;
    selectedViewerReplayComparisonExportId?: string;
    comparerWorkspaces?: ComparerWorkspace[];
    selectedComparerWorkspaceId?: string;
    comparerDiffPackages?: ComparerDiffPackage[];
    selectedComparerDiffPackageId?: string;
    comparerAdvancedRuns?: ComparerAdvancedResult[];
    selectedComparerAdvancedRunId?: string;
    comparerNormalizationPresetId?: ComparerNormalizationPresetId;
    comparerReplayDeltaReviews?: ComparerReplayDeltaReview[];
    selectedComparerReplayDeltaReviewId?: string;
    comparerLibraries?: ComparerLibraryPackage[];
    selectedComparerLibraryId?: string;
    comparerEvidenceAttachments?: ComparerEvidenceAttachment[];
    selectedComparerEvidenceAttachmentId?: string;
    targetSiteMapAnalysisPackages?: TargetSiteMapAnalysisPackage[];
    selectedTargetSiteMapAnalysisPackageId?: string;
    targetSiteMapComparisonPackages?: TargetSiteMapComparisonPackage[];
    selectedTargetSiteMapComparisonPackageId?: string;
    targetSiteMapEvidenceAttachments?: TargetSiteMapEvidenceAttachment[];
    selectedTargetSiteMapEvidenceAttachmentId?: string;
    decoderAnalysisRuns?: DecoderAnalysisRun[];
    selectedDecoderAnalysisId?: string;
    decoderRecipes?: DecoderRecipe[];
    selectedDecoderRecipeId?: string;
    decoderJwtWorkspaces?: DecoderJwtWorkspace[];
    selectedDecoderJwtWorkspaceId?: string;
    decoderBinaryInspections?: DecoderBinaryInspection[];
    selectedDecoderBinaryInspectionId?: string;
    decoderTransformLibraries?: DecoderTransformLibraryPackage[];
    selectedDecoderTransformLibraryId?: string;
    decoderReportExports?: DecoderReportExportArtifact[];
    selectedDecoderReportExportId?: string;
    aiRunHistory?: AiRunResult[];
    aiActionExecutionPackages?: AiActionExecutionPackage[];
    selectedAiActionExecutionPackageId?: string;
    aiPromptTemplates?: AiPromptTemplate[];
    aiEvaluationBaselines?: AiEvaluationBaseline[];
    aiPromptComparisons?: AiPromptComparison[];
    aiBenchmarkRuns?: AiBenchmarkRun[];
    sequencerResults?: SequencerAnalysisResult[];
    selectedSequencerResultId?: string;
    sequencerLiveCaptures?: SequencerLiveCapture[];
    selectedSequencerLiveCaptureId?: string;
    sequencerProfileComparisons?: SequencerProfileComparison[];
    selectedSequencerProfileComparisonId?: string;
    sequencerExports?: SequencerExportArtifact[];
    selectedSequencerExportId?: string;
    reportCustomTemplateName?: string;
    reportCustomTemplateBody?: string;
    reportLoggerArchiveReviewIds?: string[];
    reportFullPackages?: ReportFullPackage[];
    selectedReportFullPackageId?: string;
    issueTriageOverrides?: IssueTriageOverride[];
    importedBundleIssues?: Issue[];
    scannerAuditQueue?: ScannerAuditQueueItem[];
    scannerRetestWorkflows?: ScannerRetestWorkflow[];
    selectedScannerRetestWorkflowId?: string;
    scannerIssueRules?: ScannerIssueRule[];
    selectedScannerIssueRuleId?: string;
    scannerEvidenceDeltas?: ScannerEvidenceDelta[];
    selectedScannerEvidenceDeltaId?: string;
    scannerActiveScanPlans?: ScannerActiveScanPlan[];
    selectedScannerActiveScanPlanId?: string;
    scannerInsertionPointReviews?: ScannerInsertionPointReview[];
    selectedScannerInsertionPointReviewId?: string;
    scannerAuthenticatedStateMatrices?: ScannerAuthenticatedStateMatrix[];
    selectedScannerAuthenticatedStateMatrixId?: string;
    scannerReplayCheckPackages?: ScannerReplayCheckPackage[];
    selectedScannerReplayCheckPackageId?: string;
    scannerActiveScanEvidencePackages?: ScannerActiveScanEvidencePackage[];
    selectedScannerActiveScanEvidencePackageId?: string;
    anvilDefinitions?: AnvilDefinition[];
    selectedAnvilDefinitionId?: string;
    anvilRuleLibraries?: AnvilRuleLibrary[];
    selectedAnvilRuleLibraryId?: string;
    anvilFixtures?: AnvilFixture[];
    selectedAnvilFixtureId?: string;
    anvilValidationRuns?: AnvilValidationRun[];
    selectedAnvilValidationRunId?: string;
    anvilHeadlessRuns?: AnvilHeadlessRun[];
    selectedAnvilHeadlessRunId?: string;
    anvilPackageReviews?: AnvilPackageReview[];
    selectedAnvilPackageReviewId?: string;
}
export interface ProjectFileArtifact {
    id: string;
    fileName: string;
    path: string;
    exportedAt: string;
    projectName: string;
    exchangeCount: number;
    scopeCount: number;
    sizeBytes: number;
    content?: string;
}
export interface ProjectStoreStats {
    projectName: string;
    schemaVersion: 2;
    exchangeCount: number;
    scopeRuleCount: number;
    auditEventCount: number;
    projectSettingCount: number;
    sessionCookieCount: number;
    targetHostCount: number;
    targetRouteCount: number;
    parameterCount: number;
    callbackPayloadCount: number;
    callbackInteractionCount: number;
    repeaterTabCount: number;
    repeaterSendCount: number;
    webSocketConnectionCount: number;
    webSocketFrameCount: number;
    intruderAttackCount: number;
    intruderResultCount: number;
    scannerTaskCount: number;
    scannerFindingCount: number;
    scannerSuppressedFindingCount: number;
    issueCount: number;
    reportExportCount: number;
    automationRunCount: number;
    aiRunCount: number;
    extensionRunCount: number;
    blobCount: number;
    requestBytes: number;
    responseBytes: number;
    callbackBytes: number;
    repeaterRequestBytes: number;
    repeaterResponseBytes: number;
    webSocketPayloadBytes: number;
    intruderRequestBytes: number;
    intruderResponseBytes: number;
    reportBytes: number;
    aiPromptBytes: number;
    aiOutputBytes: number;
}
export interface ProjectLifecycleAuditEvent {
    id: string;
    actor: string;
    action: string;
    targetRef: string;
    decision: 'allowed' | 'blocked' | 'completed' | 'updated';
    detail: string;
    createdAt: string;
    previousHash?: string;
    hash: string;
}
export interface ProjectLifecycleCreateRequest {
    projectName?: string;
    projectId?: string;
    rootDir?: string;
    operator?: string;
    allowExternalRoot?: boolean;
}
export interface ProjectLifecycleOpenRequest {
    rootDir: string;
    operator?: string;
    recover?: boolean;
    allowExternalRoot?: boolean;
}
export interface ProjectLifecycleCloseRequest {
    operator?: string;
}
export interface ProjectLifecycleBackupRequest {
    backupRootDir?: string;
    label?: string;
    operator?: string;
    allowExternalRoot?: boolean;
}
export interface ProjectLifecycleState {
    kind: 'proxyforge-project-lifecycle-state';
    status: 'open' | 'closed';
    projectsRootDir: string;
    backupsRootDir: string;
    activeProject?: {
        projectId: string;
        projectName: string;
        rootDir: string;
        snapshotPath: string;
        manifest: {
            kind: 'proxyforge-project-store';
            schemaVersion: 2;
            projectId: string;
            projectName: string;
            createdAt: string;
            updatedAt: string;
        };
        stats: ProjectStoreStats;
        auditEvents: ProjectLifecycleAuditEvent[];
    };
    recentProjects: Array<{
        projectId: string;
        projectName: string;
        rootDir: string;
        openedAt: string;
    }>;
    requirements: {
        typedIpcContract: boolean;
        projectStoreBackbone: boolean;
        activeProjectRebindsRecorders: boolean;
        lifecycleAuditLedger: boolean;
        pathTraversalRejected: boolean;
        rawOperationalSecretsPreserved: boolean;
        reportPhaseOnlyRedaction: boolean;
    };
}
export interface ProjectLifecycleBackupResponse {
    kind: 'proxyforge-project-lifecycle-backup-response';
    backup: {
        kind: 'proxyforge-project-store-backup';
        schemaVersion: 1;
        projectId: string;
        projectName: string;
        sourceRootDir: string;
        backupRootDir: string;
        backupDir: string;
        label: string;
        createdAt: string;
        manifestPath: string;
        stats: ProjectStoreStats;
        content: string;
        requirements: {
            manifestCopied: boolean;
            databaseCopied: boolean;
            blobsCopied: boolean;
            recoveryJournalCopied: boolean;
            rawOperationalSecretsPreserved: boolean;
            reportPhaseOnlyRedaction: boolean;
        };
        secretHandling: string;
        reportRedactionBoundary: string;
    };
    state: ProjectLifecycleState;
}
export interface ProjectSafetyPolicy {
    requireScopeMatch: boolean;
    auditLogging: boolean;
    redactAuditSecrets: boolean;
    minThrottleMs: number;
    maxRequestsPerRun: number;
}
export interface PolicyOverride {
    id: string;
    operator: string;
    role: string;
    enabled: boolean;
    createdAt: string;
    expiresAt: string;
    scopeAdditions: string[];
    minThrottleMs?: number;
    maxRequestsPerRun?: number;
    reason: string;
}
export interface HttpsInspectionSettings {
    upstreamTlsMode: HttpsInspectionStatus['upstreamTlsMode'];
}
export interface AuditEvent {
    id: string;
    at: string;
    operator?: string;
    tool: ToolId | 'system';
    action: string;
    target: string;
    decision: 'allowed' | 'blocked' | 'completed' | 'updated';
    detail: string;
    requestCount: number;
    scope: string[];
    risk: Severity;
}
export interface ApprovalRecord {
    id: string;
    at: string;
    operator: string;
    tool: ToolId;
    action: string;
    target: string;
    risk: Severity;
    status: 'approved' | 'used' | 'revoked';
    expiresAt: string;
    detail: string;
    scope: string[];
    evidenceIds: string[];
}
export interface SignedAuditExport {
    id: string;
    fileName: string;
    path: string;
    exportedAt: string;
    projectName: string;
    signerName: string;
    keyId: string;
    digestSha256: string;
    signature: string;
    status: 'signed' | 'missing-secret';
    eventCount: number;
    approvalCount: number;
    overrideCount: number;
    sizeBytes: number;
    content?: string;
}
export type EnterpriseIdentityProvider = 'manual' | 'saml' | 'oidc';
export interface EnterpriseOperatorIdentity {
    id: string;
    provider: EnterpriseIdentityProvider;
    subject: string;
    email: string;
    displayName: string;
    roles: string[];
    assertedAt: string;
    expiresAt?: string;
    source: 'manual' | 'sso-claim' | 'team-sync';
}
export interface EnterpriseTeamSync {
    teamName: string;
    mode: 'manual' | 'pull' | 'push';
    policyUrl: string;
    lastSyncedAt?: string;
    policyDigestSha256?: string;
    status: 'idle' | 'exported' | 'imported' | 'error';
    message: string;
}
export interface EnterpriseSsoProviderConfig {
    provider: EnterpriseIdentityProvider;
    issuer: string;
    audience: string;
    subjectClaim: string;
    emailClaim: string;
    nameClaim: string;
    roleClaim: string;
    groupClaim: string;
    jitProvisioning: boolean;
    lastConfiguredAt?: string;
    status: 'draft' | 'configured' | 'error';
    message: string;
}
export interface EnterpriseRemotePolicyTransport {
    endpoint: string;
    authHeaderName: string;
    credentialLabel: string;
    lastPulledAt?: string;
    lastPushedAt?: string;
    pullCount: number;
    pushCount: number;
    lastPackageDigestSha256?: string;
    status: 'not-configured' | 'ready' | 'pulled' | 'pushed' | 'error';
    message: string;
}
export interface EnterprisePolicyPackage {
    version?: number;
    kind?: string;
    digestSha256?: string;
    [key: string]: unknown;
}
export interface EnterprisePolicyTransportRuntimeRequest {
    transport: EnterpriseRemotePolicyTransport;
    policyPackage?: EnterprisePolicyPackage;
    timeoutMs?: number;
    authHeaderValue?: string;
}
export interface EnterprisePolicyTransportRuntimeResult {
    endpoint: string;
    method: 'GET' | 'POST';
    statusCode: number;
    completedAt: string;
    digestSha256: string;
    receiptId?: string;
    responseBody: string;
    message: string;
    policyPackage?: EnterprisePolicyPackage;
}
export type GovernanceRunnerId = 'automations' | 'scanner' | 'exploit-lab' | 'ci-headless';
export interface GovernanceRunnerPolicyBinding {
    id: string;
    runnerId: GovernanceRunnerId;
    label: string;
    scopeAllowlist: string[];
    minThrottleMs: number;
    maxRequestsPerRun: number;
    requiresApproval: boolean;
    approvalRole: string;
    status: 'ready' | 'review-required' | 'active';
    detail: string;
}
export interface GovernancePolicyPackage {
    id: string;
    title: string;
    fileName: string;
    path: string;
    exportedAt: string;
    reviewedAt?: string;
    activatedAt?: string;
    status: 'draft' | 'signed' | 'reviewed' | 'active';
    teamName: string;
    activeOperator: string;
    operatorRole: string;
    runnerBindings: GovernanceRunnerPolicyBinding[];
    policy: {
        safetyPolicy: ProjectSafetyPolicy;
        scopeAllowlist: string[];
        policyOverrides: PolicyOverride[];
        remotePolicyTransport: EnterpriseRemotePolicyTransport;
        enterpriseTeamSync: EnterpriseTeamSync;
        operatorIdentities: EnterpriseOperatorIdentity[];
        approvalRecords: ApprovalRecord[];
    };
    signature: {
        algorithm: 'HMAC-SHA256';
        signerName: string;
        keyId: string;
        status: 'signed' | 'reviewed' | 'active';
        digestPreview: string;
    };
    content: string;
}
export interface GovernanceApprovalReview {
    id: string;
    packageId: string;
    reviewedAt: string;
    reviewer: string;
    role: string;
    status: 'reviewed' | 'active';
    summary: string;
    runnerCount: number;
    approvalRequiredCount: number;
}
export interface RemoteAuditRetention {
    enabled: boolean;
    endpoint: string;
    retentionDays: number;
    mode: 'manual' | 'push-after-export';
    status: 'not-configured' | 'ready' | 'queued' | 'sent' | 'failed';
    lastQueuedAt?: string;
    lastAttemptAt?: string;
    lastSentAt?: string;
    nextRetryAt?: string;
    lastPackageId?: string;
    retryCount?: number;
    deliveryReceiptId?: string;
    lastError?: string;
    message: string;
}
export type SessionInjectionMode = 'merge' | 'replace';
export type SessionInjectionTarget = 'headers' | 'cookies' | 'headers-and-cookies';
export interface RuntimeSessionProfile {
    id?: string;
    name?: string;
    headerText?: string;
    cookieText?: string;
}
export interface SessionApplyOptions {
    mode?: SessionInjectionMode;
    target?: SessionInjectionTarget;
}
export interface ReplayRequest {
    rawRequest: string;
    targetUrl: string;
    scopeAllowlist: string[];
    settings?: ReplayTransportSettings;
    sessionProfile?: RuntimeSessionProfile;
    sessionOptions?: SessionApplyOptions;
    oastPayloads?: CallbackPayload[];
    repeaterTabId?: string;
    repeaterTabName?: string;
    repeaterTabGroup?: string;
    repeaterSendId?: string;
    sourceExchangeId?: string;
    operator?: string;
    tags?: string[];
    notes?: string;
}
export interface SessionProfile {
    id: string;
    name: string;
    role: string;
    targetUrl: string;
    source: 'manual' | 'browser' | 'traffic' | 'ci';
    status: 'ready' | 'stale' | 'needs-refresh';
    headerText: string;
    cookieText: string;
    createdAt: string;
    updatedAt: string;
    lastUsedAt?: string;
    headerCount: number;
    cookieCount: number;
    notes: string;
    refreshUrl?: string;
    expiresAt?: string;
    lastRefreshAt?: string;
    refreshStatus?: 'never' | 'refreshed' | 'unchanged' | 'failed';
    refreshCookieCount?: number;
    refreshMessage?: string;
}
export interface SessionProfileRefreshRequest {
    profile: SessionProfile;
    timeoutMs?: number;
}
export interface SessionProfileRefreshResult {
    profile: SessionProfile;
    status: 'refreshed' | 'unchanged' | 'failed';
    statusCode?: number;
    setCookieCount: number;
    headerCount: number;
    cookieCount: number;
    message: string;
    rawResponseHead: string;
}
export type ManagedBrowserFamily = 'auto' | 'chromium' | 'chrome' | 'edge' | 'firefox';
export interface BrowserLaunchRequest {
    targetUrl: string;
    browser: ManagedBrowserFamily;
    proxyHost?: string;
    proxyPort: number;
    profileName?: string;
    ignoreCertificateErrors?: boolean;
}
export interface BrowserLaunchResult {
    id: string;
    status: 'launched' | 'preview' | 'not-found' | 'error';
    browser: ManagedBrowserFamily | 'unknown';
    browserName: string;
    targetUrl: string;
    proxyHost: string;
    proxyPort: number;
    profilePath: string;
    command: string;
    args: string[];
    pid?: number;
    startedAt: string;
    message: string;
}
export interface BrowserCookieExtractionRequest {
    targetUrl: string;
    browser: ManagedBrowserFamily;
    profilePath: string;
}
export interface BrowserCookieEntry {
    name: string;
    value: string;
    domain: string;
    path: string;
    expiresAt?: string;
    secure: boolean;
    httpOnly: boolean;
    sameSite?: string;
    source: 'chromium' | 'firefox';
}
export interface BrowserCookieExtractionResult {
    id: string;
    status: 'complete' | 'partial' | 'empty' | 'unsupported' | 'error';
    targetUrl: string;
    browser: ManagedBrowserFamily | 'unknown';
    profilePath: string;
    cookieHeader: string;
    cookieCount: number;
    decryptedCount: number;
    encryptedCount: number;
    skippedCount: number;
    extractedAt: string;
    cookies: BrowserCookieEntry[];
    message: string;
}
export type ReplayRedirectMode = 'manual' | 'follow';
export type ReplayConnectionMode = 'default' | 'close' | 'keep-alive';
export interface ReplayTransportSettings {
    redirectMode: ReplayRedirectMode;
    maxRedirects: number;
    connectionMode: ReplayConnectionMode;
    timeoutMs: number;
}
export type ReplaySessionProfileInjectionMode = 'merge' | 'replace';
export type ReplaySessionProfileInjectionTarget = 'headers' | 'cookies' | 'headers-and-cookies';
export interface ReplaySessionProfileInjection {
    id: string;
    name: string;
    sessionProfileId: string;
    sessionProfileName: string;
    target: ReplaySessionProfileInjectionTarget;
    mode: ReplaySessionProfileInjectionMode;
    headerNames: string[];
    cookieNames: string[];
    createdAt: string;
    updatedAt: string;
    lastAppliedAt?: string;
    notes: string;
}
export type ReplayBulkRunStatus = 'queued' | 'running' | 'completed' | 'partial' | 'blocked' | 'failed';
export interface ReplayBulkRunItem {
    id: string;
    name: string;
    targetUrl: string;
    rawRequest: string;
    status: ReplayBulkRunStatus;
    blocked: boolean;
    message: string;
    sessionProfileId?: string;
    sessionProfileInjectionId?: string;
    sourceExchangeId?: string;
    sourceRepeaterTabId?: string;
    exchangeId?: string;
    statusCode?: number;
    length?: number;
    timing?: number;
    risk?: Severity;
}
export interface ReplayBulkRun {
    id: string;
    name: string;
    startedAt: string;
    completedAt?: string;
    status: ReplayBulkRunStatus;
    totalRequests: number;
    completedRequests: number;
    blockedRequests: number;
    failedRequests: number;
    message: string;
    sessionProfileId?: string;
    sessionProfileInjectionId?: string;
    authorizationMatrixId?: string;
    throttleMs?: number;
    items: ReplayBulkRunItem[];
}
export type ReplayAuthorizationExpectation = 'allow' | 'deny' | 'same-as-baseline' | 'changed-from-baseline';
export type ReplayAuthorizationOutcome = 'allowed' | 'denied' | 'changed' | 'same' | 'blocked' | 'error' | 'unknown';
export interface ReplayAuthorizationMatrixIdentity {
    id: string;
    name: string;
    role: string;
    sessionProfileId?: string;
    sessionProfileInjectionId?: string;
    notes: string;
}
export interface ReplayAuthorizationMatrixRoute {
    id: string;
    name: string;
    method: string;
    targetUrl: string;
    rawRequest: string;
    baselineExchangeId?: string;
    notes: string;
}
export interface ReplayAuthorizationMatrixCell {
    id: string;
    identityId: string;
    routeId: string;
    expectation: ReplayAuthorizationExpectation;
    outcome: ReplayAuthorizationOutcome;
    lastRunAt?: string;
    bulkRunItemId?: string;
    exchangeId?: string;
    statusCode?: number;
    length?: number;
    timing?: number;
    risk?: Severity;
    notes: string;
}
export interface ReplayAuthorizationMatrix {
    id: string;
    name: string;
    description: string;
    createdAt: string;
    updatedAt: string;
    targetUrl: string;
    identities: ReplayAuthorizationMatrixIdentity[];
    routes: ReplayAuthorizationMatrixRoute[];
    cells: ReplayAuthorizationMatrixCell[];
    lastBulkRunId?: string;
    notes: string;
}
export interface RepeaterSavedRequest {
    id: string;
    name: string;
    folder: string;
    targetUrl: string;
    rawRequest: string;
    createdAt: string;
    updatedAt: string;
    tags: string[];
}
export interface RepeaterRequestSnapshot {
    id: string;
    tabId: string;
    label: string;
    targetUrl: string;
    rawRequest: string;
    createdAt: string;
    changedLines: number;
}
export interface RepeaterRequestDiff {
    id: string;
    tabId: string;
    label: string;
    fromLabel: string;
    toLabel: string;
    targetUrl: string;
    createdAt: string;
    changedLines: number;
    addedLines: number;
    removedLines: number;
    preview: string[];
}
export interface RepeaterWorkspaceTab {
    id: string;
    name: string;
    group: string;
    targetUrl: string;
    rawRequest: string;
    createdAt: string;
    updatedAt: string;
    dirty: boolean;
    sourceExchangeId?: string;
    lastStatus?: number;
    lastReplayId?: string;
    snapshots: RepeaterRequestSnapshot[];
    diffs: RepeaterRequestDiff[];
}
export interface RepeaterBatchResult {
    tabId: string;
    tabName: string;
    targetUrl: string;
    status: number;
    length: number;
    timing: number;
    risk: Severity;
    notes: string;
    blocked: boolean;
    exchangeId?: string;
}
export interface RepeaterBatchRun {
    id: string;
    startedAt: string;
    completedAt: string;
    totalRequests: number;
    blocked: boolean;
    message: string;
    results: RepeaterBatchResult[];
}
export type DesyncTechnique = 'cl0' | 'client-side-desync' | 'pause-based' | 'parallel-race';
export type RepeaterGroupSendMode = 'sequence-single-connection' | 'sequence-separate-connections' | 'parallel';
export type RepeaterSyncTechnique = 'single-connection' | 'last-byte' | 'single-packet' | 'pause-window';
export interface DesyncProbeRequest {
    id: string;
    name: string;
    targetUrl: string;
    rawRequest: string;
    role: 'baseline' | 'poison' | 'victim' | 'warmup';
}
export interface DesyncProbePlan {
    id: string;
    createdAt: string;
    targetUrl: string;
    host: string;
    path: string;
    techniques: DesyncTechnique[];
    sendMode: RepeaterGroupSendMode;
    syncTechnique: RepeaterSyncTechnique;
    scopeStatus: 'authorized' | 'blocked';
    requestCount: number;
    requests: DesyncProbeRequest[];
    summary: string;
    content: string;
}
export interface DesyncConnectionEvidence {
    id: string;
    planId: string;
    createdAt: string;
    protocol: 'HTTP/1.1' | 'HTTP/2';
    syncTechnique: RepeaterSyncTechnique;
    connectionStrategy: string;
    responseOrder: string[];
    jitterMs: number;
    raceWindowMs: number;
    timingNotes: string;
    summary: string;
    evidence: string;
}
export type RepeaterDesyncTransportStatus = 'proof' | 'blocked' | 'error';
export interface RepeaterDesyncRuntimeRequest {
    planId?: string;
    targetUrl: string;
    requests: DesyncProbeRequest[];
    scopeAllowlist: string[];
    timeoutMs?: number;
    syncTechnique?: RepeaterSyncTechnique;
    pauseMs?: number;
}
export interface RepeaterDesyncRuntimeResponse {
    requestId: string;
    role: DesyncProbeRequest['role'];
    name: string;
    targetUrl: string;
    status?: number;
    statusLine?: string;
    bytes: number;
    startedAt: string;
    completedAt?: string;
    timingMs: number;
    headers: Record<string, string>;
    bodyPreview: string;
    rawRequest: string;
    rawResponse: string;
    error?: string;
}
export interface RepeaterDesyncRuntimeResult {
    id: string;
    planId?: string;
    createdAt: string;
    targetUrl: string;
    protocol: 'HTTP/1.1';
    transport: 'single-connection' | 'parallel-last-byte' | 'parallel-single-packet';
    syncTechnique: RepeaterSyncTechnique;
    status: RepeaterDesyncTransportStatus;
    requestCount: number;
    responseOrder: string[];
    jitterMs: number;
    raceWindowMs: number;
    releaseSkewMs?: number;
    connectionStrategy: string;
    timingNotes: string;
    responses: RepeaterDesyncRuntimeResponse[];
    rawTranscript: string;
    summary: string;
}
export interface ParallelRaceRun {
    id: string;
    planId: string;
    evidenceId?: string;
    createdAt: string;
    status: 'ready' | 'proof' | 'blocked';
    requestCount: number;
    syncTechnique: RepeaterSyncTechnique;
    raceWindowMs: number;
    jitterMs: number;
    responseOrder: string[];
    summary: string;
    evidence: string;
}
export interface DesyncProofBundle {
    id: string;
    title: string;
    fileName: string;
    path: string;
    createdAt: string;
    planId: string;
    evidenceId?: string;
    raceRunId?: string;
    issueId?: string;
    reportReady: boolean;
    summary: string;
    content: string;
}
export interface ReplayMatrixResult {
    id: string;
    identity: string;
    headerName: string;
    status: number;
    length: number;
    timing: number;
    risk: Severity;
    delta: string;
    notes: string;
    exchange: HttpExchange;
}
export interface ReplayMatrixRun {
    id: string;
    targetUrl: string;
    headerName: string;
    startedAt: string;
    completedAt: string;
    baselineStatus: number;
    baselineLength: number;
    totalRequests: number;
    blocked: boolean;
    message: string;
    results: ReplayMatrixResult[];
}
export type ViewerSourceKind = 'http-exchange' | 'websocket-message' | 'replay-matrix-result' | 'replay-bulk-item' | 'repeater-tab' | 'report-artifact' | 'logger-import' | 'manual';
export type ViewerPayloadSide = 'request' | 'response' | 'websocket-frame' | 'replay-baseline' | 'replay-candidate' | 'report-artifact' | 'manual-note';
export type ViewerSnapshotRepresentation = 'raw' | 'decoded' | 'raw-and-decoded';
export type ViewerDecoderId = 'none' | 'url' | 'base64' | 'hex' | 'json' | 'html' | 'jwt' | 'gzip' | 'brotli' | 'deflate';
export type ViewerReplayComparisonExportFormat = 'markdown' | 'html' | 'json';
export interface ViewerSourceReference {
    kind: ViewerSourceKind;
    id: string;
    label: string;
    toolId?: ToolId;
    exchangeId?: string;
    webSocketMessageId?: string;
    replayMatrixRunId?: string;
    replayMatrixResultId?: string;
    replayBulkRunId?: string;
    replayBulkRunItemId?: string;
    repeaterTabId?: string;
    reportArtifactId?: string;
    loggerArchiveReviewId?: string;
    method?: string;
    host?: string;
    path?: string;
    url?: string;
}
export interface ViewerEvidenceSelection {
    side: ViewerPayloadSide;
    representation: ViewerSnapshotRepresentation;
    byteStart?: number;
    byteEnd?: number;
    lineStart?: number;
    lineEnd?: number;
    selectedText?: string;
}
export interface ViewerEvidencePin {
    id: string;
    title: string;
    createdAt: string;
    updatedAt: string;
    source: ViewerSourceReference;
    selection: ViewerEvidenceSelection;
    snapshotId?: string;
    severity?: Severity;
    tags: string[];
    linkedIssueIds: string[];
    linkedExchangeIds: string[];
    reportReady: boolean;
    reportSection?: ReportSection;
    notes: string;
}
export interface ViewerDecodedRawSnapshot {
    id: string;
    title: string;
    createdAt: string;
    updatedAt: string;
    source: ViewerSourceReference;
    side: ViewerPayloadSide;
    representation: ViewerSnapshotRepresentation;
    decoderPipeline: ViewerDecoderId[];
    mime?: string;
    charset?: string;
    rawContent: string;
    decodedContent?: string;
    contentSha256?: string;
    sizeBytes: number;
    evidencePinIds: string[];
    notes: string;
}
export interface ViewerReplayComparisonExportRow {
    id: string;
    label: string;
    method: string;
    url: string;
    baselineSource: ViewerSourceReference;
    candidateSource: ViewerSourceReference;
    baselineStatus?: number;
    candidateStatus?: number;
    baselineLength?: number;
    candidateLength?: number;
    baselineTiming?: number;
    candidateTiming?: number;
    statusChanged: boolean;
    lengthDelta?: number;
    timingDelta?: number;
    risk?: Severity;
    snapshotIds: string[];
    evidencePinIds: string[];
    diffSummary: string;
    notes: string;
}
export interface ViewerReplayComparisonExport {
    id: string;
    title: string;
    fileName: string;
    path: string;
    exportedAt: string;
    format: ViewerReplayComparisonExportFormat;
    replayMatrixRunId?: string;
    replayBulkRunId?: string;
    authorizationMatrixId?: string;
    baselineSessionProfileId?: string;
    candidateSessionProfileIds: string[];
    reportReady: boolean;
    reportSection?: ReportSection;
    issueIds: string[];
    exchangeIds: string[];
    snapshotIds: string[];
    evidencePinIds: string[];
    rows: ViewerReplayComparisonExportRow[];
    summary: string;
    content?: string;
}
export interface ComparerWorkspace {
    id: string;
    name: string;
    createdAt: string;
    updatedAt: string;
    left: string;
    right: string;
    ignoreWhitespace: boolean;
    sourceLabel: string;
    linkedExchangeIds: string[];
    linkedIssueIds: string[];
    similarity: number;
    changed: number;
    added: number;
    removed: number;
    notes: string;
}
export interface ComparerDiffPackage {
    id: string;
    title: string;
    fileName: string;
    path: string;
    exportedAt: string;
    format: 'json' | 'markdown';
    workspaceId?: string;
    reportReady: boolean;
    reportSection?: ReportSection;
    issueIds: string[];
    exchangeIds: string[];
    summary: string;
    leftLabel: string;
    rightLabel: string;
    similarity: number;
    changed: number;
    added: number;
    removed: number;
    unifiedDiff: string;
    content: string;
}
export type ComparerDiffMode = 'lines' | 'words' | 'bytes' | 'structured-http' | 'binary-hex';
export type ComparerNormalizationPresetId = 'raw' | 'ignore-whitespace' | 'http-noise' | 'authz-review' | 'text-only';
export type ComparerAdvancedRowType = 'equal' | 'added' | 'removed' | 'changed';
export interface ComparerNormalizationPreset {
    id: ComparerNormalizationPresetId;
    label: string;
    detail: string;
    ignoreWhitespace: boolean;
    ignoreHeaderNames: string[];
    focusHeaderNames: string[];
    textOnly: boolean;
}
export interface ComparerTokenDiffRow {
    id: string;
    type: ComparerAdvancedRowType;
    leftIndex?: number;
    rightIndex?: number;
    left: string;
    right: string;
    weight: number;
    notes: string;
}
export interface ComparerByteDiffRow {
    id: string;
    type: ComparerAdvancedRowType;
    offset: number;
    leftHex: string;
    rightHex: string;
    leftAscii: string;
    rightAscii: string;
    runLength: number;
    notes: string;
}
export interface ComparerStructuredHttpDiff {
    id: string;
    section: 'start-line' | 'headers' | 'body' | 'json' | 'form' | 'metadata';
    key: string;
    type: ComparerAdvancedRowType;
    left: string;
    right: string;
    severity: Severity;
    notes: string;
}
export interface ComparerAdvancedResult {
    id: string;
    label: string;
    createdAt: string;
    mode: ComparerDiffMode;
    normalizationPresetId: ComparerNormalizationPresetId;
    normalizationLabel: string;
    leftBytes: number;
    rightBytes: number;
    similarity: number;
    differenceCount: number;
    tokenRows: ComparerTokenDiffRow[];
    byteRows: ComparerByteDiffRow[];
    structuredRows: ComparerStructuredHttpDiff[];
    textView: string;
    hexView: string;
    reportReady: boolean;
    summary: string;
}
export interface ComparerReplayDeltaReview {
    id: string;
    createdAt: string;
    baselineLabel: string;
    candidateLabel: string;
    statusChanged: boolean;
    lengthDelta: number;
    timingDelta: number;
    risk: Severity;
    verdict: 'same' | 'changed' | 'privilege-drift' | 'regression';
    advancedRunId?: string;
    linkedExchangeIds: string[];
    linkedIssueIds: string[];
    summary: string;
    evidence: string;
    reportReady: boolean;
}
export interface ComparerLibraryPackage {
    id: string;
    title: string;
    fileName: string;
    path: string;
    exportedAt: string;
    advancedRunIds: string[];
    workspaceIds: string[];
    diffPackageIds: string[];
    replayDeltaReviewIds: string[];
    normalizationPresetIds: ComparerNormalizationPresetId[];
    reportReady: boolean;
    digestPreview: string;
    summary: string;
    content: string;
}
export interface ComparerEvidenceAttachment {
    id: string;
    title: string;
    fileName: string;
    path: string;
    createdAt: string;
    advancedRunId?: string;
    libraryPackageId?: string;
    replayDeltaReviewId?: string;
    issueId?: string;
    reportReady: boolean;
    summary: string;
    content: string;
}
export type DecoderLayerKind = 'url' | 'html' | 'base64' | 'base64url' | 'hex' | 'binary' | 'octal' | 'json' | 'jwt' | 'jws' | 'jwe' | 'raw';
export type DecoderFindingSeverity = 'pass' | 'review' | 'warning';
export interface DecoderDetectedLayer {
    id: string;
    kind: DecoderLayerKind;
    operation: string;
    confidence: number;
    inputPreview: string;
    outputPreview: string;
    output: string;
    notes: string[];
}
export interface DecoderHashInsight {
    algorithm: 'SHA-1' | 'SHA-256';
    value: string;
}
export interface DecoderEncodingInsight {
    id: string;
    label: string;
    severity: DecoderFindingSeverity;
    detail: string;
}
export interface DecoderAnalysisRun {
    id: string;
    label: string;
    createdAt: string;
    inputLength: number;
    byteLength: number;
    printableRatio: number;
    entropyBitsPerByte: number;
    detectedLayers: DecoderDetectedLayer[];
    recommendedRecipe: string[];
    encodingInsights: DecoderEncodingInsight[];
    hashes: DecoderHashInsight[];
    finalPreview: string;
    reportReady: boolean;
    summary: string;
}
export interface DecoderRecipeStep {
    id: string;
    transformId: string;
    label: string;
    direction: 'decode' | 'encode' | 'hash' | 'format';
    reversible: boolean;
    notes: string;
}
export interface DecoderRecipe {
    id: string;
    name: string;
    createdAt: string;
    inputPreview: string;
    outputPreview: string;
    steps: DecoderRecipeStep[];
    reportReady: boolean;
    summary: string;
    content: string;
}
export interface DecoderJwtWorkspace {
    id: string;
    title: string;
    createdAt: string;
    tokenType: 'jwt' | 'jws' | 'jwe';
    algorithm: string;
    headerJson: string;
    payloadJson: string;
    signaturePreview: string;
    secretLabel: string;
    signedTokenPreview: string;
    status: 'decoded' | 'edited' | 'signed-preview' | 'jwe-detected' | 'jwe-key-required' | 'jwe-decrypted' | 'jwe-reencrypted' | 'jwe-unsupported' | 'invalid';
    notes: string[];
    reportReady: boolean;
    summary: string;
}
export interface DecoderBinaryInspection {
    id: string;
    title: string;
    createdAt: string;
    byteLength: number;
    printableRatio: number;
    nullBytes: number;
    highBytes: number;
    hexDump: string;
    asciiPreview: string;
    hashes: DecoderHashInsight[];
    encodingInsights: DecoderEncodingInsight[];
    reportReady: boolean;
    summary: string;
}
export interface DecoderTransformLibraryPackage {
    id: string;
    title: string;
    fileName: string;
    path: string;
    exportedAt: string;
    recipeIds: string[];
    analysisIds: string[];
    jwtWorkspaceIds: string[];
    binaryInspectionIds: string[];
    reportReady: boolean;
    digestPreview: string;
    summary: string;
    content: string;
}
export interface DecoderReportExportArtifact {
    id: string;
    title: string;
    fileName: string;
    path: string;
    exportedAt: string;
    analysisId?: string;
    recipeId?: string;
    jwtWorkspaceId?: string;
    binaryInspectionId?: string;
    libraryPackageId?: string;
    issueId?: string;
    reportReady: boolean;
    summary: string;
    content: string;
}
export type IntruderAttackMode = 'sniper' | 'battering-ram' | 'pitchfork' | 'cluster-bomb';
export type IntruderPayloadProcessor = 'url-encode' | 'double-url-encode' | 'base64' | 'html-encode' | 'json-escape' | 'hex-encode' | 'uppercase' | 'lowercase';
export type IntruderPayloadRuleId = 'case-variants' | 'url-recursive' | 'path-depth' | 'delimiter-variants' | 'extension-bypass' | 'null-byte';
export interface IntruderOastPayloadReference {
    id: string;
    token: string;
    endpoint: string;
    label?: string;
    protocol?: 'http' | 'dns' | 'smtp';
}
export interface IntruderOastCorrelationSummary {
    payloadCount: number;
    interactionCount: number;
    correlatedResultCount: number;
    correlatedInteractionCount: number;
    pendingPayloadIds: string[];
}
export interface IntruderAttackRequest {
    rawRequest: string;
    targetUrl: string;
    payloads: string[];
    payloadSets?: string[][];
    attackMode?: IntruderAttackMode;
    payloadProcessors?: IntruderPayloadProcessor[];
    payloadRules?: IntruderPayloadRuleId[];
    scopeAllowlist: string[];
    throttleMs: number;
    grepTerms: string[];
    extractRegexes?: string[];
    startOffset?: number;
    maxPayloadRequests?: number;
    resourcePoolName?: string;
    resourcePoolMaxConcurrent?: number;
    streamChunkSize?: number;
    resultWindowSize?: number;
    memoryBudgetBytes?: number;
    sessionProfile?: RuntimeSessionProfile;
    sessionOptions?: SessionApplyOptions;
    oastPayloads?: IntruderOastPayloadReference[];
}
export interface IntruderAttackResult {
    id: string;
    payload: string;
    payloads: string[];
    attackMode: IntruderAttackMode;
    status: number;
    length: number;
    mime: string;
    timing: number;
    grepMatches: string[];
    extractMatches: string[];
    notes: string;
    requestRaw: string;
    responseRaw: string;
    tags: string[];
    oastPayloadIds?: string[];
    callbackInteractionIds?: string[];
}
export interface IntruderAttackSummary {
    id: string;
    targetUrl: string;
    startedAt: string;
    completedAt: string;
    attackMode: IntruderAttackMode;
    payloadPositions: number;
    totalRequests: number;
    blocked: boolean;
    message: string;
    results: IntruderAttackResult[];
    startOffset?: number;
    nextOffset?: number;
    hasMore?: boolean;
    payloadPlanCount?: number;
    payloadRuleCount?: number;
    resourcePoolName?: string;
    resourcePoolMaxConcurrent?: number;
    streaming?: IntruderStreamingSummary;
    oast?: IntruderOastCorrelationSummary;
}
export interface IntruderStreamingSummary {
    chunkSize: number;
    chunkCount: number;
    completedChunks: number;
    maxConcurrency: number;
    maxInFlight: number;
    durationMs: number;
    requestRatePerSecond: number;
    resultWindowSize: number;
    retainedResultCount: number;
    droppedResultCount: number;
    firstRetainedOffset: number;
    lastRetainedOffset: number;
    estimatedMemoryBytes: number;
    memoryBudgetBytes?: number;
    memoryPressure: 'low' | 'medium' | 'high';
}
export interface IntruderResultComparison {
    id: string;
    createdAt: string;
    summaryId: string;
    baselineResultId: string;
    candidateResultId: string;
    baselinePayload: string;
    candidatePayload: string;
    statusDelta: number;
    lengthDelta: number;
    timingDelta: number;
    grepDelta: string[];
    extractDelta: string[];
    verdict: 'interesting' | 'similar' | 'regression';
    notes: string;
}
export interface IntruderPayloadPositionDiff {
    id: string;
    createdAt: string;
    summaryId: string;
    position: number;
    baselinePayload: string;
    candidatePayload: string;
    changedRequests: number;
    statusSpread: number;
    lengthSpread: number;
    evidence: string;
}
export interface IntruderResultCluster {
    id: string;
    createdAt: string;
    summaryId: string;
    title: string;
    signature: string;
    verdict: 'interesting' | 'similar' | 'regression';
    status: number;
    mime: string;
    resultCount: number;
    representativeResultId: string;
    payloads: string[];
    averageLength: number;
    averageTiming: number;
    grepSignals: string[];
    extractSignals: string[];
    relatedSavedAttackIds: string[];
    relatedSavedAttackNames: string[];
    notes: string;
}
export interface IntruderStatisticalRanking {
    id: string;
    createdAt: string;
    summaryId: string;
    resultId: string;
    payload: string;
    rank: number;
    score: number;
    verdict: 'interesting' | 'similar' | 'regression';
    status: number;
    length: number;
    timing: number;
    lengthZScore: number;
    timingZScore: number;
    statusRarity: number;
    grepSignalCount: number;
    extractSignalCount: number;
    relatedSavedAttackIds: string[];
    reasons: string[];
}
export interface IntruderSavedAttack {
    id: string;
    name: string;
    targetUrl: string;
    rawRequest: string;
    attackMode: IntruderAttackMode;
    payloads: string;
    payloadSetTwo: string;
    payloadProcessors: IntruderPayloadProcessor[];
    payloadRules?: IntruderPayloadRuleId[];
    grepTerms: string;
    extractRegexes: string;
    throttleMs: number;
    createdAt: string;
    updatedAt: string;
}
export interface IntruderPayloadGenerator {
    id: string;
    name: string;
    kind: 'wordlist' | 'number-range' | 'role-matrix' | 'case-mutation' | 'date-range' | 'bruteforce' | 'injection-probes';
    description: string;
    payloads: string[];
    updatedAt: string;
}
export interface IntruderAttackQueueItem {
    id: string;
    attackName: string;
    targetUrl: string;
    attackMode: IntruderAttackMode;
    status: 'queued' | 'running' | 'complete' | 'blocked' | 'paused';
    totalRequests: number;
    completedRequests: number;
    message: string;
    createdAt: string;
    updatedAt: string;
    latestSummaryId?: string;
    checkpointOffset?: number;
    resourcePoolName?: string;
    payloadRules?: IntruderPayloadRuleId[];
}
export type ActiveScanCheckId = 'security-headers' | 'cors-origin' | 'cache-key' | 'method-options' | 'authz-diff' | 'jwt-claims' | 'graphql-introspection' | 'oast-ssrf' | 'reflected-xss' | 'sql-injection' | 'path-traversal' | 'open-redirect' | 'command-injection';
export interface ActiveScanRequest {
    rawRequest: string;
    targetUrl: string;
    scopeAllowlist: string[];
    checks: ActiveScanCheckId[];
    throttleMs: number;
    maxRequests: number;
    sessionProfile?: RuntimeSessionProfile;
    sessionOptions?: SessionApplyOptions;
    oastPayloadUrl?: string;
    oastPayloadToken?: string;
    oastPayloadId?: string;
}
export interface ActiveScanFinding {
    id: string;
    checkId: ActiveScanCheckId;
    title: string;
    severity: Severity;
    confidence: 'certain' | 'firm' | 'tentative';
    host: string;
    path: string;
    detail: string;
    remediation: string;
    evidenceExchangeId?: string;
    dedupeKey?: string;
    confidenceReason?: string;
}
export interface ActiveScanSuppressedFinding {
    id: string;
    checkId: ActiveScanCheckId;
    title: string;
    host: string;
    path: string;
    evidenceExchangeId?: string;
    dedupeKey?: string;
    reason: string;
}
export interface ActiveScanTuningMetadata {
    profile: 'browser-app-calibration';
    falsePositiveControls: string[];
    suppressedFindingCount: number;
    dedupedFindingCount: number;
    findingDedupeKeys: string[];
    calibrationNotes: string[];
}
export interface ActiveScanSummary {
    id: string;
    targetUrl: string;
    startedAt: string;
    completedAt: string;
    totalRequests: number;
    blocked: boolean;
    message: string;
    findings: ActiveScanFinding[];
    suppressedFindings?: ActiveScanSuppressedFinding[];
    tuning?: ActiveScanTuningMetadata;
    exchanges: HttpExchange[];
}
export type CrawlRouteSource = 'seed' | 'link' | 'script' | 'form' | 'redirect' | 'import';
export type CrawlInsertionPointType = 'query' | 'form' | 'path' | 'cookie' | 'header' | 'body' | 'json' | 'xml' | 'multipart' | 'graphql';
export interface CrawlRequest {
    startUrl: string;
    scopeAllowlist: string[];
    maxDepth: number;
    maxPages: number;
    throttleMs: number;
    userAgent: string;
    includeForms: boolean;
    headers?: Record<string, string>;
}
export interface CrawlInsertionPoint {
    id: string;
    routeId: string;
    type: CrawlInsertionPointType;
    name: string;
    method: string;
    url: string;
    evidence: string;
}
export interface CrawlRoute {
    id: string;
    method: string;
    url: string;
    host: string;
    path: string;
    status: number;
    mime: string;
    depth: number;
    source: CrawlRouteSource;
    parentUrl?: string;
    title: string;
    discoveredAt: string;
    insertionPoints: string[];
}
export interface CrawlSummary {
    id: string;
    startUrl: string;
    startedAt: string;
    completedAt: string;
    totalRequests: number;
    blocked: boolean;
    message: string;
    routes: CrawlRoute[];
    insertionPoints: CrawlInsertionPoint[];
    exchanges: HttpExchange[];
}
export type TargetSiteMapView = 'url' | 'crawl-path';
export type TargetSiteMapSourceFilter = 'all' | CrawlRouteSource;
export type TargetSiteMapStatusFilter = 'all' | '2xx' | '3xx' | '4xx' | '5xx' | 'errors' | 'with-params';
export interface TargetTechnologyInsight {
    id: string;
    label: string;
    category: 'client' | 'server' | 'api' | 'transport' | 'asset';
    confidence: 'certain' | 'firm' | 'tentative';
    routeCount: number;
    evidence: string;
}
export interface TargetParameterInsight {
    id: string;
    name: string;
    location: string;
    method: string;
    routeCount: number;
    routes: string[];
    evidence: string;
}
export interface TargetContentDiscoveryCandidate {
    id: string;
    host: string;
    path: string;
    source: 'wordlist' | 'script' | 'route' | 'backup' | 'api';
    priority: Severity;
    reason: string;
}
export interface TargetPackageRefreshProof {
    refreshedAt: string;
    linkedPackageKinds: string[];
    linkedPackageDigests: Array<{
        id: string;
        kind: string;
        digest: string;
        reportReady: boolean;
    }>;
    stalePackageIds: string[];
    freshDigest: string;
    sourceRouteCount?: number;
    sourceInsertionPointCount?: number;
    sourceRoleCount?: number;
    sourceCandidateCount?: number;
    rawMaterialDigestPreview?: string;
}
export interface TargetContentDiscoveryHandoff {
    id: string;
    createdAt: string;
    hostCount: number;
    candidateCount: number;
    wordlistProfile: string;
    throttleMs: number;
    scopeSummary: string;
    candidates: TargetContentDiscoveryCandidate[];
    packageRefreshProof?: TargetPackageRefreshProof;
    requirements?: {
        packageRefreshCovered: boolean;
        scopeAndThrottleCovered: boolean;
        candidateDiversityCovered: boolean;
        reportPhaseOnlyRedaction: boolean;
    };
    summary: string;
}
export type TargetAccessControlExpectation = 'visible' | 'denied' | 'hidden';
export type TargetAccessControlObservation = 'visible' | 'denied' | 'hidden' | 'unknown';
export type TargetAccessControlDrift = 'none' | 'overexposed' | 'underexposed' | 'missing-observation';
export interface TargetAccessControlRouteDecision {
    id: string;
    role: string;
    routeId: string;
    route: string;
    method: string;
    host: string;
    path: string;
    expected: TargetAccessControlExpectation;
    observed: TargetAccessControlObservation;
    observedStatus?: number;
    drift: TargetAccessControlDrift;
    severity: Severity;
    evidence: string;
    exchangeIds: string[];
}
export interface TargetAccessControlReviewLane {
    id: string;
    role: string;
    routeCount: number;
    visibleRouteCount?: number;
    deniedRouteCount?: number;
    hiddenRouteCount?: number;
    driftCount?: number;
    overexposedCount?: number;
    underexposedCount?: number;
    missingObservationCount?: number;
    riskyRoutes: string[];
    routeDecisions?: TargetAccessControlRouteDecision[];
    expectedVisibility: string;
    reviewAction: string;
    severity: Severity;
    evidenceSummary?: string;
    capturedAt?: string;
    packageRefreshProof?: TargetPackageRefreshProof;
    requirements?: {
        packageRefreshCovered: boolean;
        roleObservationCovered: boolean;
        driftClassificationCovered: boolean;
        rawExchangeLinksCovered: boolean;
        reportPhaseOnlyRedaction: boolean;
    };
}
export interface TargetRouteFindingOverlay {
    id: string;
    title: string;
    severity: Severity;
    host: string;
    path: string;
    status: string;
    source: 'issue' | 'activity' | 'crawler' | 'scanner';
}
export interface TargetSiteMapAnalysisPackage {
    id: string;
    title: string;
    fileName: string;
    path: string;
    createdAt: string;
    reportReady: boolean;
    routeCount: number;
    hostCount: number;
    insertionPointCount: number;
    technologyInventory: TargetTechnologyInsight[];
    parameterInventory: TargetParameterInsight[];
    contentDiscoveryHandoff: TargetContentDiscoveryHandoff;
    accessControlReview: TargetAccessControlReviewLane[];
    overlays: TargetRouteFindingOverlay[];
    packageRefreshProof?: TargetPackageRefreshProof;
    requirements?: {
        contentDiscoveryPackageRefreshCovered: boolean;
        accessControlPackageRefreshCovered: boolean;
        inventoryPackageRefreshCovered: boolean;
        reportPhaseOnlyRedaction: boolean;
    };
    summary: string;
    content: string;
}
export interface TargetSiteMapComparisonDelta {
    id: string;
    kind: 'added' | 'removed' | 'changed';
    changeTypes?: Array<'status' | 'mime' | 'parameter' | 'method' | 'host' | 'authz' | 'technology' | 'visibility'>;
    route: string;
    severity: Severity;
    detail: string;
    baseline?: {
        status?: number;
        mime?: string;
        insertionPointCount?: number;
        host?: string;
        method?: string;
    };
    candidate?: {
        status?: number;
        mime?: string;
        insertionPointCount?: number;
        host?: string;
        method?: string;
    };
    affectedParameters?: string[];
    evidence?: string[];
}
export interface TargetSiteMapComparisonPackage {
    id: string;
    title: string;
    fileName: string;
    path: string;
    createdAt: string;
    reportReady: boolean;
    baselineName: string;
    candidateName: string;
    baselineRouteCount: number;
    candidateRouteCount: number;
    added: number;
    removed: number;
    changed: number;
    statusChanged?: number;
    mimeChanged?: number;
    parameterChanged?: number;
    authzSensitiveChanged?: number;
    highRiskDeltaCount?: number;
    hostDeltaCount?: number;
    normalization?: string[];
    digestPreview: string;
    deltas: TargetSiteMapComparisonDelta[];
    packageRefreshProof?: TargetPackageRefreshProof;
    requirements?: {
        packageRefreshCovered: boolean;
        baselineCandidateCovered: boolean;
        deltaEvidenceCovered: boolean;
        reportPhaseOnlyRedaction: boolean;
    };
    summary: string;
    content: string;
}
export interface TargetSiteMapEvidenceAttachment {
    id: string;
    title: string;
    fileName: string;
    path: string;
    createdAt: string;
    reportReady: boolean;
    issueId?: string;
    analysisPackageId?: string;
    comparisonPackageId?: string;
    packageRefreshProof?: TargetPackageRefreshProof;
    requirements?: {
        packageRefreshCovered: boolean;
        analysisPackageLinked: boolean;
        comparisonPackageLinked: boolean;
        reportPhaseOnlyRedaction: boolean;
    };
    summary: string;
    content: string;
}
export type BrowserClientSignalKind = 'dom-source' | 'dom-sink' | 'web-message' | 'prototype-source' | 'prototype-gadget' | 'dom-clobbering';
export type BrowserClientInstrumentationKind = 'fetch' | 'xhr' | 'websocket' | 'storage';
export type BrowserClientRouteSource = 'dom-route' | 'script-route' | 'source-map';
export interface BrowserClientSignal {
    id: string;
    kind: BrowserClientSignalKind;
    name: string;
    location: string;
    controllable: boolean;
    sanitizer: 'none' | 'html-encoded' | 'url-encoded' | 'json-stringified' | 'unknown';
    evidence: string;
}
export interface BrowserClientInstrumentationEvent {
    id: string;
    kind: BrowserClientInstrumentationKind;
    method?: string;
    url?: string;
    storageKey?: string;
    origin?: string;
    summary: string;
}
export interface BrowserClientRouteDiscovery {
    id: string;
    path: string;
    source: BrowserClientRouteSource;
    fileName: string;
    evidence: string;
}
export interface BrowserClientFinding {
    id: string;
    title: string;
    severity: Severity;
    confidence: Issue['confidence'];
    source: string;
    sink: string;
    route: string;
    summary: string;
    reportReady: boolean;
}
export interface BrowserClientAnalysisRun {
    id: string;
    routeId?: string;
    url: string;
    host: string;
    path: string;
    createdAt: string;
    canary: string;
    status: 'ready' | 'promoted';
    reportReady: boolean;
    sourcesAndSinks: BrowserClientSignal[];
    instrumentation: BrowserClientInstrumentationEvent[];
    routes: BrowserClientRouteDiscovery[];
    findings: BrowserClientFinding[];
    summary: string;
    content: string;
}
export interface BrowserWebMessageReplay {
    id: string;
    analysisId?: string;
    createdAt: string;
    url: string;
    origin: string;
    targetOrigin: string;
    payload: string;
    sink: string;
    status: 'ready' | 'replayed' | 'blocked';
    summary: string;
    evidence: string;
}
export interface BrowserPrototypeGadgetScan {
    id: string;
    analysisId?: string;
    createdAt: string;
    url: string;
    source: string;
    gadget: string;
    sink: string;
    status: 'candidate' | 'proof' | 'blocked';
    proof: string;
    summary: string;
    evidence: string;
}
export interface BrowserClientEvidencePackage {
    id: string;
    title: string;
    fileName: string;
    path: string;
    createdAt: string;
    analysisId: string;
    webMessageReplayId?: string;
    prototypeScanId?: string;
    issueId?: string;
    reportReady: boolean;
    summary: string;
    content: string;
}
export interface CrawlAuditRequest {
    scopeAllowlist: string[];
    checks: ActiveScanCheckId[];
    insertionPoints: CrawlInsertionPoint[];
    sessionHeaders?: Record<string, string>;
    throttleMs: number;
    maxInsertionPoints: number;
}
export interface CrawlAuditSummary extends ActiveScanSummary {
    auditedInsertionPoints: number;
}
export interface InterceptedRequest {
    id: string;
    direction: 'request' | 'response';
    method: string;
    host: string;
    path: string;
    url: string;
    status?: number;
    time: string;
    rawRequest: string;
    source: 'http' | 'https';
    tags: string[];
}
export interface InterceptDecision {
    id: string;
    action: 'forward' | 'drop';
    rawRequest?: string;
}
export interface Issue {
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
export interface IssueTriageOverride {
    issueId: string;
    status: Issue['status'];
    assignee: string;
    triageNote: string;
    updatedAt: string;
}
export interface ScannerAuditQueueItem {
    id: string;
    kind: 'passive' | 'active-scan' | 'crawl-audit' | 'authz-replay' | 'manual-review';
    label: string;
    target: string;
    status: 'queued' | 'running' | 'complete' | 'blocked';
    priority: Severity;
    requestCount: number;
    detail: string;
    createdAt: string;
    updatedAt: string;
}
export type ScannerRetestOutcome = 'fixed' | 'regressed' | 'still-vulnerable' | 'inconclusive' | 'blocked';
export interface ScannerRetestWorkflow {
    id: string;
    issueId: string;
    issueTitle: string;
    host: string;
    path: string;
    checkPackId: string;
    checkCount: number;
    baselineStatus: Issue['status'];
    outcome: ScannerRetestOutcome;
    startedAt: string;
    completedAt: string;
    sessionProfileName?: string;
    baselineExchangeId?: string;
    retestExchangeId?: string;
    evidenceDeltaId?: string;
    summary: string;
}
export interface ScannerIssueRule {
    id: string;
    name: string;
    createdAt: string;
    checkId: ActiveScanCheckId | 'all';
    severity: Severity;
    confidence: Issue['confidence'];
    action: 'raise' | 'lower' | 'suppress' | 'require-review';
    status: 'active' | 'draft';
    summary: string;
}
export interface ScannerEvidenceDelta {
    id: string;
    title: string;
    fileName: string;
    path: string;
    createdAt: string;
    issueId: string;
    issueTitle: string;
    host: string;
    issuePath: string;
    outcome: ScannerRetestOutcome;
    baselineStatus: Issue['status'];
    retestStatus: Issue['status'];
    severity: Severity;
    confidence: Issue['confidence'];
    baselineExchangeId?: string;
    retestExchangeId?: string;
    ruleIds: string[];
    reportReady: boolean;
    signature: {
        algorithm: 'HMAC-SHA256';
        signerName: string;
        keyId: string;
        status: 'signed' | 'ready-on-export';
        digestPreview: string;
    };
    summary: string;
    content: string;
}
export interface ScannerActiveScanPlan {
    id: string;
    title: string;
    fileName: string;
    path: string;
    createdAt: string;
    checkPackId: string;
    checkPackLabel: string;
    checkIds: ActiveScanCheckId[];
    targetUrl: string;
    targetHost: string;
    targetPath: string;
    scopeAllowlist: string[];
    throttleMs: number;
    maxRequests: number;
    sessionProfileName?: string;
    insertionPointCount: number;
    replayCandidateCount: number;
    reportReady: boolean;
    summary: string;
    content: string;
}
export interface ScannerInsertionPointReviewRow {
    id: string;
    label: string;
    type: CrawlInsertionPointType | 'replay' | 'selected-request';
    method: string;
    url: string;
    source: 'crawler' | 'replay' | 'selected-request';
    status: 'covered' | 'untested' | 'skipped' | 'duplicate';
    checks: ActiveScanCheckId[];
    reason: string;
}
export interface ScannerInsertionPointReview {
    id: string;
    title: string;
    fileName: string;
    path: string;
    createdAt: string;
    totalCount: number;
    coveredCount: number;
    untestedCount: number;
    skippedCount: number;
    duplicateCount: number;
    rows: ScannerInsertionPointReviewRow[];
    reportReady: boolean;
    summary: string;
    content: string;
}
export interface ScannerAuthenticatedStateMatrixRow {
    id: string;
    route: string;
    baselineRole: string;
    alternateRole: string;
    baselineStatus?: number;
    alternateStatus?: number;
    baselineExchangeId?: string;
    alternateExchangeId?: string;
    delta: 'same' | 'status-drift' | 'privilege-drift' | 'missing-baseline' | 'missing-alternate';
    risk: Severity;
    checks: ActiveScanCheckId[];
    summary: string;
}
export interface ScannerAuthenticatedStateMatrix {
    id: string;
    title: string;
    fileName: string;
    path: string;
    createdAt: string;
    baselineProfileName: string;
    alternateProfileName: string;
    rowCount: number;
    driftCount: number;
    highRiskCount: number;
    rows: ScannerAuthenticatedStateMatrixRow[];
    reportReady: boolean;
    summary: string;
    content: string;
}
export interface ScannerReplayCheckPackage {
    id: string;
    title: string;
    fileName: string;
    path: string;
    createdAt: string;
    replaySource: 'repeater' | 'proxy-history' | 'scanner' | 'mixed';
    exchangeIds: string[];
    generatedChecks: ActiveScanCheckId[];
    replayDerivedCheckCount: number;
    authorizationCandidateCount: number;
    reportReady: boolean;
    summary: string;
    content: string;
}
export interface ScannerActiveScanEvidencePackage {
    id: string;
    kind: 'proxyforge-scanner-active-scan-evidence-package';
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
    rawExchangeSamples: Array<{
        id: string;
        method: string;
        host: string;
        path: string;
        status: number;
        source: HttpExchange['source'];
        tags: string[];
        requestRaw: string;
        responseRaw: string;
    }>;
    operationalSecretSignals: string[];
    findingStatusSummary: {
        total: number;
        severityCounts: Partial<Record<Severity, number>>;
        confidenceCounts: Partial<Record<ActiveScanFinding['confidence'], number>>;
        suppressedFindingCount: number;
        highestSeverity: Severity;
        affectedExchangeIds: string[];
    };
    reportAttachments: Array<{
        id: string;
        kind: 'active-scan-plan' | 'insertion-point-review' | 'authenticated-state-matrix' | 'replay-check-package' | 'active-scan-summary';
        artifactId: string;
        fileName: string;
        reportReady: boolean;
        redactionPhase: 'report-export-only';
    }>;
    requirements: {
        activeScanPlanLinked: boolean;
        insertionPointReviewLinked: boolean;
        authenticatedStateMatrixLinked: boolean;
        replayChecksLinked: boolean;
        ciHeadlessHandoffCovered: boolean;
        reportAttachmentsLinked: boolean;
        issueConfidencePreserved: boolean;
        rawExchangeSamplesPreserved: boolean;
        operationalSecretsPreserved: boolean;
        reportPhaseOnlyRedaction: boolean;
    };
    secretHandling: 'execution-full-fidelity-secrets-preserved';
    reportRedactionBoundary: 'redact-only-during-report-export';
    reportReady: boolean;
    summary: string;
    content: string;
}
export interface ScannerLiveTargetProfilePackage {
    id: string;
    kind: 'proxyforge-scanner-live-target-profile-package';
    title: string;
    fileName: string;
    path: string;
    generatedAt: string;
    targetUrlCount: number;
    targetHostCount: number;
    routeCount: number;
    statusClasses: string[];
    totalRequests: number;
    findingCount: number;
    suppressedFindingCount: number;
    checkCoverage: ActiveScanCheckId[];
    tuningProfiles: string[];
    falsePositiveControls: string[];
    packageRefreshProof: {
        refreshedAt: string;
        linkedPackageIds: string[];
        linkedPackageKinds: string[];
        linkedPackageDigests: Array<{
            id: string;
            kind: string;
            digest: string;
            reportReady: boolean;
        }>;
        stalePackageIds: string[];
        freshDigest: string;
    };
    requirements: {
        liveTargetDiversityCovered: boolean;
        checkPackDepthCovered: boolean;
        longRunningTuningCovered: boolean;
        passiveDedupeCovered: boolean;
        insertionInventoryCovered: boolean;
        anvilCompatibilityCovered: boolean;
        oastPromotionCovered: boolean;
        retestEvidenceCovered: boolean;
        reportAttachmentScaleCovered: boolean;
        packageRefreshCovered: boolean;
        rawExecutorMaterialPreserved: boolean;
        operationalSecretsPreserved: boolean;
        reportPhaseOnlyRedaction: boolean;
    };
    operationalSecretSamples: string[];
    secretHandling: 'execution-full-fidelity-secrets-preserved';
    reportRedactionBoundary: 'redact-only-during-report-export';
    reportReady: boolean;
    summary: string;
    content: string;
}
export interface ScannerOastIssuePromotionPackage {
    id: string;
    kind: 'proxyforge-scanner-oast-issue-promotion-package';
    title: string;
    fileName: string;
    path: string;
    createdAt: string;
    projectName: string;
    issue: Issue;
    finding?: Partial<ActiveScanFinding>;
    sourceExchangeId?: string;
    scannerExchangeId: string;
    callbackPayloadId: string;
    callbackInteractionId: string;
    dedupeKey: string;
    evidence: {
        sourceExchange?: {
            id?: string;
            method?: string;
            url?: string;
            host?: string;
            path?: string;
            requestRaw: string;
            responseRaw: string;
        };
        scannerExchange: {
            id?: string;
            method?: string;
            url?: string;
            host?: string;
            path?: string;
            status?: number;
            requestRaw: string;
            responseRaw: string;
        };
        callbackPayload: {
            id?: string;
            token?: string;
            protocol?: CallbackProtocol;
            endpoint?: string;
            sourceExchangeId?: string;
            sourceHost?: string;
            sourcePath?: string;
            status?: CallbackPayloadStatus;
            notes?: string;
        };
        callbackInteraction: {
            id?: string;
            payloadId?: string;
            protocol?: CallbackProtocol;
            observedAt?: string;
            sourceIp?: string;
            sourceHost?: string;
            requestLine?: string;
            userAgent?: string;
            raw: string;
            severity?: Severity;
            tags?: string[];
        };
    };
    reproductionSteps: string[];
    retestCommands: string[];
    reportAttachments: Array<{
        id: string;
        kind: 'source-exchange' | 'scanner-exchange' | 'callback-payload' | 'callback-interaction' | 'issue-draft';
        artifactId: string;
        reportReady: boolean;
        redactionPhase: 'report-export-only';
    }>;
    operationalSecretSignals: string[];
    requirements: {
        sourceExchangeLinked: boolean;
        scannerExchangeLinked: boolean;
        callbackPayloadLinked: boolean;
        callbackInteractionLinked: boolean;
        activeFindingLinked: boolean;
        oastTokenObserved: boolean;
        rawScannerRequestPreserved: boolean;
        rawScannerResponsePreserved: boolean;
        rawCallbackInteractionPreserved: boolean;
        issueDraftReady: boolean;
        dedupeKeyStable: boolean;
        reportAttachmentsLinked: boolean;
        operationalSecretsPreserved: boolean;
        reportPhaseOnlyRedaction: boolean;
    };
    secretHandling: 'execution-full-fidelity-secrets-preserved';
    reportRedactionBoundary: 'redact-only-during-report-export';
    reportReady: boolean;
    summary: string;
    content: string;
}
export type AnvilPhase = 'active' | 'passive' | 'unspecified';
export type AnvilRunScope = 'per-insertion-point' | 'per-request' | 'per-host' | 'per-path';
export type AnvilFixtureExpectation = 'match' | 'no-match';
export interface AnvilDefinition {
    id: string;
    name: string;
    language: 'v2-beta';
    createdAt: string;
    updatedAt: string;
    author: string;
    description: string;
    tags: string[];
    phase: AnvilPhase;
    runScope: AnvilRunScope;
    enabled: boolean;
    severity: Severity;
    confidence: Issue['confidence'];
    libraryId?: string;
    fixtureIds: string[];
    lastValidationRunId?: string;
    headlessRunIds: string[];
    packageReviewId?: string;
    reportReady: boolean;
    summary: string;
    source: string;
}
export interface AnvilRuleLibrary {
    id: string;
    name: string;
    description: string;
    createdAt: string;
    updatedAt: string;
    ruleIds: string[];
    tags: string[];
    trust: 'local' | 'imported' | 'signed';
    summary: string;
    content: string;
}
export interface AnvilFixture {
    id: string;
    checkId: string;
    name: string;
    createdAt: string;
    enabled: boolean;
    requestRaw: string;
    responseRaw: string;
    expected: AnvilFixtureExpectation;
    status: 'untested' | 'passed' | 'failed';
    summary: string;
    evidence: string;
}
export interface AnvilValidationFixtureResult {
    fixtureId: string;
    name: string;
    expected: AnvilFixtureExpectation;
    matched: boolean;
    status: 'passed' | 'failed';
    evidence: string;
}
export interface AnvilValidationRun {
    id: string;
    checkId: string;
    checkName: string;
    createdAt: string;
    status: 'passed' | 'failed' | 'blocked';
    fixtureCount: number;
    passedCount: number;
    failedCount: number;
    requestCount: number;
    issueCount: number;
    errorCount: number;
    auditItemCount: number;
    loggerCount: number;
    reportReady: boolean;
    summary: string;
    fixtureResults: AnvilValidationFixtureResult[];
    content: string;
}
export interface AnvilHeadlessRun {
    id: string;
    checkId: string;
    checkName: string;
    createdAt: string;
    targetUrl: string;
    status: 'complete' | 'blocked';
    requestCount: number;
    issueCount: number;
    auditItemCount: number;
    loggerCount: number;
    builtInChecksDisabled: boolean;
    extensionChecksDisabled: boolean;
    issueIds: string[];
    exchangeIds: string[];
    reportReady: boolean;
    summary: string;
    content: string;
}
export interface AnvilPackageReview {
    id: string;
    checkId: string;
    libraryId?: string;
    title: string;
    fileName: string;
    path: string;
    reviewedAt: string;
    status: 'trusted' | 'warning' | 'blocked';
    packageDigest: string;
    signature: {
        algorithm: 'HMAC-SHA256';
        signerName: string;
        keyId: string;
        status: 'verified' | 'unsigned' | 'mismatch';
        digestPreview: string;
    };
    reusableRuleCount: number;
    fixtureCount: number;
    findingCount: number;
    summary: string;
    content: string;
}
export interface ProxyStatus {
    running: boolean;
    port: number;
    mode: 'electron' | 'browser';
    message: string;
}
export interface CertificateAuthorityStatus {
    ready: boolean;
    rootCertificatePath: string;
    projectId: string;
    projectLabel: string;
    projectCertificateDir: string;
    fingerprintSha256?: string;
    validUntil?: string;
    hostCertificateCount: number;
    lastRotatedAt?: string;
    revokedAt?: string;
    message: string;
}
export interface CertificateAuthorityExport {
    pem: string;
    path: string;
    fingerprintSha256?: string;
}
export interface HttpsInspectionStatus {
    enabled: boolean;
    upstreamTlsMode: 'strict' | 'relaxed';
    message: string;
}
export interface InterceptStatus {
    enabled: boolean;
    responseEnabled: boolean;
    pendingCount: number;
    message: string;
}
export interface MatchReplaceRule {
    id: string;
    name: string;
    enabled: boolean;
    direction: 'request' | 'response' | 'both';
    match: string;
    replace: string;
    isRegex: boolean;
    caseSensitive: boolean;
}
export type ProxyHistoryStatusFilter = 'all' | '2xx' | '3xx' | '4xx' | '5xx' | 'errors' | 'has-params' | 'http2' | 'modified';
export type ProxyHistoryMethodFilter = 'all' | 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'OPTIONS' | 'CONNECT' | 'HEAD' | string;
export type ProxyHistorySourceFilter = 'all' | HttpExchange['source'];
export type ProxyHistoryRiskFilter = 'all' | Severity;
export interface ProxyHistoryFilter {
    query: string;
    method: ProxyHistoryMethodFilter;
    source: ProxyHistorySourceFilter;
    status: ProxyHistoryStatusFilter | string;
    risk: ProxyHistoryRiskFilter;
    mime: string;
    tag: string;
}
export interface ProxyHttp2ExchangeMetadata {
    detected: boolean;
    alpn: 'h2' | 'h2c' | 'unknown';
    streamId?: number;
    requestPseudoHeaders: Record<string, string>;
    responsePseudoHeaders: Record<string, string>;
    requestHeaderOrder: string[];
    responseHeaderOrder: string[];
    requestAuthority?: string;
    requestScheme?: string;
    requestPath?: string;
    responseStatus?: number;
    requestTrailerNames: string[];
    responseTrailerNames: string[];
    fidelityChecks: string[];
    warnings: string[];
}
export interface ProxyHistoryMetadata {
    id: string;
    exchangeId: string;
    method: string;
    host: string;
    path: string;
    status: number;
    source: HttpExchange['source'];
    risk: Severity;
    requestLine: string;
    responseLine: string;
    protocol: 'HTTP/2' | 'HTTP/1.1' | 'CONNECT' | 'unknown';
    tls: boolean;
    hasParameters: boolean;
    requestHeaderCount: number;
    responseHeaderCount: number;
    requestBytes: number;
    responseBytes: number;
    durationBucket: 'fast' | 'normal' | 'slow' | 'timeout';
    statusClass: string;
    annotationSummary: string;
    fingerprint: string;
    scannerReady: boolean;
    repeaterReady: boolean;
    modified: boolean;
    http2?: ProxyHttp2ExchangeMetadata;
}
export interface ProxyAnnotationLane {
    id: string;
    label: string;
    severity: Severity;
    exchangeIds: string[];
    count: number;
    summary: string;
}
export interface ProxyHistoryViewModel {
    id: string;
    title: string;
    summary: string;
    totalCount: number;
    filteredCount: number;
    hostCount: number;
    http2Count: number;
    modifiedCount: number;
    filters: ProxyHistoryFilter;
    rows: ProxyHistoryMetadata[];
    annotationLanes: ProxyAnnotationLane[];
    methodFacets: Record<string, number>;
    sourceFacets: Record<string, number>;
    statusFacets: Record<string, number>;
    riskFacets: Record<string, number>;
}
export interface ProxyHistorySavedFilterResult {
    id: string;
    label: string;
    filters: ProxyHistoryFilter;
    filterSummary: string;
    matchedExchangeIds: string[];
    matchedCount: number;
    unmatchedCount: number;
    facets: {
        methods: Record<string, number>;
        sources: Record<string, number>;
        statuses: Record<string, number>;
        risks: Record<string, number>;
    };
    annotationLaneCounts: Record<string, number>;
    sampleExchanges: Array<{
        exchangeId: string;
        method: string;
        host: string;
        path: string;
        status: number;
        risk: Severity;
        requestRaw: string;
        responseRaw: string;
        secretSignals: string[];
    }>;
}
export interface ProxyHistoryFilterSetPackage {
    id: string;
    kind: 'proxyforge-proxy-history-filter-set-package';
    title: string;
    fileName: string;
    path: string;
    createdAt: string;
    totalExchangeCount: number;
    savedFilterCount: number;
    unionMatchedExchangeIds: string[];
    intersectionMatchedExchangeIds: string[];
    unmatchedExchangeIds: string[];
    predicateCoverage: string[];
    secretSignalCount: number;
    savedFilters: ProxyHistorySavedFilterResult[];
    requirements: {
        savedPredicatesRoundTrip: boolean;
        advancedStatusPredicatesCovered: boolean;
        annotationLanesCovered: boolean;
        rawSamplesPreserved: boolean;
        operationalSecretsPreserved: boolean;
        reportPhaseOnlyRedaction: boolean;
    };
    secretHandling: 'execution-full-fidelity-secrets-preserved';
    reportReady: boolean;
    summary: string;
    content: string;
}
export interface ProxyInterceptRuleReviewRow {
    ruleId: string;
    name: string;
    direction: MatchReplaceRule['direction'];
    enabled: boolean;
    mode: 'regex' | 'literal';
    match: string;
    replacementPreview: string;
    affectedExchangeIds: string[];
    affectedCount: number;
    risk: Severity;
    notes: string;
}
export interface ProxyInterceptRuleReview {
    id: string;
    title: string;
    reviewedAt: string;
    ruleCount: number;
    activeRuleCount: number;
    riskyRuleCount: number;
    requestRuleCount: number;
    responseRuleCount: number;
    affectedExchangeCount: number;
    rules: ProxyInterceptRuleReviewRow[];
    recommendations: string[];
    reportReady: boolean;
    summary: string;
    content: string;
}
export interface ProxyCapturePresetHandoff {
    id: string;
    title: string;
    fileName: string;
    path: string;
    createdAt: string;
    presetName: string;
    filterSummary: string;
    exchangeIds: string[];
    includedSources: HttpExchange['source'][];
    reportReady: boolean;
    summary: string;
    content: string;
}
export interface ProxyTrafficComparisonDelta {
    id: string;
    route: string;
    method: string;
    host: string;
    path: string;
    state: 'added' | 'removed' | 'changed' | 'unchanged';
    baselineStatus?: number;
    candidateStatus?: number;
    baselineLength?: number;
    candidateLength?: number;
    risk: Severity;
    summary: string;
}
export interface ProxyTrafficComparisonPackage {
    id: string;
    title: string;
    fileName: string;
    path: string;
    createdAt: string;
    baselineName: string;
    candidateName: string;
    added: number;
    removed: number;
    changed: number;
    statusDrift: number;
    digestPreview: string;
    deltas: ProxyTrafficComparisonDelta[];
    reportReady: boolean;
    summary: string;
    content: string;
}
export type ProxyCrossToolHandoffDestination = 'repeater' | 'scanner' | 'reports';
export interface ProxyRepeaterHandoffRequest {
    exchangeId: string;
    tabName: string;
    group: string;
    targetUrl: string;
    rawRequest: string;
    sourceFingerprint: string;
    transportHints: string[];
    secretSignals: string[];
}
export interface ProxyScannerHandoffCandidate {
    exchangeId: string;
    issueId: string;
    method: string;
    host: string;
    path: string;
    status: number;
    risk: Severity;
    insertionPoints: string[];
    checkHints: string[];
    rawRequest: string;
    rawResponse: string;
    scannerReadyReason: string;
}
export interface ProxyReportHandoffAttachment {
    exchangeId: string;
    title: string;
    fileName: string;
    requestFingerprint: string;
    responseFingerprint: string;
    reportReady: boolean;
    redactionPhase: 'report-export-only';
}
export interface ProxyCrossToolHandoffPackage {
    id: string;
    kind: 'proxyforge-proxy-cross-tool-handoff-package';
    title: string;
    fileName: string;
    path: string;
    createdAt: string;
    exchangeIds: string[];
    destinations: ProxyCrossToolHandoffDestination[];
    repeaterRequests: ProxyRepeaterHandoffRequest[];
    scannerCandidates: ProxyScannerHandoffCandidate[];
    reportAttachments: ProxyReportHandoffAttachment[];
    issueId: string;
    requirements: {
        stableExchangeIds: boolean;
        repeaterRawRequestsPreserved: boolean;
        scannerCandidatesLinked: boolean;
        reportAttachmentsLinked: boolean;
        crossToolAuditTrail: boolean;
        operationalSecretsPreserved: boolean;
        reportPhaseOnlyRedaction: boolean;
    };
    secretHandling: 'execution-full-fidelity-secrets-preserved';
    reportReady: boolean;
    summary: string;
    content: string;
}
export interface ProxyHistoryEvidenceAttachment {
    id: string;
    title: string;
    fileName: string;
    path: string;
    createdAt: string;
    viewModelId?: string;
    ruleReviewId?: string;
    capturePresetId?: string;
    comparisonPackageId?: string;
    http2FidelityReportId?: string;
    http2MultiplexingReportId?: string;
    filterSetPackageId?: string;
    crossToolHandoffPackageId?: string;
    issueId?: string;
    exchangeIds: string[];
    reportReady: boolean;
    summary: string;
    content: string;
}
export interface ProxyHttp2FidelityExchange {
    exchangeId: string;
    method: string;
    host: string;
    path: string;
    status: number;
    protocol: ProxyHistoryMetadata['protocol'];
    alpn: ProxyHttp2ExchangeMetadata['alpn'];
    streamId?: number;
    requestPseudoHeaders: Record<string, string>;
    responsePseudoHeaders: Record<string, string>;
    requestTrailerNames: string[];
    responseTrailerNames: string[];
    fidelityChecks: string[];
    warnings: string[];
    summary: string;
}
export interface ProxyHttp2FidelityReport {
    id: string;
    title: string;
    fileName: string;
    path: string;
    createdAt: string;
    exchangeCount: number;
    http2ExchangeCount: number;
    pseudoHeaderExchangeCount: number;
    trailerExchangeCount: number;
    warningCount: number;
    exchanges: ProxyHttp2FidelityExchange[];
    reportReady: boolean;
    summary: string;
    content: string;
}
export interface ProxyHttp2ConnectionSummary {
    id: string;
    authority: string;
    scheme?: string;
    alpn: ProxyHttp2ExchangeMetadata['alpn'];
    exchangeIds: string[];
    streamIds: number[];
    reusedStreamIds: number[];
    methodCounts: Record<string, number>;
    statusCounts: Record<string, number>;
    headerOrderVariants: string[];
    trailerExchangeCount: number;
    warningCount: number;
    multiplexed: boolean;
    summary: string;
}
export interface ProxyHttp2MultiplexingReport {
    id: string;
    title: string;
    fileName: string;
    path: string;
    createdAt: string;
    exchangeCount: number;
    http2ExchangeCount: number;
    connectionCount: number;
    multiplexedConnectionCount: number;
    h2cExchangeCount: number;
    streamIdCoverage: number;
    connectionSummaries: ProxyHttp2ConnectionSummary[];
    requirements: {
        pseudoHeaderFidelity: boolean;
        streamIdCoverage: boolean;
        multiplexedConnectionGrouping: boolean;
        h2cOrAlpnCaptured: boolean;
        trailerMetadataPreserved: boolean;
        warningReviewReady: boolean;
    };
    reportReady: boolean;
    summary: string;
    content: string;
}
export interface ProxyEdgeProfilePackage {
    id: string;
    kind: 'proxyforge-proxy-edge-profile-package';
    title: string;
    fileName: string;
    path: string;
    generatedAt: string;
    hostCount: number;
    routeCount: number;
    statusClasses: string[];
    protocolCoverage: Array<ProxyHistoryMetadata['protocol'] | 'WebSocket'>;
    methodCoverage: string[];
    linkedPackageIds: string[];
    packageRefreshProof: {
        refreshedAt: string;
        linkedPackageKinds: string[];
        linkedPackageDigests: Array<{
            id: string;
            kind: string;
            digest: string;
            reportReady: boolean;
        }>;
        stalePackageIds: string[];
        freshDigest: string;
    };
    requirements: {
        httpListenerCaptureCovered: boolean;
        connectTunnelCovered: boolean;
        httpsMitmCovered: boolean;
        interceptControlsCovered: boolean;
        matchReplaceCovered: boolean;
        http2FidelityCovered: boolean;
        crossToolHandoffCovered: boolean;
        websocketEdgeCovered: boolean;
        browserProxyChainCovered: boolean;
        packageRefreshCovered: boolean;
        rawExecutorMaterialPreserved: boolean;
        operationalSecretsPreserved: boolean;
        reportPhaseOnlyRedaction: boolean;
    };
    operationalSecretSamples: string[];
    secretHandling: 'execution-full-fidelity-secrets-preserved';
    reportRedactionBoundary: 'redact-only-during-report-export';
    reportReady: boolean;
    summary: string;
    content: string;
}
export interface ProxyBrowserProxyChainProfile {
    id: string;
    platform: 'linux' | 'windows';
    browserFamily: 'chromium' | 'chrome' | 'edge' | 'firefox';
    profilePath: string;
    proxyMode: 'direct' | 'upstream-http' | 'upstream-auth' | 'connect-chain' | 'pac';
    certificateMode: 'project-ca' | 'trusted-ca' | 'manual-import' | 'pinned-nonblocking';
    protocolCoverage: Array<ProxyHistoryMetadata['protocol'] | 'CONNECT' | 'WebSocket'>;
    hostCount: number;
    routeCount: number;
    capturedHttp: boolean;
    capturedHttpsMitm: boolean;
    capturedConnect: boolean;
    capturedHttp2: boolean;
    capturedWebSocket: boolean;
    upstreamProxyHost?: string;
    upstreamProxyAuthorization?: string;
    isolatedProfile: boolean;
    cookieStoreCovered: boolean;
    rawRequestSample: string;
    rawResponseSample: string;
}
export interface ProxyBrowserProxyChainDiversityPackage {
    id: string;
    kind: 'proxyforge-proxy-browser-proxy-chain-diversity-package';
    title: string;
    fileName: string;
    path: string;
    generatedAt: string;
    profileCount: number;
    browserFamilies: string[];
    platforms: string[];
    proxyModes: string[];
    certificateModes: string[];
    hostCount: number;
    routeCount: number;
    requirements: {
        multiBrowserFamilyCovered: boolean;
        linuxWindowsProfileCoverage: boolean;
        proxyChainModeDiversityCovered: boolean;
        httpsMitmTrustModesCovered: boolean;
        connectHttp2WebSocketCovered: boolean;
        isolatedProfileAndCookieStoresCovered: boolean;
        upstreamCredentialPreservationCovered: boolean;
        edgeProfileLinked: boolean;
        packageRefreshCovered: boolean;
        rawExecutorMaterialPreserved: boolean;
        operationalSecretsPreserved: boolean;
        reportPhaseOnlyRedaction: boolean;
    };
    linkedEdgeProfileId: string;
    profiles: ProxyBrowserProxyChainProfile[];
    packageRefreshProof: {
        refreshedAt: string;
        linkedPackageKinds: string[];
        linkedPackageDigests: Array<{
            id: string;
            kind: string;
            digest: string;
            reportReady: boolean;
        }>;
        stalePackageIds: string[];
        freshDigest: string;
    };
    secretHandling: 'execution-full-fidelity-secrets-preserved';
    reportRedactionBoundary: 'redact-only-during-report-export';
    reportReady: boolean;
    summary: string;
    content: string;
}
export interface WebSocketMessage {
    id: string;
    connectionId: string;
    time: string;
    direction: 'client' | 'server';
    host: string;
    path: string;
    url: string;
    opcode: number;
    type: 'text' | 'binary' | 'close' | 'ping' | 'pong' | 'other';
    payload: string;
    payloadEncoding?: 'text' | 'hex' | 'base64';
    length: number;
    tags: string[];
}
export interface WebSocketInterceptStatus {
    enabled: boolean;
    clientEnabled?: boolean;
    serverEnabled?: boolean;
    pendingCount: number;
    message: string;
}
export interface WebSocketInterceptSettings {
    enabled: boolean;
    clientEnabled: boolean;
    serverEnabled: boolean;
}
export interface WebSocketFrameDecision {
    id: string;
    action: 'forward' | 'drop';
    payload?: string;
    payloadEncoding?: 'text' | 'hex' | 'base64';
    opcode?: number;
}
export interface WebSocketReplayRequest {
    connectionId: string;
    direction: 'client' | 'server';
    payload: string;
    payloadEncoding?: 'text' | 'hex' | 'base64';
    opcode?: number;
}
export interface WebSocketSavedReplay {
    id: string;
    name: string;
    connectionId: string;
    direction: 'client' | 'server';
    host: string;
    path: string;
    url: string;
    opcode: number;
    type: WebSocketMessage['type'];
    payload: string;
    payloadEncoding?: 'text' | 'hex' | 'base64';
    createdAt: string;
    updatedAt: string;
    tags: string[];
}
export interface WebSocketFrameRewriteRule {
    id: string;
    name: string;
    enabled: boolean;
    direction: 'client' | 'server' | 'both';
    frameType: WebSocketMessage['type'] | 'both';
    match: string;
    replace: string;
    isRegex: boolean;
    caseSensitive: boolean;
}
export interface WebSocketConnectionNotebook {
    id: string;
    name: string;
    connectionId: string;
    host: string;
    path: string;
    url: string;
    notes: string;
    pinnedFrameIds: string[];
    frameCount: number;
    tags: string[];
    createdAt: string;
    updatedAt: string;
}
export interface WebSocketAnomalyCluster {
    id: string;
    createdAt: string;
    connectionId: string;
    host: string;
    path: string;
    title: string;
    severity: Severity;
    confidence: Issue['confidence'];
    frameIds: string[];
    frameCount: number;
    clientFrames: number;
    serverFrames: number;
    binaryFrames: number;
    replayFrames: number;
    rewrittenFrames: number;
    privilegedHints: string[];
    detail: string;
    recommendation: string;
}
export interface WebSocketConnectionClusterSummary {
    id: string;
    createdAt: string;
    title: string;
    severity: Severity;
    confidence: Issue['confidence'];
    hosts: string[];
    paths: string[];
    connectionIds: string[];
    frameIds: string[];
    connectionCount: number;
    frameCount: number;
    clientFrames: number;
    serverFrames: number;
    binaryFrames: number;
    replayFrames: number;
    rewrittenFrames: number;
    closeFrames: number;
    privilegedHints: string[];
    sharedStates: string[];
    summary: string;
    recommendation: string;
}
export interface WebSocketFuzzProbeResult {
    id: string;
    name: string;
    mutation: string;
    direction: WebSocketMessage['direction'];
    payload: string;
    payloadEncoding?: WebSocketMessage['payloadEncoding'];
    opcode: number;
    outcome: 'accepted' | 'blocked' | 'state-drift' | 'closed' | 'error';
    severity: Severity;
    closeCode?: number;
    closeReason?: string;
    stateBefore: string;
    stateAfter: string;
    diffSummary: string;
    requestFrameId: string;
    responseFrameId: string;
}
export interface WebSocketSequenceFuzzRun {
    id: string;
    createdAt: string;
    sourceFrameId: string;
    connectionId: string;
    host: string;
    path: string;
    url: string;
    baselineState: string[];
    totalProbes: number;
    acceptedProbes: number;
    closedProbes: number;
    stateDriftProbes: number;
    highValueProbes: number;
    probes: WebSocketFuzzProbeResult[];
    summary: string;
    recommendation: string;
}
export interface WebSocketCloseCodeInsight {
    id: string;
    connectionId: string;
    host: string;
    path: string;
    code: number;
    reason: string;
    severity: Severity;
    count: number;
    frameIds: string[];
    detail: string;
    recommendation: string;
}
export interface WebSocketStateMachineDiff {
    id: string;
    connectionId: string;
    host: string;
    path: string;
    severity: Severity;
    baselineStates: string[];
    observedStates: string[];
    addedTransitions: string[];
    missingTransitions: string[];
    privilegedTransitions: string[];
    frameIds: string[];
    summary: string;
    recommendation: string;
}
export interface WebSocketStateGraphNode {
    id: string;
    label: string;
    kind: 'baseline' | 'observed' | 'privileged' | 'close';
    count: number;
    frameIds: string[];
}
export interface WebSocketStateGraphEdge {
    id: string;
    from: string;
    to: string;
    label: string;
    kind: 'baseline' | 'added' | 'missing' | 'privileged';
    count: number;
    frameIds: string[];
}
export interface WebSocketStateGraph {
    id: string;
    connectionId: string;
    host: string;
    path: string;
    nodes: WebSocketStateGraphNode[];
    edges: WebSocketStateGraphEdge[];
    totalNodeCount: number;
    totalEdgeCount: number;
    truncatedNodeCount: number;
    truncatedEdgeCount: number;
    summary: string;
}
export interface WebSocketStateGraphExportArtifact {
    id: string;
    title: string;
    fileName: string;
    filePath: string;
    createdAt: string;
    graphId: string;
    connectionId: string;
    host: string;
    path: string;
    format: 'png' | 'svg';
    nodeCount: number;
    edgeCount: number;
    totalNodeCount?: number;
    totalEdgeCount?: number;
    truncatedNodeCount?: number;
    truncatedEdgeCount?: number;
    frameCount: number;
    sizeBytes: number;
    content?: string;
}
export interface WebSocketReplayDelta {
    id: string;
    fuzzRunId: string;
    probeId: string;
    title: string;
    severity: Severity;
    outcome: WebSocketFuzzProbeResult['outcome'];
    baselinePayload: string;
    replayPayload: string;
    responsePayload: string;
    similarity: number;
    changedLines: number;
    unifiedDiff: string;
    summary: string;
}
export interface WebSocketTranscriptExport {
    id: string;
    title: string;
    fileName: string;
    filePath: string;
    createdAt: string;
    connectionId: string;
    host: string;
    path: string;
    format: 'markdown' | 'json';
    frameCount: number;
    fuzzRunIds: string[];
    stateDiffIds: string[];
    closeCodeCount: number;
    sizeBytes: number;
    content: string;
}
export interface WebSocketRestoredTranscriptFrame extends WebSocketMessage {
    transcriptId: string;
    originalFrameId?: string;
    restoredAt: string;
    sourceFormat: WebSocketTranscriptExport['format'];
}
export type WebSocketTranscriptImportResult = WebSocketTranscriptExport;
export type CallbackProtocol = 'dns' | 'http' | 'smtp';
export type CallbackPayloadStatus = 'waiting' | 'observed' | 'archived';
export interface CallbackPayload {
    id: string;
    token: string;
    label: string;
    protocol: CallbackProtocol;
    endpoint: string;
    createdAt: string;
    status: CallbackPayloadStatus;
    sourceExchangeId?: string;
    sourceHost?: string;
    sourcePath?: string;
    lastInteractionAt?: string;
    notes: string;
}
export interface CallbackInteraction {
    id: string;
    payloadId: string;
    protocol: CallbackProtocol;
    observedAt: string;
    sourceIp: string;
    sourceHost: string;
    requestLine: string;
    userAgent: string;
    raw: string;
    severity: Severity;
    tags: string[];
}
export interface CallbackWorkspace {
    id: string;
    name: string;
    createdAt: string;
    updatedAt: string;
    owner: string;
    payloadIds: string[];
    interactionIds: string[];
    sourceExchangeIds: string[];
    linkedIssueIds: string[];
    linkedExploitRunIds: string[];
    protocols: CallbackProtocol[];
    severity: Severity;
    status: 'monitoring' | 'confirmed' | 'archived';
    signedEvidencePackageId?: string;
    notes: string;
}
export interface CallbackEvidencePackage {
    id: string;
    title: string;
    fileName: string;
    path: string;
    exportedAt: string;
    workspaceId?: string;
    owner: string;
    reportReady: boolean;
    attachedAt?: string;
    reportSection?: ReportSection;
    payloadIds: string[];
    interactionIds: string[];
    issueIds: string[];
    exploitRunIds: string[];
    signature: {
        algorithm: 'HMAC-SHA256';
        signerName: string;
        keyId: string;
        status: 'signed' | 'ready-on-export';
        digestPreview: string;
    };
    summary: string;
    content: string;
}
export type CallbackListenerMode = 'browser-preview' | 'local-http' | 'local-dns' | 'local-smtp' | 'hybrid-local';
export type CallbackListenerStatus = 'planned' | 'running' | 'stopped' | 'blocked';
export type CallbackCiProvider = 'github-actions' | 'gitlab-ci' | 'azure-pipelines' | 'jenkins';
export interface CallbackListenerProfile {
    id: string;
    name: string;
    createdAt: string;
    mode: CallbackListenerMode;
    status: CallbackListenerStatus;
    host: string;
    publicBaseUrl: string;
    protocols: CallbackProtocol[];
    httpPort: number;
    dnsPort: number;
    smtpPort: number;
    pollIntervalSeconds: number;
    retentionHours: number;
    signingKeyId: string;
    ciCommand: string;
    healthChecks: string[];
    deploymentPlan?: {
        kind: 'proxyforge-callback-relay-deployment-plan';
        publicBaseUrl: string;
        protocols: CallbackProtocol[];
        dnsRecords: string[];
        routes: string[];
        healthChecks: string[];
        retentionHours: number;
        secretStorageRef: string;
    };
    secretStorage?: {
        kind: 'proxyforge-callback-secret-storage-plan';
        mode: 'local-encrypted' | 'os-keychain' | 'ci-secret' | 'external-vault';
        signingKeyId: string;
        secretRef: string;
        rotationDays: number;
        operationalSecretPolicy: 'full-fidelity-until-reporting';
    };
    summary: string;
    content: string;
}
export interface CallbackListenerRuntimeStatus {
    profileId: string;
    running: boolean;
    mode: CallbackListenerMode;
    host: string;
    protocols: CallbackProtocol[];
    ports: Partial<Record<CallbackProtocol, number>>;
    interactionCount: number;
    retentionHours?: number;
    retentionPrunedCount?: number;
    startedAt?: string;
    stoppedAt?: string;
    healthChecks: string[];
    message: string;
}
export interface CallbackListenerPollResult {
    status: CallbackListenerRuntimeStatus;
    interactions: CallbackInteraction[];
    newInteractionIds: string[];
}
export interface CallbackSignedPollBatch {
    id: string;
    title: string;
    createdAt: string;
    listenerProfileId: string;
    payloadIds: string[];
    interactionIds: string[];
    newInteractionIds: string[];
    scannerIssueIds: string[];
    exploitRunIds: string[];
    status: 'no-new-interactions' | 'observed' | 'blocked';
    reportReady: boolean;
    signature: {
        algorithm: 'HMAC-SHA256';
        signerName: string;
        keyId: string;
        status: 'signed' | 'ready-on-export';
        digestPreview: string;
    };
    summary: string;
    content: string;
}
export interface CallbackCorrelationReplayPackage {
    id: string;
    title: string;
    createdAt: string;
    payloadId?: string;
    listenerProfileId?: string;
    interactionIds: string[];
    scannerIssueIds: string[];
    exploitRunIds: string[];
    sourceExchangeId?: string;
    targetTool: 'scanner' | 'exploit-lab' | 'repeater' | 'reports';
    replayRequestRaw: string;
    severity: Severity;
    reportReady: boolean;
    summary: string;
    content: string;
}
export type CallbackReplayExecutionMode = 'dry-run' | 'local-verified' | 'live';
export type CallbackReplayExecutionStatus = 'completed' | 'partial' | 'blocked' | 'failed';
export interface CallbackReplayExecutionResult {
    id: string;
    replayPackageId: string;
    targetTool: CallbackCorrelationReplayPackage['targetTool'];
    status: CallbackReplayExecutionStatus;
    command: string;
    requestDigestPreview: string;
    sourceExchangeId?: string;
    sourceHost?: string;
    interactionIds: string[];
    scannerIssueIds: string[];
    exploitRunIds: string[];
    verification: {
        scopeMatched: boolean;
        replayRequestReady: boolean;
        callbackInjected: boolean;
        observedInteractionsMatched: boolean;
        scannerIssueLinked: boolean;
        exploitRunLinked: boolean;
        reportReady: boolean;
    };
    evidence: string[];
    summary: string;
}
export interface CallbackReplayExecutionBatch {
    id: string;
    title: string;
    createdAt: string;
    mode: CallbackReplayExecutionMode;
    listenerProfileId?: string;
    replayPackageIds: string[];
    status: CallbackReplayExecutionStatus;
    completedCount: number;
    blockedCount: number;
    failedCount: number;
    verifiedCount: number;
    reportReady: boolean;
    targetResults: CallbackReplayExecutionResult[];
    summary: string;
    content: string;
}
export interface CallbackPayloadLifecycleReview {
    id: string;
    title: string;
    createdAt: string;
    listenerProfileId?: string;
    retentionHours: number;
    observedPayloadIds: string[];
    waitingPayloadIds: string[];
    archivedPayloadIds: string[];
    stalePayloadIds: string[];
    expiredPayloadIds?: string[];
    expiredInteractionIds?: string[];
    retainedPayloadIds?: string[];
    retainedInteractionIds?: string[];
    recommendedArchiveIds: string[];
    retentionActionCount?: number;
    pruneSummary?: string;
    reportReady: boolean;
    summary: string;
    content: string;
}
export interface CallbackCiHandoffPackage {
    id: string;
    title: string;
    fileName: string;
    path: string;
    createdAt: string;
    listenerProfileId?: string;
    workspaceId?: string;
    provider: CallbackCiProvider;
    command: string;
    env: Record<string, string>;
    payloadIds: string[];
    interactionIds: string[];
    reportReady: boolean;
    summary: string;
    content: string;
}
export interface CallbackPublicRelaySoakPackage {
    id: string;
    title: string;
    fileName: string;
    path: string;
    createdAt: string;
    listenerProfileId?: string;
    workspaceId?: string;
    publicBaseUrl: string;
    protocols: CallbackProtocol[];
    payloadIds: string[];
    interactionIds: string[];
    signedPollBatchIds: string[];
    replayExecutionBatchIds: string[];
    lifecycleReviewIds: string[];
    ciHandoffPackageIds: string[];
    payloadCount: number;
    interactionCount: number;
    observedProtocolCount: number;
    rawInteractionBytes: number;
    retentionHours: number;
    relayHealthChecks: string[];
    dnsRecords: string[];
    routes: string[];
    secretStorageRef?: string;
    status: 'pass' | 'warning' | 'fail';
    warnings: string[];
    reportReady: boolean;
    secretHandling: 'execution-full-fidelity-secrets-preserved';
    summary: string;
    content: string;
}
export interface CallbackExternalRelayTenantPoll {
    tenantId: string;
    relayBaseUrl: string;
    publicBaseUrl: string;
    payloadIds: string[];
    interactionIds: string[];
    statusCode: number;
    rawRequest: string;
    rawResponse: string;
    interactions: CallbackInteraction[];
    signature: {
        algorithm: 'HMAC-SHA256';
        keyId: string;
        status: 'signed' | 'invalid' | 'missing';
        digestPreview: string;
    };
    isolationStatus: 'isolated' | 'leaked' | 'blocked';
    warnings: string[];
}
export interface CallbackExternalRelayIntegrationPackage {
    id: string;
    kind: 'proxyforge-callback-external-relay-integration-package';
    title: string;
    fileName: string;
    path: string;
    createdAt: string;
    listenerProfileId?: string;
    publicBaseUrl: string;
    relayBaseUrl: string;
    tenantCount: number;
    payloadCount: number;
    interactionCount: number;
    observedProtocolCount: number;
    tenantPolls: CallbackExternalRelayTenantPoll[];
    leakedInteractionIds: string[];
    status: 'pass' | 'warning' | 'fail';
    reportReady: boolean;
    secretHandling: 'execution-full-fidelity-secrets-preserved';
    reportRedactionBoundary: 'redact-only-during-report-export';
    summary: string;
    content: string;
}
export type CallbackExternalOastProviderKind = 'generic-http-relay' | 'dns-webhook-relay' | 'smtp-relay' | 'oast-compatible';
export interface CallbackExternalOastProviderProbe {
    id: string;
    providerId: string;
    providerName: string;
    providerKind: CallbackExternalOastProviderKind;
    tenantId: string;
    baseUrl: string;
    publicBaseUrl: string;
    protocol: CallbackProtocol;
    payloadIds: string[];
    interactionIds: string[];
    statusCode: number;
    rawRequest: string;
    rawResponse: string;
    interactions: CallbackInteraction[];
    signature: {
        algorithm: 'HMAC-SHA256';
        keyId: string;
        status: 'signed' | 'invalid' | 'missing';
        digestPreview: string;
    };
    isolationStatus: 'isolated' | 'leaked' | 'blocked';
    replaySupported: boolean;
    warnings: string[];
}
export interface CallbackExternalOastProviderDiversityPackage {
    id: string;
    kind: 'proxyforge-callback-external-oast-provider-diversity-package';
    title: string;
    fileName: string;
    path: string;
    createdAt: string;
    listenerProfileId?: string;
    providerCount: number;
    providerKinds: CallbackExternalOastProviderKind[];
    protocolCount: number;
    payloadCount: number;
    interactionCount: number;
    providerProbes: CallbackExternalOastProviderProbe[];
    leakedInteractionIds: string[];
    linkedRelayIntegrationPackageIds: string[];
    status: 'pass' | 'warning' | 'fail';
    reportReady: boolean;
    secretHandling: 'execution-full-fidelity-secrets-preserved';
    reportRedactionBoundary: 'redact-only-during-report-export';
    summary: string;
    content: string;
}
export interface CallbackReportRoundTripPackage {
    id: string;
    kind: 'proxyforge-callback-report-roundtrip-package';
    title: string;
    fileName: string;
    path: string;
    createdAt: string;
    reportPackageKind: string;
    reportPackageSignatureStatus: string;
    artifactManifest: {
        signedPollBatchIds: string[];
        correlationReplayIds: string[];
        replayExecutionBatchIds: string[];
        lifecycleReviewIds: string[];
        ciHandoffPackageIds: string[];
        publicRelaySoakPackageIds: string[];
        externalRelayIntegrationPackageIds: string[];
        externalProviderDiversityPackageIds: string[];
        evidencePackageIds: string[];
        totalArtifactCount: number;
        importedArtifactCount: number;
        rawArtifactBytes: number;
        reportPackageBytes: number;
        exportedReportBytes: number;
    };
    importedArtifactIds: string[];
    missingArtifactIds: string[];
    operationalSecretSamples: string[];
    requirements: {
        signedPollsPreserved: boolean;
        correlationReplaysPreserved: boolean;
        replayExecutionsPreserved: boolean;
        lifecycleReviewsPreserved: boolean;
        ciHandoffsPreserved: boolean;
        publicRelaySoaksPreserved: boolean;
        externalRelayIntegrationsPreserved: boolean;
        externalProviderDiversityPreserved: boolean;
        reportPackageImportCovered: boolean;
        operationalSecretsPreservedBeforeExport: boolean;
        reportExportRedacted: boolean;
        reportPhaseOnlyRedaction: boolean;
    };
    status: 'pass' | 'warning' | 'fail';
    reportReady: boolean;
    secretHandling: 'execution-full-fidelity-secrets-preserved';
    reportRedactionBoundary: 'redact-only-during-report-export';
    summary: string;
    content: string;
}
export type ExtensionPermission = 'read-traffic' | 'modify-traffic' | 'create-issues' | 'run-automations' | 'callback-access';
export type ExtensionHook = 'passive-scan' | 'request-editor' | 'response-editor' | 'message-editor' | 'scanner-check' | 'intruder-payload' | 'traffic-enrichment' | 'report-transform' | 'headless-runner';
export type ExtensionTrustLevel = 'built-in' | 'verified' | 'local';
export interface ExtensionCatalogItem {
    id: string;
    name: string;
    author: string;
    version: string;
    category: 'scanner' | 'editor' | 'reporting' | 'automation' | 'analysis';
    description: string;
    hooks: ExtensionHook[];
    permissions: ExtensionPermission[];
    trustLevel: ExtensionTrustLevel;
    dependencies?: ExtensionDependency[];
}
export type ExtensionSandboxActionKind = 'tag' | 'note' | 'request-header' | 'response-header' | 'request-response-annotation' | 'request-listener' | 'response-listener' | 'proxy-listener' | 'issue' | 'scanner-check' | 'scanner-insertion-point-provider' | 'editor-tab' | 'context-menu' | 'context-menu-multi-selection' | 'session-handling-action' | 'session-token-refresh' | 'extension-state-listener' | 'helpers-analyze-request' | 'helpers-analyze-response' | 'helpers-build-http-message' | 'helpers-update-parameter' | 'helpers-url-encode' | 'helpers-url-decode' | 'helpers-base64-encode' | 'helpers-bytes-string' | 'policy-denied' | 'unsupported';
export interface ExtensionSandboxAction {
    hook: ExtensionHook;
    kind: ExtensionSandboxActionKind;
    requestedKind?: string;
    name?: string;
    value?: string;
    title?: string;
    detail?: string;
    remediation?: string;
    severity?: Severity;
    confidence?: Issue['confidence'];
    requires?: ExtensionPermission[];
}
export interface ExtensionSandboxRuntime {
    apiVersion: string;
    sandbox: 'isolated-worker' | 'node-disabled' | 'headless-ci';
    actions: ExtensionSandboxAction[];
}
export interface InstalledExtension {
    id: string;
    catalogId?: string;
    name: string;
    author: string;
    version: string;
    description: string;
    enabled: boolean;
    hooks: ExtensionHook[];
    permissions: ExtensionPermission[];
    trustLevel: ExtensionTrustLevel;
    installedAt: string;
    dependencies?: ExtensionDependency[];
    runtimeApi?: ExtensionSandboxRuntime;
}
export interface ExtensionRun {
    id: string;
    extensionId: string;
    extensionName: string;
    hook: ExtensionHook;
    status: 'complete' | 'blocked' | 'error';
    target: string;
    startedAt: string;
    completedAt: string;
    summary: string;
    logs: string[];
    issue?: Issue;
    exchange?: HttpExchange;
}
export interface ExtensionApiCapabilities {
    trafficMutationApi: boolean;
    replayApi: boolean;
    issueHandoff: boolean;
    evidenceHandoff: boolean;
}
export interface ExtensionSignature {
    algorithm: 'HMAC-SHA256';
    signerName: string;
    keyId: string;
    status: 'signed' | 'ready-on-export';
    digestPreview: string;
}
export interface ExtensionPackageManifest {
    id: string;
    title: string;
    fileName: string;
    path: string;
    exportedAt: string;
    extensionId: string;
    extensionName: string;
    author: string;
    version: string;
    hooks: ExtensionHook[];
    permissions: ExtensionPermission[];
    trustLevel: ExtensionTrustLevel;
    apiCapabilities: ExtensionApiCapabilities;
    signature: ExtensionSignature;
    content: string;
}
export interface ExtensionDependency {
    name: string;
    version: string;
}
export interface ExtensionRuntimeApiPolicy {
    id: string;
    extensionId: string;
    extensionName: string;
    reviewedAt: string;
    apiVersion: string;
    sandbox: 'isolated-worker' | 'node-disabled' | 'headless-ci';
    allowedHooks: ExtensionHook[];
    deniedHooks: ExtensionHook[];
    networkAccess: 'blocked' | 'callback-only' | 'scoped-targets';
    filesystemAccess: 'none' | 'workspace-readonly' | 'evidence-write';
    dependencyReviewStatus: 'pending' | 'approved' | 'blocked';
    signatureStatus: ExtensionSignature['status'];
    reviewer: string;
    summary: string;
}
export interface ExtensionDependencyReviewItem {
    name: string;
    version: string;
    policy: string;
    status: 'approved' | 'needs-review' | 'blocked';
}
export interface ExtensionDependencyReview {
    id: string;
    extensionId: string;
    extensionName: string;
    reviewedAt: string;
    status: 'pending' | 'approved' | 'blocked';
    apiVersion: string;
    dependencies: ExtensionDependencyReviewItem[];
    summary: string;
    signature: ExtensionSignature;
    content: string;
}
export interface ExtensionHeadlessExecutionEvidence {
    id: string;
    title: string;
    fileName: string;
    path: string;
    createdAt: string;
    extensionId: string;
    extensionName: string;
    apiPolicyId: string;
    dependencyReviewId?: string;
    hookCoverage: ExtensionHook[];
    headlessCommand: string;
    status: 'ready' | 'exported';
    runIds: string[];
    runtimePolicyStatus: ExtensionDependencyReview['status'];
    reportReady: boolean;
    summary: string;
    signature: ExtensionSignature;
    content: string;
}
export interface ExtensionSignedUpdate {
    id: string;
    extensionId: string;
    extensionName: string;
    checkedAt: string;
    channel: 'stable' | 'beta' | 'local';
    currentVersion: string;
    availableVersion: string;
    status: 'current' | 'available' | 'blocked';
    apiVersion: string;
    signature: ExtensionSignature;
    summary: string;
    content: string;
}
export interface ExtensionCompatibilityFixture {
    id: string;
    extensionId: string;
    extensionName: string;
    executedAt: string;
    name: string;
    hook: ExtensionHook;
    apiVersion: string;
    legacyExtensionApi?: string;
    operation?: string;
    expectedOutcome?: string;
    policyOutcome?: 'allowed' | 'adapter-required' | 'denied';
    status: 'pass' | 'warning' | 'fail';
    summary: string;
}
export interface ExtensionRuntimeDiagnosticPackage {
    id: string;
    title: string;
    fileName: string;
    path: string;
    createdAt: string;
    extensionId: string;
    extensionName: string;
    apiVersion: string;
    updateId?: string;
    fixtureIds: string[];
    runIds: string[];
    status: 'ready' | 'exported';
    reportReady: boolean;
    signature: ExtensionSignature;
    summary: string;
    content: string;
}
export interface ExtensionLegacySdkCompatibilityProbe {
    id: string;
    extensionId: string;
    extensionName: string;
    executedAt: string;
    legacyExtensionApi: string;
    operation: string;
    hook: ExtensionHook;
    status: 'pass' | 'adapter-required' | 'denied' | 'unsupported';
    policyOutcome: 'allowed' | 'adapter-required' | 'denied';
    runId?: string;
    fixtureId?: string;
    rawRequest: string;
    rawResponse: string;
    evidence: string[];
    warnings: string[];
}
export interface ExtensionLegacySdkCompatibilityPackage {
    id: string;
    kind: 'proxyforge-extension-legacy-sdk-compatibility-package';
    title: string;
    fileName: string;
    path: string;
    createdAt: string;
    extensionId: string;
    extensionName: string;
    apiVersion: string;
    probeCount: number;
    supportedApiCount: number;
    adapterRequiredApiCount: number;
    deniedApiCount: number;
    unsupportedApiCount: number;
    coveredApis: string[];
    missingApis: string[];
    probes: ExtensionLegacySdkCompatibilityProbe[];
    reportReady: boolean;
    secretHandling: 'execution-full-fidelity-secrets-preserved';
    reportRedactionBoundary: 'redact-only-during-report-export';
    summary: string;
    content: string;
}
export type ExtensionThirdPartySdkEdgeCategory = 'http-message-mutation' | 'helpers-transform' | 'context-menu-multi-selection' | 'session-handling-token-refresh' | 'scanner-insertion-point' | 'editor-state-lifecycle' | 'unsupported-api-fail-closed' | 'manifest-dependency-edge' | 'package-refresh';
export interface ExtensionThirdPartySdkProfileEdge {
    category: ExtensionThirdPartySdkEdgeCategory;
    legacyExtensionApi: string;
    operation: string;
    hook: ExtensionHook;
    adapterAction: string;
    fixtureId?: string;
    status?: 'pass' | 'warning' | 'fail';
    evidence?: string[];
    rawRequest?: string;
    rawResponse?: string;
}
export interface ExtensionThirdPartySdkCompatibilityProfile {
    id: string;
    name: string;
    source: 'extension-catalog' | 'local-manifest' | 'agent-manifest' | 'legacy-extension' | string;
    packageName: string;
    version: string;
    hooks: ExtensionHook[];
    manifestFeatures: string[];
    dependencies: ExtensionDependency[];
    signature: ExtensionSignature;
    edgeCases: ExtensionThirdPartySdkProfileEdge[];
}
export interface ExtensionThirdPartySdkCompatibilityCase {
    id: string;
    profileId: string;
    profileName: string;
    source: string;
    category: ExtensionThirdPartySdkEdgeCategory;
    legacyExtensionApi: string;
    operation: string;
    hook: ExtensionHook;
    adapterAction: string;
    status: 'pass' | 'warning' | 'fail';
    fixtureId?: string;
    rawRequest: string;
    rawResponse: string;
    evidence: string[];
}
export interface ExtensionThirdPartySdkCompatibilityPackage {
    id: string;
    kind: 'proxyforge-extension-third-party-sdk-compatibility-package';
    title: string;
    fileName: string;
    path: string;
    createdAt: string;
    extensionId: string;
    extensionName: string;
    apiVersion: string;
    profileCount: number;
    edgeCaseCount: number;
    passCount: number;
    warningCount: number;
    failCount: number;
    coveredCategories: ExtensionThirdPartySdkEdgeCategory[];
    missingCategories: ExtensionThirdPartySdkEdgeCategory[];
    profiles: ExtensionThirdPartySdkCompatibilityProfile[];
    edgeCases: ExtensionThirdPartySdkCompatibilityCase[];
    packageRefreshProof: {
        refreshedAt: string;
        profileDigests: string[];
        edgeCaseDigest: string;
        signatureStatuses: ExtensionSignature['status'][];
        staleProfileIds: string[];
    };
    requirements: {
        profileDiversityCovered: boolean;
        httpRequestResponseMutationCovered: boolean;
        helpersTransformCovered: boolean;
        contextMenuMultiSelectionCovered: boolean;
        sessionHandlingTokenRefreshCovered: boolean;
        insertionPointProviderCovered: boolean;
        editorStateLifecycleCovered: boolean;
        unsupportedApisFailClosedCovered: boolean;
        dependencyAndManifestEdgesCovered: boolean;
        packageRefreshCovered: boolean;
        sdkPackageLinked: boolean;
        rawExecutorMaterialPreserved: boolean;
        operationalSecretsPreserved: boolean;
        reportPhaseOnlyRedaction: boolean;
    };
    reportReady: boolean;
    secretHandling: 'execution-full-fidelity-secrets-preserved';
    reportRedactionBoundary: 'redact-only-during-report-export';
    summary: string;
    content: string;
}
export interface ExtensionMigrationGuide {
    id: string;
    title: string;
    fileName: string;
    path: string;
    createdAt: string;
    extensionId: string;
    extensionName: string;
    source: 'legacy-extension';
    apiVersion: string;
    diagnosticId?: string;
    reportReady: boolean;
    signature: ExtensionSignature;
    summary: string;
    content: string;
}
export interface ExtensionRuntimeHealthEntry {
    id: string;
    extensionId: string;
    extensionName: string;
    hook: ExtensionHook;
    runId?: string;
    status: 'success' | 'blocked' | 'error';
    observedAt: string;
    latencyMs: number;
    permissionScope: ExtensionPermission[];
    apiCapabilities: ExtensionApiCapabilities;
    summary: string;
}
export interface ExtensionPolicyPreset {
    id: string;
    name: string;
    createdAt: string;
    hooks: ExtensionHook[];
    permissions: ExtensionPermission[];
    trustLevels: ExtensionTrustLevel[];
    apiCapabilities: ExtensionApiCapabilities;
    content: string;
}
export interface ExtensionEvidenceHandoff {
    id: string;
    title: string;
    fileName: string;
    path: string;
    createdAt: string;
    attachedAt: string;
    extensionId: string;
    extensionName: string;
    runId?: string;
    manifestId?: string;
    reportReady: boolean;
    signature: ExtensionSignature;
    summary: string;
    content: string;
}
export interface AutomationRun {
    id: string;
    name: string;
    status: 'ready' | 'running' | 'blocked' | 'complete';
    trigger: string;
    scope: string;
    lastRun: string;
    steps: string[];
}
export type AutomationWorkflowStatus = 'ready' | 'running' | 'blocked' | 'complete';
export type AutomationTrigger = 'manual' | 'scheduled' | 'on-tag' | 'ci';
export type AutomationStepType = 'replay' | 'crawl' | 'active-scan' | 'callback-poll' | 'report-export' | 'delay';
export type AutomationCiProvider = 'github-actions' | 'gitlab-ci' | 'azure-pipelines' | 'jenkins';
export type AutomationSchedulerServiceStatus = 'running' | 'paused' | 'stopped';
export type AutomationSchedulerJobStatus = 'queued' | 'leased' | 'complete' | 'blocked' | 'expired';
export interface AutomationWorkflowStep {
    id: string;
    type: AutomationStepType;
    label: string;
    target: string;
    throttleMs: number;
    maxRequests: number;
    requiresApproval: boolean;
}
export interface AutomationWorkflow {
    id: string;
    name: string;
    status: AutomationWorkflowStatus;
    trigger: AutomationTrigger;
    scope: string;
    scheduleEnabled: boolean;
    scheduleIntervalMinutes: number;
    nextRunAt: string;
    nextRunAtIso?: string;
    lastRun: string;
    lastSchedulerRunAt?: string;
    steps: AutomationWorkflowStep[];
}
export interface AutomationExecution {
    id: string;
    workflowId: string;
    workflowName: string;
    status: AutomationWorkflowStatus;
    trigger: AutomationTrigger;
    startedAt: string;
    completedAt: string;
    durationMs: number;
    totalRequests: number;
    logs: string[];
    exchange?: HttpExchange;
    issue?: Issue;
    operationalRawMaterial?: {
        sourceExchangeId: string;
        requestRaw: string;
        responseRaw: string;
        secretHandling: 'execution-full-fidelity-secrets-preserved';
        reportRedactionBoundary: 'redact-only-during-report-export';
    };
    schedulerJobId?: string;
    schedulerLeaseId?: string;
    ciProvider?: AutomationCiProvider;
    ciConfig: string;
}
export interface AutomationSchedulerJob {
    id: string;
    workflowId: string;
    workflowName: string;
    scheduledFor: string;
    status: AutomationSchedulerJobStatus;
    attempts: number;
    createdAt: string;
    updatedAt: string;
    leaseId?: string;
    leasedBy?: string;
    leaseExpiresAt?: string;
    executionId?: string;
    summary?: string;
}
export interface AutomationSchedulerState {
    id: string;
    status: AutomationSchedulerServiceStatus;
    ownerId: string;
    leaseTtlMs: number;
    maxConcurrentJobs: number;
    heartbeatAt: string;
    updatedAt: string;
    queue: AutomationSchedulerJob[];
}
export interface AutomationSchedulerTickResult {
    state: AutomationSchedulerState;
    workflows: AutomationWorkflow[];
    executions: AutomationExecution[];
    logs: string[];
    claimedJobs: number;
    completedJobs: number;
    blockedJobs: number;
}
export interface AiProvider {
    id: 'codex' | 'claude' | 'local';
    label: string;
    status: 'configured' | 'needs-key' | 'offline';
    model: string;
    purpose: string;
}
export type AiProviderId = 'codex' | 'claude' | 'local';
export type AiTaskKind = 'triage' | 'replay-plan' | 'exploit-review' | 'report-draft';
export interface AiContextExchange {
    method: string;
    host: string;
    path: string;
    status: number;
    risk: string;
    notes: string;
    requestRaw: string;
    responseRaw: string;
    tags: string[];
}
export interface AiContextIssue {
    title: string;
    severity: string;
    host: string;
    path: string;
    detail: string;
    remediation: string;
}
export interface AiContextBundle {
    projectName: string;
    scopeAllowlist: string[];
    taskHint: string;
    exchanges: AiContextExchange[];
    issues: AiContextIssue[];
}
export interface AiProviderConfig {
    id: AiProviderId;
    label: string;
    mode: 'cli' | 'http';
    enabled: boolean;
    model: string;
    command?: string;
    args?: string[];
    endpoint?: string;
    apiKeyEnv?: string;
    timeoutMs: number;
    inputCostPerMillionTokens?: number;
    outputCostPerMillionTokens?: number;
}
export interface AiProviderRuntime extends AiProviderConfig {
    available: boolean;
    secretPresent: boolean;
    status: 'configured' | 'needs-key' | 'offline';
    message: string;
}
export interface AiRunRequest {
    providerId: AiProviderId;
    task: AiTaskKind;
    prompt: string;
    context: AiContextBundle;
}
export interface AiRunUsage {
    promptTokens: number;
    completionTokens: number;
    totalTokens: number;
    estimatedCostUsd: number;
    latencyMs: number;
    source?: 'provider' | 'estimated' | 'browser-preview';
}
export interface AiRunStreamEvent {
    id: string;
    at: string;
    source: 'prompt' | 'stdout' | 'stderr' | 'http' | 'fallback' | 'complete';
    text: string;
}
export interface AiPromptEvaluationCheck {
    label: string;
    status: 'ready' | 'warning' | 'blocked';
    detail: string;
}
export interface AiPromptEvaluation {
    score: number;
    providerId: AiProviderId;
    model: string;
    checks: AiPromptEvaluationCheck[];
    recommendations: string[];
}
export type AiSuggestedActionKind = 'stage-repeater' | 'stage-replay-matrix' | 'queue-active-scan' | 'open-exploit-review' | 'record-automation' | 'draft-report';
export interface AiSuggestedAction {
    id: string;
    kind: AiSuggestedActionKind;
    label: string;
    detail: string;
    target: string;
    priority: Severity;
}
export type AiActionExecutionStatus = 'completed' | 'queued' | 'blocked';
export type AiActionExecutionMode = 'ui-controlled';
export interface AiActionExecutionPackage {
    id: string;
    title: string;
    createdAt: string;
    aiRunId?: string;
    providerId?: AiProviderId;
    actionId: string;
    actionKind: AiSuggestedActionKind;
    actionLabel: string;
    mode: AiActionExecutionMode;
    status: AiActionExecutionStatus;
    targetTool: ToolId;
    target: string;
    scopePassed: boolean;
    approvalRequired: boolean;
    approvalSatisfied: boolean;
    trafficSent: boolean;
    requestCount: number;
    maxRequests: number;
    safetyGates: string[];
    artifacts: string[];
    summary: string;
    content: string;
}
export interface AiRunResult {
    id: string;
    providerId: AiProviderId;
    task: AiTaskKind;
    status: 'complete' | 'unavailable' | 'error';
    model: string;
    startedAt: string;
    completedAt: string;
    summary: string;
    output: string;
    evidenceCount: number;
    command?: string;
    providerLabel?: string;
    prompt?: string;
    contextDigest?: string;
    usage?: AiRunUsage;
    streamEvents?: AiRunStreamEvent[];
    promptEvaluation?: AiPromptEvaluation;
    suggestedActions?: AiSuggestedAction[];
}
export interface AiPromptTemplate {
    id: string;
    task: AiTaskKind;
    title: string;
    prompt: string;
    updatedAt: string;
}
export interface AiEvaluationBaseline {
    id: string;
    name: string;
    providerId: AiProviderId;
    providerLabel: string;
    model: string;
    task: AiTaskKind;
    prompt: string;
    contextDigest: string;
    score: number;
    usage?: AiRunUsage;
    checks: AiPromptEvaluationCheck[];
    notes: string;
    createdAt: string;
    updatedAt: string;
}
export interface AiPromptComparison {
    id: string;
    createdAt: string;
    baselineId?: string;
    providerId: AiProviderId;
    providerLabel: string;
    model: string;
    task: AiTaskKind;
    score: number;
    scoreDelta: number;
    promptTokens: number;
    estimatedCostUsd: number;
    checkDelta: string[];
    verdict: 'improved' | 'similar' | 'regressed' | 'unbaselined';
    notes: string;
}
export interface AiBenchmarkResult extends AiPromptComparison {
    baselineName: string;
    baselineScore: number;
    projectName: string;
    contextDigest: string;
}
export interface AiBenchmarkRun {
    id: string;
    createdAt: string;
    projectName: string;
    projectSavedAt?: string;
    providerCount: number;
    baselineCount: number;
    resultCount: number;
    averageScore: number;
    improvedCount: number;
    regressedCount: number;
    unbaselinedCount: number;
    results: AiBenchmarkResult[];
    notes: string;
}
export type ReportFormat = 'markdown' | 'html' | 'json' | 'bundle' | 'pdf';
export type ReportSection = 'executive' | 'technical' | 'remediation' | 'evidence' | 'appendix';
export type ReportTemplateId = 'executive-board' | 'technical-remediation' | 'evidence-bundle' | 'custom';
export interface ReportLoggerImportAttachment {
    id: string;
    importedAt: string;
    format: LoggerArchiveImportFormat;
    mappingPresetName: string;
    normalization: LoggerArchiveNormalizationMode;
    notes: string;
    addedEntries: number;
    changedEntries: number;
    duplicateEntries: number;
    sourceHosts: string[];
    replayCount: number;
    replayedAt?: string;
    exchangeCount: number;
    provenanceManifest?: LoggerImportJobAttachmentProvenanceManifest;
    redactionControl?: LoggerImportJobRedactionControl;
}
export interface ReportExportRequest {
    projectName: string;
    scopeAllowlist: string[];
    issues: Issue[];
    exchanges: HttpExchange[];
    format: ReportFormat;
    sections: ReportSection[];
    templateId?: ReportTemplateId;
    brandName?: string;
    preparedFor?: string;
    engagementId?: string;
    customTemplateName?: string;
    customTemplateBody?: string;
    signEvidenceBundle?: boolean;
    signingKeyId?: string;
    signingSecret?: string;
    signerName?: string;
    loggerImportJobs?: ReportLoggerImportAttachment[];
    comparerDiffPackages?: ComparerDiffPackage[];
    comparerEvidenceAttachments?: ComparerEvidenceAttachment[];
    targetSiteMapEvidenceAttachments?: TargetSiteMapEvidenceAttachment[];
    proxyHistoryEvidenceAttachments?: ProxyHistoryEvidenceAttachment[];
    scannerActiveScanEvidencePackages?: ScannerActiveScanEvidencePackage[];
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
export interface ReportAffectedAsset {
    host: string;
    issueCount: number;
    evidenceCount: number;
    highestSeverity: Severity;
    paths: string[];
}
export interface ReportEvidenceManifestEntry {
    id: string;
    label: string;
    method: string;
    host: string;
    path: string;
    status: number;
    source: HttpExchange['source'];
    linkedIssueIds: string[];
}
export interface ReportReadinessCheck {
    id: string;
    label: string;
    status: 'ready' | 'warning' | 'blocked';
    detail: string;
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
export interface ReportCallbackArtifactManifest {
    signedPollBatchIds: string[];
    correlationReplayIds: string[];
    replayExecutionBatchIds: string[];
    lifecycleReviewIds: string[];
    ciHandoffPackageIds: string[];
    publicRelaySoakPackageIds: string[];
    externalRelayIntegrationPackageIds: string[];
    externalProviderDiversityPackageIds: string[];
    totalArtifactCount: number;
    summary: string;
}
export interface ReportFullPackage {
    id: string;
    title: string;
    fileName: string;
    path: string;
    generatedAt: string;
    exportedAt?: string;
    importedAt?: string;
    reportReady: boolean;
    issueCount: number;
    evidenceCount: number;
    affectedAssets: ReportAffectedAsset[];
    evidenceManifest: ReportEvidenceManifestEntry[];
    callbackArtifactManifest?: ReportCallbackArtifactManifest;
    readiness: ReportReadinessCheck[];
    governanceAttestation: ReportGovernanceAttestation;
    signature: {
        algorithm: 'HMAC-SHA256';
        signerName: string;
        keyId: string;
        status: 'signed' | 'ready-on-export' | 'verified-import';
        digestPreview: string;
    };
    content: string;
}
export type SequencerSampleSource = 'manual' | 'traffic' | 'browser-preview';
export type SequencerVerdict = 'strong' | 'watch' | 'weak';
export type SequencerReliability = 'rough' | 'indicative' | 'reliable' | 'fips-ready';
export type SequencerTokenLocationKind = 'cookie' | 'form-field' | 'custom';
export interface SequencerSampleRequest {
    label: string;
    samples: string[];
    source: SequencerSampleSource;
}
export interface SequencerCharacterSet {
    name: string;
    size: number;
    observed: number;
}
export interface SequencerFinding {
    title: string;
    severity: Severity;
    detail: string;
}
export interface SequencerReliabilitySummary {
    level: SequencerReliability;
    sampleTarget: number;
    maxSupportedSamples: number;
    fipsSampleTarget: number;
    message: string;
}
export interface SequencerEntropySignificancePoint {
    significance: string;
    effectiveEntropyBits: number;
}
export interface SequencerPositionStat {
    index: number;
    samplesObserved: number;
    observedCharacters: number;
    maxEntropyBits: number;
    shannonBits: number;
    dominantCharacter: string;
    dominantRate: number;
    transitionRepeatRate: number;
    bitStart: number;
    bitLength: number;
}
export interface SequencerBitStat {
    index: number;
    sourcePosition: number;
    ones: number;
    zeros: number;
    monobitPValue: number;
    pokerScore: number;
    runCount: number;
    passedFips: boolean;
}
export interface SequencerStatisticalTest {
    id: string;
    name: string;
    level: 'summary' | 'character' | 'bit' | 'fips';
    significance: string;
    passed: boolean;
    score: number;
    detail: string;
    failedPositions: number[];
}
export interface SequencerAnalysisResult {
    id: string;
    label: string;
    source: SequencerSampleSource;
    generatedAt: string;
    sampleCount: number;
    uniqueCount: number;
    duplicateCount: number;
    minLength: number;
    maxLength: number;
    averageLength: number;
    shannonBitsPerChar: number;
    estimatedEntropyBits: number;
    collisionRate: number;
    serialCorrelation: number;
    monobitRatio: number;
    repeatedPrefixLength: number;
    characterSets: SequencerCharacterSet[];
    reliability: SequencerReliabilitySummary;
    entropyBySignificance: SequencerEntropySignificancePoint[];
    positionStats: SequencerPositionStat[];
    bitStats: SequencerBitStat[];
    statisticalTests: SequencerStatisticalTest[];
    verdict: SequencerVerdict;
    findings: SequencerFinding[];
}
export interface SequencerTokenLocation {
    kind: SequencerTokenLocationKind;
    name: string;
    extractor: string;
}
export interface SequencerLiveCapture {
    id: string;
    label: string;
    createdAt: string;
    exchangeId: string;
    targetUrl: string;
    tokenLocation: SequencerTokenLocation;
    requestedSamples: number;
    capturedSamples: number;
    status: 'captured' | 'blocked';
    extractedTokens: string[];
    summary: string;
}
export interface SequencerProfileComparison {
    id: string;
    comparedAt: string;
    baselineResultId: string;
    candidateResultId: string;
    baselineLabel: string;
    candidateLabel: string;
    entropyDeltaBits: number;
    collisionDelta: number;
    verdictChange: string;
    changedTests: string[];
    reportReady: boolean;
    summary: string;
}
export interface SequencerExportArtifact {
    id: string;
    title: string;
    fileName: string;
    path: string;
    exportedAt: string;
    resultId: string;
    profileComparisonId?: string;
    reportReady: boolean;
    issueId?: string;
    summary: string;
    content: string;
}
export interface ExploitTemplate {
    id: string;
    title: string;
    className: string;
    status: 'draft' | 'ready' | 'requires-approval';
    target: string;
    safety: string;
    evidence: string;
}
export type ExploitRunStatus = 'complete' | 'blocked' | 'error';
export type ExploitMode = 'dry-run' | 'approved';
export type ExploitBackendExecutionMode = 'browser-preview' | 'electron-replay' | 'deterministic-preview';
export type ExploitBackendExecutionStatus = 'completed' | 'blocked' | 'error';
export type ExploitChainStepStatus = 'queued' | 'running' | 'complete' | 'blocked';
export interface ExploitChainStep {
    id: string;
    templateId: string;
    label: string;
    status: ExploitChainStepStatus;
    runId?: string;
    evidenceExchangeId?: string;
    callbackPayloadId?: string;
    callbackInteractionIds?: string[];
    notes: string;
}
export interface ExploitReportPackage {
    id: string;
    createdAt: string;
    planId: string;
    title: string;
    summary: string;
    runIds: string[];
    issueIds: string[];
    evidenceIds: string[];
    callbackPayloadIds: string[];
    callbackInteractionIds: string[];
    markdown: string;
}
export interface ExploitChainPackageReview {
    id: string;
    reviewedAt: string;
    packageDigestSha256: string;
    digestVerified: boolean;
    sourceProjectName: string;
    packageTitle: string;
    planId: string;
    planName: string;
    status: 'ready' | 'blocked';
    stepCount: number;
    completeSteps: number;
    blockedSteps: number;
    runCount: number;
    issueCount: number;
    evidenceCount: number;
    callbackPayloadCount: number;
    callbackInteractionCount: number;
    importedPlan: ExploitChainPlan;
    importedRuns: ExploitRun[];
    importedCallbackPayloads: CallbackPayload[];
    importedCallbackInteractions: CallbackInteraction[];
    packageMarkdown: string;
}
export interface ExploitChainComparisonStep {
    templateId: string;
    label: string;
    baselineStatus?: ExploitChainStepStatus;
    candidateStatus?: ExploitChainStepStatus;
    baselineEvidence?: string;
    candidateEvidence?: string;
    note: string;
}
export interface ExploitChainComparison {
    id: string;
    comparedAt: string;
    baselinePlanId: string;
    candidatePlanId: string;
    baselineName: string;
    candidateName: string;
    verdict: 'same' | 'candidate-improved' | 'candidate-regressed' | 'changed';
    stepCountDelta: number;
    completedDelta: number;
    evidenceDelta: number;
    callbackDelta: number;
    changedSteps: ExploitChainComparisonStep[];
    summary: string;
}
export interface ExploitChainPlan {
    id: string;
    name: string;
    target: string;
    createdAt: string;
    updatedAt: string;
    status: 'draft' | 'running' | 'complete' | 'blocked';
    steps: ExploitChainStep[];
    lastReportPackage?: ExploitReportPackage;
}
export interface ExploitRun {
    id: string;
    templateId: string;
    templateTitle: string;
    mode: ExploitMode;
    status: ExploitRunStatus;
    target: string;
    startedAt: string;
    completedAt: string;
    approvalRequired: boolean;
    approvalSatisfied: boolean;
    scopePassed: boolean;
    stopReason: string;
    payloadPreview: string;
    logs: string[];
    backendExecution?: ExploitBackendExecution;
    exchange?: HttpExchange;
    issue?: Issue;
}
export interface ExploitBackendExecution {
    id: string;
    createdAt: string;
    mode: ExploitBackendExecutionMode;
    status: ExploitBackendExecutionStatus;
    targetUrl: string;
    transport: 'repeater-backend' | 'preview-simulator' | 'not-sent';
    requestDigestPreview: string;
    responseStatus?: number;
    responseLength?: number;
    responseMime?: string;
    responseDigestPreview?: string;
    exchangeId?: string;
    scopePassed: boolean;
    approvalSatisfied: boolean;
    stopOnProof: boolean;
    maxRequests: number;
    destructiveAction: false;
    evidence: string[];
    summary: string;
    content: string;
}
export interface NativeBridge {
    startProxy: (port: number) => Promise<ProxyStatus>;
    stopProxy: () => Promise<ProxyStatus>;
    getProxyStatus: () => Promise<ProxyStatus>;
    launchBrowser: (request: BrowserLaunchRequest) => Promise<BrowserLaunchResult>;
    extractBrowserCookies: (request: BrowserCookieExtractionRequest) => Promise<BrowserCookieExtractionResult>;
    refreshSessionProfile: (request: SessionProfileRefreshRequest) => Promise<SessionProfileRefreshResult>;
    createProject: (request: ProjectLifecycleCreateRequest) => Promise<ProjectLifecycleState>;
    openProject: (request: ProjectLifecycleOpenRequest) => Promise<ProjectLifecycleState>;
    closeProject: (request?: ProjectLifecycleCloseRequest) => Promise<ProjectLifecycleState>;
    getProjectLifecycle: () => Promise<ProjectLifecycleState>;
    backupProject: (request?: ProjectLifecycleBackupRequest) => Promise<ProjectLifecycleBackupResponse>;
    loadProject: () => Promise<ProjectSnapshot | null>;
    saveProject: (snapshot: ProjectSnapshot) => Promise<ProjectSnapshot>;
    resetProject: () => Promise<void>;
    exportProjectFile: (snapshot: ProjectSnapshot) => Promise<ProjectFileArtifact | null>;
    importProjectFile: (content?: string) => Promise<ProjectSnapshot | null>;
    exportSignedAuditPackage: (artifact: SignedAuditExport) => Promise<SignedAuditExport | null>;
    exportWebSocketTranscript: (artifact: WebSocketTranscriptExport) => Promise<WebSocketTranscriptExport | null>;
    importWebSocketTranscript: (content?: string) => Promise<WebSocketTranscriptImportResult | null>;
    pushEnterprisePolicy: (request: EnterprisePolicyTransportRuntimeRequest) => Promise<EnterprisePolicyTransportRuntimeResult>;
    pullEnterprisePolicy: (request: EnterprisePolicyTransportRuntimeRequest) => Promise<EnterprisePolicyTransportRuntimeResult>;
    replayRequest: (request: ReplayRequest) => Promise<HttpExchange>;
    runRepeaterDesyncProbe: (request: RepeaterDesyncRuntimeRequest) => Promise<RepeaterDesyncRuntimeResult>;
    runRepeaterParallelRace: (request: RepeaterDesyncRuntimeRequest) => Promise<RepeaterDesyncRuntimeResult>;
    runIntruderAttack: (request: IntruderAttackRequest) => Promise<IntruderAttackSummary>;
    runCrawl: (request: CrawlRequest) => Promise<CrawlSummary>;
    runCrawlAudit: (request: CrawlAuditRequest) => Promise<CrawlAuditSummary>;
    runActiveScan: (request: ActiveScanRequest) => Promise<ActiveScanSummary>;
    getInterceptStatus: () => Promise<InterceptStatus>;
    setIntercept: (enabled: boolean) => Promise<InterceptStatus>;
    setResponseIntercept: (enabled: boolean) => Promise<InterceptStatus>;
    listIntercepts: () => Promise<InterceptedRequest[]>;
    resolveIntercept: (decision: InterceptDecision) => Promise<InterceptStatus>;
    getWebSocketInterceptStatus: () => Promise<WebSocketInterceptStatus>;
    setWebSocketIntercept: (settings: boolean | WebSocketInterceptSettings) => Promise<WebSocketInterceptStatus>;
    listWebSocketIntercepts: () => Promise<WebSocketMessage[]>;
    resolveWebSocketIntercept: (decision: WebSocketFrameDecision) => Promise<WebSocketInterceptStatus>;
    replayWebSocketFrame: (request: WebSocketReplayRequest) => Promise<WebSocketMessage>;
    getMatchReplaceRules: () => Promise<MatchReplaceRule[]>;
    setMatchReplaceRules: (rules: MatchReplaceRule[]) => Promise<MatchReplaceRule[]>;
    getWebSocketFrameRewriteRules: () => Promise<WebSocketFrameRewriteRule[]>;
    setWebSocketFrameRewriteRules: (rules: WebSocketFrameRewriteRule[]) => Promise<WebSocketFrameRewriteRule[]>;
    setCertificateProject: (projectName: string) => Promise<CertificateAuthorityStatus>;
    getCertificateStatus: () => Promise<CertificateAuthorityStatus>;
    ensureRootCertificate: () => Promise<CertificateAuthorityStatus>;
    exportRootCertificate: () => Promise<CertificateAuthorityExport>;
    rotateRootCertificate: () => Promise<CertificateAuthorityStatus>;
    revokeRootCertificate: () => Promise<CertificateAuthorityStatus>;
    getHttpsInspectionStatus: () => Promise<HttpsInspectionStatus>;
    setHttpsInspection: (enabled: boolean) => Promise<HttpsInspectionStatus>;
    setUpstreamTlsValidation: (mode: HttpsInspectionStatus['upstreamTlsMode']) => Promise<HttpsInspectionStatus>;
    startCallbackListener: (profile: CallbackListenerProfile, payloads: CallbackPayload[]) => Promise<CallbackListenerRuntimeStatus>;
    stopCallbackListener: (profileId: string) => Promise<CallbackListenerRuntimeStatus>;
    pollCallbackListener: (profileId: string, payloads: CallbackPayload[]) => Promise<CallbackListenerPollResult>;
    getCallbackListenerStatus: (profileId: string) => Promise<CallbackListenerRuntimeStatus>;
    getAiProviders: () => Promise<AiProviderRuntime[]>;
    setAiProviders: (configs: AiProviderConfig[]) => Promise<AiProviderRuntime[]>;
    runAiTask: (request: AiRunRequest) => Promise<AiRunResult>;
    recordAutomationRun: (execution: AutomationExecution) => Promise<ProjectRunStatePersistResult>;
    recordExtensionRun: (run: ExtensionRun) => Promise<ProjectRunStatePersistResult>;
    exportReport: (request: ReportExportRequest) => Promise<ReportArtifact>;
    analyzeSequencerSamples: (request: SequencerSampleRequest) => Promise<SequencerAnalysisResult>;
    onInterceptQueue: (handler: (pending: InterceptedRequest[]) => void) => () => void;
    onExchange: (handler: (exchange: HttpExchange) => void) => () => void;
    onWebSocketMessage: (handler: (message: WebSocketMessage) => void) => () => void;
    onWebSocketInterceptQueue: (handler: (pending: WebSocketMessage[]) => void) => () => void;
}
export interface ProjectRunStatePersistResult {
    kind: 'proxyforge-project-run-state-persist-result';
    runType: 'automation' | 'ai' | 'extension';
    id: string;
    stats: Pick<ProjectStoreStats, 'automationRunCount' | 'aiRunCount' | 'extensionRunCount' | 'auditEventCount'>;
}
declare global {
    interface Window {
        proxyForge?: NativeBridge;
    }
}
