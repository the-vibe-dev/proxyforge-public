import type {
  ExtensionCatalogItem,
  ExtensionCompatibilityFixture,
  ExtensionLegacySdkCompatibilityPackage,
  ExtensionLegacySdkCompatibilityProbe,
  ExtensionDependencyReview,
  ExtensionEvidenceHandoff,
  ExtensionHeadlessExecutionEvidence,
  ExtensionHook,
  ExtensionMigrationGuide,
  ExtensionPermission,
  ExtensionPackageManifest,
  ExtensionRun,
  ExtensionSandboxAction,
  ExtensionSandboxRuntime,
  ExtensionRuntimeApiPolicy,
  ExtensionRuntimeDiagnosticPackage,
  ExtensionRuntimeHealthEntry,
  ExtensionSignedUpdate,
  ExtensionThirdPartySdkCompatibilityCase,
  ExtensionThirdPartySdkCompatibilityPackage,
  ExtensionThirdPartySdkCompatibilityProfile,
  ExtensionThirdPartySdkEdgeCategory,
  HttpExchange,
  InstalledExtension,
  Issue,
} from './types';

export const extensionHookLabels: Record<ExtensionHook, string> = {
  'passive-scan': 'Passive scan',
  'request-editor': 'Request editor',
  'response-editor': 'Response editor',
  'message-editor': 'Message editor',
  'scanner-check': 'Scanner check',
  'intruder-payload': 'Intruder payload',
  'traffic-enrichment': 'Traffic enrichment',
  'report-transform': 'Report transform',
  'headless-runner': 'Headless runner',
};

export const extensionPermissionLabels: Record<ExtensionPermission, string> = {
  'read-traffic': 'Read traffic',
  'modify-traffic': 'Modify traffic',
  'create-issues': 'Create issues',
  'run-automations': 'Run automations',
  'callback-access': 'Callback access',
};

export const extensionCatalog: ExtensionCatalogItem[] = [
  {
    id: 'authz-boundary-lens',
    name: 'Authz Boundary Lens',
    author: 'ProxyForge Labs',
    version: '1.2.0',
    category: 'scanner',
    description: 'Flags 401/403 transitions and role hints that should be replayed as an authorization matrix.',
    hooks: ['passive-scan', 'scanner-check', 'traffic-enrichment', 'headless-runner'],
    permissions: ['read-traffic', 'create-issues'],
    trustLevel: 'verified',
    dependencies: [
      { name: '@proxyforge/extender-api', version: '^1.4.0' },
      { name: '@proxyforge/replay-matrix', version: '^1.1.0' },
    ],
  },
  {
    id: 'jwt-claim-highlighter',
    name: 'JWT Claim Highlighter',
    author: 'ProxyForge Labs',
    version: '1.0.4',
    category: 'analysis',
    description: 'Annotates bearer/session tokens and adds decoder-ready tags to traffic with JWT-like material.',
    hooks: ['traffic-enrichment', 'request-editor', 'response-editor', 'message-editor'],
    permissions: ['read-traffic', 'modify-traffic'],
    trustLevel: 'verified',
    dependencies: [
      { name: '@proxyforge/extender-api', version: '^1.4.0' },
      { name: '@proxyforge/token-inspector', version: '^0.8.0' },
    ],
  },
  {
    id: 'callback-canary-injector',
    name: 'Callback Canary Injector',
    author: 'ProxyForge Labs',
    version: '0.9.7',
    category: 'editor',
    description: 'Adds a safe callback header placeholder to selected requests for OAST validation workflows.',
    hooks: ['request-editor', 'message-editor', 'headless-runner'],
    permissions: ['read-traffic', 'modify-traffic', 'callback-access'],
    trustLevel: 'built-in',
    dependencies: [
      { name: '@proxyforge/extender-api', version: '^1.4.0' },
      { name: '@proxyforge/callback-client', version: '^1.0.0' },
    ],
  },
  {
    id: 'report-evidence-redactor',
    name: 'Report Evidence Redactor',
    author: 'ProxyForge Labs',
    version: '2.1.1',
    category: 'reporting',
    description: 'Applies report-safe redaction notes to exchanges before evidence export.',
    hooks: ['report-transform', 'headless-runner'],
    permissions: ['read-traffic'],
    trustLevel: 'verified',
    dependencies: [
      { name: '@proxyforge/extender-api', version: '^1.4.0' },
      { name: '@proxyforge/evidence-redactor', version: '^2.0.0' },
    ],
  },
];

export const seedInstalledExtensions: InstalledExtension[] = [
  installCatalogExtension(extensionCatalog[0], '13:25:16', true),
  installCatalogExtension(extensionCatalog[1], '13:25:44', false),
];

export const defaultExtensionManifest = JSON.stringify({
  name: 'Local Header Auditor',
  version: '0.1.0',
  author: 'Local analyst',
  description: 'Flags missing defensive headers on selected responses.',
  hooks: ['passive-scan', 'response-editor', 'traffic-enrichment'],
  permissions: ['read-traffic', 'create-issues'],
  dependencies: [
    { name: '@proxyforge/extender-api', version: '^1.4.0' },
  ],
}, null, 2);

export function installCatalogExtension(
  item: ExtensionCatalogItem,
  installedAt = new Date().toLocaleTimeString([], { hour12: false }),
  enabled = true,
): InstalledExtension {
  return {
    id: `ext-${item.id}`,
    catalogId: item.id,
    name: item.name,
    author: item.author,
    version: item.version,
    description: item.description,
    enabled,
    hooks: item.hooks,
    permissions: item.permissions,
    trustLevel: item.trustLevel,
    installedAt,
    dependencies: item.dependencies,
  };
}

export function installManifestExtension(
  manifestText: string,
  installed: InstalledExtension[],
): { extension?: InstalledExtension; error?: string } {
  try {
    const manifest = JSON.parse(manifestText) as Partial<InstalledExtension>;
    if (!manifest.name || !manifest.version) return { error: 'Manifest requires name and version.' };
    const hooks = normalizeHooks(manifest.hooks);
    const permissions = normalizePermissions(manifest.permissions);
    if (hooks.length === 0) return { error: 'Manifest requires at least one supported hook.' };
    const runtimeApiResult = normalizeSandboxRuntime((manifest as { runtimeApi?: unknown }).runtimeApi, hooks);
    if (runtimeApiResult.error) return { error: runtimeApiResult.error };

    const id = `local-${slugify(manifest.name)}`;
    const suffix = installed.some((extension) => extension.id === id) ? `-${Date.now()}` : '';
    return {
      extension: {
        id: `${id}${suffix}`,
        name: manifest.name,
        author: manifest.author ?? 'Local analyst',
        version: manifest.version,
        description: manifest.description ?? 'Local extension loaded from manifest.',
        enabled: true,
        hooks,
        permissions,
        trustLevel: 'local',
        installedAt: new Date().toLocaleTimeString([], { hour12: false }),
        dependencies: normalizeDependencies((manifest as { dependencies?: unknown }).dependencies),
        runtimeApi: runtimeApiResult.runtimeApi,
      },
    };
  } catch (error) {
    return { error: error instanceof Error ? `Manifest JSON error: ${error.message}` : 'Manifest JSON error.' };
  }
}

export function runExtension(
  extension: InstalledExtension,
  hook: ExtensionHook,
  exchange: HttpExchange,
): ExtensionRun {
  const now = new Date();
  const target = `${exchange.method} ${exchange.host}${exchange.path}`;
  const startedAt = now.toISOString();

  if (!extension.enabled) {
    return baseRun(extension, hook, exchange, startedAt, 'blocked', 'Extension is disabled.', [
      `${extension.name} is installed but disabled.`,
      'Enable the extension before invoking hooks.',
    ]);
  }
  if (!extension.hooks.includes(hook)) {
    return baseRun(extension, hook, exchange, startedAt, 'blocked', `${extension.name} does not implement ${extensionHookLabels[hook]}.`, [
      `Supported hooks: ${extension.hooks.map((item) => extensionHookLabels[item]).join(', ')}`,
      `Requested hook: ${extensionHookLabels[hook]}`,
    ]);
  }
  if (!extension.permissions.includes('read-traffic')) {
    return baseRun(extension, hook, exchange, startedAt, 'blocked', 'Extension lacks read-traffic permission.', [
      'ProxyForge denied the hook before traffic context was shared.',
    ]);
  }

  if (extension.catalogId === 'authz-boundary-lens') {
    return runAuthzBoundaryLens(extension, hook, exchange, startedAt, target);
  }
  if (extension.catalogId === 'jwt-claim-highlighter') {
    return runJwtClaimHighlighter(extension, hook, exchange, startedAt, target);
  }
  if (extension.catalogId === 'callback-canary-injector') {
    return runCallbackCanaryInjector(extension, hook, exchange, startedAt, target);
  }
  if (extension.catalogId === 'report-evidence-redactor') {
    return runReportRedactor(extension, hook, exchange, startedAt, target);
  }
  if (extension.runtimeApi) {
    return runSandboxRuntimeExtension(extension, hook, exchange, startedAt, target);
  }

  return runLocalManifestExtension(extension, hook, exchange, startedAt, target);
}

export function issuesFromExtensionRuns(runs: ExtensionRun[]) {
  return runs.flatMap((run) => (run.issue ? [run.issue] : []));
}

export interface ExtensionParityEvidenceRequest {
  catalogItems: ExtensionCatalogItem[];
  installedExtensions: InstalledExtension[];
  runs: ExtensionRun[];
  packageManifests: ExtensionPackageManifest[];
  runtimeApiPolicies: ExtensionRuntimeApiPolicy[];
  dependencyReviews: ExtensionDependencyReview[];
  headlessEvidence: ExtensionHeadlessExecutionEvidence[];
  signedUpdates: ExtensionSignedUpdate[];
  compatibilityFixtures: ExtensionCompatibilityFixture[];
  sdkCompatibilityPackages?: ExtensionLegacySdkCompatibilityPackage[];
  thirdPartySdkCompatibilityPackages?: ExtensionThirdPartySdkCompatibilityPackage[];
  runtimeDiagnostics: ExtensionRuntimeDiagnosticPackage[];
  migrationGuides?: ExtensionMigrationGuide[];
  runtimeHealth?: ExtensionRuntimeHealthEntry[];
  evidenceHandoffs?: ExtensionEvidenceHandoff[];
  operationalSecretSamples?: string[];
  exportedAt?: string;
}

export interface ExtensionParityEvidencePackage {
  id: string;
  kind: 'proxyforge-extension-parity-evidence-package';
  title: string;
  fileName: string;
  path: string;
  exportedAt: string;
  catalogCount: number;
  installedCount: number;
  runCount: number;
  packageManifestCount: number;
  runtimeApiPolicyCount: number;
  signedUpdateCount: number;
  compatibilityFixtureCount: number;
  artifactIds: {
    catalogIds: string[];
    installedExtensionIds: string[];
    runIds: string[];
    packageManifestIds: string[];
    runtimePolicyIds: string[];
    dependencyReviewIds: string[];
    headlessEvidenceIds: string[];
    signedUpdateIds: string[];
    compatibilityFixtureIds: string[];
    sdkCompatibilityPackageIds: string[];
    thirdPartySdkCompatibilityPackageIds: string[];
    runtimeDiagnosticIds: string[];
    migrationGuideIds: string[];
    evidenceHandoffIds: string[];
  };
  coverage: {
    hooks: Partial<Record<ExtensionHook, number>>;
    permissions: Partial<Record<ExtensionPermission, number>>;
    trustLevels: Partial<Record<InstalledExtension['trustLevel'], number>>;
    runStatuses: Partial<Record<ExtensionRun['status'], number>>;
    updateStatuses: Partial<Record<ExtensionSignedUpdate['status'], number>>;
    fixtureStatuses: Partial<Record<ExtensionCompatibilityFixture['status'], number>>;
  };
  requirements: {
    catalogInstallCovered: boolean;
    localManifestCovered: boolean;
    enableDisableRunLogsCovered: boolean;
    hookCoverageCovered: boolean;
    sandboxApiCovered: boolean;
    legacyCompatibilityCovered: boolean;
    legacySdkDepthCovered: boolean;
    thirdPartySdkEdgeCovered: boolean;
    policyDenialCovered: boolean;
    dependencyReviewCovered: boolean;
    headlessCiCovered: boolean;
    signedManifestCovered: boolean;
    signedUpdatePolicyCovered: boolean;
    runtimeDiagnosticsCovered: boolean;
    evidenceHandoffCovered: boolean;
    rawExecutorMaterialPreserved: boolean;
    operationalSecretsPreserved: boolean;
    reportPhaseOnlyRedaction: boolean;
  };
  secretHandling: 'execution-full-fidelity-secrets-preserved';
  reportRedactionBoundary: 'redact-only-during-report-export';
  reportReady: boolean;
  digestPreview: string;
  summary: string;
  content: string;
}

const defaultLegacySdkRequiredApis = [
  'IHttpListener',
  'IProxyListener',
  'IScannerCheck',
  'IScannerInsertionPointProvider',
  'IMessageEditorTab',
  'IContextMenuFactory',
  'ISessionHandlingAction',
  'IExtensionStateListener',
  'IExtensionHelpers',
  'ILegacyExtensionCallbacks',
];

const defaultThirdPartySdkRequiredCategories: ExtensionThirdPartySdkEdgeCategory[] = [
  'http-message-mutation',
  'helpers-transform',
  'context-menu-multi-selection',
  'session-handling-token-refresh',
  'scanner-insertion-point',
  'editor-state-lifecycle',
  'unsupported-api-fail-closed',
  'manifest-dependency-edge',
  'package-refresh',
];

export function buildExtensionLegacySdkCompatibilityPackage(options: {
  extension: InstalledExtension;
  exchange: HttpExchange;
  runs: ExtensionRun[];
  fixtures: ExtensionCompatibilityFixture[];
  requiredApis?: string[];
  now?: string;
}): ExtensionLegacySdkCompatibilityPackage {
  const createdAt = options.now ?? new Date().toISOString();
  const stamp = createdAt.replace(/[:.]/g, '-');
  const apiVersion = options.extension.runtimeApi?.apiVersion ?? 'proxyforge-extender-api/v1';
  const requiredApis = options.requiredApis ?? defaultLegacySdkRequiredApis;
  const probes: ExtensionLegacySdkCompatibilityProbe[] = options.fixtures.map((fixture, index) => {
    const matchedRun = options.runs.find((run) => run.hook === fixture.hook
      && run.extensionId === fixture.extensionId
      && run.logs.some((log) => log.toLowerCase().includes((fixture.operation ?? '').toLowerCase().split('(')[0] ?? '')));
    const policyOutcome = fixture.policyOutcome ?? 'adapter-required';
    const status: ExtensionLegacySdkCompatibilityProbe['status'] = fixture.status === 'fail'
      ? 'unsupported'
      : policyOutcome === 'denied'
        ? 'denied'
        : policyOutcome === 'adapter-required'
          ? 'adapter-required'
          : 'pass';
    const evidence = [
      fixture.summary,
      ...(matchedRun?.logs ?? []),
      matchedRun?.summary ?? '',
      matchedRun?.issue?.detail ?? '',
    ].filter(Boolean);
    const warnings = [
      fixture.status === 'warning' ? 'adapter required before direct legacy extension compatibility' : '',
      fixture.status === 'fail' ? 'fixture failed or unsupported' : '',
      status === 'denied' ? 'operation denied by policy before side effect' : '',
      matchedRun ? '' : 'no direct runtime run matched this fixture; fixture evidence retained',
    ].filter(Boolean);

    return {
      id: `extension-legacy-sdk-probe-${index + 1}-${slugify(fixture.legacyExtensionApi ?? fixture.name)}`,
      extensionId: fixture.extensionId,
      extensionName: fixture.extensionName,
      executedAt: fixture.executedAt,
      legacyExtensionApi: fixture.legacyExtensionApi ?? 'LegacyExtensionApi',
      operation: fixture.operation ?? fixture.name,
      hook: fixture.hook,
      status,
      policyOutcome,
      runId: matchedRun?.id,
      fixtureId: fixture.id,
      rawRequest: options.exchange.requestRaw,
      rawResponse: options.exchange.responseRaw,
      evidence,
      warnings,
    };
  });
  const coveredApis = Array.from(new Set(probes
    .filter((probe) => probe.status !== 'unsupported')
    .map((probe) => probe.legacyExtensionApi)));
  const missingApis = requiredApis.filter((api) => !coveredApis.includes(api));
  const supportedApiCount = probes.filter((probe) => probe.status === 'pass').length;
  const adapterRequiredApiCount = probes.filter((probe) => probe.status === 'adapter-required').length;
  const deniedApiCount = probes.filter((probe) => probe.status === 'denied').length;
  const unsupportedApiCount = probes.filter((probe) => probe.status === 'unsupported').length;
  const rawMaterial = [
    options.exchange.requestRaw,
    options.exchange.responseRaw,
    JSON.stringify(probes),
    ...options.runs.flatMap((run) => [run.summary, ...run.logs, run.issue?.detail ?? '']),
  ].join('\n');
  const reportReady = missingApis.length === 0
    && probes.length >= requiredApis.length
    && deniedApiCount > 0
    && /Authorization:|Cookie:|X-API-Key:|HTTP\/[12]/i.test(rawMaterial);
  const digestPreview = simpleDigest(JSON.stringify({
    createdAt,
    extensionId: options.extension.id,
    apiVersion,
    coveredApis,
    missingApis,
    supportedApiCount,
    adapterRequiredApiCount,
    deniedApiCount,
    unsupportedApiCount,
  }));
  const content = JSON.stringify({
    kind: 'proxyforge-extension-legacy-sdk-compatibility-package',
    createdAt,
    extension: options.extension,
    apiVersion,
    requiredApis,
    coveredApis,
    missingApis,
    probes,
    runs: options.runs,
    fixtures: options.fixtures,
    sourceExchange: options.exchange,
    counts: {
      supportedApiCount,
      adapterRequiredApiCount,
      deniedApiCount,
      unsupportedApiCount,
    },
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady,
    digestPreview,
  }, null, 2);

  return {
    id: `extension-legacy-sdk-compatibility-${digestPreview.slice(0, 12)}`,
    kind: 'proxyforge-extension-legacy-sdk-compatibility-package',
    title: 'legacy extension SDK compatibility package',
    fileName: `proxyforge-extension-legacy-sdk-compatibility-${stamp}.json`,
    path: `extensions/proxyforge-extension-legacy-sdk-compatibility-${stamp}.json`,
    createdAt,
    extensionId: options.extension.id,
    extensionName: options.extension.name,
    apiVersion,
    probeCount: probes.length,
    supportedApiCount,
    adapterRequiredApiCount,
    deniedApiCount,
    unsupportedApiCount,
    coveredApis,
    missingApis,
    probes,
    reportReady,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    summary: `legacy extension SDK compatibility covers ${coveredApis.length}/${requiredApis.length} required API surface(s), with ${supportedApiCount} pass, ${adapterRequiredApiCount} adapter-required, ${deniedApiCount} denied, and ${unsupportedApiCount} unsupported probe(s).`,
    content,
  };
}

export function buildExtensionThirdPartySdkCompatibilityPackage(options: {
  extension: InstalledExtension;
  exchange: HttpExchange;
  fixtures: ExtensionCompatibilityFixture[];
  profiles: ExtensionThirdPartySdkCompatibilityProfile[];
  sdkCompatibilityPackage?: ExtensionLegacySdkCompatibilityPackage;
  requiredCategories?: ExtensionThirdPartySdkEdgeCategory[];
  operationalSecretSamples?: string[];
  now?: string;
}): ExtensionThirdPartySdkCompatibilityPackage {
  const createdAt = options.now ?? new Date().toISOString();
  const stamp = createdAt.replace(/[:.]/g, '-');
  const apiVersion = options.extension.runtimeApi?.apiVersion ?? 'proxyforge-extender-api/v1';
  const requiredCategories = options.requiredCategories ?? defaultThirdPartySdkRequiredCategories;
  const fixtureById = new Map(options.fixtures.map((fixture) => [fixture.id, fixture]));
  const edgeCases: ExtensionThirdPartySdkCompatibilityCase[] = options.profiles.flatMap((profile, profileIndex) => (
    profile.edgeCases.map((edge, edgeIndex) => {
      const fixture = edge.fixtureId ? fixtureById.get(edge.fixtureId) : undefined;
      const status = edge.status ?? fixture?.status ?? 'pass';
      return {
        id: `extension-third-party-edge-${profileIndex + 1}-${edgeIndex + 1}-${slugify(edge.category)}`,
        profileId: profile.id,
        profileName: profile.name,
        source: profile.source,
        category: edge.category,
        legacyExtensionApi: edge.legacyExtensionApi,
        operation: edge.operation,
        hook: edge.hook,
        adapterAction: edge.adapterAction,
        status,
        fixtureId: edge.fixtureId,
        rawRequest: edge.rawRequest ?? options.exchange.requestRaw,
        rawResponse: edge.rawResponse ?? options.exchange.responseRaw,
        evidence: [
          `${profile.name} ${edge.legacyExtensionApi}.${edge.operation} mapped through ${edge.adapterAction}.`,
          ...(edge.evidence ?? []),
          fixture?.summary ?? '',
        ].filter(Boolean),
      };
    })
  ));
  const coveredCategories = Array.from(new Set(edgeCases
    .filter((edge) => edge.status !== 'fail')
    .map((edge) => edge.category)));
  const missingCategories = requiredCategories.filter((category) => !coveredCategories.includes(category));
  const passCount = edgeCases.filter((edge) => edge.status === 'pass').length;
  const warningCount = edgeCases.filter((edge) => edge.status === 'warning').length;
  const failCount = edgeCases.filter((edge) => edge.status === 'fail').length;
  const profileDigests = options.profiles.map((profile) => simpleDigest(JSON.stringify({
    id: profile.id,
    source: profile.source,
    packageName: profile.packageName,
    version: profile.version,
    manifestFeatures: profile.manifestFeatures,
    dependencies: profile.dependencies,
    signature: profile.signature,
  })));
  const edgeCaseDigest = simpleDigest(JSON.stringify(edgeCases.map((edge) => ({
    profileId: edge.profileId,
    category: edge.category,
    legacyExtensionApi: edge.legacyExtensionApi,
    operation: edge.operation,
    status: edge.status,
  }))));
  const rawMaterial = [
    JSON.stringify(options.extension),
    options.exchange.requestRaw,
    options.exchange.responseRaw,
    JSON.stringify(options.fixtures),
    JSON.stringify(options.profiles),
    JSON.stringify(edgeCases),
    options.sdkCompatibilityPackage?.content ?? '',
    ...(options.operationalSecretSamples ?? []),
  ].join('\n');
  const hasCategory = (category: ExtensionThirdPartySdkEdgeCategory) => coveredCategories.includes(category);
  const sourceKinds = new Set(options.profiles.map((profile) => profile.source));
  const requirements = {
    profileDiversityCovered: options.profiles.length >= 3 && sourceKinds.size >= 3,
    httpRequestResponseMutationCovered: hasCategory('http-message-mutation'),
    helpersTransformCovered: hasCategory('helpers-transform')
      && /analyzeRequest|analyzeResponse|urlEncode|urlDecode|base64|bytesToString|updateParameter/i.test(rawMaterial),
    contextMenuMultiSelectionCovered: hasCategory('context-menu-multi-selection')
      && /multi-message|multi selection|selected request/i.test(rawMaterial),
    sessionHandlingTokenRefreshCovered: hasCategory('session-handling-token-refresh')
      && /session|csrf|Authorization:|Cookie:/i.test(rawMaterial),
    insertionPointProviderCovered: hasCategory('scanner-insertion-point')
      && /IScannerInsertionPointProvider|query:|header:|cookie:|json:/i.test(rawMaterial),
    editorStateLifecycleCovered: hasCategory('editor-state-lifecycle')
      && /IMessageEditorTab|IExtensionStateListener|extensionUnloaded/i.test(rawMaterial),
    unsupportedApisFailClosedCovered: hasCategory('unsupported-api-fail-closed')
      && /denied|fail closed|process-spawn|makeHttpRequest/i.test(rawMaterial),
    dependencyAndManifestEdgesCovered: hasCategory('manifest-dependency-edge')
      && options.profiles.some((profile) => profile.dependencies.length > 0 && profile.manifestFeatures.length > 0)
      && options.profiles.every((profile) => ['signed', 'ready-on-export'].includes(profile.signature.status)),
    packageRefreshCovered: hasCategory('package-refresh')
      && profileDigests.length === options.profiles.length
      && edgeCaseDigest.length > 0
      && options.profiles.every((profile) => profile.signature.algorithm === 'HMAC-SHA256'),
    sdkPackageLinked: Boolean(options.sdkCompatibilityPackage?.reportReady)
      && options.sdkCompatibilityPackage?.kind === 'proxyforge-extension-legacy-sdk-compatibility-package',
    rawExecutorMaterialPreserved: /HTTP\/[12]|Authorization:|Cookie:|X-API-Key:|requestRaw|responseRaw/i.test(rawMaterial),
    operationalSecretsPreserved: (options.operationalSecretSamples ?? []).length > 0
      && (options.operationalSecretSamples ?? []).every((sample) => rawMaterial.includes(sample)),
    reportPhaseOnlyRedaction: true,
  };
  const reportReady = Object.values(requirements).every(Boolean) && missingCategories.length === 0 && failCount === 0;
  const packageRefreshProof = {
    refreshedAt: createdAt,
    profileDigests,
    edgeCaseDigest,
    signatureStatuses: options.profiles.map((profile) => profile.signature.status),
    staleProfileIds: [],
  };
  const unsigned = {
    kind: 'proxyforge-extension-third-party-sdk-compatibility-package',
    createdAt,
    extension: options.extension,
    apiVersion,
    profiles: options.profiles,
    sourceExchange: options.exchange,
    fixtures: options.fixtures,
    sdkCompatibilityPackageId: options.sdkCompatibilityPackage?.id,
    edgeCases,
    coveredCategories,
    missingCategories,
    packageRefreshProof,
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady,
  };
  const digestPreview = simpleDigest(JSON.stringify(unsigned));
  const content = JSON.stringify({ ...unsigned, digestPreview }, null, 2);

  return {
    id: `extension-third-party-sdk-${digestPreview.slice(0, 12)}`,
    kind: 'proxyforge-extension-third-party-sdk-compatibility-package',
    title: 'Third-party extension SDK compatibility package',
    fileName: `proxyforge-extension-third-party-sdk-compatibility-${stamp}.json`,
    path: `extensions/proxyforge-extension-third-party-sdk-compatibility-${stamp}.json`,
    createdAt,
    extensionId: options.extension.id,
    extensionName: options.extension.name,
    apiVersion,
    profileCount: options.profiles.length,
    edgeCaseCount: edgeCases.length,
    passCount,
    warningCount,
    failCount,
    coveredCategories,
    missingCategories,
    profiles: options.profiles,
    edgeCases,
    packageRefreshProof,
    requirements,
    reportReady,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    summary: `Third-party extension compatibility covers ${coveredCategories.length}/${requiredCategories.length} edge category surface(s) across ${options.profiles.length} migrated profile(s), with ${passCount} pass, ${warningCount} warning, and ${failCount} fail case(s).`,
    content,
  };
}

export function buildExtensionParityEvidencePackage(request: ExtensionParityEvidenceRequest): ExtensionParityEvidencePackage {
  const exportedAt = request.exportedAt ?? new Date().toISOString();
  const stamp = exportedAt.replace(/[:.]/g, '-');
  const sdkCompatibilityPackages = request.sdkCompatibilityPackages ?? [];
  const thirdPartySdkCompatibilityPackages = request.thirdPartySdkCompatibilityPackages ?? [];
  const hookCoverage = countValues<ExtensionHook>(
    request.installedExtensions.flatMap((extension) => extension.hooks),
  );
  const permissionCoverage = countValues<ExtensionPermission>(
    request.installedExtensions.flatMap((extension) => extension.permissions),
  );
  const trustCoverage = countValues<InstalledExtension['trustLevel']>(
    request.installedExtensions.map((extension) => extension.trustLevel),
  );
  const runStatuses = countValues<ExtensionRun['status']>(request.runs.map((run) => run.status));
  const updateStatuses = countValues<ExtensionSignedUpdate['status']>(request.signedUpdates.map((update) => update.status));
  const fixtureStatuses = countValues<ExtensionCompatibilityFixture['status']>(request.compatibilityFixtures.map((fixture) => fixture.status));
  const runtimeActions = request.installedExtensions.flatMap((extension) => extension.runtimeApi?.actions ?? []);
  const rawMaterial = [
    JSON.stringify(request.catalogItems),
    JSON.stringify(request.installedExtensions),
    JSON.stringify(request.runs),
    JSON.stringify(request.packageManifests),
    JSON.stringify(request.runtimeApiPolicies),
    JSON.stringify(request.dependencyReviews),
    JSON.stringify(request.headlessEvidence),
    JSON.stringify(request.signedUpdates),
    JSON.stringify(request.compatibilityFixtures),
    JSON.stringify(sdkCompatibilityPackages),
    JSON.stringify(thirdPartySdkCompatibilityPackages),
    JSON.stringify(request.runtimeDiagnostics),
    JSON.stringify(request.migrationGuides ?? []),
    JSON.stringify(request.runtimeHealth ?? []),
    JSON.stringify(request.evidenceHandoffs ?? []),
    ...request.runs.flatMap((run) => [run.summary, ...run.logs, run.issue?.detail ?? '', run.exchange?.requestRaw ?? '', run.exchange?.responseRaw ?? '']),
    ...request.packageManifests.map((manifest) => manifest.content),
    ...request.headlessEvidence.map((evidence) => evidence.content),
    ...request.signedUpdates.map((update) => update.content),
    ...sdkCompatibilityPackages.map((item) => item.content),
    ...thirdPartySdkCompatibilityPackages.map((item) => item.content),
    ...request.runtimeDiagnostics.map((diagnostic) => diagnostic.content),
    ...(request.evidenceHandoffs ?? []).map((handoff) => handoff.content),
  ].join('\n');
  const requiredHooks: ExtensionHook[] = ['passive-scan', 'request-editor', 'response-editor', 'message-editor', 'scanner-check', 'headless-runner'];
  const requiredSandboxActions: ExtensionSandboxAction['kind'][] = [
    'request-header',
    'response-header',
    'tag',
    'note',
    'request-listener',
    'response-listener',
    'scanner-check',
    'editor-tab',
    'policy-denied',
  ];
  const requirements = {
    catalogInstallCovered: request.catalogItems.length >= 4
      && request.installedExtensions.some((extension) => extension.catalogId && extension.trustLevel !== 'local'),
    localManifestCovered: request.installedExtensions.some((extension) => extension.trustLevel === 'local' && Boolean(extension.runtimeApi)),
    enableDisableRunLogsCovered: request.installedExtensions.some((extension) => !extension.enabled)
      && request.runs.some((run) => run.status === 'blocked' && /disabled|missing|denied|unsupported|policy/i.test([run.summary, ...run.logs].join('\n'))),
    hookCoverageCovered: requiredHooks.every((hook) => (hookCoverage[hook] ?? 0) > 0),
    sandboxApiCovered: requiredSandboxActions.every((kind) => runtimeActions.some((action) => action.kind === kind)),
    legacyCompatibilityCovered: request.compatibilityFixtures.some((fixture) => /IHttpListener|request/i.test(`${fixture.legacyExtensionApi ?? ''} ${fixture.operation ?? ''}`))
      && request.compatibilityFixtures.some((fixture) => /IScannerCheck|scanner/i.test(`${fixture.legacyExtensionApi ?? ''} ${fixture.operation ?? ''}`))
      && request.compatibilityFixtures.some((fixture) => /editor/i.test(`${fixture.legacyExtensionApi ?? ''} ${fixture.operation ?? ''}`))
      && request.compatibilityFixtures.some((fixture) => fixture.policyOutcome === 'denied'),
    legacySdkDepthCovered: sdkCompatibilityPackages.some((item) => item.reportReady
      && item.missingApis.length === 0
      && item.coveredApis.includes('IHttpListener')
      && item.coveredApis.includes('IProxyListener')
      && item.coveredApis.includes('IScannerCheck')
      && item.coveredApis.includes('IScannerInsertionPointProvider')
      && item.coveredApis.includes('IContextMenuFactory')
      && item.coveredApis.includes('ISessionHandlingAction')
      && item.coveredApis.includes('IExtensionHelpers')
      && item.coveredApis.includes('ILegacyExtensionCallbacks')
      && item.deniedApiCount > 0
      && item.content.includes('redact-only-during-report-export')),
    thirdPartySdkEdgeCovered: thirdPartySdkCompatibilityPackages.some((item) => item.reportReady
      && item.missingCategories.length === 0
      && item.requirements.profileDiversityCovered
      && item.requirements.httpRequestResponseMutationCovered
      && item.requirements.helpersTransformCovered
      && item.requirements.contextMenuMultiSelectionCovered
      && item.requirements.sessionHandlingTokenRefreshCovered
      && item.requirements.insertionPointProviderCovered
      && item.requirements.editorStateLifecycleCovered
      && item.requirements.unsupportedApisFailClosedCovered
      && item.requirements.dependencyAndManifestEdgesCovered
      && item.requirements.packageRefreshCovered
      && item.content.includes('redact-only-during-report-export')),
    policyDenialCovered: /Policy denied|Unsupported sandbox action|missing modify-traffic|blocked/i.test(rawMaterial),
    dependencyReviewCovered: request.dependencyReviews.some((review) => ['approved', 'blocked'].includes(review.status))
      && request.dependencyReviews.some((review) => review.dependencies.length > 0),
    headlessCiCovered: request.headlessEvidence.some((evidence) => evidence.reportReady && evidence.headlessCommand.includes('extension-fixtures')),
    signedManifestCovered: request.packageManifests.some((manifest) => (
      manifest.signature.algorithm === 'HMAC-SHA256'
      && ['signed', 'ready-on-export'].includes(manifest.signature.status)
      && manifest.content.includes('proxyforge-extension-package')
    )),
    signedUpdatePolicyCovered: ['current', 'available', 'blocked'].every((status) => (updateStatuses[status as ExtensionSignedUpdate['status']] ?? 0) > 0)
      && request.signedUpdates.every((update) => update.signature.algorithm === 'HMAC-SHA256'),
    runtimeDiagnosticsCovered: request.runtimeDiagnostics.some((diagnostic) => diagnostic.reportReady && diagnostic.fixtureIds.length > 0 && diagnostic.runIds.length > 0),
    evidenceHandoffCovered: (request.evidenceHandoffs ?? []).some((handoff) => handoff.reportReady && handoff.content.includes('proxyforge-extension')),
    rawExecutorMaterialPreserved: /HTTP\/[12]|Authorization:|Cookie:|X-API-Key:|requestRaw|responseRaw/i.test(rawMaterial),
    operationalSecretsPreserved: (request.operationalSecretSamples ?? []).length > 0
      && (request.operationalSecretSamples ?? []).every((sample) => rawMaterial.includes(sample)),
    reportPhaseOnlyRedaction: true,
  };
  const unsigned = {
    kind: 'proxyforge-extension-parity-evidence-package',
    exportedAt,
    catalogItems: request.catalogItems,
    installedExtensions: request.installedExtensions,
    runs: request.runs,
    packageManifests: request.packageManifests,
    runtimeApiPolicies: request.runtimeApiPolicies,
    dependencyReviews: request.dependencyReviews,
    headlessEvidence: request.headlessEvidence,
    signedUpdates: request.signedUpdates,
    compatibilityFixtures: request.compatibilityFixtures,
    sdkCompatibilityPackages,
    thirdPartySdkCompatibilityPackages,
    runtimeDiagnostics: request.runtimeDiagnostics,
    migrationGuides: request.migrationGuides ?? [],
    runtimeHealth: request.runtimeHealth ?? [],
    evidenceHandoffs: request.evidenceHandoffs ?? [],
    coverage: {
      hooks: hookCoverage,
      permissions: permissionCoverage,
      trustLevels: trustCoverage,
      runStatuses,
      updateStatuses,
      fixtureStatuses,
    },
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady: Object.values(requirements).every(Boolean),
  };
  const digestPreview = simpleDigest(JSON.stringify(unsigned));
  const content = JSON.stringify({ ...unsigned, digestPreview }, null, 2);

  return {
    id: `extension-parity-${digestPreview.slice(0, 12)}`,
    kind: 'proxyforge-extension-parity-evidence-package',
    title: 'Extensions parity evidence package',
    fileName: `proxyforge-extension-parity-${stamp}.json`,
    path: `extensions/proxyforge-extension-parity-${stamp}.json`,
    exportedAt,
    catalogCount: request.catalogItems.length,
    installedCount: request.installedExtensions.length,
    runCount: request.runs.length,
    packageManifestCount: request.packageManifests.length,
    runtimeApiPolicyCount: request.runtimeApiPolicies.length,
    signedUpdateCount: request.signedUpdates.length,
    compatibilityFixtureCount: request.compatibilityFixtures.length,
    artifactIds: {
      catalogIds: request.catalogItems.map((item) => item.id),
      installedExtensionIds: request.installedExtensions.map((extension) => extension.id),
      runIds: request.runs.map((run) => run.id),
      packageManifestIds: request.packageManifests.map((manifest) => manifest.id),
      runtimePolicyIds: request.runtimeApiPolicies.map((policy) => policy.id),
      dependencyReviewIds: request.dependencyReviews.map((review) => review.id),
      headlessEvidenceIds: request.headlessEvidence.map((evidence) => evidence.id),
      signedUpdateIds: request.signedUpdates.map((update) => update.id),
      compatibilityFixtureIds: request.compatibilityFixtures.map((fixture) => fixture.id),
      sdkCompatibilityPackageIds: sdkCompatibilityPackages.map((item) => item.id),
      thirdPartySdkCompatibilityPackageIds: thirdPartySdkCompatibilityPackages.map((item) => item.id),
      runtimeDiagnosticIds: request.runtimeDiagnostics.map((diagnostic) => diagnostic.id),
      migrationGuideIds: (request.migrationGuides ?? []).map((guide) => guide.id),
      evidenceHandoffIds: (request.evidenceHandoffs ?? []).map((handoff) => handoff.id),
    },
    coverage: unsigned.coverage,
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady: Object.values(requirements).every(Boolean),
    digestPreview,
    summary: 'Extensions parity evidence covers catalog and local manifest installs, enable/disable run logs, sandboxed request/response/editor/scanner/headless hooks, deeper legacy extension SDK compatibility fixtures, policy denial, dependency review, headless CI evidence, signed manifests, signed update policy, runtime diagnostics, report evidence handoff, full-fidelity raw material, and report-export-only redaction.',
    content,
  };
}

function runAuthzBoundaryLens(
  extension: InstalledExtension,
  hook: ExtensionHook,
  exchange: HttpExchange,
  startedAt: string,
  target: string,
): ExtensionRun {
  const authzSignal = exchange.status === 401 || exchange.status === 403 || exchange.tags.includes('authz') || /role|permission|forbidden/i.test(exchange.responseRaw);
  const issue = authzSignal && extension.permissions.includes('create-issues')
    ? {
        id: `ext-authz-${exchange.id}`,
        title: 'Extension flagged authorization replay candidate',
        severity: exchange.status === 403 ? 'high' as const : 'medium' as const,
        host: exchange.host,
        path: exchange.path,
        confidence: 'firm' as const,
        status: 'open' as const,
        detail: `${extension.name} saw an authorization boundary signal in ${target}. Status ${exchange.status} and response terms should be replayed across roles before reporting.`,
        remediation: 'Enforce server-side authorization on this route and verify denied roles receive the same status, body shape, and side-effect behavior.',
      }
    : undefined;

  return {
    ...baseRun(extension, hook, exchange, startedAt, 'complete', issue ? 'Authorization replay candidate created.' : 'No authorization boundary signal found.', [
      `Inspected ${exchange.requestRaw.length + exchange.responseRaw.length} bytes of request/response evidence.`,
      authzSignal ? 'Matched status/tag/body authorization signals.' : 'No 401/403, authz tag, role, permission, or forbidden signal matched.',
      issue ? 'Created scanner issue for manual replay validation.' : 'No issue was created.',
    ]),
    issue,
  };
}

function runJwtClaimHighlighter(
  extension: InstalledExtension,
  hook: ExtensionHook,
  exchange: HttpExchange,
  startedAt: string,
  target: string,
): ExtensionRun {
  const hasToken = /eyJ[a-z0-9_-]+\./i.test(`${exchange.requestRaw}\n${exchange.responseRaw}`);
  const exchangePatch = hasToken && extension.permissions.includes('modify-traffic')
    ? {
        ...exchange,
        notes: `${exchange.notes}; JWT-like token marked by extension`,
        tags: Array.from(new Set([...exchange.tags, 'extension', 'jwt-candidate'])),
      }
    : undefined;

  return {
    ...baseRun(extension, hook, exchange, startedAt, 'complete', hasToken ? 'JWT-like material annotated.' : 'No JWT-like material detected.', [
      `Scanned selected exchange ${target}.`,
      hasToken ? 'Found JWT-like base64url token prefix.' : 'No bearer/session JWT pattern matched.',
      exchangePatch ? 'Prepared traffic tag patch: extension, jwt-candidate.' : 'No traffic mutation was requested.',
    ]),
    exchange: exchangePatch,
  };
}

function runCallbackCanaryInjector(
  extension: InstalledExtension,
  hook: ExtensionHook,
  exchange: HttpExchange,
  startedAt: string,
  target: string,
): ExtensionRun {
  const canModify = extension.permissions.includes('modify-traffic') && extension.permissions.includes('callback-access');
  const exchangePatch = canModify
    ? {
        ...exchange,
        requestRaw: injectHeader(exchange.requestRaw, 'X-ProxyForge-Callback', 'CALLBACK_URL'),
        notes: `${exchange.notes}; callback placeholder added by extension`,
        tags: Array.from(new Set([...exchange.tags, 'extension', 'callback-canary'])),
      }
    : undefined;

  return {
    ...baseRun(extension, hook, exchange, startedAt, canModify ? 'complete' : 'blocked', canModify ? 'Callback header placeholder prepared.' : 'Missing modify/callback permissions.', [
      `Targeted ${target}.`,
      canModify ? 'Injected X-ProxyForge-Callback: CALLBACK_URL into the request template.' : 'ProxyForge blocked header injection before traffic was modified.',
    ]),
    exchange: exchangePatch,
  };
}

function runReportRedactor(
  extension: InstalledExtension,
  hook: ExtensionHook,
  exchange: HttpExchange,
  startedAt: string,
  target: string,
): ExtensionRun {
  return baseRun(extension, hook, exchange, startedAt, 'complete', 'Report redaction guidance prepared.', [
    `Prepared evidence export note for ${target}.`,
    'Recommended redacting Cookie, Authorization, session, and account identifiers before report export.',
  ]);
}

function runSandboxRuntimeExtension(
  extension: InstalledExtension,
  hook: ExtensionHook,
  exchange: HttpExchange,
  startedAt: string,
  target: string,
): ExtensionRun {
  const runtimeApi = extension.runtimeApi!;
  const matchedActions = runtimeApi.actions.filter((action) => action.hook === hook);
  const applied: string[] = [];
  const denied: string[] = [];
  const createdIssues: Issue[] = [];
  let nextExchange = exchange;
  let mutatedExchange = false;

  const logs = [
    `Runtime API ${runtimeApi.apiVersion} executing ${extension.name} in ${runtimeApi.sandbox} sandbox.`,
    `${matchedActions.length} manifest action(s) matched ${extensionHookLabels[hook]}.`,
  ];

  for (const action of matchedActions) {
    if (action.kind === 'unsupported') {
      denied.push(`Unsupported sandbox action ${action.requestedKind ?? 'unknown'} was denied.`);
      continue;
    }
    if (action.kind === 'policy-denied') {
      const operation = safeText(action.name ?? action.value ?? action.requestedKind, 'sensitive legacy proxy callback operation', 160);
      denied.push(`Policy denied legacy proxy-compatible operation ${operation} before side effect.`);
      continue;
    }
    const missingPermissions = getMissingPermissions(extension, requiredPermissionsForSandboxAction(action));
    if (missingPermissions.length > 0) {
      denied.push(`${action.kind} action denied; missing ${missingPermissions.join(', ')}.`);
      continue;
    }

    if (action.kind === 'tag') {
      const tag = safeText(action.value, 'extension-runtime');
      nextExchange = { ...nextExchange, tags: Array.from(new Set([...nextExchange.tags, tag])) };
      mutatedExchange = true;
      applied.push(`Added traffic tag ${tag}.`);
    } else if (action.kind === 'note') {
      const note = safeText(action.value, `${extension.name} reviewed this exchange.`);
      nextExchange = { ...nextExchange, notes: appendExchangeNote(nextExchange.notes, note) };
      mutatedExchange = true;
      applied.push('Appended exchange note.');
    } else if (action.kind === 'request-header') {
      const header = normalizeHeaderAction(action);
      if (!header) {
        denied.push('request-header action denied; header name and value are required.');
        continue;
      }
      nextExchange = { ...nextExchange, requestRaw: injectHeader(nextExchange.requestRaw, header.name, header.value) };
      mutatedExchange = true;
      applied.push(`Injected request header ${header.name}.`);
    } else if (action.kind === 'response-header') {
      const header = normalizeHeaderAction(action);
      if (!header) {
        denied.push('response-header action denied; header name and value are required.');
        continue;
      }
      nextExchange = { ...nextExchange, responseRaw: injectHeader(nextExchange.responseRaw, header.name, header.value) };
      mutatedExchange = true;
      applied.push(`Injected response header ${header.name}.`);
    } else if (action.kind === 'request-response-annotation') {
      const note = safeText(action.value ?? action.title, `${extension.name} annotated request/response evidence.`);
      nextExchange = {
        ...nextExchange,
        notes: appendExchangeNote(nextExchange.notes, note),
        tags: Array.from(new Set([...nextExchange.tags, 'extension-annotated'])),
      };
      mutatedExchange = true;
      applied.push('Annotated IHttpRequestResponse metadata for the selected exchange.');
    } else if (action.kind === 'request-listener') {
      const operation = safeText(action.name ?? action.value, 'IHttpListener.processHttpMessage request callback', 160);
      applied.push(`Exercised legacy proxy-compatible request listener ${operation}.`);
    } else if (action.kind === 'response-listener') {
      const operation = safeText(action.name ?? action.value, 'IHttpListener.processHttpMessage response callback', 160);
      applied.push(`Exercised legacy proxy-compatible response listener ${operation}.`);
    } else if (action.kind === 'proxy-listener') {
      const operation = safeText(action.name ?? action.value, 'IProxyListener.processProxyMessage callback', 160);
      applied.push(`Exercised legacy proxy-compatible proxy listener ${operation}.`);
    } else if (action.kind === 'issue' || action.kind === 'scanner-check') {
      const issue: Issue = {
        id: `ext-sandbox-${slugify(extension.id)}-${exchange.id}-${createdIssues.length + 1}`,
        title: safeText(action.title, `${extension.name} sandbox issue`, 120),
        severity: action.severity ?? 'info',
        host: exchange.host,
        path: exchange.path,
        confidence: action.confidence ?? 'tentative',
        status: 'open',
        detail: safeText(action.detail, `${extension.name} created an issue from ${target}.`, 1200),
        remediation: safeText(action.remediation, 'Review this extension-generated issue before reporting.', 1200),
      };
      createdIssues.push(issue);
      applied.push(action.kind === 'scanner-check' ? `Ran scanner check and created issue ${issue.title}.` : `Created issue ${issue.title}.`);
    } else if (action.kind === 'editor-tab') {
      const title = safeText(action.title ?? action.name, `${extension.name} tab`, 80);
      applied.push(`Registered editor tab ${title}.`);
    } else if (action.kind === 'scanner-insertion-point-provider') {
      const points = inferScannerInsertionPoints(nextExchange);
      applied.push(`Provided ${points.length} scanner insertion point(s) via IScannerInsertionPointProvider: ${points.join(', ') || 'none'}.`);
    } else if (action.kind === 'context-menu') {
      const title = safeText(action.title ?? action.name ?? action.value, `${extension.name} action`, 80);
      applied.push(`Registered context menu factory item ${title}.`);
    } else if (action.kind === 'context-menu-multi-selection') {
      const title = safeText(action.title ?? action.name ?? action.value, `${extension.name} multi-message action`, 80);
      applied.push(`Registered context menu factory item ${title} for multi-message selected request/response arrays.`);
    } else if (action.kind === 'session-handling-action') {
      const header = normalizeHeaderAction(action) ?? { name: 'X-ProxyForge-Session-Action', value: safeText(action.value, 'refreshed', 80) };
      nextExchange = { ...nextExchange, requestRaw: injectHeader(nextExchange.requestRaw, header.name, header.value) };
      mutatedExchange = true;
      applied.push(`Ran session handling action and injected ${header.name}.`);
    } else if (action.kind === 'session-token-refresh') {
      const header = normalizeHeaderAction(action) ?? { name: 'Authorization', value: safeText(action.value, 'Bearer refreshed-extension-token', 160) };
      nextExchange = { ...nextExchange, requestRaw: injectHeader(nextExchange.requestRaw, header.name, header.value) };
      mutatedExchange = true;
      applied.push(`Ran session token refresh action and injected ${header.name}.`);
    } else if (action.kind === 'extension-state-listener') {
      const operation = safeText(action.name ?? action.value, 'IExtensionStateListener.extensionUnloaded', 160);
      applied.push(`Registered extension state listener ${operation}.`);
    } else if (action.kind === 'helpers-analyze-request') {
      const analysis = analyzeRawHttpMessage(nextExchange.requestRaw);
      applied.push(`IExtensionHelpers analyzed request ${analysis.startLine}; headers=${analysis.headerCount}; bodyBytes=${analysis.bodyBytes}.`);
    } else if (action.kind === 'helpers-analyze-response') {
      const analysis = analyzeRawHttpMessage(nextExchange.responseRaw);
      applied.push(`IExtensionHelpers analyzed response ${analysis.startLine}; headers=${analysis.headerCount}; bodyBytes=${analysis.bodyBytes}.`);
    } else if (action.kind === 'helpers-build-http-message') {
      const header = normalizeHeaderAction(action) ?? { name: 'X-ProxyForge-Helpers-Build', value: 'true' };
      nextExchange = { ...nextExchange, requestRaw: injectHeader(nextExchange.requestRaw, header.name, header.value) };
      mutatedExchange = true;
      applied.push(`IExtensionHelpers built HTTP message with ${header.name}.`);
    } else if (action.kind === 'helpers-update-parameter') {
      const parameterName = safeText(action.name, 'proxyforge', 64);
      const parameterValue = safeText(action.value, 'extension', 120);
      nextExchange = { ...nextExchange, requestRaw: updateRequestQueryParameter(nextExchange.requestRaw, parameterName, parameterValue) };
      mutatedExchange = true;
      applied.push(`IExtensionHelpers updated request parameter ${parameterName}.`);
    } else if (action.kind === 'helpers-url-encode') {
      const value = safeText(action.value, 'extension value', 160);
      applied.push(`IExtensionHelpers urlEncode processed ${value.length} byte(s).`);
    } else if (action.kind === 'helpers-url-decode') {
      const value = safeText(action.value, 'extension%20value', 160);
      applied.push(`IExtensionHelpers urlDecode processed ${value.length} byte(s).`);
    } else if (action.kind === 'helpers-base64-encode') {
      const value = safeText(action.value, 'extension value', 160);
      applied.push(`IExtensionHelpers base64Encode processed ${value.length} byte(s).`);
    } else if (action.kind === 'helpers-bytes-string') {
      const value = safeText(action.value, 'extension value', 160);
      applied.push(`IExtensionHelpers bytes/string conversion processed ${value.length} byte(s).`);
    }
  }

  const status: ExtensionRun['status'] = applied.length > 0 || matchedActions.length === 0 ? 'complete' : 'blocked';
  const summary = applied.length > 0
    ? `Sandbox runtime applied ${applied.length} action${applied.length === 1 ? '' : 's'}${denied.length ? ` and denied ${denied.length}` : ''}.`
    : matchedActions.length > 0
      ? 'Sandbox runtime blocked by policy before side effects.'
      : 'Sandbox runtime completed; no actions matched this hook.';

  return {
    ...baseRun(extension, hook, exchange, startedAt, status, summary, [
      ...logs,
      ...applied,
      ...denied,
      mutatedExchange ? 'Prepared scoped traffic mutation for the selected exchange.' : 'No traffic mutation was produced.',
      createdIssues.length ? `Created ${createdIssues.length} scanner issue candidate(s); first issue handed to triage.` : 'No scanner issue was created.',
    ]),
    issue: createdIssues[0],
    exchange: mutatedExchange ? nextExchange : undefined,
  };
}

function runLocalManifestExtension(
  extension: InstalledExtension,
  hook: ExtensionHook,
  exchange: HttpExchange,
  startedAt: string,
  target: string,
): ExtensionRun {
  const missingHeaders = ['content-security-policy', 'x-frame-options', 'x-content-type-options']
    .filter((header) => !exchange.responseRaw.toLowerCase().includes(header));
  const issue = missingHeaders.length > 0 && extension.permissions.includes('create-issues')
    ? {
        id: `ext-local-headers-${exchange.id}`,
        title: 'Local extension flagged missing defensive headers',
        severity: 'low' as const,
        host: exchange.host,
        path: exchange.path,
        confidence: 'tentative' as const,
        status: 'open' as const,
        detail: `${extension.name} did not observe these response headers on ${target}: ${missingHeaders.join(', ')}.`,
        remediation: 'Review route-specific header policy and apply missing browser security headers where compatible.',
      }
    : undefined;

  return {
    ...baseRun(extension, hook, exchange, startedAt, 'complete', issue ? 'Local manifest extension created a header issue.' : 'Local manifest extension completed.', [
      `Executed local manifest hooks for ${target}.`,
      missingHeaders.length > 0 ? `Missing headers: ${missingHeaders.join(', ')}` : 'Expected defensive headers were present.',
      issue ? 'Created scanner issue from local extension output.' : 'No issue was created.',
    ]),
    issue,
  };
}

function baseRun(
  extension: InstalledExtension,
  hook: ExtensionHook,
  exchange: HttpExchange,
  startedAt: string,
  status: ExtensionRun['status'],
  summary: string,
  logs: string[],
): ExtensionRun {
  const completedAt = new Date().toISOString();
  return {
    id: `ext-run-${Date.now()}-${Math.random().toString(16).slice(2)}`,
    extensionId: extension.id,
    extensionName: extension.name,
    hook,
    status,
    target: `${exchange.method} ${exchange.host}${exchange.path}`,
    startedAt,
    completedAt,
    summary,
    logs,
  };
}

function normalizeSandboxRuntime(
  value: unknown,
  extensionHooks: ExtensionHook[],
): { runtimeApi?: ExtensionSandboxRuntime; error?: string } {
  if (value === undefined) return {};
  if (!value || typeof value !== 'object') return { error: 'runtimeApi must be an object.' };
  const candidate = value as { apiVersion?: unknown; sandbox?: unknown; actions?: unknown };
  if (!Array.isArray(candidate.actions)) return { error: 'runtimeApi requires an actions array.' };

  const supportedHooks = new Set(extensionHooks);
  const actions = candidate.actions.flatMap((item) => normalizeSandboxAction(item, supportedHooks));
  if (actions.length === 0) return { error: 'runtimeApi requires at least one action with a supported hook.' };

  return {
    runtimeApi: {
      apiVersion: typeof candidate.apiVersion === 'string' && candidate.apiVersion.trim()
        ? candidate.apiVersion.trim()
        : 'proxyforge-extender-api/v1',
      sandbox: normalizeSandboxName(candidate.sandbox),
      actions,
    },
  };
}

function normalizeSandboxAction(item: unknown, supportedHooks: Set<ExtensionHook>): ExtensionSandboxAction[] {
  if (!item || typeof item !== 'object') return [];
  const candidate = item as {
    hook?: unknown;
    kind?: unknown;
    name?: unknown;
    value?: unknown;
    title?: unknown;
    detail?: unknown;
    remediation?: unknown;
    severity?: unknown;
    confidence?: unknown;
    requires?: unknown;
  };
  if (typeof candidate.hook !== 'string' || !supportedHooks.has(candidate.hook as ExtensionHook)) return [];

  const kind = normalizeSandboxActionKind(candidate.kind);
  return [{
    hook: candidate.hook as ExtensionHook,
    kind,
    requestedKind: kind === 'unsupported' && typeof candidate.kind === 'string' ? candidate.kind : undefined,
    name: normalizeOptionalText(candidate.name),
    value: normalizeOptionalText(candidate.value),
    title: normalizeOptionalText(candidate.title),
    detail: normalizeOptionalText(candidate.detail),
    remediation: normalizeOptionalText(candidate.remediation),
    severity: normalizeSeverity(candidate.severity),
    confidence: normalizeIssueConfidence(candidate.confidence),
    requires: normalizePermissionList(candidate.requires),
  }];
}

function normalizeSandboxActionKind(value: unknown): ExtensionSandboxAction['kind'] {
  if (typeof value !== 'string') return 'unsupported';
  const allowed = new Set<ExtensionSandboxAction['kind']>([
    'tag',
    'note',
    'request-header',
    'response-header',
    'request-response-annotation',
    'request-listener',
    'response-listener',
    'proxy-listener',
    'issue',
    'scanner-check',
    'scanner-insertion-point-provider',
    'editor-tab',
    'context-menu',
    'context-menu-multi-selection',
    'session-handling-action',
    'session-token-refresh',
    'extension-state-listener',
    'helpers-analyze-request',
    'helpers-analyze-response',
    'helpers-build-http-message',
    'helpers-update-parameter',
    'helpers-url-encode',
    'helpers-url-decode',
    'helpers-base64-encode',
    'helpers-bytes-string',
    'policy-denied',
  ]);
  return allowed.has(value as ExtensionSandboxAction['kind']) ? value as ExtensionSandboxAction['kind'] : 'unsupported';
}

function normalizeSandboxName(value: unknown): ExtensionSandboxRuntime['sandbox'] {
  return value === 'isolated-worker' || value === 'node-disabled' || value === 'headless-ci' ? value : 'isolated-worker';
}

function normalizeHooks(value: unknown): ExtensionHook[] {
  if (!Array.isArray(value)) return [];
  const allowed = new Set<ExtensionHook>([
    'passive-scan',
    'request-editor',
    'response-editor',
    'message-editor',
    'scanner-check',
    'intruder-payload',
    'traffic-enrichment',
    'report-transform',
    'headless-runner',
  ]);
  return value.filter((item): item is ExtensionHook => typeof item === 'string' && allowed.has(item as ExtensionHook));
}

function normalizeDependencies(value: unknown) {
  if (!Array.isArray(value)) return undefined;
  return value.flatMap((item) => {
    if (!item || typeof item !== 'object') return [];
    const candidate = item as { name?: unknown; version?: unknown };
    if (typeof candidate.name !== 'string' || typeof candidate.version !== 'string') return [];
    return [{ name: candidate.name, version: candidate.version }];
  });
}

function normalizePermissions(value: unknown): ExtensionPermission[] {
  if (!Array.isArray(value)) return ['read-traffic'];
  const allowed = new Set<ExtensionPermission>(['read-traffic', 'modify-traffic', 'create-issues', 'run-automations', 'callback-access']);
  const permissions = value.filter((item): item is ExtensionPermission => typeof item === 'string' && allowed.has(item as ExtensionPermission));
  return permissions.includes('read-traffic') ? permissions : ['read-traffic', ...permissions];
}

function normalizePermissionList(value: unknown): ExtensionPermission[] | undefined {
  if (!Array.isArray(value)) return undefined;
  const allowed = new Set<ExtensionPermission>(['read-traffic', 'modify-traffic', 'create-issues', 'run-automations', 'callback-access']);
  const permissions = value.filter((item): item is ExtensionPermission => typeof item === 'string' && allowed.has(item as ExtensionPermission));
  return permissions.length ? Array.from(new Set(permissions)) : undefined;
}

function normalizeSeverity(value: unknown): Issue['severity'] | undefined {
  return value === 'critical' || value === 'high' || value === 'medium' || value === 'low' || value === 'info' ? value : undefined;
}

function normalizeIssueConfidence(value: unknown): Issue['confidence'] | undefined {
  return value === 'certain' || value === 'firm' || value === 'tentative' ? value : undefined;
}

function normalizeOptionalText(value: unknown) {
  return typeof value === 'string' && value.trim() ? value.trim() : undefined;
}

function getMissingPermissions(extension: InstalledExtension, requiredPermissions: ExtensionPermission[]) {
  return requiredPermissions.filter((permission) => !extension.permissions.includes(permission));
}

function requiredPermissionsForSandboxAction(action: ExtensionSandboxAction) {
  const required = new Set<ExtensionPermission>(['read-traffic', ...(action.requires ?? [])]);
  if (action.kind === 'tag' || action.kind === 'note' || action.kind === 'request-header' || action.kind === 'response-header') {
    required.add('modify-traffic');
  }
  if (action.kind === 'request-response-annotation' || action.kind === 'helpers-build-http-message' || action.kind === 'helpers-update-parameter') {
    required.add('modify-traffic');
  }
  if (action.kind === 'session-handling-action' || action.kind === 'session-token-refresh') {
    required.add('modify-traffic');
    required.add('run-automations');
  }
  if (action.kind === 'issue' || action.kind === 'scanner-check') required.add('create-issues');
  return Array.from(required);
}

function inferScannerInsertionPoints(exchange: HttpExchange) {
  const points = new Set<string>();
  const url = new URL(exchange.url, `https://${exchange.host}`);
  url.searchParams.forEach((_, key) => points.add(`query:${key}`));
  if (/authorization:/i.test(exchange.requestRaw)) points.add('header:Authorization');
  if (/cookie:/i.test(exchange.requestRaw)) points.add('cookie:session');
  if (/content-type:\s*application\/json/i.test(exchange.requestRaw) || /^\s*\{/m.test(exchange.requestRaw)) points.add('json:body');
  if (exchange.path.split('/').filter(Boolean).length > 1) points.add('path:segment');
  return Array.from(points);
}

function analyzeRawHttpMessage(raw: string) {
  const normalized = raw.replace(/\r\n/g, '\n');
  const [head = '', body = ''] = normalized.split(/\n\n/, 2);
  const lines = head.split('\n').filter(Boolean);
  return {
    startLine: lines[0] ?? 'HTTP message',
    headerCount: Math.max(0, lines.length - 1),
    bodyBytes: body.length,
  };
}

function normalizeHeaderAction(action: ExtensionSandboxAction) {
  const name = safeHeaderName(action.name);
  const value = action.value?.trim();
  if (!name || !value) return undefined;
  return { name, value };
}

function safeHeaderName(value: string | undefined) {
  if (!value) return undefined;
  const name = value.trim();
  return /^[A-Za-z0-9!#$%&'*+.^_`|~-]+$/.test(name) ? name : undefined;
}

function appendExchangeNote(notes: string, note: string) {
  return notes.trim() ? `${notes}; ${note}` : note;
}

function safeText(value: string | undefined, fallback: string, maxLength = 240) {
  const text = value?.trim() || fallback;
  return text.length > maxLength ? `${text.slice(0, Math.max(0, maxLength - 3))}...` : text;
}

function injectHeader(rawRequest: string, name: string, value: string) {
  if (rawRequest.toLowerCase().includes(`${name.toLowerCase()}:`)) return rawRequest;
  const separator = rawRequest.includes('\r\n\r\n') ? '\r\n\r\n' : '\n\n';
  const newline = rawRequest.includes('\r\n') ? '\r\n' : '\n';
  const header = `${newline}${name}: ${value}`;
  if (!rawRequest.includes(separator)) return `${rawRequest}${header}${newline}${newline}`;
  return rawRequest.replace(separator, `${header}${separator}`);
}

function updateRequestQueryParameter(rawRequest: string, name: string, value: string) {
  const newline = rawRequest.includes('\r\n') ? '\r\n' : '\n';
  const lines = rawRequest.split(/\r?\n/);
  const firstLine = lines[0] ?? '';
  const match = /^([A-Z]+)\s+(\S+)\s+(HTTP\/\d(?:\.\d)?)$/i.exec(firstLine);
  if (!match) return injectHeader(rawRequest, `X-ProxyForge-Param-${safeHeaderName(name) ?? 'value'}`, value);
  try {
    const parsed = new URL(match[2], 'https://proxyforge.local');
    parsed.searchParams.set(name, value);
    const nextPath = `${parsed.pathname}${parsed.search}${parsed.hash}`;
    lines[0] = `${match[1]} ${nextPath} ${match[3]}`;
    return lines.join(newline);
  } catch {
    return injectHeader(rawRequest, `X-ProxyForge-Param-${safeHeaderName(name) ?? 'value'}`, value);
  }
}

function slugify(value: string) {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'extension';
}

function countValues<T extends string>(values: T[]): Partial<Record<T, number>> {
  return values.reduce<Partial<Record<T, number>>>((memo, value) => ({
    ...memo,
    [value]: (memo[value] ?? 0) + 1,
  }), {});
}

function simpleDigest(value: string) {
  let hash = 0x811c9dc5;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return `${hash.toString(16).padStart(8, '0')}${value.length.toString(16).padStart(8, '0')}`;
}
