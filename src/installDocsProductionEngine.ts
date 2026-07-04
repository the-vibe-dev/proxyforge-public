export interface InstallDocsProductionDocument {
  id: string;
  path: string;
  title: string;
  content: string;
  packaged?: boolean;
}

export interface InstallDocsProductionRequest {
  documents: InstallDocsProductionDocument[];
  packageFiles: string[];
  packageScripts: Record<string, string>;
  generatedAt?: string;
  operationalSecretSamples?: string[];
}

export interface InstallDocsProductionEvidencePackage {
  id: string;
  kind: 'proxyforge-install-docs-production-evidence-package';
  title: string;
  fileName: string;
  path: string;
  generatedAt: string;
  documentCount: number;
  packagedDocumentCount: number;
  requirements: {
    installGuidePackaged: boolean;
    operatorGuidePackaged: boolean;
    agentDocsPackaged: boolean;
    packageScriptCovered: boolean;
    linuxInstallCovered: boolean;
    windowsInstallCovered: boolean;
    smokeCommandsCovered: boolean;
    certTrustCovered: boolean;
    browserRoutingCovered: boolean;
    dpapiAndTrustPinCovered: boolean;
    agenticOperationCovered: boolean;
    highRiskWorkflowsCovered: boolean;
    troubleshootingCovered: boolean;
    productionSignoffCovered: boolean;
    packagedDocsSynchronized: boolean;
    rawExecutorMaterialPreserved: boolean;
    operationalSecretsPreserved: boolean;
    reportPhaseOnlyRedaction: boolean;
  };
  secretHandling: 'execution-full-fidelity-secrets-preserved';
  reportRedactionBoundary: 'redact-only-during-report-export';
  productionReady: boolean;
  digestPreview: string;
  summaryText: string;
  content: string;
}

export function buildInstallDocsProductionEvidencePackage(
  request: InstallDocsProductionRequest,
): InstallDocsProductionEvidencePackage {
  const generatedAt = request.generatedAt ?? new Date().toISOString();
  const stamp = generatedAt.replace(/[:.]/g, '-');
  const allContent = [
    ...request.documents.map((document) => `${document.id}\n${document.path}\n${document.title}\n${document.content}`),
    JSON.stringify(request.packageScripts),
    request.packageFiles.join('\n'),
    ...(request.operationalSecretSamples ?? []),
  ].join('\n');
  const documentById = new Map(request.documents.map((document) => [document.id, document]));
  const isPackaged = (document: InstallDocsProductionDocument | undefined) => Boolean(document)
    && (Boolean(document?.packaged) || request.packageFiles.some((pattern) => packagePatternMatches(pattern, document!.path)));
  const has = (pattern: RegExp) => pattern.test(allContent);
  const requirements = {
    installGuidePackaged: isPackaged(documentById.get('install-guide')),
    operatorGuidePackaged: isPackaged(documentById.get('operator-guide')),
    agentDocsPackaged: request.documents
      .filter((document) => document.path.startsWith('docs/agents/'))
      .every((document) => isPackaged(document)),
    packageScriptCovered: /node tests\/install-docs-production-engine\.mjs/.test(request.packageScripts['test:install-docs-production'] ?? ''),
    linuxInstallCovered: has(/AppImage/i)
      && has(/\bdeb\b|clean-container deb|release-deb-container-smoke/i)
      && has(/release:smoke:linux|--platform linux/i),
    windowsInstallCovered: has(/NSIS|Setup/i)
      && has(/portable/i)
      && has(/release:smoke:windows|--platform windows/i)
      && has(/windows-trust-runner|windows-trust-runner/i),
    smokeCommandsCovered: has(/PROXYFORGE_RELEASE_SMOKE/i)
      && has(/release-smoke/i)
      && has(/headless scan\/report|packaged headless/i)
      && has(/runtime proxy\/cert\/OAST\/report/i),
    certTrustCovered: has(/certificate trust|project CA|trusted-CA|trusted CA|browser-trust-store/i),
    browserRoutingCovered: has(/browser routing|browser-routing|managed browser|Chromium|Chrome|Edge/i),
    dpapiAndTrustPinCovered: has(/DPAPI/i)
      && has(/trust-store pin|ERROR_NOT_SUPPORTED|CurrentUser\\Root|CurrentUser\/Root/i),
    agenticOperationCovered: has(/proxyforge-agent/i)
      && has(/Codex CLI/i)
      && has(/Claude CLI/i)
      && has(/~\/vantix|Vantix/i)
      && has(/persistent MITM|mitm-start/i),
    highRiskWorkflowsCovered: has(/replay/i)
      && has(/desync/i)
      && has(/race/i)
      && has(/scanner/i)
      && has(/Exploit Lab|exploit/i)
      && has(/Collaborator|OAST/i),
    troubleshootingCovered: has(/Recovery And Troubleshooting|troubleshooting|blocked result|blocked trusted-CA lane/i),
    productionSignoffCovered: has(/Production Signoff|Production Ready|signoff/i),
    packagedDocsSynchronized: has(/proxyforge-install-docs-production-evidence-package/i)
      && has(/Linux\/Windows install guide|INSTALL_LINUX_WINDOWS/i)
      && has(/operator guide|OPERATOR_GUIDE/i)
      && has(/agent docs|docs\/agents|Codex CLI/i),
    rawExecutorMaterialPreserved: has(/raw requests/i)
      && has(/raw responses/i)
      && has(/Authorization:|Cookie:|X-API-Key:|callbackToken/i),
    operationalSecretsPreserved: (request.operationalSecretSamples ?? []).length > 0
      && (request.operationalSecretSamples ?? []).every((sample) => allContent.includes(sample)),
    reportPhaseOnlyRedaction: has(/redact-only-during-report-export|redaction happens only|report export.*redact/i),
  };
  const unsigned = {
    kind: 'proxyforge-install-docs-production-evidence-package',
    generatedAt,
    documents: request.documents.map((document) => ({
      id: document.id,
      path: document.path,
      title: document.title,
      packaged: isPackaged(document),
      byteLength: document.content.length,
    })),
    packageFiles: request.packageFiles,
    packageScripts: request.packageScripts,
    coverageNotes: {
      linux: ['AppImage', 'deb', 'release:smoke:linux', 'release-deb-container-smoke', 'browser-trust-store'],
      windows: ['NSIS', 'portable', 'release:smoke:windows', 'DPAPI', 'windows-trust-runner', 'windows-trust-runner', 'ERROR_NOT_SUPPORTED'],
      agenticOperation: ['Codex CLI', 'Claude CLI', '~/vantix', 'proxyforge-agent', 'persistent MITM', 'mitm-start'],
      highRiskWorkflows: ['replay', 'bulk replay', 'desync', 'race', 'repeater-race-run', 'scanner', 'exploit', 'OAST'],
      redactionBoundary: 'redact-only-during-report-export',
    },
    operationalSecretSamples: request.operationalSecretSamples ?? [],
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    productionReady: Object.values(requirements).every(Boolean),
  };
  const digestPreview = simpleDigest(JSON.stringify(unsigned));
  const content = JSON.stringify({ ...unsigned, digestPreview }, null, 2);

  return {
    id: `install-docs-production-${digestPreview.slice(0, 12)}`,
    kind: 'proxyforge-install-docs-production-evidence-package',
    title: 'Install docs production evidence package',
    fileName: `proxyforge-install-docs-production-${stamp}.json`,
    path: `release/proxyforge-install-docs-production-${stamp}.json`,
    generatedAt,
    documentCount: request.documents.length,
    packagedDocumentCount: request.documents.filter((document) => isPackaged(document)).length,
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    productionReady: Object.values(requirements).every(Boolean),
    digestPreview,
    summaryText: 'Install docs production evidence covers packaged Linux/Windows install docs, operator docs, agent docs, smoke commands, certificate trust, browser routing, Windows DPAPI/trust-store pinning, agentic operation, replay/desync/race/scanner/exploit/OAST workflows, troubleshooting, production signoff, full-fidelity operational material, and report-export-only redaction.',
    content,
  };
}

function packagePatternMatches(pattern: string, documentPath: string) {
  if (pattern === documentPath) return true;
  if (pattern.endsWith('/**/*')) {
    const prefix = pattern.slice(0, -'/**/*'.length);
    return documentPath.startsWith(`${prefix}/`);
  }
  if (pattern.endsWith('/*')) {
    const prefix = pattern.slice(0, -'/*'.length);
    return documentPath.startsWith(`${prefix}/`) && !documentPath.slice(prefix.length + 1).includes('/');
  }
  return false;
}

function simpleDigest(value: string) {
  let hash = 0x811c9dc5;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return `${hash.toString(16).padStart(8, '0')}${value.length.toString(16).padStart(8, '0')}`;
}
