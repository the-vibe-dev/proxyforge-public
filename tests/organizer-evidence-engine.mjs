import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import path from 'node:path';
import vm from 'node:vm';

const require = createRequire(import.meta.url);
const ts = require('typescript');

const expectedExports = ['buildOrganizerParityEvidencePackage'];
const enginePath = path.resolve('src/organizerEvidenceEngine.ts');
const organizerEvidenceEngine = normalizeModuleExports(await loadEngine(enginePath));
const missingExports = expectedExports.filter((name) => typeof organizerEvidenceEngine[name] !== 'function');
assert.deepEqual(missingExports, [], `organizer-evidence-engine: missing export(s): ${missingExports.join(', ')}`);

const sample = buildSampleContext();
const parityPackage = organizerEvidenceEngine.buildOrganizerParityEvidencePackage(sample);
const parityContent = JSON.parse(parityPackage.content);

assert.equal(parityPackage.kind, 'proxyforge-organizer-parity-evidence-package');
assert.equal(parityPackage.secretHandling, 'execution-full-fidelity-secrets-preserved');
assert.equal(parityPackage.reportRedactionBoundary, 'redact-only-during-report-export');
assert.equal(parityPackage.reportReady, true);
assert(Object.values(parityPackage.requirements).every(Boolean), 'all Organizer parity requirements should be true');
assert.equal(parityPackage.collectionCount, 2);
assert.equal(parityPackage.itemCount, 5);
assert.equal(parityPackage.reviewerCount, 3);
assert.equal(parityPackage.packageArtifactCount, 2);
assert.equal(parityPackage.importReviewCount, 2);
assert.equal(parityPackage.conflictAuditCount, 3);
assert.equal(parityContent.kind, 'proxyforge-organizer-parity-evidence-package');
assert.match(parityPackage.content, /Authorization: Bearer organizer-secret-token/);
assert.match(parityPackage.content, /session=organizer-session/);
assert.match(parityPackage.content, /X-API-Key: organizer-api-key/);
assert.match(parityPackage.content, /organizer-passphrase/);
assert.match(parityPackage.content, /organizer-signing-secret/);
assert.match(parityPackage.content, /request_base64,response_base64/);
assert.match(parityPackage.content, /passphrase-sealed|AES-256-GCM|PBKDF2-SHA256-120000/);
assert.match(parityPackage.content, /HMAC-SHA256|valid|trusted signer/);
assert.match(parityPackage.content, /new-only|keep-both|replace-conflicts/);
assert.match(parityPackage.content, /reviewed|merged|kept-both/);
assert.match(parityPackage.content, /redact-only-during-report-export/);

const artifactDir = path.resolve('.gitignored/test-artifacts/organizer-evidence-engine');
await fs.mkdir(artifactDir, { recursive: true });
await fs.writeFile(path.join(artifactDir, 'organizer-parity-evidence-package.json'), parityPackage.content);

console.log('organizer-evidence-engine: exercised collections, reviewer workflow, SLA export, sealed/signed packages, trust review, conflict dedupe, merge modes, and full-fidelity raw material');

async function loadEngine(filePath) {
  const source = await fs.readFile(filePath, 'utf8');
  const transpiled = ts.transpileModule(source, {
    compilerOptions: {
      module: ts.ModuleKind.CommonJS,
      target: ts.ScriptTarget.ES2022,
      esModuleInterop: true,
    },
    fileName: filePath,
  }).outputText;
  const module = { exports: {} };
  const sandbox = {
    module,
    exports: module.exports,
    TextDecoder,
    TextEncoder,
    URL,
    URLSearchParams,
    Buffer,
    console,
    require,
  };
  vm.runInNewContext(transpiled, sandbox, { filename: filePath });
  return module.exports;
}

function normalizeModuleExports(moduleExports) {
  const hasNamedHelper = expectedExports.some((name) => typeof moduleExports[name] === 'function');
  if (hasNamedHelper) return moduleExports;
  if (moduleExports.default && typeof moduleExports.default === 'object') return moduleExports.default;
  return moduleExports;
}

function buildSampleContext() {
  const now = '2026-05-25T22:15:00.000Z';
  const reviewers = [
    { id: 'reviewer-lead', name: 'Lead Reviewer', role: 'AppSec Lead', email: 'lead.reviewer@shop.local' },
    { id: 'reviewer-appsec', name: 'AppSec Analyst', role: 'Security Engineer', email: 'appsec.reviewer@shop.local' },
    { id: 'reviewer-remediation', name: 'Remediation Owner', role: 'Engineering Owner', email: 'remediation@shop.local' },
  ];
  const inboxItems = [
    makeItem('organizer-item-proxy', 'organizer-inbox', 'proxy', 'inbox', 'yellow', reviewers[0], '/api/refunds/101', 'POST', now, '2026-05-24T09:00:00.000Z'),
    makeItem('organizer-item-logger', 'organizer-inbox', 'logger', 'reviewing', 'green', reviewers[1], '/api/refunds/102', 'GET', now, '2026-05-25T23:00:00.000Z'),
    makeItem('organizer-item-repeater', 'organizer-inbox', 'repeater', 'interesting', 'red', reviewers[2], '/api/refunds/103', 'POST', now, '2026-05-27T10:00:00.000Z'),
    makeItem('organizer-item-scanner', 'organizer-inbox', 'scanner', 'done', 'none', reviewers[0], '/api/refunds/104', 'GET', now, '2026-05-24T09:00:00.000Z'),
  ];
  const researchItems = [
    makeItem('organizer-item-search', 'organizer-research', 'search', 'reviewing', 'yellow', reviewers[1], '/api/search/evidence', 'GET', now, '2026-05-26T09:00:00.000Z'),
  ];
  const collections = [
    {
      id: 'organizer-inbox',
      name: 'Inbox',
      description: 'Curated messages from proxy, logger, repeater, scanner, and search.',
      createdAt: now,
      updatedAt: now,
      items: inboxItems,
      shareLink: 'proxyforge://organizer/organizer-inbox',
      lastExportCsv: [
        'time,status,highlight,reviewer,review_due,tool,method,host,path,status_code,length,mime,notes,request_base64,response_base64',
        '2026-05-25T22:15:00.000Z,inbox,yellow,Lead Reviewer,2026-05-24T09:00:00.000Z,proxy,POST,app.shop.local,/api/refunds/101,403,612,application/json,authz evidence,UkVRVUVTVA==,UkVTUE9OU0U=',
      ].join('\n'),
      lastPackageDigest: 'organizer-digest-sealed',
      lastPackageExportedAt: now,
    },
    {
      id: 'organizer-research',
      name: 'Research',
      description: 'Search and viewer triage items for report staging.',
      createdAt: now,
      updatedAt: now,
      items: researchItems,
      shareLink: 'proxyforge://organizer/organizer-research',
      lastExportCsv: 'time,status,highlight,reviewer,review_due,tool,method,host,path,status_code,length,mime,notes,request_base64,response_base64',
    },
  ];
  const reviewerSlaExports = [
    {
      id: 'organizer-sla-export-main',
      fileName: 'organizer-reviewer-sla-2026-05-25T22-15-00-000Z.json',
      path: 'reports/organizer-reviewer-sla-2026-05-25T22-15-00-000Z.json',
      exportedAt: now,
      projectName: 'ProxyForge parity workspace',
      format: 'json',
      collectionIds: collections.map((collection) => collection.id),
      reviewerCount: reviewers.length,
      assignedCount: 5,
      openCount: 4,
      overdueCount: 1,
      dueSoonCount: 1,
      doneCount: 1,
      rows: [
        { reviewerId: reviewers[0].id, reviewerName: reviewers[0].name, reviewerRole: reviewers[0].role, reviewerEmail: reviewers[0].email, assigned: 2, open: 1, overdue: 1, dueSoon: 0, done: 1, oldestOverdueAt: '2026-05-24T09:00:00.000Z', nextDueAt: '2026-05-24T09:00:00.000Z' },
        { reviewerId: reviewers[1].id, reviewerName: reviewers[1].name, reviewerRole: reviewers[1].role, reviewerEmail: reviewers[1].email, assigned: 2, open: 2, overdue: 0, dueSoon: 1, done: 0, nextDueAt: '2026-05-25T23:00:00.000Z' },
        { reviewerId: reviewers[2].id, reviewerName: reviewers[2].name, reviewerRole: reviewers[2].role, reviewerEmail: reviewers[2].email, assigned: 1, open: 1, overdue: 0, dueSoon: 0, done: 0, nextDueAt: '2026-05-27T10:00:00.000Z' },
      ],
      content: '{"kind":"proxyforge-organizer-reviewer-sla","rows":[{"reviewerName":"Lead Reviewer","overdue":1}]}',
    },
  ];
  const packageArtifacts = [
    makePackageArtifact('organizer-package-sealed', 'passphrase-sealed', 'valid', now, ['keep-both', 'replace-conflicts']),
    makePackageArtifact('organizer-package-plain', 'plain', 'signed', now, ['new-only']),
  ];
  const trustPolicyPresets = [
    {
      id: 'organizer-trust-strict',
      name: 'Strict signed organizer packages',
      description: 'Block unsigned and invalid package imports unless signer and key are trusted.',
      pinned: true,
      decisionOnUnsigned: 'blocked',
      decisionOnUnverified: 'warn',
      decisionOnInvalid: 'blocked',
      trustedSignerNames: ['Trusted Organizer'],
      trustedSigningKeyIds: ['organizer-key-1'],
      allowedPackageModes: ['plain', 'passphrase-sealed'],
      createdAt: now,
      updatedAt: now,
    },
  ];
  const collectionDiffs = [
    {
      id: 'organizer-diff-sealed',
      importedAt: now,
      sourceProjectName: 'Imported partner project',
      sourceCollectionId: 'incoming-refunds',
      sourceCollectionName: 'Incoming Refund Evidence',
      targetCollectionId: 'organizer-inbox',
      targetCollectionName: 'Inbox',
      addedItems: 1,
      changedItems: 1,
      duplicateItems: 1,
      reviewerChanges: 1,
      statusChanges: 1,
      dueDateChanges: 1,
      packageDigest: 'organizer-digest-sealed',
      packageMode: 'passphrase-sealed',
      signatureStatus: 'valid',
      signerName: 'Trusted Organizer',
      signingKeyId: 'organizer-key-1',
      signedAt: now,
      trustEvaluation: {
        presetId: 'organizer-trust-strict',
        presetName: 'Strict signed organizer packages',
        decision: 'trusted',
        reasons: ['signature valid for organizer-key-1', 'trusted signer Trusted Organizer'],
        evaluatedAt: now,
      },
      conflictRoutes: [
        {
          route: 'POST app.shop.local/api/refunds/101',
          localStatus: 'inbox',
          incomingStatus: 'reviewing',
          localReviewer: 'Lead Reviewer',
          incomingReviewer: 'AppSec Analyst',
          localDueAt: '2026-05-24T09:00:00.000Z',
          incomingDueAt: '2026-05-26T09:00:00.000Z',
        },
      ],
      collection: collections[0],
    },
    {
      id: 'organizer-diff-plain',
      importedAt: now,
      sourceProjectName: 'Plain export workspace',
      sourceCollectionId: 'plain-evidence',
      sourceCollectionName: 'Plain Evidence',
      targetCollectionId: 'organizer-research',
      targetCollectionName: 'Research',
      addedItems: 1,
      changedItems: 0,
      duplicateItems: 1,
      reviewerChanges: 0,
      statusChanges: 0,
      dueDateChanges: 0,
      packageDigest: 'organizer-digest-plain',
      packageMode: 'plain',
      signatureStatus: 'signed',
      signerName: 'Trusted Organizer',
      signingKeyId: 'organizer-key-1',
      signedAt: now,
      trustEvaluation: {
        presetId: 'organizer-trust-strict',
        presetName: 'Strict signed organizer packages',
        decision: 'warn',
        reasons: ['signature unverified'],
        evaluatedAt: now,
      },
      conflictRoutes: [],
      collection: collections[1],
    },
  ];
  const conflictAuditTrail = [
    makeConflictAudit('organizer-conflict-reviewed', 'reviewed', 'keep-both', collectionDiffs[0], now),
    makeConflictAudit('organizer-conflict-merged', 'merged', 'replace-conflicts', collectionDiffs[0], now),
    makeConflictAudit('organizer-conflict-kept-both', 'kept-both', 'new-only', collectionDiffs[0], now),
  ];

  return {
    projectName: 'ProxyForge parity workspace',
    collections,
    reviewers,
    reviewerSlaExports,
    packageArtifacts,
    collectionDiffs,
    trustPolicyPresets,
    conflictAuditTrail,
    operationalSecretSamples: [
      'organizer-secret-token',
      'organizer-session',
      'organizer-api-key',
      'organizer-passphrase',
      'organizer-signing-secret',
    ],
    exportedAt: now,
  };
}

function makeItem(id, collectionId, originalTool, status, highlight, reviewer, routePath, method, now, dueAt) {
  return {
    id,
    exchangeId: `hx-${id}`,
    collectionId,
    addedAt: now,
    originalTool,
    status,
    highlight,
    reviewerId: reviewer.id,
    reviewerName: reviewer.name,
    reviewDueAt: dueAt,
    notes: `Organizer ${status} note preserving full executor context for ${routePath}.`,
    method,
    host: 'app.shop.local',
    path: routePath,
    url: `https://app.shop.local${routePath}?api_key=organizer-api-key`,
    statusCode: status === 'done' ? 200 : 403,
    length: 600,
    mime: 'application/json',
    risk: status === 'interesting' ? 'high' : 'medium',
    requestRaw: [
      `${method} ${routePath}?api_key=organizer-api-key HTTP/1.1`,
      'Host: app.shop.local',
      'Authorization: Bearer organizer-secret-token',
      'Cookie: session=organizer-session; csrf=organizer-csrf',
      'X-API-Key: organizer-api-key',
      '',
      '{"amount":500,"reason":"organizer"}',
    ].join('\n'),
    responseRaw: [
      `HTTP/1.1 ${status === 'done' ? '200 OK' : '403 Forbidden'}`,
      'Content-Type: application/json',
      '',
      '{"workflow":"refund","token":"organizer-secret-token","status":"preserved"}',
    ].join('\n'),
  };
}

function makePackageArtifact(id, mode, signatureStatus, now, mergeModes) {
  return {
    id,
    kind: 'proxyforge-organizer-package',
    exportedAt: now,
    projectName: 'ProxyForge parity workspace',
    collectionId: mode === 'plain' ? 'organizer-research' : 'organizer-inbox',
    collectionName: mode === 'plain' ? 'Research' : 'Inbox',
    itemCount: mode === 'plain' ? 1 : 4,
    mode,
    digestSha256: mode === 'plain' ? 'organizer-digest-plain' : 'organizer-digest-sealed',
    content: JSON.stringify({
      kind: 'proxyforge-organizer-package',
      mode,
      passphrase: mode === 'passphrase-sealed' ? 'organizer-passphrase' : '',
      signingSecret: 'organizer-signing-secret',
      requestRaw: 'Authorization: Bearer organizer-secret-token\nCookie: session=organizer-session\nX-API-Key: organizer-api-key',
    }),
    algorithm: mode === 'passphrase-sealed' ? 'AES-256-GCM' : undefined,
    kdf: mode === 'passphrase-sealed' ? 'PBKDF2-SHA256-120000' : undefined,
    passphrase: mode === 'passphrase-sealed' ? 'organizer-passphrase' : undefined,
    signingSecret: 'organizer-signing-secret',
    signature: {
      algorithm: 'HMAC-SHA256',
      status: signatureStatus,
      signerName: 'Trusted Organizer',
      keyId: 'organizer-key-1',
      signedAt: now,
      packageDigestSha256: mode === 'plain' ? 'organizer-digest-plain' : 'organizer-digest-sealed',
      signature: `hmac-${mode}-signature`,
    },
    importReviewIds: [mode === 'plain' ? 'organizer-diff-plain' : 'organizer-diff-sealed'],
    mergeModes,
  };
}

function makeConflictAudit(id, action, mergeMode, diff, now) {
  return {
    id,
    at: now,
    diffId: diff.id,
    packageDigest: diff.packageDigest,
    sourceCollectionId: diff.sourceCollectionId,
    targetCollectionId: diff.targetCollectionId,
    route: 'POST app.shop.local/api/refunds/101',
    action,
    mergeMode,
    actor: 'local-operator',
    localItemId: 'organizer-item-proxy',
    incomingItemId: 'incoming-organizer-item-proxy',
    localStatus: 'inbox',
    incomingStatus: 'reviewing',
    localReviewer: 'Lead Reviewer',
    incomingReviewer: 'AppSec Analyst',
    localDueAt: '2026-05-24T09:00:00.000Z',
    incomingDueAt: '2026-05-26T09:00:00.000Z',
    notes: `${action} package conflicts with ${mergeMode}`,
  };
}
