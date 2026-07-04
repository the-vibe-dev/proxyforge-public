import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import path from 'node:path';
import vm from 'node:vm';

const require = createRequire(import.meta.url);
const ts = require('typescript');

const expectedExports = [
  'evaluateSafetyPolicyRequest',
  'buildSafetyEnterpriseParityEvidencePackage',
];
const enginePath = path.resolve('src/safetyEnterpriseEngine.ts');
const safetyEnterpriseEngine = normalizeModuleExports(await loadEngine(enginePath));
const missingExports = expectedExports.filter((name) => typeof safetyEnterpriseEngine[name] !== 'function');
assert.deepEqual(missingExports, [], `safety-enterprise-engine: missing export(s): ${missingExports.join(', ')}`);

const context = buildSafetyEnterpriseContext();
const decisions = context.runnerRequests.map((request) => safetyEnterpriseEngine.evaluateSafetyPolicyRequest(
  context.policy,
  request,
  context.approvals,
  context.overrides,
));

assert.equal(decisions.find((decision) => decision.requestId === 'request-replay-allowed')?.status, 'allowed');
assert.equal(decisions.find((decision) => decision.requestId === 'request-out-of-scope')?.status, 'blocked');
assert.equal(decisions.find((decision) => decision.requestId === 'request-throttle-low')?.status, 'blocked');
assert.equal(decisions.find((decision) => decision.requestId === 'request-cap-high')?.status, 'blocked');
assert.equal(decisions.find((decision) => decision.requestId === 'request-exploit-needs-approval')?.status, 'requires-approval');
assert.equal(decisions.find((decision) => decision.requestId === 'request-exploit-approved')?.status, 'allowed');
assert.equal(decisions.find((decision) => decision.requestId === 'request-override-partner')?.overrideApplied, true);

const parityPackage = safetyEnterpriseEngine.buildSafetyEnterpriseParityEvidencePackage({
  ...context,
  decisions,
});
const parityContent = JSON.parse(parityPackage.content);

assert.equal(parityPackage.kind, 'proxyforge-safety-enterprise-parity-evidence-package');
assert.equal(parityPackage.secretHandling, 'execution-full-fidelity-secrets-preserved');
assert.equal(parityPackage.reportRedactionBoundary, 'redact-only-during-report-export');
assert.equal(parityPackage.reportReady, true);
assert(Object.values(parityPackage.requirements).every(Boolean), 'all Safety/Enterprise parity requirements should be true');
assert.equal(parityPackage.decisionCount, 7);
assert.equal(parityPackage.auditEventCount, 7);
assert.equal(parityPackage.governancePackageCount, 1);
assert.equal(parityPackage.ssoIdentityCount, 2);
assert.equal(parityPackage.transportReceiptCount, 2);
assert.equal(parityPackage.backendSoakCount, 1);
assert.equal(parityContent.kind, 'proxyforge-safety-enterprise-parity-evidence-package');
assert.match(parityPackage.content, /Authorization: Bearer safety-secret-token/);
assert.match(parityPackage.content, /session=safety-session/);
assert.match(parityPackage.content, /X-API-Key: safety-api-key/);
assert.match(parityPackage.content, /safety-signing-secret/);
assert.match(parityPackage.content, /sso-federation-secret/);
assert.match(parityPackage.content, /proxyforge-governance-policy-package/);
assert.match(parityPackage.content, /proxyforge-sso-federation-fixture/);
assert.match(parityPackage.content, /proxyforge-enterprise-policy-backend-soak/);
assert.match(parityPackage.content, /proxyforge-remote-audit-retention/);
assert.match(parityPackage.content, /redact-only-during-report-export/);

const artifactDir = path.resolve('.gitignored/test-artifacts/safety-enterprise-engine');
await fs.mkdir(artifactDir, { recursive: true });
await fs.writeFile(path.join(artifactDir, 'safety-enterprise-parity-evidence-package.json'), parityPackage.content);

console.log('safety-enterprise-engine: exercised scope/throttle/cap/approval gates, override audit, governance, SSO federation, remote policy soak, and full-fidelity evidence');

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

function buildSafetyEnterpriseContext() {
  const now = '2026-05-25T23:55:00.000Z';
  const policy = {
    id: 'policy-release-parity',
    name: 'Release parity active testing policy',
    scopeAllowlist: ['app.shop.local', 'api.shop.local'],
    requireScopeMatch: true,
    minThrottleMs: 250,
    maxRequestsPerRun: 50,
    requireApprovalFor: ['exploit', 'callback-replay', 'intruder'],
    auditLogging: true,
    redactAuditSecrets: false,
  };
  const overrides = [
    {
      id: 'override-partner-sandbox',
      operatorId: 'operator-partner',
      operatorName: 'Partner Analyst',
      role: 'enterprise-tester',
      enabled: true,
      reason: 'Approved partner sandbox lane for api.partner.shop.local',
      scopeAdditions: ['api.partner.shop.local'],
      minThrottleMs: 250,
      maxRequestsPerRun: 75,
      expiresAt: '2026-05-26T23:55:00.000Z',
      approvedBy: 'security-lead',
    },
  ];
  const runnerRequests = [
    makeRequest('request-replay-allowed', 'replay', 'https://app.shop.local/api/profile', 'operator-alice', 3, 250),
    makeRequest('request-out-of-scope', 'scanner', 'https://evil.example.net/api/profile', 'operator-alice', 3, 250),
    makeRequest('request-throttle-low', 'scanner', 'https://app.shop.local/api/search', 'operator-alice', 3, 10),
    makeRequest('request-cap-high', 'scanner', 'https://app.shop.local/api/catalog', 'operator-alice', 51, 250),
    makeRequest('request-exploit-needs-approval', 'exploit', 'https://app.shop.local/api/admin/refunds', 'operator-alice', 1, 500),
    makeRequest('request-exploit-approved', 'exploit', 'https://app.shop.local/api/admin/refunds', 'operator-alice', 1, 500, 'approval-exploit-admin'),
    makeRequest('request-override-partner', 'scanner', 'https://api.partner.shop.local/v1/status', 'operator-partner', 60, 250),
  ];
  const approvals = [
    {
      id: 'approval-exploit-admin',
      runner: 'exploit',
      targetUrl: 'https://app.shop.local/api/admin/refunds',
      requestedBy: 'operator-alice',
      approvedBy: 'security-lead',
      status: 'approved',
      reason: 'Authorized non-destructive exploit validation.',
      createdAt: now,
      rawRequest: rawRequest('/api/admin/refunds'),
    },
  ];
  const auditEvents = runnerRequests.map((request, index) => ({
    id: `audit-event-${index + 1}`,
    time: now,
    actor: request.requestedBy,
    runner: request.runner,
    targetUrl: request.targetUrl,
    decision: request.id === 'request-exploit-approved'
      ? 'approved'
      : request.id === 'request-override-partner'
        ? 'override-applied'
        : request.id.includes('allowed')
          ? 'allowed'
          : 'blocked',
    policyId: policy.id,
    requestId: request.id,
    approvalId: request.approvalId,
    overrideId: request.id === 'request-override-partner' ? 'override-partner-sandbox' : undefined,
    rawRequest: request.rawRequest,
    rawResponse: request.rawResponse,
    detail: `${request.runner} decision retained with full-fidelity request material and report-export-only redaction.`,
  }));
  return {
    policy,
    overrides,
    runnerRequests,
    approvals,
    auditEvents,
    signedAuditExports: [
      {
        id: 'signed-audit-release-parity',
        signerName: 'ProxyForge Safety Signer',
        keyId: 'safety-key-1',
        algorithm: 'HMAC-SHA256',
        signatureStatus: 'valid',
        eventIds: auditEvents.map((event) => event.id),
        approvalIds: approvals.map((approval) => approval.id),
        overrideIds: overrides.map((override) => override.id),
        exportedAt: now,
        content: JSON.stringify({
          kind: 'proxyforge-signed-audit-export',
          signingSecret: 'safety-signing-secret',
          eventIds: auditEvents.map((event) => event.id),
          rawRequest: rawRequest('/api/admin/refunds'),
        }),
      },
    ],
    governancePackages: [
      {
        id: 'governance-package-release-parity',
        teamName: 'ProxyForge Enterprise',
        policyId: policy.id,
        exportedAt: now,
        signerName: 'ProxyForge Governance',
        keyId: 'governance-key-1',
        signatureStatus: 'valid',
        runnerBindings: [
          { runner: 'scanner', scopeAllowlist: policy.scopeAllowlist, minThrottleMs: 250, maxRequestsPerRun: 50, requiresApproval: false },
          { runner: 'exploit', scopeAllowlist: policy.scopeAllowlist, minThrottleMs: 500, maxRequestsPerRun: 5, requiresApproval: true },
          { runner: 'intruder', scopeAllowlist: policy.scopeAllowlist, minThrottleMs: 250, maxRequestsPerRun: 50, requiresApproval: true },
        ],
        content: JSON.stringify({
          kind: 'proxyforge-governance-policy-package',
          policyId: policy.id,
          signingSecret: 'safety-signing-secret',
          authHeader: 'Authorization: Bearer safety-secret-token',
        }),
      },
    ],
    ssoIdentities: [
      {
        id: 'sso-identity-alice',
        provider: 'oidc',
        issuer: 'https://idp.shop.local',
        subject: 'alice-subject',
        email: 'alice@shop.local',
        name: 'Alice Analyst',
        roles: ['security-engineer'],
        groups: ['appsec', 'enterprise-testers'],
        mappedPolicyOverrideIds: [],
        assertionDigestPreview: 'alice-assertion-digest',
      },
      {
        id: 'sso-identity-partner',
        provider: 'saml',
        issuer: 'https://sso.partner.shop.local',
        subject: 'partner-subject',
        email: 'partner@shop.local',
        name: 'Partner Analyst',
        roles: ['enterprise-tester'],
        groups: ['partner-sandbox'],
        mappedPolicyOverrideIds: ['override-partner-sandbox'],
        assertionDigestPreview: 'partner-assertion-digest',
      },
    ],
    ssoFederationFixtures: [
      {
        id: 'sso-fixture-partner',
        provider: 'saml',
        issuer: 'https://sso.partner.shop.local',
        audience: 'proxyforge-enterprise',
        jwksDigestPreview: 'jwks-digest-preview',
        assertionStatus: 'accepted',
        mappedIdentityId: 'sso-identity-partner',
        jitProvisioned: true,
        content: JSON.stringify({
          kind: 'proxyforge-sso-federation-fixture',
          assertionSecret: 'sso-federation-secret',
          mappedOverride: 'override-partner-sandbox',
        }),
      },
    ],
    policyTransportReceipts: [
      {
        id: 'transport-push',
        mode: 'push',
        endpoint: 'https://policy.shop.local/proxyforge',
        status: 'delivered',
        digestSha256: 'abcdef1234567890abcdef1234567890',
        credentialLabel: 'team-policy-token',
        authHeaderPresent: true,
        content: JSON.stringify({
          kind: 'proxyforge-enterprise-policy-transport',
          mode: 'push',
          Authorization: 'Bearer safety-secret-token',
          digest: 'abcdef1234567890abcdef1234567890',
        }),
      },
      {
        id: 'transport-pull',
        mode: 'pull',
        endpoint: 'https://policy.shop.local/proxyforge',
        status: 'received',
        digestSha256: 'fedcba0987654321fedcba0987654321',
        credentialLabel: 'team-policy-token',
        authHeaderPresent: true,
        content: JSON.stringify({
          kind: 'proxyforge-enterprise-policy-transport',
          mode: 'pull',
          Authorization: 'Bearer safety-secret-token',
          digest: 'fedcba0987654321fedcba0987654321',
        }),
      },
    ],
    enterpriseBackendSoaks: [
      {
        id: 'backend-soak-release-parity',
        endpoint: 'https://policy.shop.local/proxyforge',
        iterationCount: 25,
        successCount: 25,
        failureCount: 0,
        maxLatencyMs: 42,
        policyDigestSha256: 'abcdef1234567890abcdef1234567890',
        content: JSON.stringify({
          kind: 'proxyforge-enterprise-policy-backend-soak',
          iterations: 25,
          Authorization: 'Bearer safety-secret-token',
        }),
      },
    ],
    remoteAuditRetentionRecords: [
      {
        id: 'remote-audit-retention-release-parity',
        endpoint: 'https://audit.shop.local/proxyforge',
        mode: 'append-only',
        retentionDays: 90,
        queuedEventIds: auditEvents.map((event) => event.id),
        deliveredEventIds: auditEvents.map((event) => event.id),
        status: 'delivered',
        content: JSON.stringify({
          kind: 'proxyforge-remote-audit-retention',
          Cookie: 'session=safety-session',
          delivered: auditEvents.map((event) => event.id),
        }),
      },
    ],
    operationalSecretSamples: ['safety-secret-token', 'safety-session', 'safety-api-key', 'safety-signing-secret', 'sso-federation-secret'],
    exportedAt: now,
  };
}

function makeRequest(id, runner, targetUrl, requestedBy, requestCount, throttleMs, approvalId) {
  return {
    id,
    runner,
    targetUrl,
    requestedBy,
    requestCount,
    throttleMs,
    approvalId,
    rawRequest: rawRequest(new URL(targetUrl).pathname),
    rawResponse: [
      'HTTP/1.1 200 OK',
      'Content-Type: application/json',
      '',
      '{"ok":true,"session":"safety-session"}',
    ].join('\r\n'),
  };
}

function rawRequest(requestPath) {
  return [
    `POST ${requestPath || '/'} HTTP/1.1`,
    'Host: app.shop.local',
    'Authorization: Bearer safety-secret-token',
    'Cookie: session=safety-session; csrf=safety-csrf',
    'X-API-Key: safety-api-key',
    '',
    '{"token":"safety-secret-token"}',
  ].join('\r\n');
}
