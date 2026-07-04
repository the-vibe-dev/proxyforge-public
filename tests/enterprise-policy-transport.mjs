import { strict as assert } from 'node:assert';
import crypto from 'node:crypto';
import http from 'node:http';

const { EnterprisePolicyTransportService } = await import('../dist-electron/enterprisePolicyTransport.js');

let savedPackage = null;
const observed = {
  pushBody: '',
  auth: '',
  credentialLabel: '',
  digestHeader: '',
};

const server = http.createServer((request, response) => {
  if (request.url === '/policy' && request.method === 'POST') {
    observed.auth = String(request.headers.authorization ?? '');
    observed.credentialLabel = String(request.headers['x-proxyforge-credential-label'] ?? '');
    observed.digestHeader = String(request.headers['x-proxyforge-policy-digest'] ?? '');
    const chunks = [];
    request.on('data', (chunk) => chunks.push(chunk));
    request.on('end', () => {
      observed.pushBody = Buffer.concat(chunks).toString('utf8');
      savedPackage = JSON.parse(observed.pushBody);
      response.writeHead(201, { 'content-type': 'application/json' });
      response.end(JSON.stringify({
        receiptId: 'receipt-enterprise-1',
        digestSha256: savedPackage.digestSha256,
        status: 'stored',
      }));
    });
    return;
  }

  if (request.url === '/policy' && request.method === 'GET') {
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(JSON.stringify({ receiptId: 'receipt-enterprise-2', policyPackage: savedPackage }));
    return;
  }

  response.writeHead(404, { 'content-type': 'application/json' });
  response.end(JSON.stringify({ error: 'not found' }));
});

try {
  const port = await listen(server);
  const endpoint = `http://127.0.0.1:${port}/policy`;
  const policyPackage = buildPolicyPackage(endpoint);
  const service = new EnterprisePolicyTransportService();
  const transport = {
    endpoint,
    authHeaderName: 'Authorization',
    credentialLabel: 'enterprise-policy-token',
    pullCount: 0,
    pushCount: 0,
    status: 'ready',
    message: 'Ready for remote policy sync.',
  };

  const push = await service.push({
    transport,
    policyPackage,
    authHeaderValue: 'Bearer full-enterprise-policy-secret',
    timeoutMs: 5000,
  });

  assert.equal(push.statusCode, 201);
  assert.equal(push.receiptId, 'receipt-enterprise-1');
  assert.equal(push.digestSha256, policyPackage.digestSha256);
  assert.equal(observed.auth, 'Bearer full-enterprise-policy-secret');
  assert.equal(observed.credentialLabel, 'enterprise-policy-token');
  assert.equal(observed.digestHeader, policyPackage.digestSha256);
  assert.match(observed.pushBody, /full-enterprise-sso-subject/);
  assert.match(observed.pushBody, /scanner-admin/);

  const pull = await service.pull({
    transport,
    authHeaderValue: 'Bearer full-enterprise-policy-secret',
    timeoutMs: 5000,
  });

  assert.equal(pull.statusCode, 200);
  assert.equal(pull.receiptId, 'receipt-enterprise-2');
  assert.equal(pull.policyPackage.kind, 'proxyforge-enterprise-policy');
  assert.equal(pull.policyPackage.digestSha256, policyPackage.digestSha256);
  assert.equal(pull.policyPackage.ssoProviderConfig.issuer, 'https://idp.example.test/oidc');
  assert.equal(pull.policyPackage.operatorIdentities[0].subject, 'full-enterprise-sso-subject');
  assert.deepEqual(pull.policyPackage.operatorIdentities[0].roles, ['operator', 'scanner-admin']);
  assert.match(pull.responseBody, /full-enterprise-sso-subject/);

  await assert.rejects(() => service.pull({
    transport: { ...transport, endpoint: 'file:///tmp/policy.json' },
    timeoutMs: 5000,
  }), /http or https/);

  console.log('enterprise-policy-transport: verified HTTP push/pull, auth header, credential label, digest, and full-fidelity SSO policy package preservation');
} finally {
  await close(server);
}

function buildPolicyPackage(endpoint) {
  const unsigned = {
    version: 1,
    kind: 'proxyforge-enterprise-policy',
    exportedAt: '2026-05-24T23:20:00.000Z',
    projectName: 'Enterprise Transport Test',
    teamName: 'ProxyForge Enterprise QA',
    policyUrl: endpoint,
    policy: {
      scopeAllowlist: ['127.0.0.1', 'app.example.test'],
      safetyPolicy: {
        requireScopeMatch: true,
        auditLogging: true,
        redactAuditSecrets: false,
        minThrottleMs: 100,
        maxRequestsPerRun: 25,
      },
      effectiveSafetyPolicy: {
        requireScopeMatch: true,
        auditLogging: true,
        redactAuditSecrets: false,
        minThrottleMs: 100,
        maxRequestsPerRun: 25,
      },
    },
    policyOverrides: [
      {
        id: 'override-1',
        operator: 'qa-admin',
        role: 'scanner-admin',
        enabled: true,
        createdAt: '2026-05-24T23:20:00.000Z',
        expiresAt: '2026-05-25T23:20:00.000Z',
        scopeAdditions: ['app.example.test'],
        reason: 'Remote policy transport smoke.',
      },
    ],
    ssoProviderConfig: {
      provider: 'oidc',
      issuer: 'https://idp.example.test/oidc',
      audience: 'proxyforge-desktop',
      subjectClaim: 'sub',
      emailClaim: 'email',
      nameClaim: 'name',
      roleClaim: 'roles',
      groupClaim: 'groups',
      jitProvisioning: true,
      status: 'configured',
      message: 'OIDC configured.',
    },
    operatorIdentities: [
      {
        id: 'identity-1',
        provider: 'oidc',
        subject: 'full-enterprise-sso-subject',
        email: 'operator@example.test',
        displayName: 'Enterprise Operator',
        roles: ['operator', 'scanner-admin'],
        assertedAt: '2026-05-24T23:20:00.000Z',
        source: 'sso-claim',
      },
    ],
    remotePolicyTransport: {
      endpoint,
      authHeaderName: 'Authorization',
      credentialLabel: 'enterprise-policy-token',
      lastPushedAt: '2026-05-24T23:20:00.000Z',
      pullCount: 0,
      pushCount: 1,
      status: 'pushed',
      message: 'Pushed in test.',
    },
    remoteAuditRetention: {
      mode: 'signed-log',
      retentionDays: 30,
      endpoint: 'https://audit.example.test/proxyforge',
      queueCount: 0,
      status: 'ready',
      message: 'Ready.',
    },
  };
  return {
    ...unsigned,
    digestSha256: sha256(canonicalize(unsigned)),
  };
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function canonicalize(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function listen(server) {
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve(server.address().port));
  });
}

function close(server) {
  return new Promise((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  });
}
