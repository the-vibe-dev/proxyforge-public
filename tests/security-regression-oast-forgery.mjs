// Phase 18 — Security regression: OAST callback forgery rejection
// Tests that forged OAST callbacks (wrong token, wrong project) are rejected,
// and that a legitimately issued payload + matching interaction is accepted.
import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);

function tryLoad(candidates) {
  for (const c of candidates) {
    try { return require(c); } catch { }
  }
  return null;
}

const mod = tryLoad([
  '../dist-electron/scanner/oastPayloadBroker.js',
  '../dist-electron/electron/scanner/oastPayloadBroker.js',
]);
assert.ok(mod, 'oastPayloadBroker module must be loadable');

const {
  createOastPayload,
  correlateCallback,
  recordOastInteraction,
  buildOastProofPayload,
  getInteractionsForPayload,
} = mod;

assert.ok(typeof createOastPayload === 'function', 'createOastPayload must be a function');
assert.ok(typeof correlateCallback === 'function', 'correlateCallback must be a function');
assert.ok(typeof recordOastInteraction === 'function', 'recordOastInteraction must be a function');
assert.ok(typeof buildOastProofPayload === 'function', 'buildOastProofPayload must be a function');

const PROJECT_ID = 'proj-test-oast-security';
const PROJECT_SECRET = 'super-secret-project-key';
const OAST_BASE = 'https://oast.proxyforge.local';
const CHECK_ID = 'ssrf-basic';
const INSERTION_POINT = 'url-param-target';
const EXCHANGE_ID = 'ex-001';

// ── Test 1: Issue a real OAST payload ─────────────────────────────────────
const payload = createOastPayload(
  PROJECT_ID,
  CHECK_ID,
  INSERTION_POINT,
  EXCHANGE_ID,
  OAST_BASE,
  'http',
  PROJECT_SECRET,
);

assert.ok(payload.id, 'payload must have an id');
assert.ok(payload.token, 'payload must have a token');
assert.equal(payload.projectId, PROJECT_ID, 'payload.projectId must match');
assert.equal(payload.status, 'pending', 'new payload status must be pending');
assert.ok(
  payload.endpoint.startsWith(OAST_BASE),
  'payload endpoint must start with OAST base URL',
);
assert.ok(
  payload.endpoint.endsWith(payload.token),
  'payload endpoint must end with the HMAC token',
);

// ── Test 2: Forged token is rejected ──────────────────────────────────────
{
  const forgedToken = 'deadbeef00000000000000000000000000000000000000000';
  const correlated = correlateCallback(forgedToken, PROJECT_ID);
  assert.equal(
    correlated,
    null,
    'Forged token must not correlate to any payload (got: ' + JSON.stringify(correlated) + ')',
  );
}

// ── Test 3: Real token + wrong project is rejected ────────────────────────
{
  const correlated = correlateCallback(payload.token, 'wrong-project-id');
  assert.equal(
    correlated,
    null,
    'Real token with wrong projectId must not correlate',
  );
}

// ── Test 4: Real token + correct project correlates ───────────────────────
{
  const correlated = correlateCallback(payload.token, PROJECT_ID);
  assert.ok(correlated, 'Real token + correct projectId must correlate');
  assert.equal(correlated.id, payload.id, 'Correlated payload id must match');
  assert.equal(correlated.token, payload.token, 'Correlated token must match');
}

// ── Test 5: recordOastInteraction with wrong payloadId is rejected ─────────
{
  const interaction = recordOastInteraction(
    'nonexistent-payload-id',
    `dns-lookup ${payload.token}`,
    '10.0.0.1',
    `GET /${payload.token} HTTP/1.1`,
  );
  assert.equal(
    interaction,
    null,
    'Interaction for unknown payloadId must return null',
  );
}

// ── Test 6: Valid interaction records and proof is verified ────────────────
{
  const interaction = recordOastInteraction(
    payload.id,
    `HTTP GET /${payload.token} from attacker`,
    '192.168.1.100',
    `GET /${payload.token} HTTP/1.1`,
  );

  assert.ok(interaction, 'Valid interaction must be recorded (not null)');
  assert.equal(interaction.payloadId, payload.id, 'interaction.payloadId must match');
  assert.equal(interaction.projectId, PROJECT_ID, 'interaction.projectId must match');

  // Payload status should now be 'triggered'
  const retriggered = correlateCallback(payload.token, PROJECT_ID);
  assert.ok(retriggered, 'Should still correlate after trigger');
  assert.equal(retriggered.status, 'triggered', 'payload status must be triggered');

  // Build proof
  const proof = buildOastProofPayload(payload, interaction);
  assert.ok(proof.verified === true, 'Proof must be verified=true for legitimate callback');
  assert.ok(
    proof.evidence.some((line) => line.includes(payload.token)),
    'Proof evidence must reference the token',
  );
}

// ── Test 7: Forged interaction (token not in raw) is NOT verified ──────────
{
  const fakePayload = createOastPayload(
    PROJECT_ID,
    CHECK_ID,
    'ip-2',
    'ex-002',
    OAST_BASE,
    'http',
    PROJECT_SECRET,
  );
  const fakeInteraction = recordOastInteraction(
    fakePayload.id,
    'HTTP GET /completely-different-path from attacker',
    '10.0.0.1',
    'GET /completely-different-path HTTP/1.1',
  );

  assert.ok(fakeInteraction, 'Interaction must be recorded');

  const proof = buildOastProofPayload(fakePayload, fakeInteraction);
  assert.ok(
    proof.verified === false,
    'Proof must be verified=false when token is NOT in the interaction raw data',
  );
}

// ── Test 8: getInteractionsForPayload only returns own interactions ─────────
{
  // payload (from test 6) should have exactly one interaction
  const interactions = getInteractionsForPayload(payload.id);
  assert.ok(
    interactions.length >= 1,
    'Must return at least one interaction for the payload',
  );
  for (const itr of interactions) {
    assert.equal(
      itr.payloadId,
      payload.id,
      'All returned interactions must belong to the queried payload',
    );
  }
}

console.log('PASS security-regression-oast-forgery');
