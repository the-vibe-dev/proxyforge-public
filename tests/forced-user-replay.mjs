// Phase 3b — Contexts: Forced User mode roundtrip.
// Tests createUser, setForcedUser, getForcedUser, clearForcedUser, and
// isForcedUserMode from usersEngine.
import { createRequire } from 'node:module';
import assert from 'node:assert/strict';

const require = createRequire(import.meta.url);

let usersMod;
try {
  usersMod = require('../dist-electron/src/users/usersEngine.js');
} catch {
  console.log('SKIP: users/usersEngine.js not compiled — run tsc first.');
  process.exit(0);
}

const {
  createUser,
  getUser,
  deleteUser,
  setForcedUser,
  getForcedUser,
  clearForcedUser,
  isForcedUserMode,
  getUsersForContext,
} = usersMod;

// ---------------------------------------------------------------------------
// Test 1: createUser returns a well-formed user object
// ---------------------------------------------------------------------------
{
  const user = createUser({
    name: 'Alice',
    role: 'admin',
    authMethodId: 'auth-method-001',
    credentials: { username: 'alice', password: 'secret' },
    contextIds: ['ctx-alpha'],
  });

  assert.ok(typeof user.id === 'string' && user.id.length > 0,
    'createUser must generate a non-empty id');
  assert.strictEqual(user.name, 'Alice');
  assert.strictEqual(user.role, 'admin');
  assert.deepEqual(user.contextIds, ['ctx-alpha']);
  assert.strictEqual(typeof user.createdAt, 'string');

  console.log('PASS: createUser returns user with id, name, contextIds');
}

// ---------------------------------------------------------------------------
// Test 2: setForcedUser + getForcedUser roundtrip
// ---------------------------------------------------------------------------
{
  const user = createUser({
    name: 'Bob',
    authMethodId: 'auth-method-002',
    credentials: { username: 'bob' },
    contextIds: ['ctx-beta'],
  });

  const ctxId = 'ctx-beta';

  // Before setting forced user, getForcedUser should return undefined
  assert.strictEqual(getForcedUser(ctxId), undefined,
    'getForcedUser should return undefined before any forced user is set');

  // Set forced user
  setForcedUser(ctxId, user.id);

  const forcedUser = getForcedUser(ctxId);
  assert.ok(forcedUser !== undefined, 'getForcedUser should return the user after setForcedUser');
  assert.strictEqual(forcedUser.id, user.id,
    'getForcedUser must return the same user that was set');
  assert.strictEqual(forcedUser.name, 'Bob');

  console.log('PASS: setForcedUser / getForcedUser roundtrip');
}

// ---------------------------------------------------------------------------
// Test 3: isForcedUserMode reflects current state
// ---------------------------------------------------------------------------
{
  const user = createUser({
    name: 'Carol',
    authMethodId: 'auth-method-003',
    credentials: { username: 'carol' },
  });

  const ctxId = 'ctx-gamma';

  assert.strictEqual(isForcedUserMode(ctxId), false,
    'isForcedUserMode should be false before setting a forced user');

  setForcedUser(ctxId, user.id);
  assert.strictEqual(isForcedUserMode(ctxId), true,
    'isForcedUserMode should be true after setForcedUser');

  console.log('PASS: isForcedUserMode reflects forced user state');
}

// ---------------------------------------------------------------------------
// Test 4: clearForcedUser removes the binding
// ---------------------------------------------------------------------------
{
  const user = createUser({
    name: 'Dave',
    authMethodId: 'auth-method-004',
    credentials: { username: 'dave' },
  });

  const ctxId = 'ctx-delta';

  setForcedUser(ctxId, user.id);
  assert.ok(getForcedUser(ctxId) !== undefined, 'forced user should exist before clear');

  clearForcedUser(ctxId);

  assert.strictEqual(getForcedUser(ctxId), undefined,
    'getForcedUser must return undefined after clearForcedUser');
  assert.strictEqual(isForcedUserMode(ctxId), false,
    'isForcedUserMode must be false after clearForcedUser');

  console.log('PASS: clearForcedUser removes forced user binding');
}

// ---------------------------------------------------------------------------
// Test 5: setForcedUser throws for non-existent userId
// ---------------------------------------------------------------------------
{
  assert.throws(
    () => setForcedUser('ctx-epsilon', 'non-existent-user-id'),
    /does not exist/i,
    'setForcedUser should throw for a userId not in the store',
  );

  console.log('PASS: setForcedUser throws for non-existent userId');
}

// ---------------------------------------------------------------------------
// Test 6: getUser retrieves by id
// ---------------------------------------------------------------------------
{
  const user = createUser({
    name: 'Eve',
    authMethodId: 'auth-method-005',
    credentials: { username: 'eve' },
  });

  const retrieved = getUser(user.id);
  assert.ok(retrieved !== undefined, 'getUser must find a just-created user');
  assert.strictEqual(retrieved.id, user.id);
  assert.strictEqual(retrieved.name, 'Eve');

  console.log('PASS: getUser retrieves user by id');
}

// ---------------------------------------------------------------------------
// Test 7: default role is 'user' when not specified
// ---------------------------------------------------------------------------
{
  const user = createUser({
    name: 'Frank',
    authMethodId: 'auth-method-006',
    credentials: { username: 'frank' },
  });

  assert.strictEqual(user.role, 'user', "default role should be 'user'");
  assert.deepEqual(user.contextIds, [], 'default contextIds should be []');
  assert.strictEqual(user.forcedUserMode, false, 'default forcedUserMode should be false');

  console.log('PASS: createUser defaults (role=user, contextIds=[], forcedUserMode=false)');
}

console.log('\nAll forced-user-replay tests passed.');
