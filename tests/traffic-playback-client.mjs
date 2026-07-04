// Tests for playback — client run descriptor management.

import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

let playback;

try {
  playback = require('../dist-electron/traffic/playback.js');
} catch (err) {
  console.log(`SKIP: compiled module not found (${err.message})`);
  process.exit(0);
}

const {
  createClientPlaybackRun,
  advanceClientPlayback,
  startServerPlayback,
  stopServerPlayback,
} = playback;

// ---------------------------------------------------------------------------
// Helper factories
// ---------------------------------------------------------------------------

function makeExchange(id) {
  return {
    id,
    requestRaw: `GET /path/${id} HTTP/1.1\r\nHost: example.com\r\n\r\n`,
    responseRaw: 'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK',
    delayMs: 0,
  };
}

function makeSession(exchangeCount) {
  const exchanges = Array.from({ length: exchangeCount }, (_, i) =>
    makeExchange(`ex-${i + 1}`),
  );
  return {
    id: 'session-abc',
    name: 'Test Session',
    mode: 'client',
    exchanges,
    createdAt: new Date().toISOString(),
  };
}

const defaultClientConfig = {
  targetHost: '127.0.0.1',
  targetPort: 8080,
  useTls: false,
  throttleMs: 0,
  maxConcurrent: 1,
};

const defaultServerConfig = {
  listenPort: 9000,
  listenHost: '127.0.0.1',
};

// ---------------------------------------------------------------------------
// createClientPlaybackRun — returns run with correct total count
// ---------------------------------------------------------------------------

{
  const session = makeSession(5);
  const run = createClientPlaybackRun(session, defaultClientConfig);

  assert.equal(run.sessionId, 'session-abc', 'sessionId should match session.id');
  assert.equal(run.total, 5, 'total should equal number of exchanges');
  assert.equal(run.completed, 0, 'completed should start at 0');
  assert.equal(run.status, 'running', 'status should start as running');
  assert.ok(Array.isArray(run.errors), 'errors should be an array');
  assert.equal(run.errors.length, 0, 'errors should start empty');
  assert.ok(typeof run.startedAt === 'string', 'startedAt should be a string');

  console.log('PASS createClientPlaybackRun returns run descriptor with correct shape');
}

{
  // Session with zero exchanges
  const session = makeSession(0);
  const run = createClientPlaybackRun(session, defaultClientConfig);
  assert.equal(run.total, 0, 'total should be 0 for empty session');
  assert.equal(run.completed, 0, 'completed should be 0');

  console.log('PASS createClientPlaybackRun handles zero-exchange session');
}

{
  // Session with one exchange
  const session = makeSession(1);
  const run = createClientPlaybackRun(session, defaultClientConfig);
  assert.equal(run.total, 1, 'total should be 1');

  console.log('PASS createClientPlaybackRun handles single-exchange session');
}

// ---------------------------------------------------------------------------
// advanceClientPlayback — increments completed count
// ---------------------------------------------------------------------------

{
  const session = makeSession(3);
  const run = createClientPlaybackRun(session, defaultClientConfig);

  advanceClientPlayback(run, session.exchanges[0]);
  assert.equal(run.completed, 1, 'completed should be 1 after first advance');
  assert.equal(run.status, 'running', 'status should still be running');

  advanceClientPlayback(run, session.exchanges[1]);
  assert.equal(run.completed, 2, 'completed should be 2 after second advance');
  assert.equal(run.status, 'running', 'status should still be running');

  advanceClientPlayback(run, session.exchanges[2]);
  assert.equal(run.completed, 3, 'completed should be 3 after third advance');
  assert.equal(run.status, 'complete', 'status should be complete after all advances');

  console.log('PASS advanceClientPlayback increments completed and transitions to complete');
}

{
  // Single-exchange run completes after one advance
  const session = makeSession(1);
  const run = createClientPlaybackRun(session, defaultClientConfig);

  assert.equal(run.status, 'running', 'initial status should be running');
  advanceClientPlayback(run, session.exchanges[0]);
  assert.equal(run.completed, 1, 'completed should be 1');
  assert.equal(run.status, 'complete', 'status should be complete');

  console.log('PASS advanceClientPlayback completes run after final exchange');
}

// ---------------------------------------------------------------------------
// ClientPlaybackRun.status — starts as 'running'
// ---------------------------------------------------------------------------

{
  const session = makeSession(10);
  const run = createClientPlaybackRun(session, defaultClientConfig);
  assert.equal(run.status, 'running', 'status should be running immediately after creation');
  assert.notEqual(run.status, 'complete', 'status should not be complete initially');
  assert.notEqual(run.status, 'error', 'status should not be error initially');

  console.log("PASS ClientPlaybackRun.status starts as 'running'");
}

// ---------------------------------------------------------------------------
// startServerPlayback — creates state descriptor
// ---------------------------------------------------------------------------

{
  const session = {
    id: 'server-session-1',
    name: 'Server Session',
    mode: 'server',
    exchanges: [makeExchange('e1')],
    createdAt: new Date().toISOString(),
  };

  const matchFn = (_raw) => null;
  const state = startServerPlayback(session, defaultServerConfig, matchFn);

  assert.equal(state.sessionId, 'server-session-1', 'sessionId should match');
  assert.equal(state.status, 'running', 'status should be running');
  assert.equal(state.matchCount, 0, 'matchCount should start at 0');

  console.log('PASS startServerPlayback returns state descriptor with correct shape');
}

// ---------------------------------------------------------------------------
// stopServerPlayback — marks state as stopped
// ---------------------------------------------------------------------------

{
  const session = {
    id: 'server-session-2',
    name: 'Server Session 2',
    mode: 'server',
    exchanges: [],
    createdAt: new Date().toISOString(),
  };

  const matchFn = (_raw) => null;
  const state = startServerPlayback(session, defaultServerConfig, matchFn);
  assert.equal(state.status, 'running', 'initial status should be running');

  stopServerPlayback(state);
  assert.equal(state.status, 'stopped', 'status should be stopped after stopServerPlayback');

  console.log('PASS stopServerPlayback transitions status to stopped');
}

console.log('\nAll traffic-playback-client tests passed.');
