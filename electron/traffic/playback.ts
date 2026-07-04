// Client + server playback engine — descriptor types and state management.
// Actual async execution is driven by the caller via the async iterator
// pattern; this module manages descriptors and state only.

import type { PlaybackMatchFn } from './playbackMatcher';

export interface PlaybackExchange {
  id: string;
  requestRaw: string;
  responseRaw: string;
  delayMs?: number;
}

export interface PlaybackSession {
  id: string;
  name: string;
  mode: 'client' | 'server';
  exchanges: PlaybackExchange[];
  createdAt: string;
}

export interface PlaybackClientConfig {
  targetHost: string;
  targetPort: number;
  useTls: boolean;
  throttleMs?: number;
  maxConcurrent?: number;
}

export interface PlaybackServerConfig {
  listenPort: number;
  listenHost?: string;
}

export interface ClientPlaybackRun {
  sessionId: string;
  status: 'running' | 'complete' | 'error';
  completed: number;
  total: number;
  errors: string[];
  startedAt: string;
}

export interface ServerPlaybackState {
  sessionId: string;
  status: 'running' | 'stopped';
  matchCount: number;
}

/**
 * Creates a ClientPlaybackRun descriptor for the given session and config.
 * The run starts in 'running' state with completed=0.
 * Actual exchange execution is handled externally via advanceClientPlayback().
 */
export function createClientPlaybackRun(
  session: PlaybackSession,
  _config: PlaybackClientConfig,
): ClientPlaybackRun {
  return {
    sessionId: session.id,
    status: 'running',
    completed: 0,
    total: session.exchanges.length,
    errors: [],
    startedAt: new Date().toISOString(),
  };
}

/**
 * Records that one exchange has been processed.  Updates status to 'complete'
 * when all exchanges have been advanced through.
 * Mutates run in place.
 */
export function advanceClientPlayback(
  run: ClientPlaybackRun,
  _exchange: PlaybackExchange,
): void {
  run.completed += 1;
  if (run.completed >= run.total) {
    run.status = 'complete';
  }
}

/**
 * Creates a ServerPlaybackState descriptor.  The caller is responsible for
 * actually binding a server socket; this module only manages the state object.
 */
export function startServerPlayback(
  session: PlaybackSession,
  _config: PlaybackServerConfig,
  _matchFn: PlaybackMatchFn,
): ServerPlaybackState {
  return {
    sessionId: session.id,
    status: 'running',
    matchCount: 0,
  };
}

/**
 * Marks a ServerPlaybackState as stopped.
 * Mutates state in place.
 */
export function stopServerPlayback(state: ServerPlaybackState): void {
  state.status = 'stopped';
}
