// DOM tracer engine — session/canary/event reducer (off-thread state machine).
// Receives instrumented events from domTracerInstrumentation.ts and maintains
// session state: sources observed, sinks fired, canary traces.
// No external dependencies.

import { randomBytes } from 'node:crypto';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type SourceKind =
  | 'location.search' | 'location.hash' | 'location.href' | 'document.referrer'
  | 'window.name' | 'postMessage' | 'localStorage' | 'sessionStorage'
  | 'document.cookie' | 'fetch.response' | 'xhr.response' | 'window.opener';

export type SinkKind =
  | 'innerHTML' | 'outerHTML' | 'insertAdjacentHTML' | 'document.write'
  | 'eval' | 'Function' | 'setTimeout(string)' | 'setInterval(string)'
  | 'srcdoc' | 'location.href' | 'location.assign' | 'location.replace'
  | 'element.src' | 'element.href' | 'element.action' | 'element.formaction'
  | 'postMessage.send' | 'Worker' | 'importScripts' | 'fetch.url' | 'xhr.open';

export interface SourceEvent {
  id: string;
  sessionId: string;
  source: SourceKind;
  value: string;
  url: string;
  timestamp: string;
}

export interface SinkEvent {
  id: string;
  sessionId: string;
  sink: SinkKind;
  value: string;
  canaryMatched?: boolean;
  canaryTransformation?: string;
  stack?: string;
  url: string;
  timestamp: string;
}

export interface CanaryConfig {
  nonce: string;
  source: SourceKind;
  probeCharSet?: string[];
}

export interface TracerSession {
  id: string;
  tabId: string;
  projectId: string;
  url: string;
  canary?: CanaryConfig;
  sources: SourceEvent[];
  sinks: SinkEvent[];
  status: 'active' | 'stopped' | 'promoted';
  startedAt: string;
  stoppedAt?: string;
}

// ---------------------------------------------------------------------------
// Session management
// ---------------------------------------------------------------------------

const sessions = new Map<string, TracerSession>();

export function createTracerSession(tabId: string, projectId: string, url: string): TracerSession {
  const session: TracerSession = {
    id: randomBytes(8).toString('hex'),
    tabId,
    projectId,
    url,
    sources: [],
    sinks: [],
    status: 'active',
    startedAt: new Date().toISOString(),
  };
  sessions.set(session.id, session);
  return session;
}

export function getTracerSession(sessionId: string): TracerSession | null {
  return sessions.get(sessionId) ?? null;
}

export function stopTracerSession(sessionId: string): void {
  const s = sessions.get(sessionId);
  if (s) { s.status = 'stopped'; s.stoppedAt = new Date().toISOString(); }
}

export function getAllSessions(): TracerSession[] {
  return Array.from(sessions.values());
}

// ---------------------------------------------------------------------------
// Event ingestion
// ---------------------------------------------------------------------------

export function recordSourceEvent(
  sessionId: string,
  source: SourceKind,
  value: string,
  url: string,
): SourceEvent | null {
  const s = sessions.get(sessionId);
  if (!s || s.status !== 'active') return null;
  const evt: SourceEvent = {
    id: randomBytes(6).toString('hex'),
    sessionId,
    source,
    value,
    url,
    timestamp: new Date().toISOString(),
  };
  s.sources.push(evt);
  return evt;
}

export function recordSinkEvent(
  sessionId: string,
  sink: SinkKind,
  value: string,
  url: string,
  stack?: string,
): SinkEvent | null {
  const s = sessions.get(sessionId);
  if (!s || s.status !== 'active') return null;

  const canaryMatched = s.canary ? value.includes(s.canary.nonce) : undefined;
  const canaryTransformation = canaryMatched && s.canary
    ? detectTransformation(s.canary.nonce, value)
    : undefined;

  const evt: SinkEvent = {
    id: randomBytes(6).toString('hex'),
    sessionId,
    sink,
    value,
    canaryMatched,
    canaryTransformation,
    stack,
    url,
    timestamp: new Date().toISOString(),
  };
  s.sinks.push(evt);
  return evt;
}

// ---------------------------------------------------------------------------
// Canary management
// ---------------------------------------------------------------------------

export function setCanary(sessionId: string, source: SourceKind, probeCharSet?: string[]): CanaryConfig | null {
  const s = sessions.get(sessionId);
  if (!s) return null;
  const canary: CanaryConfig = {
    nonce: `pf-${randomBytes(6).toString('hex')}`,
    source,
    probeCharSet,
  };
  s.canary = canary;
  return canary;
}

export function clearCanary(sessionId: string): void {
  const s = sessions.get(sessionId);
  if (s) s.canary = undefined;
}

// ---------------------------------------------------------------------------
// Analysis
// ---------------------------------------------------------------------------

export function getCanaryTraces(sessionId: string): SinkEvent[] {
  const s = sessions.get(sessionId);
  if (!s) return [];
  return s.sinks.filter((e) => e.canaryMatched === true);
}

export function getHighValueSinks(sessionId: string): SinkEvent[] {
  const HIGH_VALUE: SinkKind[] = ['innerHTML', 'outerHTML', 'eval', 'Function', 'document.write', 'setTimeout(string)', 'location.href', 'location.assign'];
  const s = sessions.get(sessionId);
  if (!s) return [];
  return s.sinks.filter((e) => HIGH_VALUE.includes(e.sink));
}

function detectTransformation(nonce: string, sinkValue: string): string {
  if (sinkValue.includes(encodeURIComponent(nonce))) return 'url-encoded';
  if (sinkValue.includes(nonce.replace(/-/g, '_'))) return 'dash-to-underscore';
  if (sinkValue.toLowerCase().includes(nonce.toLowerCase())) return 'case-normalized';
  if (sinkValue.includes(nonce.replace('<', '&lt;'))) return 'html-encoded';
  return 'raw';
}
