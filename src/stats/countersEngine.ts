// Global stats counter engine — lightweight project-wide event counter.
// Used by every subsystem to record events; passive stats rule reads counters
// and emits findings when thresholds trip.
// No external dependencies.

export type CounterBucket = 'global' | string; // or 'host:example.com' / 'context:myCtx'

export interface CounterKey {
  event: string;
  bucket?: CounterBucket;
}

export interface CounterEntry {
  event: string;
  bucket: CounterBucket;
  count: number;
  lastUpdatedAt: string;
  windowStart: string;
}

export interface CounterSnapshot {
  capturedAt: string;
  entries: CounterEntry[];
}

export interface CounterDecayConfig {
  windowMs: number;      // sliding window size in ms (default: 60 minutes)
  decayIntervalMs: number; // how often old windows are cleared (default: 5 minutes)
}

const DEFAULT_DECAY: CounterDecayConfig = {
  windowMs: 60 * 60 * 1000,
  decayIntervalMs: 5 * 60 * 1000,
};

// In-memory counter store
const store = new Map<string, CounterEntry>();
let decayConfig = { ...DEFAULT_DECAY };

function makeKey(event: string, bucket: CounterBucket): string {
  return `${bucket}::${event}`;
}

export function configureDecay(config: Partial<CounterDecayConfig>): void {
  decayConfig = { ...decayConfig, ...config };
}

export function increment(event: string, bucket: CounterBucket = 'global', by = 1): void {
  const k = makeKey(event, bucket);
  const existing = store.get(k);
  const now = new Date().toISOString();
  if (existing) {
    existing.count += by;
    existing.lastUpdatedAt = now;
  } else {
    store.set(k, { event, bucket, count: by, lastUpdatedAt: now, windowStart: now });
  }
}

export function getCount(event: string, bucket: CounterBucket = 'global'): number {
  return store.get(makeKey(event, bucket))?.count ?? 0;
}

export function getEntry(event: string, bucket: CounterBucket = 'global'): CounterEntry | null {
  return store.get(makeKey(event, bucket)) ?? null;
}

export function getAllEntries(bucket?: CounterBucket): CounterEntry[] {
  const entries = Array.from(store.values());
  if (bucket) return entries.filter((e) => e.bucket === bucket);
  return entries;
}

export function getTopEvents(bucket: CounterBucket = 'global', limit = 10): CounterEntry[] {
  return getAllEntries(bucket)
    .sort((a, b) => b.count - a.count)
    .slice(0, limit);
}

export function resetCounter(event: string, bucket: CounterBucket = 'global'): void {
  store.delete(makeKey(event, bucket));
}

export function resetBucket(bucket: CounterBucket): void {
  for (const [k, e] of store) {
    if (e.bucket === bucket) store.delete(k);
  }
}

export function resetAll(): void {
  store.clear();
}

export function snapshot(): CounterSnapshot {
  return { capturedAt: new Date().toISOString(), entries: getAllEntries() };
}

export function pruneExpiredWindows(): number {
  const cutoff = Date.now() - decayConfig.windowMs;
  let pruned = 0;
  for (const [k, e] of store) {
    if (new Date(e.windowStart).getTime() < cutoff) {
      store.delete(k);
      pruned++;
    }
  }
  return pruned;
}
