// Persistence + sliding-window decay for the stats counter engine.
// Serializes counter snapshots to/from JSON for project store integration.
// No external dependencies.

import type { CounterSnapshot, CounterEntry } from './countersEngine';

export function serializeSnapshot(snapshot: CounterSnapshot): string {
  return JSON.stringify(snapshot, null, 2);
}

export function deserializeSnapshot(json: string): CounterSnapshot {
  const obj = JSON.parse(json);
  if (!obj.capturedAt || !Array.isArray(obj.entries)) {
    throw new Error('Invalid CounterSnapshot JSON');
  }
  return obj as CounterSnapshot;
}

export function mergeSnapshots(base: CounterSnapshot, delta: CounterSnapshot): CounterSnapshot {
  const merged = new Map<string, CounterEntry>();
  for (const e of base.entries) merged.set(`${e.bucket}::${e.event}`, { ...e });
  for (const e of delta.entries) {
    const k = `${e.bucket}::${e.event}`;
    const existing = merged.get(k);
    if (existing) {
      existing.count += e.count;
      if (e.lastUpdatedAt > existing.lastUpdatedAt) existing.lastUpdatedAt = e.lastUpdatedAt;
    } else {
      merged.set(k, { ...e });
    }
  }
  return { capturedAt: new Date().toISOString(), entries: Array.from(merged.values()) };
}

export function filterSnapshotByWindow(snapshot: CounterSnapshot, windowMs: number): CounterSnapshot {
  const cutoff = Date.now() - windowMs;
  return {
    capturedAt: snapshot.capturedAt,
    entries: snapshot.entries.filter((e) => new Date(e.windowStart).getTime() >= cutoff),
  };
}
