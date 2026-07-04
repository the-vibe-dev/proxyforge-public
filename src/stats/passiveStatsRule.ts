// Passive stats rule — converts counter thresholds into findings.
// Reads from the counters engine and emits Issue-like objects when
// thresholds trip (e.g. excessive 5xx clustering, excessive redirects).
// No external dependencies.

import { getCount, getAllEntries } from './countersEngine';

export interface StatsThreshold {
  event: string;
  bucket?: string;
  threshold: number;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  title: string;
  detail: string;
}

export interface StatsIssue {
  ruleEvent: string;
  bucket: string;
  count: number;
  threshold: number;
  severity: StatsThreshold['severity'];
  title: string;
  detail: string;
  triggeredAt: string;
}

export const DEFAULT_THRESHOLDS: StatsThreshold[] = [
  {
    event: 'proxy.exchange.5xx',
    threshold: 20,
    severity: 'medium',
    title: 'Excessive 5xx responses on host',
    detail: 'More than 20 server errors observed from a single host — possible instability or scanning artifact.',
  },
  {
    event: 'proxy.exchange.redirect',
    threshold: 50,
    severity: 'low',
    title: 'Excessive redirect chain',
    detail: 'More than 50 redirects observed from a single host — possible open redirect or loop.',
  },
  {
    event: 'scanner.probe.high-confidence-finding',
    threshold: 10,
    severity: 'high',
    title: 'High-confidence finding cluster',
    detail: 'More than 10 high-confidence findings from a single host — may indicate a systemic vulnerability class.',
  },
  {
    event: 'proxy.exchange.4xx',
    threshold: 100,
    severity: 'info',
    title: 'High 4xx rate on host',
    detail: 'More than 100 client errors from a single host — check for misconfigured scope or aggressive scan.',
  },
];

export function evaluateThresholds(
  thresholds: StatsThreshold[] = DEFAULT_THRESHOLDS,
): StatsIssue[] {
  const issues: StatsIssue[] = [];
  const now = new Date().toISOString();

  for (const t of thresholds) {
    if (t.bucket) {
      const count = getCount(t.event, t.bucket);
      if (count >= t.threshold) {
        issues.push({ ruleEvent: t.event, bucket: t.bucket, count, threshold: t.threshold, severity: t.severity, title: t.title, detail: t.detail, triggeredAt: now });
      }
    } else {
      // check all buckets for this event
      const entries = getAllEntries().filter((e) => e.event === t.event);
      for (const entry of entries) {
        if (entry.count >= t.threshold) {
          issues.push({ ruleEvent: t.event, bucket: entry.bucket, count: entry.count, threshold: t.threshold, severity: t.severity, title: t.title, detail: t.detail, triggeredAt: now });
        }
      }
    }
  }

  return issues;
}

export function addThreshold(threshold: StatsThreshold, thresholds: StatsThreshold[]): StatsThreshold[] {
  return [...thresholds.filter((t) => t.event !== threshold.event || t.bucket !== threshold.bucket), threshold];
}
