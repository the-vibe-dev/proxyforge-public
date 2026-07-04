import { useMemo, type ReactNode } from 'react';
import { AlertTriangle, ArrowUpRight, Bug, Cog, FileBarChart, FolderClock, Globe2, Pause, Play, ShieldCheck } from 'lucide-react';
import type { HttpExchange, Issue, ProjectSafetyPolicy, ToolId } from '../../types';
import { Badge, Banner, Button, IconButton, KV, Panel, SevDot, Sparkline, Stat, Toggle, Method, Status, type Severity } from './ui';
import { WorkspaceHeader } from './shell';

interface DashboardProps {
  projectName: string;
  workspaceLabel: string;
  exchanges: HttpExchange[];
  issues: Issue[];
  scopeAllowlist: string[];
  listenerHost: string;
  listenerPort: number;
  listenerRunning: boolean;
  safetyPolicy: ProjectSafetyPolicy;
  auditEventsCount: number;
  onLaunchBrowser: () => void;
  onToggleListener: () => void;
  onOpenWizard: () => void;
  onNavigate?: (tool: ToolId) => void;
}

function sevTone(sev: Severity | string): 'crit' | 'high' | 'med' | 'dim' {
  const k = String(sev).toLowerCase();
  if (k === 'critical') return 'crit';
  if (k === 'high') return 'high';
  if (k === 'medium') return 'med';
  return 'dim';
}

function severityRank(sev: string): number {
  const k = sev.toLowerCase();
  return k === 'critical' ? 4 : k === 'high' ? 3 : k === 'medium' ? 2 : k === 'low' ? 1 : 0;
}

export function DashboardScreen({
  projectName,
  workspaceLabel,
  exchanges,
  issues,
  scopeAllowlist,
  listenerHost,
  listenerPort,
  listenerRunning,
  safetyPolicy,
  auditEventsCount,
  onLaunchBrowser,
  onToggleListener,
  onOpenWizard,
  onNavigate,
}: DashboardProps) {
  const openIssues = useMemo(() => issues.filter((i) => i.status !== 'fixed'), [issues]);
  const criticalCount = useMemo(() => openIssues.filter((i) => severityRank(i.severity) >= 4).length, [openIssues]);
  const highCount = useMemo(() => openIssues.filter((i) => severityRank(i.severity) === 3).length, [openIssues]);
  const mediumCount = useMemo(() => openIssues.filter((i) => severityRank(i.severity) === 2).length, [openIssues]);
  const lowCount = useMemo(() => openIssues.filter((i) => severityRank(i.severity) === 1).length, [openIssues]);
  const fixedCount = useMemo(() => issues.filter((i) => i.status === 'fixed').length, [issues]);
  const triagedCount = useMemo(() => issues.filter((i) => i.status === 'triaged').length, [issues]);

  const inScopeExchanges = useMemo(() => {
    if (!scopeAllowlist.length) return exchanges;
    const hosts = new Set(scopeAllowlist.map((s) => s.trim().toLowerCase().replace(/^\*\./, '')));
    return exchanges.filter((e) => hosts.has((e.host || '').toLowerCase()) || scopeAllowlist.some((p) => {
      const norm = p.trim().toLowerCase();
      if (norm.startsWith('*.')) return (e.host || '').toLowerCase().endsWith(norm.slice(1));
      return (e.host || '').toLowerCase() === norm;
    }));
  }, [exchanges, scopeAllowlist]);

  const recentExchanges = useMemo(() => exchanges.slice(0, 12), [exchanges]);

  const sparkSamples = useMemo(() => {
    if (exchanges.length === 0) return Array(24).fill(0);
    const buckets = Array(24).fill(0);
    const now = Date.now();
    const span = 60 * 60 * 1000;
    for (const ex of exchanges) {
      const t = new Date(ex.time).getTime();
      const dt = (now - t) / span;
      const idx = Math.min(23, Math.max(0, 23 - Math.floor(dt)));
      buckets[idx] += 1;
    }
    return buckets;
  }, [exchanges]);

  const coverageList = useMemo(() => {
    const byHost = new Map<string, { reached: number; issues: number }>();
    for (const ex of exchanges) {
      if (!ex.host) continue;
      const entry = byHost.get(ex.host) ?? { reached: 0, issues: 0 };
      entry.reached += 1;
      byHost.set(ex.host, entry);
    }
    for (const issue of issues) {
      const host = issue.host;
      if (!host) continue;
      const entry = byHost.get(host) ?? { reached: 0, issues: 0 };
      entry.issues += 1;
      byHost.set(host, entry);
    }
    const inScopeHosts = new Set(scopeAllowlist.map((s) => s.replace(/^\*\./, '')));
    return Array.from(byHost.entries())
      .map(([host, v]) => ({ host, reached: v.reached, issues: v.issues, inScope: inScopeHosts.has(host) || inScopeHosts.size === 0 }))
      .sort((a, b) => b.reached - a.reached)
      .slice(0, 6);
  }, [exchanges, issues, scopeAllowlist]);

  const topCritical = openIssues
    .filter((i) => severityRank(i.severity) >= 3)
    .slice(0, 3)
    .map((i) => i.title)
    .join(' · ');

  return (
    <>
      <WorkspaceHeader
        maturity="alpha"
        maturityHint="Real-time view over captured exchanges, open findings, scope, and listener health."
        eyebrow={`PROJECT · ${workspaceLabel || 'WORKSPACE'}`}
        title={projectName || 'No project loaded'}
        subtitle={
          projectName
            ? <>
                Live capture on {listenerHost}:{listenerPort}
                {scopeAllowlist.length > 0 ? <> · {scopeAllowlist.length} scope hosts</> : null}
                {safetyPolicy.requireScopeMatch ? <> · scope-gated</> : null}
              </>
            : 'Open the Setup wizard to name a project and define scope before capturing.'
        }
        actions={
          <>
            <Button icon={Globe2} onClick={onLaunchBrowser}>Launch managed browser</Button>
            <Button variant="ghost" icon={listenerRunning ? Pause : Play} onClick={onToggleListener}>
              {listenerRunning ? 'Pause capture' : 'Start capture'}
            </Button>
            {!projectName ? <Button variant="accent" onClick={onOpenWizard}>Setup wizard</Button> : null}
          </>
        }
      />

      <div className="ws-body">
        {criticalCount + highCount > 0 && topCritical ? (
          <Banner tone="warn" icon={AlertTriangle}
            action={<Button size="sm" variant="ghost" onClick={() => onNavigate?.('scanner')} title="Open Scanner to triage findings">Review →</Button>}>
            <strong>{criticalCount + highCount} findings need triage</strong> · {topCritical}
          </Banner>
        ) : null}

        <div className="pf-cards cols-4">
          <Stat
            label="In-scope requests · 24h"
            value={inScopeExchanges.length.toLocaleString()}
            delta={exchanges.length > inScopeExchanges.length
              ? `${exchanges.length - inScopeExchanges.length} excluded by scope`
              : 'all captured'}
            spark={sparkSamples}
            accent
          />
          <Stat
            label="Findings open"
            value={openIssues.length}
            delta={`${criticalCount} critical · ${highCount} high`}
          />
          <Stat
            label="Scope"
            value={`${scopeAllowlist.length}`}
            delta={scopeAllowlist.length ? scopeAllowlist.slice(0, 2).join(', ') : 'not configured'}
          />
          <Stat
            label="Listener"
            value={listenerRunning ? `${listenerPort}` : 'stopped'}
            delta={listenerRunning ? `${listenerHost} ready` : 'start to begin capture'}
            deltaDir={listenerRunning ? 'up' : undefined}
          />
        </div>

        <div className="pf-cards cols-2" style={{ gridTemplateColumns: '2fr 1fr' }}>
          <Panel
            title="Findings by severity"
            actions={
              <>
                <span className="pf-legend">
                  <span className="pf-legend-item"><SevDot level="Critical" /> Critical</span>
                  <span className="pf-legend-item"><SevDot level="High" /> High</span>
                  <span className="pf-legend-item"><SevDot level="Medium" /> Medium</span>
                  <span className="pf-legend-item"><SevDot level="Low" /> Low</span>
                </span>
              </>
            }
            bodyStyle={{ padding: 0 }}
          >
            <SeverityBars
              data={[
                { label: 'Critical', count: criticalCount, tone: 'crit' },
                { label: 'High', count: highCount, tone: 'high' },
                { label: 'Medium', count: mediumCount, tone: 'med' },
                { label: 'Low', count: lowCount, tone: 'low' },
              ]}
            />
            <div style={{ padding: '12px 14px', borderTop: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div className="pf-row-meta">
                <span>{openIssues.length} open</span>
                <span className="sep">·</span>
                <span>{fixedCount} fixed</span>
                <span className="sep">·</span>
                <span>{triagedCount} triaged</span>
              </div>
              <Button size="sm" variant="ghost" iconRight={ArrowUpRight} onClick={() => onNavigate?.('scanner')} title="Open the Scanner workbench">Open Scanner</Button>
            </div>
          </Panel>

          <Panel title="Policy & runners" actions={safetyPolicy.auditLogging ? <Badge tone="ok">AUDITED</Badge> : <Badge tone="dim">OFF</Badge>}>
            <KV compact data={[
              ['Scope match required', safetyPolicy.requireScopeMatch ? 'yes' : 'no'],
              ['Throttle floor', `${safetyPolicy.minThrottleMs ?? 0} ms`],
              ['Max requests/run', `${safetyPolicy.maxRequestsPerRun ?? 0}`],
              ['Redact secrets', safetyPolicy.redactAuditSecrets ? 'yes' : 'no'],
              ['Audit logging', safetyPolicy.auditLogging ? `on (${auditEventsCount} events)` : 'off'],
              ['Listener', `${listenerHost}:${listenerPort}`],
              ['Scope hosts', `${scopeAllowlist.length}`],
            ]} />
            <div style={{ marginTop: 14, display: 'flex', gap: 8 }}>
              <Button size="sm" variant="ghost" icon={ShieldCheck} onClick={() => onNavigate?.('settings')} title="Open Settings → Policy">Review policy</Button>
            </div>
          </Panel>
        </div>

        <div className="pf-cards cols-2" style={{ gridTemplateColumns: '2fr 1fr' }}>
          <Panel
            title="Recent traffic"
            eyebrow={listenerRunning ? 'LIVE' : 'IDLE'}
            flush
            actions={
              <>
                <Toggle on={listenerRunning} onChange={() => onToggleListener()} label="Capture" />
                <Button size="sm" variant="ghost" iconRight={ArrowUpRight} onClick={() => onNavigate?.('proxy')} title="Open the Proxy workbench">Open Proxy</Button>
              </>
            }
          >
            <div style={{ maxHeight: 320, overflow: 'auto', background: 'var(--surface)' }}>
              <table className="pf-table">
                <thead><tr>
                  <th style={{ width: 70 }}>Method</th>
                  <th>Host</th>
                  <th>Path</th>
                  <th className="right" style={{ width: 70 }}>Status</th>
                  <th className="right" style={{ width: 80 }}>Size</th>
                  <th className="right" style={{ width: 60 }}>ms</th>
                </tr></thead>
                <tbody>
                  {recentExchanges.length === 0 ? (
                    <tr><td colSpan={6} style={{ padding: '24px 14px', color: 'var(--text-faint)', textAlign: 'center' }}>
                      No traffic captured yet. Start the listener and configure a browser.
                    </td></tr>
                  ) : recentExchanges.map((t) => (
                    <tr key={t.id}>
                      <td><Method m={t.method} /></td>
                      <td className="dim">{t.host}</td>
                      <td>{t.path}</td>
                      <td className="right"><Status s={t.status} /></td>
                      <td className="right dim">{((t.length || 0) / 1024).toFixed(1)}k</td>
                      <td className="right dim">{t.timing}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Panel>

          <Panel title="Open critical findings">
            {openIssues.filter((i) => severityRank(i.severity) >= 3).slice(0, 6).length === 0 ? (
              <div style={{ padding: '20px 0', color: 'var(--text-faint)', fontSize: 12.5 }}>
                No critical or high-severity issues yet.
              </div>
            ) : (
              <div className="pf-list" style={{ margin: -12 }}>
                {openIssues.filter((i) => severityRank(i.severity) >= 3).slice(0, 6).map((issue) => (
                  <div className="pf-list-item" key={issue.id} style={{ padding: '11px 14px' }}>
                    <div className="pf-list-item-mark" />
                    <div style={{ paddingTop: 1 }}>
                      <Badge tone={sevTone(issue.severity)}>{issue.severity}</Badge>
                    </div>
                    <div className="pf-list-item-main">
                      <div className="pf-list-item-title">{issue.title}</div>
                      <div className="pf-list-item-meta">
                        <span>{issue.host || '—'}{issue.path ? issue.path : ''}</span>
                        <span className="sep">·</span>
                        <span>{issue.status}</span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </Panel>
        </div>

        <div className="pf-cards cols-2">
          <Panel
            title="Coverage by host"
            actions={<Button size="sm" variant="ghost" iconRight={ArrowUpRight} onClick={() => onNavigate?.('target')} title="Open the Target Map">Open Target Map</Button>}
          >
            {coverageList.length === 0 ? (
              <div style={{ padding: '20px 0', color: 'var(--text-faint)', fontSize: 12.5 }}>
                No hosts captured yet.
              </div>
            ) : (
              <div className="pf-list" style={{ margin: -12 }}>
                {(() => {
                  const maxReached = Math.max(...coverageList.map((c) => c.reached), 1);
                  return coverageList.map((d) => {
                    const pct = Math.min(100, Math.round((d.reached / maxReached) * 100));
                    return (
                    <div className="pf-list-item" key={d.host} style={{ padding: '11px 14px' }}>
                      <div className="pf-list-item-mark" />
                      <div className="pf-list-item-main">
                        <div className="pf-list-item-title">
                          <span className="mono" style={{ fontSize: 12, fontWeight: 500 }}>{d.host}</span>
                          {!d.inScope ? <Badge tone="dim">OUT</Badge> : null}
                          <span style={{ marginLeft: 'auto' }} className="pf-row-meta">
                            <span>{d.reached} req</span>
                            <span className="sep">·</span>
                            <span>{d.issues} issues</span>
                          </span>
                        </div>
                        <div style={{ height: 4, background: 'var(--surface-3)', borderRadius: 2, overflow: 'hidden', marginTop: 4 }}>
                          <div style={{ height: '100%', width: `${pct}%`, background: d.inScope ? 'var(--accent)' : 'var(--text-mute)' }} />
                        </div>
                      </div>
                    </div>
                    );
                  });
                })()}
              </div>
            )}
          </Panel>

          <Panel title="Next steps">
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              {!projectName ? (
                <ChecklistItem done={false} action={<Button size="sm" onClick={onOpenWizard}>Open wizard</Button>}>
                  Run the setup wizard
                </ChecklistItem>
              ) : null}
              <ChecklistItem done={scopeAllowlist.length > 0}>
                Define scope (currently {scopeAllowlist.length} hosts)
              </ChecklistItem>
              <ChecklistItem done={listenerRunning} action={!listenerRunning ? <Button size="sm" onClick={onToggleListener}>Start</Button> : undefined}>
                Start the proxy listener on {listenerHost}:{listenerPort}
              </ChecklistItem>
              <ChecklistItem done={exchanges.length > 0}>
                Send traffic through the proxy ({exchanges.length} captured)
              </ChecklistItem>
              <ChecklistItem done={issues.length > 0}>
                Run a scan ({issues.length} findings)
              </ChecklistItem>
            </div>
          </Panel>
        </div>
      </div>
    </>
  );
}

function ChecklistItem({ done, children, action }: { done: boolean; children: ReactNode; action?: ReactNode }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 10, fontSize: 12.5 }}>
      <span style={{
        width: 16, height: 16, borderRadius: 4, border: '1px solid var(--border-strong)',
        background: done ? 'var(--ok)' : 'var(--surface-2)',
        color: done ? 'var(--bg-base)' : 'transparent',
        display: 'grid', placeItems: 'center', fontSize: 10,
      }}>
        {done ? '✓' : ''}
      </span>
      <span style={{ flex: 1, color: done ? 'var(--text-dim)' : 'var(--text-base)', textDecoration: done ? 'line-through' : 'none' }}>{children}</span>
      {action}
    </div>
  );
}

interface SeverityBar {
  label: string;
  count: number;
  tone: 'crit' | 'high' | 'med' | 'low';
}

function SeverityBars({ data }: { data: SeverityBar[] }) {
  const max = Math.max(...data.map((d) => d.count), 1);
  return (
    <div style={{ padding: '14px 16px', display: 'flex', flexDirection: 'column', gap: 10 }}>
      {data.map((d) => (
        <div key={d.label} style={{ display: 'grid', gridTemplateColumns: '70px 1fr 36px', alignItems: 'center', gap: 12 }}>
          <div style={{ fontSize: 12, color: 'var(--text-dim)', display: 'flex', alignItems: 'center', gap: 6 }}>
            <SevDot level={d.label} /> {d.label}
          </div>
          <div style={{ height: 8, background: 'var(--surface-3)', borderRadius: 2, overflow: 'hidden', position: 'relative' }}>
            <div
              style={{
                height: '100%',
                width: `${(d.count / max) * 100}%`,
                background:
                  d.tone === 'crit' ? 'var(--critical)'
                  : d.tone === 'high' ? 'var(--accent)'
                  : d.tone === 'med' ? 'var(--medium)'
                  : 'var(--text-faint)',
              }}
            />
          </div>
          <div className="mono" style={{ fontSize: 12, color: 'var(--text-base)', textAlign: 'right', fontWeight: 500 }}>{d.count}</div>
        </div>
      ))}
    </div>
  );
}
