import { useMemo, useState } from 'react';
import {
  Activity, ArrowRight, Bug, Check, Clock, Download, Flag,
  FlaskConical, Layers, Play, Plus, RotateCcw, ScanLine,
  Settings, ShieldCheck, Sliders, Upload, Wifi, Zap,
} from 'lucide-react';
import type { Issue, IssueTriageOverride, ScannerAuditQueueItem } from '../../../types';
import { Badge, Banner, Button, IconButton, KV, Panel, SevDot, Tabs } from '../ui';
import { WorkspaceHeader } from '../shell';

export interface ScannerCheckPackEntry {
  id: string;
  label: string;
  detail: string;
  checks: readonly string[];
}

// --- Workspace types ---

export interface WorkspaceExchange {
  id: string;
  method: string;
  url: string;
  status?: number;
  host?: string;
  path?: string;
}

export interface WorkspaceInsertionPoint {
  id: string;
  kind: 'query' | 'body' | 'header' | 'path' | 'json' | 'cookie' | 'multipart';
  name: string;
  baseValue?: string;
}

export interface WorkspaceProbeRow {
  variantId: string;
  family: string;
  encoding: string;
  intent: string;
  requiresOast: boolean;
  destructiveRisk: 'none' | 'low' | 'medium' | 'high';
}

export type ObservationClass =
  | 'expected-proof'
  | 'reflected-inert'
  | 'timing-delta'
  | 'oast-callback-confirmed'
  | 'neutral-or-not-parsed'
  | 'method-or-parser-rejected'
  | 'unknown';

export interface WorkspaceLiveObservation {
  variantId: string;
  payloadPreview: string;
  observationClass: ObservationClass;
  responseHint?: string;
  timestamp: string;
}

export interface WorkspaceConclusion {
  state: 'running' | 'finding' | 'negative' | 'inconclusive' | 'stopped';
  confidence: number;
  checkId?: string;
  family?: string;
  summary?: string;
  oastWaiting?: boolean;
}

export interface ScanWorkspaceState {
  sourceExchange?: WorkspaceExchange;
  insertionPoints: WorkspaceInsertionPoint[];
  selectedInsertionPointId?: string;
  probeMatrix: WorkspaceProbeRow[];
  liveObservations: WorkspaceLiveObservation[];
  conclusion?: WorkspaceConclusion;
  budgetUsed: number;
  budgetMax: number;
  throttleMs: number;
  oastEnabled: boolean;
}

interface ScannerProps {
  issues: Issue[];
  selectedIssueId: string;
  setSelectedIssueId: (id: string) => void;
  scannerAuditQueue: ScannerAuditQueueItem[];
  checkPacks: readonly ScannerCheckPackEntry[];
  selectedCheckPackId: string;
  setSelectedCheckPackId: (id: string) => void;
  onNewActiveScan?: () => void;
  onExportFindings?: () => void;
  onUpdateIssueTriage?: (issueId: string, patch: Partial<Pick<IssueTriageOverride, 'status' | 'assignee' | 'triageNote'>>) => void;
  onRetestIssue?: () => void;
  workspace?: ScanWorkspaceState;
  onPromoteToIssue?: () => void;
  onSendToExploitLab?: () => void;
  onSelectInsertionPoint?: (id: string) => void;
}

export function ScannerScreen(props: ScannerProps) {
  const [tab, setTab] = useState<'findings' | 'workspace' | 'queue' | 'checks' | 'anvil' | 'retests'>('findings');
  const openCount = props.issues.filter((i) => i.status !== 'fixed').length;
  const wsObs = props.workspace?.liveObservations.length ?? 0;
  return (
    <>
      <WorkspaceHeader
        eyebrow="TESTING"
        title="Scanner"
        maturity="alpha"
        maturityHint="Passive + active checks, audit queue, and Anvil rule packs are wired at the engine level. Triage actions (mark fixed / retest / add to report) and check-pack import are coming soon."
        subtitle="Passive + active checks · audit queue · retest workflows · Anvil custom rules"
        actions={
          <>
            <Button variant="ghost" icon={Upload} comingSoon title="Import a community / vendor BCheck-style check pack">Import check pack</Button>
            <Button
              variant="ghost" icon={Download}
              onClick={props.onExportFindings}
              disabled={!props.onExportFindings || props.issues.length === 0}
              title={props.issues.length === 0 ? 'No findings yet to export' : 'Download all findings as a JSON evidence pack'}
            >
              Export findings
            </Button>
            <Button icon={Settings} comingSoon title="Configure scanner check selection, throttles, and depth">Configure</Button>
            <Button
              variant="accent" icon={Play}
              onClick={props.onNewActiveScan}
              disabled={!props.onNewActiveScan}
              title={props.onNewActiveScan ? 'Start a new active scan against an in-scope target' : 'Active scan handler is not wired in this build'}
            >
              Active scan
            </Button>
          </>
        }
      />
      <Tabs<'findings' | 'workspace' | 'queue' | 'checks' | 'anvil' | 'retests'>
        value={tab}
        onChange={setTab}
        items={[
          { value: 'findings', label: 'Findings', icon: Bug, count: openCount },
          { value: 'workspace', label: 'Workspace', icon: Activity, count: wsObs || undefined },
          { value: 'queue', label: 'Audit queue', icon: ScanLine, count: props.scannerAuditQueue.length },
          { value: 'checks', label: 'Active checks', icon: Settings },
          { value: 'anvil', label: 'Anvil checks', icon: ShieldCheck },
          { value: 'retests', label: 'Retests', icon: RotateCcw },
        ]}
      />
      {tab === 'findings' ? <Findings {...props} /> : null}
      {tab === 'workspace' ? (
        <ScanWorkspace
          state={props.workspace}
          checkPacks={props.checkPacks}
          selectedCheckPackId={props.selectedCheckPackId}
          onSelectCheckPack={props.setSelectedCheckPackId}
          onPromoteToIssue={props.onPromoteToIssue}
          onSendToExploitLab={props.onSendToExploitLab}
          onSelectInsertionPoint={props.onSelectInsertionPoint}
          onStartScan={props.onNewActiveScan}
        />
      ) : null}
      {tab === 'queue' ? <Queue queue={props.scannerAuditQueue} /> : null}
      {tab === 'checks' ? (
        <Checks
          packs={props.checkPacks}
          selectedId={props.selectedCheckPackId}
          onSelect={props.setSelectedCheckPackId}
        />
      ) : null}
      {tab === 'anvil' ? <AnvilTab /> : null}
      {tab === 'retests' ? <Retests /> : null}
    </>
  );
}

// ---------------------------------------------------------------------------
// Workspace — active scan workspace
// ---------------------------------------------------------------------------

function ScanWorkspace({
  state,
  checkPacks,
  selectedCheckPackId,
  onSelectCheckPack,
  onPromoteToIssue,
  onSendToExploitLab,
  onSelectInsertionPoint,
  onStartScan,
}: {
  state?: ScanWorkspaceState;
  checkPacks: readonly ScannerCheckPackEntry[];
  selectedCheckPackId: string;
  onSelectCheckPack: (id: string) => void;
  onPromoteToIssue?: () => void;
  onSendToExploitLab?: () => void;
  onSelectInsertionPoint?: (id: string) => void;
  onStartScan?: () => void;
}) {
  if (!state) {
    return (
      <div className="ws-body" style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
        <Banner tone="warn" icon={Activity}>
          No active scan workspace. Select a captured request from the Proxy or Logger and click
          <strong> Send to Scanner</strong> to configure an active scan.
        </Banner>
        <Panel title="Quick start">
          <div style={{ padding: '12px 16px', display: 'flex', flexDirection: 'column', gap: 10 }}>
            <div style={{ fontSize: 12.5, color: 'var(--text-dim)', lineHeight: 1.6 }}>
              1. Capture traffic through the proxy or open the Logger.<br />
              2. Right-click a request → <em>Send to Scanner</em>.<br />
              3. Select insertion points, choose a check pack, configure budget/throttle.<br />
              4. Click <strong>Active scan</strong> to launch.
            </div>
            <Button variant="accent" icon={Play} onClick={onStartScan} disabled={!onStartScan}>
              Active scan
            </Button>
          </div>
        </Panel>
      </div>
    );
  }

  const { sourceExchange, insertionPoints, selectedInsertionPointId, probeMatrix,
          liveObservations, conclusion, budgetUsed, budgetMax, throttleMs, oastEnabled } = state;

  const budgetPct = budgetMax > 0 ? Math.min(100, Math.round((budgetUsed / budgetMax) * 100)) : 0;
  const selectedPt = insertionPoints.find((p) => p.id === selectedInsertionPointId) ?? insertionPoints[0];

  return (
    <div className="ws-body flush" style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
      {/* Top strip: source exchange */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 10, padding: '8px 16px',
        borderBottom: '1px solid var(--border)', background: 'var(--surface-2)', flexShrink: 0,
      }}>
        <span style={{ fontSize: 11, color: 'var(--text-faint)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Source</span>
        {sourceExchange ? (
          <>
            <Badge tone={sourceExchange.method === 'POST' ? 'accent' : 'dim'}>{sourceExchange.method}</Badge>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-base)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {sourceExchange.url}
            </span>
            {sourceExchange.status ? <Badge tone={sourceExchange.status < 400 ? 'ok' : 'high'}>{sourceExchange.status}</Badge> : null}
          </>
        ) : (
          <span style={{ fontSize: 12, color: 'var(--text-faint)' }}>No source request selected</span>
        )}
      </div>

      {/* Main layout: left rail + right panels */}
      <div style={{ display: 'grid', gridTemplateColumns: '220px 1fr', flex: 1, minHeight: 0 }}>
        {/* Left: insertion points */}
        <div style={{ borderRight: '1px solid var(--border)', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
          <div style={{ padding: '8px 12px 4px', fontSize: 11, color: 'var(--text-faint)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Insertion points
          </div>
          <div style={{ overflowY: 'auto', flex: 1 }}>
            {insertionPoints.length === 0 ? (
              <div style={{ padding: '12px', fontSize: 12, color: 'var(--text-faint)' }}>None detected</div>
            ) : insertionPoints.map((pt) => (
              <div
                key={pt.id}
                onClick={() => onSelectInsertionPoint?.(pt.id)}
                style={{
                  padding: '6px 12px', cursor: 'pointer', display: 'flex', flexDirection: 'column', gap: 2,
                  background: pt.id === selectedPt?.id ? 'var(--selected)' : undefined,
                  borderLeft: pt.id === selectedPt?.id ? '2px solid var(--accent)' : '2px solid transparent',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <InsertionPointKindBadge kind={pt.kind} />
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-base)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{pt.name}</span>
                </div>
                {pt.baseValue ? <div style={{ fontSize: 11, color: 'var(--text-faint)', paddingLeft: 2, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{pt.baseValue}</div> : null}
              </div>
            ))}
          </div>
        </div>

        {/* Right: panels */}
        <div style={{ display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
          <div style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 0 }}>

            {/* Check pack + budget config */}
            <div style={{ padding: '10px 16px', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', gap: 16, flexShrink: 0 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <Sliders size={14} style={{ color: 'var(--text-faint)' }} />
                <span style={{ fontSize: 12, color: 'var(--text-faint)' }}>Check pack</span>
                <select
                  value={selectedCheckPackId}
                  onChange={(e) => onSelectCheckPack(e.target.value)}
                  style={{ fontFamily: 'var(--font-mono)', fontSize: 12, background: 'var(--surface)', border: '1px solid var(--border-strong)', borderRadius: 4, color: 'var(--text-base)', padding: '2px 6px' }}
                >
                  {checkPacks.map((p) => <option key={p.id} value={p.id}>{p.label} ({p.checks.length} checks)</option>)}
                </select>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <Clock size={13} style={{ color: 'var(--text-faint)' }} />
                <span style={{ fontSize: 12, color: 'var(--text-faint)' }}>Throttle</span>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-base)' }}>{throttleMs}ms</span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <Wifi size={13} style={{ color: oastEnabled ? 'var(--accent)' : 'var(--text-faint)' }} />
                <span style={{ fontSize: 12, color: oastEnabled ? 'var(--accent)' : 'var(--text-faint)' }}>OAST {oastEnabled ? 'ON' : 'OFF'}</span>
              </div>
              <div style={{ flex: 1 }} />
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <div style={{
                  width: 80, height: 6, background: 'var(--surface-2)', borderRadius: 3, overflow: 'hidden',
                  border: '1px solid var(--border)',
                }}>
                  <div style={{ width: `${budgetPct}%`, height: '100%', background: budgetPct > 80 ? 'var(--crit)' : 'var(--accent)', transition: 'width 0.3s' }} />
                </div>
                <span style={{ fontSize: 11.5, color: 'var(--text-faint)' }}>{budgetUsed}/{budgetMax} req</span>
              </div>
            </div>

            {/* Probe matrix */}
            <Panel title={`Probe matrix${selectedPt ? ` · ${selectedPt.name}` : ''}`} flush>
              <div className="pf-table-wrap" style={{ maxHeight: 200, overflowY: 'auto' }}>
                <table className="pf-table">
                  <thead><tr>
                    <th>Variant</th>
                    <th style={{ width: 130 }}>Family</th>
                    <th style={{ width: 100 }}>Encoding</th>
                    <th>Intent</th>
                    <th style={{ width: 50 }}>OAST</th>
                    <th style={{ width: 60 }}>Risk</th>
                  </tr></thead>
                  <tbody>
                    {probeMatrix.length === 0 ? (
                      <tr><td colSpan={6} style={emptyRowStyle}>
                        {insertionPoints.length === 0 ? 'No insertion points detected.' : 'Select an insertion point to preview probe matrix.'}
                      </td></tr>
                    ) : probeMatrix.map((row) => (
                      <tr key={row.variantId}>
                        <td className="mono" style={{ fontSize: 11 }}>{row.variantId}</td>
                        <td><Badge tone="dim">{row.family}</Badge></td>
                        <td className="dim">{row.encoding}</td>
                        <td className="dim" style={{ fontSize: 11.5 }}>{row.intent}</td>
                        <td>{row.requiresOast ? <Badge tone="accent">OAST</Badge> : <span className="dim">—</span>}</td>
                        <td><RiskBadge risk={row.destructiveRisk} /></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Panel>

            {/* Live observations */}
            <Panel title="Live observations" flush>
              <div className="pf-table-wrap" style={{ maxHeight: 220, overflowY: 'auto' }}>
                <table className="pf-table">
                  <thead><tr>
                    <th style={{ width: 120 }}>Variant</th>
                    <th style={{ width: 160 }}>Class</th>
                    <th>Payload preview</th>
                    <th>Response hint</th>
                    <th style={{ width: 80 }}>Time</th>
                  </tr></thead>
                  <tbody>
                    {liveObservations.length === 0 ? (
                      <tr><td colSpan={5} style={emptyRowStyle}>
                        {conclusion?.state === 'running' ? 'Waiting for probe responses…' : 'No observations yet. Start an active scan to populate this view.'}
                      </td></tr>
                    ) : [...liveObservations].reverse().map((obs) => (
                      <tr key={obs.variantId + obs.timestamp}>
                        <td className="mono" style={{ fontSize: 11 }}>{obs.variantId}</td>
                        <td><ObsClassBadge cls={obs.observationClass} /></td>
                        <td className="mono" style={{ fontSize: 11, maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{obs.payloadPreview}</td>
                        <td className="dim" style={{ fontSize: 11.5 }}>{obs.responseHint ?? '—'}</td>
                        <td className="dim" style={{ fontSize: 11 }}>{obs.timestamp.slice(11, 19)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Panel>

            {/* Conclusion + OAST wait + actions */}
            {conclusion ? (
              <div style={{ padding: '12px 16px', borderTop: '1px solid var(--border)', display: 'flex', alignItems: 'center', gap: 12 }}>
                <ConclusionBadge state={conclusion.state} confidence={conclusion.confidence} />
                {conclusion.oastWaiting ? (
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <Wifi size={13} style={{ color: 'var(--accent)', animation: 'pulse 1.5s infinite' }} />
                    <span style={{ fontSize: 12, color: 'var(--accent)' }}>Waiting for OAST callback…</span>
                  </div>
                ) : null}
                {conclusion.summary ? (
                  <span style={{ fontSize: 12.5, color: 'var(--text-dim)', flex: 1 }}>{conclusion.summary}</span>
                ) : null}
                <div style={{ display: 'flex', gap: 8 }}>
                  <Button
                    size="sm" icon={ArrowRight}
                    onClick={onPromoteToIssue}
                    disabled={!onPromoteToIssue || conclusion.state !== 'finding'}
                    title={conclusion.state === 'finding' ? 'Promote this finding to the Issues list' : 'Only available when conclusion is "finding"'}
                  >
                    Promote to issue
                  </Button>
                  <Button
                    size="sm" variant="ghost" icon={FlaskConical}
                    onClick={onSendToExploitLab}
                    disabled={!onSendToExploitLab || conclusion.state === 'negative'}
                    title="Send this finding to the Exploit Lab for template-guided exploitation"
                  >
                    Send to Exploit Lab
                  </Button>
                </div>
              </div>
            ) : null}
          </div>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Workspace helper components
// ---------------------------------------------------------------------------

function InsertionPointKindBadge({ kind }: { kind: WorkspaceInsertionPoint['kind'] }) {
  const colors: Record<string, string> = {
    query: '#4a9eff', body: '#f0a030', header: '#9b59b6',
    path: '#2ecc71', json: '#e67e22', cookie: '#e74c3c', multipart: '#1abc9c',
  };
  return (
    <span style={{
      fontFamily: 'var(--font-mono)', fontSize: 10, padding: '1px 4px',
      borderRadius: 3, background: (colors[kind] ?? '#666') + '22',
      color: colors[kind] ?? '#999', border: `1px solid ${colors[kind] ?? '#666'}44`,
      textTransform: 'uppercase', letterSpacing: '0.04em', flexShrink: 0,
    }}>{kind.slice(0, 3)}</span>
  );
}

function RiskBadge({ risk }: { risk: WorkspaceProbeRow['destructiveRisk'] }) {
  const tone = risk === 'high' ? 'crit' : risk === 'medium' ? 'high' : risk === 'low' ? 'med' : 'dim';
  return risk === 'none' ? <span className="dim" style={{ fontSize: 11 }}>—</span> : <Badge tone={tone as 'crit' | 'high' | 'med' | 'dim' | 'ok' | 'accent'}>{risk}</Badge>;
}

function ObsClassBadge({ cls }: { cls: ObservationClass }) {
  const map: Record<ObservationClass, { label: string; tone: 'crit' | 'high' | 'med' | 'dim' | 'ok' | 'accent' }> = {
    'expected-proof':            { label: 'PROOF', tone: 'crit' },
    'oast-callback-confirmed':   { label: 'OAST CONFIRMED', tone: 'crit' },
    'timing-delta':              { label: 'TIMING DELTA', tone: 'high' },
    'reflected-inert':           { label: 'REFLECTED', tone: 'med' },
    'neutral-or-not-parsed':     { label: 'NEUTRAL', tone: 'dim' },
    'method-or-parser-rejected': { label: 'REJECTED', tone: 'dim' },
    'unknown':                   { label: 'UNKNOWN', tone: 'dim' },
  };
  const { label, tone } = map[cls] ?? { label: cls, tone: 'dim' };
  return <Badge tone={tone}>{label}</Badge>;
}

function ConclusionBadge({ state, confidence }: { state: WorkspaceConclusion['state']; confidence: number }) {
  const map: Record<WorkspaceConclusion['state'], { label: string; tone: 'crit' | 'high' | 'med' | 'dim' | 'ok' | 'accent' }> = {
    running:      { label: 'RUNNING', tone: 'accent' },
    finding:      { label: 'FINDING', tone: 'crit' },
    negative:     { label: 'NEGATIVE', tone: 'ok' },
    inconclusive: { label: 'INCONCLUSIVE', tone: 'med' },
    stopped:      { label: 'STOPPED', tone: 'dim' },
  };
  const { label, tone } = map[state];
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
      <Badge tone={tone}>{label}</Badge>
      <span style={{ fontSize: 11.5, color: 'var(--text-faint)' }}>{Math.round(confidence * 100)}% confidence</span>
    </div>
  );
}

function sevTone(sev: string): 'crit' | 'high' | 'med' | 'dim' | 'ok' {
  const k = sev.toLowerCase();
  if (k === 'critical') return 'crit';
  if (k === 'high') return 'high';
  if (k === 'medium') return 'med';
  if (k === 'fixed') return 'ok';
  return 'dim';
}

function severityRank(sev: string): number {
  const k = sev.toLowerCase();
  return k === 'critical' ? 4 : k === 'high' ? 3 : k === 'medium' ? 2 : k === 'low' ? 1 : 0;
}

function Findings({ issues, selectedIssueId, setSelectedIssueId, onUpdateIssueTriage, onRetestIssue }: ScannerProps) {
  const sorted = useMemo(() => [...issues].sort((a, b) => severityRank(b.severity) - severityRank(a.severity)), [issues]);
  const selected = sorted.find((i) => i.id === selectedIssueId) ?? sorted[0];
  const counts = useMemo(() => {
    const c = { crit: 0, high: 0, med: 0, low: 0 };
    for (const i of issues) {
      if (i.status === 'fixed') continue;
      const r = severityRank(i.severity);
      if (r === 4) c.crit++;
      else if (r === 3) c.high++;
      else if (r === 2) c.med++;
      else c.low++;
    }
    return c;
  }, [issues]);

  return (
    <div className="ws-body flush" style={{ display: 'flex', flexDirection: 'column', minHeight: 0, flex: 1 }}>
      <div className="pf-filterbar">
        <input className="pf-input" placeholder="Filter findings — severity:high status:open" style={inputStyle} />
        <Chip on>open</Chip>
        <Chip>critical + high</Chip>
        <Chip>mine</Chip>
        <div style={{ flex: 1 }} />
        <div className="pf-row-meta">
          <span>{counts.crit} critical</span><span className="sep">·</span>
          <span>{counts.high} high</span><span className="sep">·</span>
          <span>{counts.med} medium</span><span className="sep">·</span>
          <span>{counts.low} low</span>
        </div>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '3fr 2fr', flex: 1, minHeight: 0 }}>
        <div className="pf-table-wrap" style={{ minHeight: 0 }}>
          <table className="pf-table">
            <thead><tr>
              <th style={{ width: 22 }}></th>
              <th>Title</th>
              <th style={{ width: 220 }}>Host</th>
              <th style={{ width: 90 }}>Confidence</th>
              <th style={{ width: 80 }}>Status</th>
            </tr></thead>
            <tbody>
              {sorted.length === 0 ? (
                <tr><td colSpan={5} style={emptyRowStyle}>
                  No findings yet. Run an active scan or capture traffic to trigger passive checks.
                </td></tr>
              ) : sorted.map((i) => (
                <tr key={i.id}
                    className={i.id === selected?.id ? 'is-selected' : ''}
                    onClick={() => setSelectedIssueId(i.id)}>
                  <td><SevDot level={i.severity[0].toUpperCase() + i.severity.slice(1)} /></td>
                  <td style={{ fontFamily: 'var(--font-sans)', color: 'var(--text-base)' }}>{i.title}</td>
                  <td className="dim">{i.host}{i.path}</td>
                  <td className="dim">{i.confidence}</td>
                  <td>
                    {i.status === 'open' ? <Badge tone="accent">OPEN</Badge>
                     : i.status === 'fixed' ? <Badge tone="ok">FIXED</Badge>
                     : i.status === 'false-positive' ? <Badge tone="dim">FP</Badge>
                     : <Badge tone="med">{i.status.toUpperCase()}</Badge>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <FindingDetail issue={selected} onUpdateIssueTriage={onUpdateIssueTriage} onRetestIssue={onRetestIssue} />
      </div>
    </div>
  );
}

function FindingDetail({ issue, onUpdateIssueTriage, onRetestIssue }: { issue?: Issue; onUpdateIssueTriage?: ScannerProps['onUpdateIssueTriage']; onRetestIssue?: ScannerProps['onRetestIssue'] }) {
  if (!issue) {
    return (
      <div style={{
        background: 'var(--surface)', borderLeft: '1px solid var(--border)',
        display: 'grid', placeItems: 'center', color: 'var(--text-faint)', fontSize: 13,
      }}>
        Select a finding to inspect.
      </div>
    );
  }
  return (
    <div style={{ background: 'var(--surface)', borderLeft: '1px solid var(--border)', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <div className="pf-panel-head">
        <div className="pf-panel-title">
          <SevDot level={issue.severity[0].toUpperCase() + issue.severity.slice(1)} />
          <span style={{ fontFamily: 'var(--font-sans)', fontSize: 13 }}>{issue.title}</span>
        </div>
        <div style={{ display: 'flex', gap: 6 }}>
          <Button
            size="sm" variant="ghost" icon={Check}
            onClick={() => onUpdateIssueTriage?.(issue.id, { status: issue.status === 'fixed' ? 'open' : 'fixed' })}
            disabled={!onUpdateIssueTriage}
            title={issue.status === 'fixed' ? 'Re-open this finding' : 'Mark this finding fixed (sets status to fixed)'}
          >
            {issue.status === 'fixed' ? 'Re-open' : 'Mark fixed'}
          </Button>
          <Button
            size="sm" variant="ghost" icon={RotateCcw}
            onClick={onRetestIssue}
            disabled={!onRetestIssue}
            title={onRetestIssue
              ? 'Re-run the scanner workflow against this finding to confirm it is still present and produce a fixed/regressed evidence delta'
              : 'Retest handler not wired'}
          >
            Retest
          </Button>
          <Button
            size="sm" icon={Flag}
            onClick={() => onUpdateIssueTriage?.(issue.id, { status: 'triaged', triageNote: 'Added to report from pfv2' })}
            disabled={!onUpdateIssueTriage || issue.status === 'triaged'}
            title={issue.status === 'triaged' ? 'Already triaged for report inclusion' : 'Mark this finding triaged and queue for the report draft'}
          >
            {issue.status === 'triaged' ? 'Triaged' : 'Add to report'}
          </Button>
        </div>
      </div>
      <div style={{ padding: '14px 16px', overflow: 'auto', display: 'flex', flexDirection: 'column', gap: 14, minHeight: 0 }}>
        <KV compact data={[
          ['ID', issue.id],
          ['Severity', <Badge tone={sevTone(issue.severity)}>{issue.severity}</Badge>],
          ['Confidence', issue.confidence],
          ['Status', issue.status],
          ['Affected', `${issue.host}${issue.path}`],
          ['Owner', issue.assignee || 'unassigned'],
          ['Last triaged', issue.lastTriagedAt || '—'],
        ]} />
        <div>
          <SectionHeading>Detail</SectionHeading>
          <div style={{ fontSize: 12.5, color: 'var(--text-dim)', lineHeight: 1.55 }}>{issue.detail || '—'}</div>
        </div>
        <div>
          <SectionHeading>Remediation</SectionHeading>
          <div style={{ fontSize: 12.5, color: 'var(--text-dim)', lineHeight: 1.55 }}>{issue.remediation || '—'}</div>
        </div>
        {issue.triageNote ? (
          <div>
            <SectionHeading>Triage note</SectionHeading>
            <div style={{
              padding: '10px 12px', background: 'var(--surface-2)',
              border: '1px solid var(--border)', borderRadius: 6,
              fontSize: 12.5, color: 'var(--text-base)',
            }}>{issue.triageNote}</div>
          </div>
        ) : null}
      </div>
    </div>
  );
}

function Queue({ queue }: { queue: ScannerAuditQueueItem[] }) {
  return (
    <div className="ws-body">
      <Panel title="Scanner audit queue" flush>
        <div className="pf-table-wrap">
          <table className="pf-table">
            <thead><tr>
              <th style={{ width: 28 }}></th>
              <th>Label</th>
              <th style={{ width: 120 }}>Kind</th>
              <th style={{ width: 220 }}>Target</th>
              <th style={{ width: 80 }}>Status</th>
              <th style={{ width: 80 }} className="right">Requests</th>
            </tr></thead>
            <tbody>
              {queue.length === 0 ? (
                <tr><td colSpan={6} style={emptyRowStyle}>No queued items. Trigger a passive review, active scan, or crawl audit.</td></tr>
              ) : queue.map((q) => (
                <tr key={q.id}>
                  <td><SevDot level={q.priority[0].toUpperCase() + q.priority.slice(1)} /></td>
                  <td>{q.label}</td>
                  <td className="dim">{q.kind}</td>
                  <td className="dim">{q.target}</td>
                  <td>
                    {q.status === 'running' ? <Badge tone="accent">RUNNING</Badge>
                     : q.status === 'complete' ? <Badge tone="ok">DONE</Badge>
                     : q.status === 'blocked' ? <Badge tone="crit">BLOCKED</Badge>
                     : <Badge>QUEUED</Badge>}
                  </td>
                  <td className="right">{q.requestCount}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>
    </div>
  );
}

function Checks({ packs, selectedId, onSelect }: {
  packs: readonly ScannerCheckPackEntry[];
  selectedId: string;
  onSelect: (id: string) => void;
}) {
  const selected = packs.find((p) => p.id === selectedId) ?? packs[0];
  return (
    <div className="ws-body">
      <Panel title="Check packs" flush>
        <div className="pf-table-wrap">
          <table className="pf-table">
            <thead><tr>
              <th style={{ width: 40 }}>Active</th>
              <th>Pack</th>
              <th>Description</th>
              <th style={{ width: 80 }} className="right">Checks</th>
            </tr></thead>
            <tbody>
              {packs.length === 0 ? (
                <tr><td colSpan={4} style={emptyRowStyle}>No check packs registered.</td></tr>
              ) : packs.map((p) => (
                <tr
                  key={p.id}
                  onClick={() => onSelect(p.id)}
                  style={{ cursor: 'pointer', background: p.id === selected?.id ? 'var(--selected)' : undefined }}
                >
                  <td>
                    <input
                      type="radio"
                      name="check-pack"
                      checked={p.id === selected?.id}
                      onChange={() => onSelect(p.id)}
                    />
                  </td>
                  <td style={{ fontFamily: 'var(--font-mono)' }}>{p.id}</td>
                  <td className="dim">{p.detail}</td>
                  <td className="right">{p.checks.length}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>
      {selected ? (
        <Panel title={`${selected.label} · checks`} flush>
          <div className="pf-table-wrap">
            <table className="pf-table">
              <thead><tr><th>Check ID</th></tr></thead>
              <tbody>
                {selected.checks.map((c) => (
                  <tr key={c}><td className="mono">{c}</td></tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      ) : null}
    </div>
  );
}

function AnvilTab() {
  return (
    <div className="ws-body">
      <Banner tone="warn" icon={ShieldCheck}>
        Anvil custom checks let you author <code>.anvil</code> rules for project-specific scans.
        Definitions carry digest, signer, fixture status, and per-project policy.
      </Banner>
      <Panel title="Authored checks" flush>
        <div style={{ padding: '20px 14px', textAlign: 'center', color: 'var(--text-faint)', fontSize: 12.5 }}>
          No Anvil rules yet. Click <Button size="sm" icon={Plus} style={{ display: 'inline-flex' }} comingSoon title="Open the Anvil rule editor (not yet wired in pfv2)">New rule</Button> to start authoring.
        </div>
      </Panel>
    </div>
  );
}

function Retests() {
  return (
    <div className="ws-body">
      <Panel title="Retest workflows" flush>
        <div style={{ padding: '20px 14px', textAlign: 'center', color: 'var(--text-faint)', fontSize: 12.5 }}>
          When you mark a finding as fixed, queue a retest to verify the patch holds.
        </div>
      </Panel>
    </div>
  );
}

function SectionHeading({ children }: { children: React.ReactNode }) {
  return (
    <div style={{
      fontSize: 11, color: 'var(--text-faint)', textTransform: 'uppercase',
      letterSpacing: '0.05em', marginBottom: 6, fontWeight: 500,
    }}>{children}</div>
  );
}

function Chip({ on, children, onClick }: { on?: boolean; children: React.ReactNode; onClick?: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      style={{
        display: 'inline-flex', alignItems: 'center', gap: 5,
        height: 24, padding: '0 9px', fontSize: 12, borderRadius: 100,
        border: on ? '1px solid var(--text-base)' : '1px solid var(--border-strong)',
        background: on ? 'var(--text-base)' : 'var(--surface)',
        color: on ? 'var(--bg-base)' : 'var(--text-dim)',
        cursor: 'pointer', userSelect: 'none', whiteSpace: 'nowrap',
      }}
    >{children}</button>
  );
}

const inputStyle = {
  display: 'flex', alignItems: 'center', height: 28, padding: '0 9px',
  borderRadius: 4, background: 'var(--surface)', border: '1px solid var(--border-strong)',
  fontSize: 12.5, color: 'var(--text-base)', outline: 'none', flex: 1, maxWidth: 320,
};

const emptyRowStyle = {
  padding: '20px 14px', textAlign: 'center' as const,
  color: 'var(--text-faint)', fontSize: 12.5,
};
