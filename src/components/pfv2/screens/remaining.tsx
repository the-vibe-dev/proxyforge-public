import { useMemo, useRef, useState, type ReactNode } from 'react';
import {
  Activity, AlertTriangle, Bot, Check, ChevronRight, Code2, Crosshair, Download,
  Edit3, FileBarChart, FileText, Filter, FolderClosed, FolderOpen, GitCompareArrows,
  Globe2, Layers, Link2, Lock, MoreHorizontal, Network, Pause, Play, Plus, RotateCcw,
  ScanLine, Search as SearchIcon, Send, Settings as SettingsIcon, Share2, ShieldCheck,
  Sparkles, Square, Upload, User, Zap,
} from 'lucide-react';
import type {
  AiActionExecutionPackage, AiProviderConfig, AiProviderId, AiProviderRuntime, AiSuggestedActionKind, AutomationWorkflow,
  CallbackInteraction, CallbackPayload, HttpExchange, HttpsInspectionStatus, InstalledExtension, IntruderAttackMode,
  Issue, IssueTriageOverride, LoggerCaptureControl, LoggerToolSource, OrganizerCollection, ProjectSafetyPolicy,
  ReportArtifact, ReportFormat, ReportFullPackage, ReportSection, SequencerAnalysisResult,
} from '../../../types';
import { Badge, Banner, Button, IconButton, KV, Panel, SevDot, Stat, Status, Tabs, Toggle } from '../ui';
import { WorkspaceHeader } from '../shell';

// ============ Intruder ============

interface IntruderProps {
  exchanges: HttpExchange[];
  intruderRaw: string;
  setIntruderRaw: (v: string) => void;
  intruderAttackMode: IntruderAttackMode;
  setIntruderAttackMode: (m: IntruderAttackMode) => void;
  safetyPolicy: ProjectSafetyPolicy;
  onStartAttack?: () => void;
}

const intruderAttackModeOptions: Array<{ value: IntruderAttackMode; label: string; desc: string }> = [
  { value: 'sniper', label: 'Sniper', desc: '1 set · cycles each position' },
  { value: 'battering-ram', label: 'Battering ram', desc: 'same payload in all positions' },
  { value: 'pitchfork', label: 'Pitchfork', desc: 'N sets parallel' },
  { value: 'cluster-bomb', label: 'Cluster bomb', desc: 'cartesian product' },
];

export function IntruderScreen({
  intruderRaw, setIntruderRaw,
  intruderAttackMode, setIntruderAttackMode,
  safetyPolicy,
  onStartAttack,
}: IntruderProps) {
  const [tab, setTab] = useState<'attack' | 'results' | 'presets'>('attack');
  return (
    <>
      <WorkspaceHeader
        eyebrow="TESTING"
        title="Intruder"
        maturity="alpha"
        maturityHint="Sniper / Battering Ram / Pitchfork / Cluster Bomb attack matrix and payload processors are wired at the engine level. Live results streaming and saved attack libraries are coming soon in pfv2."
        subtitle="Sniper · Battering ram · Pitchfork · Cluster bomb — scope-gated payload runner"
        actions={
          <>
            <Button variant="ghost" icon={FolderOpen} comingSoon title="Recall a previously configured Intruder attack template">Saved attacks</Button>
            <Button variant="ghost" icon={Upload} comingSoon title="Import a payload list / wordlist from disk">Import payloads</Button>
            <Button icon={SettingsIcon} comingSoon title="Configure concurrency, throttle, retries, and resource caps for this attack">Resource pool</Button>
            <Button
              variant="accent" icon={Play}
              onClick={onStartAttack}
              disabled={!onStartAttack}
              title={onStartAttack ? 'Start the configured Intruder attack (scope-gated)' : 'Start handler is not wired in this build'}
            >
              Start attack
            </Button>
          </>
        }
      />
      <Tabs<'attack' | 'results' | 'presets'>
        value={tab}
        onChange={setTab}
        items={[
          { value: 'attack', label: 'Attack config', icon: SettingsIcon },
          { value: 'results', label: 'Results', icon: Crosshair },
          { value: 'presets', label: 'Grep/extract', icon: Filter },
        ]}
      />
      {tab === 'attack' ? (
        <div className="ws-body flush" style={{ display: 'flex', flexDirection: 'column', minHeight: 0, flex: 1 }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', flex: 1, minHeight: 0 }}>
            <div style={{ display: 'flex', flexDirection: 'column', minHeight: 0, borderRight: '1px solid var(--border)' }}>
              <div className="pf-panel-head" style={{ background: 'var(--surface)' }}>
                <div className="pf-panel-title">
                  <span className="pf-panel-eyebrow">REQUEST</span>
                  <span style={{ color: 'var(--text-dim)', fontSize: 12 }}>
                    use §marker§ to set positions
                  </span>
                </div>
              </div>
              <textarea
                value={intruderRaw}
                onChange={(e) => setIntruderRaw(e.target.value)}
                placeholder={'POST /api/v2/users/§4821§/role HTTP/1.1\nHost: api.example.test\nAuthorization: Bearer §token§\n\n{"role":"§admin§"}'}
                style={{
                  flex: 1, minHeight: 0, border: 0, outline: 0, resize: 'none',
                  padding: '12px 14px', fontSize: 12.5, lineHeight: 1.55,
                  background: 'var(--surface)', color: 'var(--text-base)',
                  fontFamily: 'var(--font-mono)',
                }}
              />
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', padding: 16, overflow: 'auto', gap: 14, minHeight: 0 }}>
              <Panel title="Attack mode" tight>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 8, padding: 6 }}>
                  {intruderAttackModeOptions.map((m) => {
                    const active = m.value === intruderAttackMode;
                    return (
                      <div
                        key={m.value}
                        onClick={() => setIntruderAttackMode(m.value)}
                        style={{
                          padding: '10px 12px', borderRadius: 4,
                          border: active ? '1px solid var(--accent)' : '1px solid var(--border)',
                          background: active ? 'var(--accent-soft)' : 'var(--surface-2)',
                          cursor: 'pointer',
                        }}
                      >
                        <div style={{ fontSize: 12.5, fontWeight: 500, color: active ? 'var(--accent)' : 'var(--text-base)' }}>{m.label}</div>
                        <div style={{ fontSize: 11, color: 'var(--text-dim)', marginTop: 2 }}>{m.desc}</div>
                      </div>
                    );
                  })}
                </div>
              </Panel>
              <Panel title="Throttle & limits" tight>
                <KV compact data={[
                  ['Throttle floor', `${safetyPolicy.minThrottleMs} ms${safetyPolicy.minThrottleMs > 0 ? ' (policy enforced)' : ''}`],
                  ['Max requests/run', safetyPolicy.maxRequestsPerRun.toLocaleString()],
                  ['Scope match required', safetyPolicy.requireScopeMatch ? 'yes' : 'no'],
                  ['Audit logging', safetyPolicy.auditLogging ? 'on' : 'off'],
                ]} />
              </Panel>
            </div>
          </div>
        </div>
      ) : tab === 'results' ? (
        <div className="ws-body">
          <Panel title="Attack results">
            <div style={{ padding: '20px 0', color: 'var(--text-faint)', fontSize: 12.5, textAlign: 'center' }}>
              No attacks run yet. Start an attack to see live results stream in.
            </div>
          </Panel>
        </div>
      ) : (
        <div className="ws-body">
          <Panel title="Saved grep/extract presets">
            <div style={{ padding: '20px 0', color: 'var(--text-faint)', fontSize: 12.5, textAlign: 'center' }}>
              No presets saved.
            </div>
          </Panel>
        </div>
      )}
    </>
  );
}

// ============ Exploit Lab ============

interface ExploitProps {
  issues: Issue[];
}

export function ExploitScreen({ issues }: ExploitProps) {
  const chains = useMemo(() => issues.filter((i) => i.severity === 'critical' || i.severity === 'high').slice(0, 8), [issues]);
  return (
    <>
      <WorkspaceHeader
        eyebrow="TESTING"
        title="Exploit Lab"
        maturity="planned"
        maturityHint="Thin in the master plan today — chain authoring, validation, and approval-gated execution are next on the roadmap. Surface is visible so you can plan."
        subtitle="PoC chains · approval-gated · stop-on-proof · OAST-correlated"
        actions={
          <>
            <Button variant="ghost" icon={FolderOpen} comingSoon title="Load a saved exploit chain definition">Saved chains</Button>
            <Button variant="ghost" icon={Upload} comingSoon title="Import a signed exploit chain package">Import package</Button>
            <Button variant="accent" icon={Play} comingSoon title="Execute the current exploit chain against the selected target">Run chain</Button>
          </>
        }
      />
      <div className="ws-body flush" style={{ display: 'flex', flexDirection: 'column', minHeight: 0, flex: 1 }}>
        <div style={{ display: 'grid', gridTemplateColumns: '300px 1fr', flex: 1, minHeight: 0 }}>
          <div style={{ background: 'var(--surface)', display: 'flex', flexDirection: 'column', overflow: 'hidden', borderRight: '1px solid var(--border)' }}>
            <div className="pf-panel-head">
              <div className="pf-panel-title">
                <span className="pf-panel-eyebrow">CHAINS</span>
                {chains.length} candidates
              </div>
              <IconButton icon={Plus} title="New chain" />
            </div>
            <div className="pf-list" style={{ flex: 1, overflowY: 'auto', minHeight: 0 }}>
              {chains.length === 0 ? (
                <div style={{ padding: 20, color: 'var(--text-faint)', fontSize: 12.5, textAlign: 'center' }}>
                  No high/critical findings yet to chain.
                </div>
              ) : chains.map((c, i) => (
                <div key={c.id} className={`pf-list-item${i === 0 ? ' is-active' : ''}`}>
                  <div className="pf-list-item-mark" />
                  <div className="pf-list-item-main">
                    <div className="pf-list-item-title">
                      <SevDot level={c.severity[0].toUpperCase() + c.severity.slice(1)} />
                      <span>{c.title}</span>
                    </div>
                    <div className="pf-list-item-meta">
                      <span>{c.host}{c.path}</span>
                      <span className="sep">·</span>
                      <span>{c.status}</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', overflow: 'hidden', minHeight: 0 }}>
            <div className="pf-panel-head" style={{ background: 'var(--surface)' }}>
              <div className="pf-panel-title">
                <span className="pf-panel-eyebrow">CHAIN</span>
                {chains[0] ? chains[0].title : 'no chain selected'}
              </div>
              <div style={{ display: 'flex', gap: 6 }}>
                <Button size="sm" variant="ghost" icon={Edit3} comingSoon title="Edit the steps in this exploit chain">Edit</Button>
                <Button size="sm" icon={FileBarChart} comingSoon title="Add this exploit chain's outcome to the report">Add to report</Button>
                <Button size="sm" variant="accent" icon={Play} comingSoon title="Validate the chain by running it against a safe target">Validate</Button>
              </div>
            </div>
            <div style={{ padding: 16, overflow: 'auto', flex: 1, display: 'flex', flexDirection: 'column', gap: 12, minHeight: 0 }}>
              {chains[0] ? (
                <>
                  <Banner tone="warn" icon={Lock}>
                    <strong>Approval gated.</strong> Destructive steps require operator approval per project policy.
                  </Banner>
                  {chains[0].detail ? (
                    <Panel title="Hypothesis">
                      <div style={{ fontSize: 12.5, color: 'var(--text-dim)', lineHeight: 1.55 }}>
                        {chains[0].detail}
                      </div>
                    </Panel>
                  ) : null}
                  {chains[0].remediation ? (
                    <Panel title="Validation plan">
                      <div style={{ fontSize: 12.5, color: 'var(--text-dim)', lineHeight: 1.55 }}>
                        {chains[0].remediation}
                      </div>
                    </Panel>
                  ) : null}
                </>
              ) : (
                <div style={{ color: 'var(--text-faint)', fontSize: 13, margin: 'auto' }}>
                  Add or select a chain to build an exploit verifier.
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </>
  );
}

// ============ Organizer ============

interface OrganizerProps {
  organizerCollections: OrganizerCollection[];
  selectedOrganizerCollectionId: string;
  setSelectedOrganizerCollectionId: (id: string) => void;
}

export function OrganizerScreen({ organizerCollections, selectedOrganizerCollectionId, setSelectedOrganizerCollectionId }: OrganizerProps) {
  const sel = organizerCollections.find((c) => c.id === selectedOrganizerCollectionId) ?? organizerCollections[0];
  return (
    <>
      <WorkspaceHeader
        eyebrow="ANALYSIS"
        title="Organizer"
        maturity="alpha"
        maturityHint="Collections + reviewer roles + signed packaging are engine-ready. The pfv2 detail editor, share-link minting, and per-collection report wiring are coming soon."
        subtitle="Collections, reviewer assignments, signed packages, share links"
        actions={
          <>
            <Button variant="ghost" icon={Upload} comingSoon title="Import a shared Organizer collection package">Import package</Button>
            <Button variant="ghost" icon={Share2} comingSoon title="Create a share link for the active collection">Share link</Button>
            <Button icon={Plus} comingSoon title="Create a new collection to group findings + evidence">New collection</Button>
          </>
        }
      />
      <div className="ws-body flush" style={{ display: 'flex', flexDirection: 'column', minHeight: 0, flex: 1 }}>
        <div style={{ display: 'grid', gridTemplateColumns: '320px 1fr', flex: 1, minHeight: 0 }}>
          <div style={{ display: 'flex', flexDirection: 'column', background: 'var(--surface)', borderRight: '1px solid var(--border)', minHeight: 0 }}>
            <div style={{ padding: '8px 10px', borderBottom: '1px solid var(--border)' }}>
              <input placeholder="Find collections…" style={{
                width: '100%', height: 28, padding: '0 9px', borderRadius: 4,
                background: 'var(--surface)', border: '1px solid var(--border-strong)',
                fontSize: 12.5, color: 'var(--text-base)', outline: 'none',
              }} />
            </div>
            <div className="pf-list" style={{ flex: 1, overflow: 'auto', minHeight: 0 }}>
              {organizerCollections.length === 0 ? (
                <div style={{ padding: 20, color: 'var(--text-faint)', fontSize: 12.5, textAlign: 'center' }}>
                  No collections yet.
                </div>
              ) : organizerCollections.map((c) => (
                <div
                  key={c.id}
                  className={`pf-list-item${c.id === sel?.id ? ' is-active' : ''}`}
                  onClick={() => setSelectedOrganizerCollectionId(c.id)}
                >
                  <div className="pf-list-item-mark" />
                  <div className="pf-list-item-main">
                    <div className="pf-list-item-title">{c.name}</div>
                    <div className="pf-list-item-meta">
                      <span>{c.items.length} items</span>
                      <span className="sep">·</span>
                      <span>{(c.updatedAt || '').slice(0, 10)}</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', overflow: 'hidden', minHeight: 0 }}>
            {sel ? (
              <>
                <div className="pf-panel-head" style={{ background: 'var(--surface)' }}>
                  <div className="pf-panel-title">
                    <span className="pf-panel-eyebrow">COLLECTION</span>
                    {sel.name}
                  </div>
                  <Button size="sm" icon={FileBarChart} comingSoon title="Attach this Organizer item to the active report">Send to Report</Button>
                </div>
                <div className="pf-table-wrap" style={{ flex: 1, minHeight: 0 }}>
                  <table className="pf-table">
                    <thead><tr>
                      <th style={{ width: 28 }}></th>
                      <th>Title (path)</th>
                      <th style={{ width: 110 }}>Tool</th>
                      <th style={{ width: 70 }}>Status</th>
                      <th style={{ width: 90 }}>Reviewer</th>
                    </tr></thead>
                    <tbody>
                      {sel.items.length === 0 ? (
                        <tr><td colSpan={5} style={emptyRowStyle}>Empty collection. Send items from Proxy / Repeater.</td></tr>
                      ) : sel.items.map((it) => (
                        <tr key={it.id}>
                          <td><SevDot level={(it.risk[0].toUpperCase() + it.risk.slice(1))} /></td>
                          <td>{`${it.method} ${it.path}`}</td>
                          <td className="dim">{it.originalTool}</td>
                          <td><Badge tone={it.status === 'done' ? 'ok' : it.status === 'reviewing' ? 'accent' : 'dim'}>{it.status.toUpperCase()}</Badge></td>
                          <td className="dim">{it.reviewerName ?? '—'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </>
            ) : (
              <div style={{ display: 'grid', placeItems: 'center', color: 'var(--text-faint)', fontSize: 13 }}>
                Select a collection or create a new one.
              </div>
            )}
          </div>
        </div>
      </div>
    </>
  );
}

// ============ Sequencer ============

interface SequencerProps {
  sequencerResults: SequencerAnalysisResult[];
  sequencerSamples: string;
  setSequencerSamples: (v: string) => void;
  onAnalyze?: () => void;
  projectName?: string;
}

export function SequencerScreen({ sequencerResults, sequencerSamples, setSequencerSamples, onAnalyze, projectName }: SequencerProps) {
  const latest = sequencerResults[0];
  const tokensInputRef = useRef<HTMLInputElement>(null);

  function handleImportTokens(file: File | undefined) {
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      const text = typeof reader.result === 'string' ? reader.result : '';
      if (!text) return;
      const tokens = text
        .split(/[\r\n,]+/)
        .map((t) => t.trim())
        .filter(Boolean);
      if (tokens.length === 0) return;
      const merged = sequencerSamples.trim()
        ? `${sequencerSamples.trim()}\n${tokens.join('\n')}`
        : tokens.join('\n');
      setSequencerSamples(merged);
    };
    reader.readAsText(file);
  }

  function exportSequencerPackage() {
    if (sequencerResults.length === 0) return;
    const payload = JSON.stringify({
      exportedAt: new Date().toISOString(),
      project: projectName ?? '',
      results: sequencerResults,
      samples: sequencerSamples,
    }, null, 2);
    const blob = new Blob([payload], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `proxyforge-sequencer-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  }

  return (
    <>
      <WorkspaceHeader
        eyebrow="ANALYSIS"
        title="Sequencer"
        maturity="alpha"
        maturityHint="Engine produces real entropy/bit-balance/character-distribution analyses. Live capture is coming soon; token import and JSON export are wired."
        subtitle={latest
          ? `Latest run · ${latest.sampleCount} samples · ${latest.estimatedEntropyBits.toFixed(1)}b entropy`
          : 'Token analyzer · entropy, collisions, bit-balance, character distribution'}
        actions={
          <>
            <input
              ref={tokensInputRef}
              type="file"
              accept=".txt,.csv,.tokens,text/plain,text/csv"
              style={{ display: 'none' }}
              onChange={(e) => {
                handleImportTokens(e.target.files?.[0]);
                e.target.value = '';
              }}
            />
            <Button
              variant="ghost"
              icon={Upload}
              onClick={() => tokensInputRef.current?.click()}
              title="Import a token sample set (newline- or comma-delimited) and append to the samples textarea"
            >
              Import tokens
            </Button>
            <Button
              variant="ghost"
              icon={Download}
              onClick={exportSequencerPackage}
              disabled={sequencerResults.length === 0}
              title={
                sequencerResults.length === 0
                  ? 'Run Analyze first — no Sequencer results yet'
                  : 'Export the Sequencer analysis results and source samples as JSON'
              }
            >
              Export package
            </Button>
            <Button
              variant="accent" icon={Play}
              onClick={onAnalyze}
              disabled={!onAnalyze || sequencerSamples.trim().length === 0}
              title={
                !onAnalyze ? 'Analyze handler not wired'
                : sequencerSamples.trim().length === 0 ? 'Paste tokens into the samples textarea below first'
                : 'Run entropy, bit-balance, collision, and character-distribution analysis on the samples'
              }
            >
              Analyze
            </Button>
          </>
        }
      />
      <div className="ws-body">
        <div className="pf-cards cols-4">
          <Stat label="Samples" value={latest?.sampleCount ?? 0} />
          <Stat label="Entropy" value={latest ? `${latest.estimatedEntropyBits.toFixed(1)}b` : '—'} accent={Boolean(latest)} />
          <Stat label="Collisions" value={latest ? `${(latest.collisionRate * 100).toFixed(2)}%` : '—'} />
          <Stat label="Verdict" value={latest?.reliability.level || '—'} />
        </div>
        <div className="pf-cards cols-2">
          <Panel title="Sample input" flush>
            <textarea
              value={sequencerSamples}
              onChange={(e) => setSequencerSamples(e.target.value)}
              placeholder="Paste one token per line…"
              style={{
                width: '100%', minHeight: 240, border: 0, outline: 0, resize: 'vertical',
                padding: '12px 14px', fontSize: 12.5, lineHeight: 1.55,
                background: 'var(--surface)', color: 'var(--text-base)',
                fontFamily: 'var(--font-mono)',
              }}
            />
          </Panel>
          <Panel title="Statistical tests">
            {latest ? (
              <div className="pf-list" style={{ margin: 0 }}>
                {latest.statisticalTests.slice(0, 8).map((test) => (
                  <div key={test.name} style={{
                    padding: '8px 0', borderBottom: '1px solid var(--border-soft)',
                    display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                  }}>
                    <div style={{ fontSize: 12.5 }}>{test.name}</div>
                    <Badge tone={test.passed ? 'ok' : 'accent'}>{test.passed ? 'PASS' : 'WEAK'}</Badge>
                  </div>
                ))}
              </div>
            ) : (
              <div style={{ padding: '20px 0', color: 'var(--text-faint)', fontSize: 12.5, textAlign: 'center' }}>
                Paste samples and click Analyze.
              </div>
            )}
          </Panel>
        </div>
      </div>
    </>
  );
}

// ============ Decoder ============

interface DecoderTransformOption { id: string; label: string; category: 'encode' | 'decode' | 'hash' | 'format' }

interface DecoderProps {
  decoderInput: string;
  setDecoderInput: (v: string) => void;
  decoderOutput: string;
  decoderStatus?: string;
  decoderTransforms?: readonly DecoderTransformOption[];
  onRunTransform?: (transformId: string) => void | Promise<void>;
  onPromoteOutput?: () => void;
  onLoadFromSelected?: () => void;
}

const decoderCategoryLabels: Record<DecoderTransformOption['category'], string> = {
  decode: 'Decode',
  encode: 'Encode',
  hash: 'Hash',
  format: 'Format',
};

export function DecoderScreen({
  decoderInput, setDecoderInput, decoderOutput, decoderStatus,
  decoderTransforms = [], onRunTransform, onPromoteOutput, onLoadFromSelected,
}: DecoderProps) {
  const grouped = useMemo(() => {
    const byCat = new Map<DecoderTransformOption['category'], DecoderTransformOption[]>();
    for (const t of decoderTransforms) {
      const arr = byCat.get(t.category) ?? [];
      arr.push(t);
      byCat.set(t.category, arr);
    }
    return Array.from(byCat.entries());
  }, [decoderTransforms]);

  function exportTransformLibrary() {
    if (decoderTransforms.length === 0) return;
    const payload = JSON.stringify({
      exportedAt: new Date().toISOString(),
      transforms: decoderTransforms,
    }, null, 2);
    const blob = new Blob([payload], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `proxyforge-decoder-library-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  }

  return (
    <>
      <WorkspaceHeader
        eyebrow="ANALYSIS"
        title="Decoder"
        maturity="alpha"
        maturityHint="Encode/decode/hash transforms run; library export is wired. Recipes / JWT inspector / binary inspection are tracked Parity Candidate work."
        subtitle="Transforms · smart decode · JWT workspace · hashes · canonicalization"
        actions={
          <>
            <Button variant="ghost" icon={FolderOpen} comingSoon title="Recall a saved decode pipeline">Recipes</Button>
            <Button
              variant="ghost"
              icon={Download}
              onClick={exportTransformLibrary}
              disabled={decoderTransforms.length === 0}
              title={
                decoderTransforms.length === 0
                  ? 'No transforms registered yet'
                  : 'Export the full decode/transform catalog as JSON'
              }
            >
              Export library
            </Button>
            <Button
              icon={Sparkles}
              onClick={() => onRunTransform?.('smart-decode')}
              disabled={!onRunTransform || !decoderInput}
              title={decoderInput ? 'Auto-detect format and decode in one click' : 'Paste a value into the input first'}
            >
              Smart decode
            </Button>
          </>
        }
      />
      <div className="ws-body flush" style={{ display: 'flex', flexDirection: 'column', minHeight: 0, flex: 1 }}>
        <div style={{
          padding: '8px 12px', borderBottom: '1px solid var(--border)',
          background: 'var(--surface)', display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center',
        }}>
          {grouped.length === 0 ? (
            <span style={{ color: 'var(--text-faint)', fontSize: 12 }}>Loading transforms…</span>
          ) : grouped.map(([cat, items]) => (
            <span key={cat} style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
              <span style={{ color: 'var(--text-faint)', fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.05em', marginRight: 4 }}>
                {decoderCategoryLabels[cat]}
              </span>
              {items.map((t) => (
                <Button
                  key={t.id}
                  size="sm"
                  variant="ghost"
                  onClick={() => onRunTransform?.(t.id)}
                  disabled={!onRunTransform || !decoderInput}
                  title={`${decoderCategoryLabels[t.category]} · ${t.label}`}
                >
                  {t.label}
                </Button>
              ))}
            </span>
          ))}
          <div style={{ flex: 1 }} />
          {decoderStatus ? <span style={{ color: 'var(--text-dim)', fontSize: 11.5 }}>{decoderStatus}</span> : null}
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', flex: 1, minHeight: 0 }}>
          <div style={{ display: 'flex', flexDirection: 'column', borderRight: '1px solid var(--border)', minHeight: 0 }}>
            <div className="pf-panel-head" style={{ background: 'var(--surface)' }}>
              <div className="pf-panel-title">
                <span className="pf-panel-eyebrow">INPUT</span>
                {decoderInput.length} chars
              </div>
              <div style={{ display: 'flex', gap: 6 }}>
                <Button
                  size="sm" variant="ghost"
                  onClick={onLoadFromSelected}
                  disabled={!onLoadFromSelected}
                  title="Load the currently selected exchange's request+response into the input"
                >
                  From selection
                </Button>
              </div>
            </div>
            <textarea
              value={decoderInput}
              onChange={(e) => setDecoderInput(e.target.value)}
              placeholder="Paste any value — JWT, base64, URL-encoded, JSON…"
              spellCheck={false}
              style={{
                flex: 1, minHeight: 0, border: 0, outline: 0, resize: 'none',
                padding: '12px 14px', fontSize: 12.5, lineHeight: 1.55,
                background: 'var(--surface)', color: 'var(--text-base)',
                fontFamily: 'var(--font-mono)',
              }}
            />
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', minHeight: 0 }}>
            <div className="pf-panel-head" style={{ background: 'var(--surface)' }}>
              <div className="pf-panel-title">
                <span className="pf-panel-eyebrow">OUTPUT</span>
                {decoderOutput ? `${decoderOutput.length} chars` : 'after transforms'}
              </div>
              <div style={{ display: 'flex', gap: 6 }}>
                <Button
                  size="sm" variant="ghost"
                  onClick={onPromoteOutput}
                  disabled={!onPromoteOutput || !decoderOutput}
                  title="Copy the output back into the input so you can chain another transform"
                >
                  Promote
                </Button>
              </div>
            </div>
            <pre style={{
              flex: 1, minHeight: 0, overflow: 'auto', margin: 0,
              padding: '12px 14px', fontFamily: 'var(--font-mono)',
              fontSize: 12.5, lineHeight: 1.55, color: 'var(--text-base)',
              background: 'var(--surface)', whiteSpace: 'pre-wrap', wordBreak: 'break-all',
            }}>{decoderOutput || '— output appears here —'}</pre>
          </div>
        </div>
      </div>
    </>
  );
}

// ============ Comparer ============

interface ComparerProps {
  comparerLeft: string;
  setComparerLeft: (v: string) => void;
  comparerRight: string;
  setComparerRight: (v: string) => void;
}

export function ComparerScreen({ comparerLeft, setComparerLeft, comparerRight, setComparerRight }: ComparerProps) {
  function exportUnifiedDiff() {
    const left = comparerLeft;
    const right = comparerRight;
    if (!left && !right) return;
    const leftLines = left.split('\n');
    const rightLines = right.split('\n');
    const header = [
      '--- a/baseline',
      '+++ b/candidate',
      `@@ -1,${leftLines.length} +1,${rightLines.length} @@`,
    ];
    const body: string[] = [];
    const max = Math.max(leftLines.length, rightLines.length);
    for (let i = 0; i < max; i += 1) {
      const a = leftLines[i];
      const b = rightLines[i];
      if (a === b) {
        if (a !== undefined) body.push(` ${a}`);
        continue;
      }
      if (a !== undefined) body.push(`-${a}`);
      if (b !== undefined) body.push(`+${b}`);
    }
    const content = [...header, ...body].join('\n') + '\n';
    const blob = new Blob([content], { type: 'text/x-diff' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `proxyforge-diff-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')}.diff`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  }

  const diffReady = Boolean(comparerLeft || comparerRight);

  return (
    <>
      <WorkspaceHeader
        eyebrow="ANALYSIS"
        title="Comparer"
        maturity="alpha"
        maturityHint="Side-by-side text + structured HTTP diff is wired. Unified-diff export is wired. Normalization presets and one-click 'add to report' are coming soon."
        subtitle="Word + byte diff · structured HTTP sections · normalization presets"
        actions={
          <>
            <Button variant="ghost" icon={SettingsIcon} comingSoon title="Apply normalization rules (whitespace, ordering, token masks) before diffing">Normalize</Button>
            <Button
              variant="ghost"
              icon={Download}
              onClick={exportUnifiedDiff}
              disabled={!diffReady}
              title={
                !diffReady
                  ? 'Paste content on both sides first'
                  : 'Download the current diff as a unified diff (.diff)'
              }
            >
              Export diff
            </Button>
            <Button variant="accent" icon={FileBarChart} comingSoon title="Attach the diff as evidence on the active report">Add to report</Button>
          </>
        }
      />
      <div className="ws-body flush" style={{ display: 'flex', flexDirection: 'column', minHeight: 0, flex: 1 }}>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', flex: 1, minHeight: 0 }}>
          <textarea
            value={comparerLeft}
            onChange={(e) => setComparerLeft(e.target.value)}
            placeholder="// A — baseline"
            style={{
              minHeight: 0, border: 0, outline: 0, resize: 'none',
              padding: '12px 14px', fontSize: 12.5, lineHeight: 1.55,
              background: 'var(--surface)', color: 'var(--text-base)',
              fontFamily: 'var(--font-mono)',
              borderRight: '1px solid var(--border)',
            }}
          />
          <textarea
            value={comparerRight}
            onChange={(e) => setComparerRight(e.target.value)}
            placeholder="// B — candidate"
            style={{
              minHeight: 0, border: 0, outline: 0, resize: 'none',
              padding: '12px 14px', fontSize: 12.5, lineHeight: 1.55,
              background: 'var(--surface)', color: 'var(--text-base)',
              fontFamily: 'var(--font-mono)',
            }}
          />
        </div>
      </div>
    </>
  );
}

// ============ Callbacks (OAST) ============

interface CallbacksProps {
  callbackInteractions: CallbackInteraction[];
  callbackPayloads: CallbackPayload[];
  onGeneratePayload?: () => void;
  onPollNow?: () => void;
  onExportPackage?: () => void;
}

export function CallbacksScreen({ callbackInteractions, callbackPayloads, onGeneratePayload, onPollNow, onExportPackage }: CallbacksProps) {
  return (
    <>
      <WorkspaceHeader
        eyebrow="CAPTURE"
        title="Callbacks"
        maturity="alpha"
        maturityHint="Engine ready (OAST listener + payload ownership). UI handoff and external relay diversity are still hardening."
        subtitle="OAST · DNS / HTTP / SMTP listeners · payload ownership · scanner & exploit correlation"
        actions={
          <>
            <Button
              variant="ghost" icon={Plus}
              onClick={onGeneratePayload}
              disabled={!onGeneratePayload}
              title={onGeneratePayload ? 'Generate a fresh OOB / Collaborator-style callback payload' : 'Generate handler not wired'}
            >
              Generate payload
            </Button>
            <Button
              variant="ghost" icon={Download}
              onClick={onExportPackage}
              disabled={!onExportPackage || callbackInteractions.length === 0}
              title={
                !onExportPackage ? 'Export handler not wired'
                : callbackInteractions.length === 0 ? 'No interactions yet — trigger a payload first'
                : 'Export the callback transcript as a JSON evidence package'
              }
            >
              Export package
            </Button>
            <Button
              variant="accent" icon={Play}
              onClick={onPollNow}
              disabled={!onPollNow || callbackPayloads.length === 0}
              title={
                !onPollNow ? 'Poll handler not wired'
                : callbackPayloads.length === 0 ? 'Generate a payload first'
                : 'Force a fetch for new callback interactions from the listener'
              }
            >
              Poll now
            </Button>
          </>
        }
      />
      <div className="ws-body flush" style={{ display: 'flex', flexDirection: 'column', minHeight: 0, flex: 1 }}>
        <div className="pf-filterbar">
          <span className="pf-row-meta">
            <span>{callbackPayloads.length} payloads</span>
            <span className="sep">·</span>
            <span>{callbackInteractions.length} interactions</span>
          </span>
        </div>
        {callbackPayloads.length === 0 ? (
          <div style={{ padding: '40px 32px', textAlign: 'center', color: 'var(--text-dim)', fontSize: 13 }}>
            <strong style={{ color: 'var(--text-base)', display: 'block', marginBottom: 6 }}>No callback payloads yet</strong>
            Click <em>Generate payload</em> above to mint an OAST token (DNS / HTTP / SMTP). Inject the token into a request body / header / parameter; any out-of-band callback to the listener will appear here.
          </div>
        ) : (
          <div className="pf-table-wrap" style={{ flex: 1, minHeight: 0 }}>
            <table className="pf-table">
              <thead><tr>
                <th style={{ width: 28 }}></th>
                <th style={{ width: 100 }}>ID</th>
                <th style={{ width: 80 }}>Protocol</th>
                <th>Payload</th>
                <th style={{ width: 130 }}>Source IP</th>
                <th style={{ width: 70 }}>When</th>
              </tr></thead>
              <tbody>
                {callbackInteractions.length === 0 ? (
                  <tr><td colSpan={6} style={emptyRowStyle}>
                    {callbackPayloads.length} payload(s) minted but no callbacks received yet. Inject one and click <em>Poll now</em>.
                  </td></tr>
                ) : callbackInteractions.map((c) => (
                  <tr key={c.id}>
                    <td><SevDot level="High" /></td>
                    <td className="faint">{c.id.slice(0, 8)}</td>
                    <td><Badge>{c.protocol.toUpperCase()}</Badge></td>
                    <td className="mono">{c.payloadId}</td>
                    <td className="dim">{c.sourceIp}</td>
                    <td className="dim">{(c.observedAt || '').slice(11, 19)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </>
  );
}

// ============ Automations ============

interface AutomationsProps {
  automationWorkflows: AutomationWorkflow[];
  projectName: string;
  scopeAllowlist: string[];
}

function buildHeadlessSnippet(projectName: string, scopeAllowlist: string[]): string {
  const lines: string[] = ['proxyforge headless \\'];
  if (projectName) {
    lines.push(`  --project ${JSON.stringify(projectName)} \\`);
  }
  if (scopeAllowlist.length === 0) {
    lines.push('  # add --scope <host> for each host before running');
  } else {
    for (const host of scopeAllowlist) {
      lines.push(`  --scope ${host} \\`);
    }
  }
  lines.push('  --crawl-audit \\');
  lines.push('  --report json,bundle \\');
  lines.push('  --sarif --junit \\');
  lines.push('  --fail-on high');
  return lines.join('\n');
}

export function AutomationsScreen({ automationWorkflows, projectName, scopeAllowlist }: AutomationsProps) {
  return (
    <>
      <WorkspaceHeader
        eyebrow="SURFACE"
        title="Automations"
        maturity="planned"
        maturityHint="Headless runner + agent CLI exist (and are Production Ready). The pfv2 surface for authoring + scheduling workflows is still being built."
        subtitle="Macros · scheduled workflows · CI presets (GitHub / GitLab / Azure / Jenkins)"
        actions={
          <>
            <Button variant="ghost" icon={Upload} comingSoon title="Import an automation workflow definition from disk">Import workflow</Button>
            <Button variant="ghost" icon={Download} comingSoon title="Export this automation as a GitHub Actions / CI preset">Export CI preset</Button>
            <Button icon={Plus} comingSoon title="Create a new automation workflow">New automation</Button>
          </>
        }
      />
      <div className="ws-body">
        <Panel title="Scheduled workflows" flush>
          <div className="pf-table-wrap">
            <table className="pf-table">
              <thead><tr>
                <th style={{ width: 40 }}>On</th>
                <th>Name</th>
                <th style={{ width: 160 }}>Schedule</th>
                <th style={{ width: 100 }}>Last run</th>
                <th style={{ width: 80 }} className="right">Steps</th>
              </tr></thead>
              <tbody>
                {automationWorkflows.length === 0 ? (
                  <tr><td colSpan={5} style={emptyRowStyle}>No automations yet. Record a macro or create a scheduled workflow.</td></tr>
                ) : automationWorkflows.map((a) => (
                  <tr key={a.id}>
                    <td><Toggle on={a.scheduleEnabled} /></td>
                    <td>{a.name}</td>
                    <td className="dim">{a.trigger}{a.scheduleEnabled ? ` · ${a.scheduleIntervalMinutes}m` : ''}</td>
                    <td className="dim">{a.lastRun ? a.lastRun.slice(0, 10) : '—'}</td>
                    <td className="right">{a.steps?.length ?? 0}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
        <Panel title="Headless CLI snippet">
          <pre style={{
            margin: 0, padding: '12px 14px', background: 'var(--surface-2)',
            border: '1px solid var(--border)', borderRadius: 4, fontSize: 11.5,
            fontFamily: 'var(--font-mono)', lineHeight: 1.55, overflow: 'auto',
            color: 'var(--text-base)',
          }}>
{buildHeadlessSnippet(projectName, scopeAllowlist)}
          </pre>
        </Panel>
      </div>
    </>
  );
}

// ============ Extensions ============

interface ExtensionsProps {
  installedExtensions: InstalledExtension[];
}

export function ExtensionsScreen({ installedExtensions }: ExtensionsProps) {
  const [sel, setSel] = useState<string>(installedExtensions[0]?.id ?? '');
  const ex = installedExtensions.find((x) => x.id === sel) ?? installedExtensions[0];
  return (
    <>
      <WorkspaceHeader
        eyebrow="SURFACE"
        title="Extensions"
        maturity="planned"
        maturityHint="Manifest format and sandboxed runtime exist (extension SDK is partial in master plan). Loading manifests, browsing the catalog, and per-extension policy are not yet wired in pfv2."
        subtitle="Sandboxed runtime · signed manifests · compatibility fixtures"
        actions={
          <>
            <Button variant="ghost" icon={Upload} comingSoon title="Load a signed extension manifest from disk">Load manifest</Button>
            <Button variant="ghost" icon={Globe2} comingSoon title="Browse the curated extension catalog">Catalog</Button>
            <Button icon={SettingsIcon} comingSoon title="Edit sandbox permissions, signing requirements, and per-extension policy">Runtime policy</Button>
          </>
        }
      />
      <div className="ws-body flush" style={{ display: 'flex', flexDirection: 'column', minHeight: 0, flex: 1 }}>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 360px', flex: 1, minHeight: 0 }}>
          <div className="pf-table-wrap" style={{ minHeight: 0 }}>
            <table className="pf-table">
              <thead><tr>
                <th style={{ width: 28 }}></th>
                <th>Extension</th>
                <th style={{ width: 90 }}>Version</th>
                <th style={{ width: 130 }}>State</th>
                <th style={{ width: 80 }}>Signed</th>
              </tr></thead>
              <tbody>
                {installedExtensions.length === 0 ? (
                  <tr><td colSpan={5} style={emptyRowStyle}>No extensions installed.</td></tr>
                ) : installedExtensions.map((x) => (
                  <tr key={x.id}
                      className={x.id === ex?.id ? 'is-selected' : ''}
                      onClick={() => setSel(x.id)}>
                    <td>
                      <span style={{
                        display: 'inline-block', width: 7, height: 7, borderRadius: '50%',
                        background: x.enabled ? 'var(--ok)' : 'var(--text-mute)',
                      }} />
                    </td>
                    <td>
                      <div style={{ display: 'flex', flexDirection: 'column' }}>
                        <span style={{ fontWeight: 500 }}>{x.name}</span>
                        <span style={{ color: 'var(--text-faint)', fontSize: 11 }}>{x.description}</span>
                      </div>
                    </td>
                    <td className="dim">{x.version}</td>
                    <td>
                      {x.enabled ? <Badge tone="ok">ACTIVE</Badge> : <Badge tone="dim">OFF</Badge>}
                    </td>
                    <td>{x.trustLevel === 'verified' || x.trustLevel === 'built-in' ? <Badge tone="ok">{x.trustLevel.toUpperCase()}</Badge> : <Badge tone="accent">{x.trustLevel.toUpperCase()}</Badge>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div style={{ background: 'var(--surface)', display: 'flex', flexDirection: 'column', borderLeft: '1px solid var(--border)', overflow: 'auto', minHeight: 0 }}>
            {ex ? (
              <>
                <div className="pf-panel-head">
                  <div className="pf-panel-title">
                    <span className="pf-panel-eyebrow">DETAIL</span>
                    {ex.name}
                  </div>
                  <Toggle on={ex.enabled} />
                </div>
                <div style={{ padding: 16, display: 'flex', flexDirection: 'column', gap: 14 }}>
                  <div style={{ fontSize: 12.5, color: 'var(--text-dim)', lineHeight: 1.5 }}>{ex.description}</div>
                  <KV compact data={[
                    ['Version', ex.version],
                    ['Author', ex.author],
                    ['State', ex.enabled ? 'enabled' : 'disabled'],
                    ['Trust', ex.trustLevel],
                    ['Permissions', ex.permissions.join(' · ')],
                  ]} />
                </div>
              </>
            ) : (
              <div style={{ padding: 20, color: 'var(--text-faint)', fontSize: 13, textAlign: 'center' }}>
                Select an extension to inspect.
              </div>
            )}
          </div>
        </div>
      </div>
    </>
  );
}

// ============ AI / Agent ============

interface AiProps {
  aiProviderSettings: AiProviderRuntime[];
  aiPrompt: string;
  setAiPrompt: (v: string) => void;
  aiRunStatus: string;
  aiActionExecutionPackages: AiActionExecutionPackage[];
  onRun?: () => void;
  onOpenProviders?: () => void;
}

const aiActionKindLabels: Record<AiSuggestedActionKind, string> = {
  'stage-repeater': 'stage-repeater',
  'stage-replay-matrix': 'stage-replay-matrix',
  'queue-active-scan': 'queue-active-scan',
  'open-exploit-review': 'open-exploit-review',
  'record-automation': 'record-automation',
  'draft-report': 'draft-report',
};

export function AiScreen({ aiProviderSettings, aiPrompt, setAiPrompt, aiRunStatus, aiActionExecutionPackages, onRun, onOpenProviders }: AiProps) {
  const hasConfiguredProvider = aiProviderSettings.some((p) => p.status === 'configured');
  const actionCounts = useMemo(() => {
    const counts = new Map<AiSuggestedActionKind, number>();
    for (const pkg of aiActionExecutionPackages) {
      counts.set(pkg.actionKind, (counts.get(pkg.actionKind) ?? 0) + 1);
    }
    return counts;
  }, [aiActionExecutionPackages]);

  function exportLatestRun() {
    if (aiActionExecutionPackages.length === 0) return;
    const payload = JSON.stringify({
      exportedAt: new Date().toISOString(),
      latestPrompt: aiPrompt,
      status: aiRunStatus,
      packages: aiActionExecutionPackages,
    }, null, 2);
    const blob = new Blob([payload], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `proxyforge-ai-run-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  }

  return (
    <>
      <WorkspaceHeader
        eyebrow="SURFACE"
        title="AI / Agent"
        maturity="alpha"
        maturityHint="Codex / Claude / OpenAI-compatible providers and the 70-command agent CLI are Production Ready. The pfv2 prompt+runner UI is alpha — Run works once a provider is configured under Settings → AI providers; Export run dumps the latest action packages."
        subtitle="Codex · Claude · OpenAI-compatible · proxyforge-agent control surface"
        actions={
          <>
            <Button variant="ghost" icon={FolderOpen} comingSoon title="Recall a previously saved AI benchmark run">Saved benchmarks</Button>
            <Button
              variant="ghost"
              icon={Download}
              onClick={exportLatestRun}
              disabled={aiActionExecutionPackages.length === 0}
              title={
                aiActionExecutionPackages.length === 0
                  ? 'No AI runs recorded yet — Run a prompt first'
                  : 'Download the recorded AI action packages and latest prompt as a JSON evidence file'
              }
            >
              Export run
            </Button>
            <Button
              icon={SettingsIcon}
              onClick={onOpenProviders}
              title="Open Settings to add API keys, choose models, and pick which provider runs the agent"
            >
              Providers
            </Button>
          </>
        }
      />
      <div className="ws-body flush" style={{ display: 'flex', flexDirection: 'column', minHeight: 0, flex: 1 }}>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 320px', flex: 1, minHeight: 0 }}>
          <div style={{ display: 'flex', flexDirection: 'column', overflow: 'hidden', borderRight: '1px solid var(--border)', minHeight: 0 }}>
            <div className="pf-panel-head" style={{ background: 'var(--surface)' }}>
              <div className="pf-panel-title">
                <span className="pf-panel-eyebrow">PROMPT</span>
                {aiRunStatus}
              </div>
              <Button
                size="sm" variant="accent" icon={Send}
                onClick={onRun}
                disabled={!hasConfiguredProvider || !aiPrompt.trim()}
                title={
                  !hasConfiguredProvider
                    ? 'No AI provider is configured. Click "Providers" above to add API keys in Settings.'
                    : !aiPrompt.trim()
                      ? 'Type a prompt describing what the agent should do'
                      : 'Run the prompt against the configured AI provider'
                }
              >
                Run
              </Button>
            </div>
            <textarea
              value={aiPrompt}
              onChange={(e) => setAiPrompt(e.target.value)}
              placeholder="Describe what the agent should do…"
              style={{
                flex: 1, minHeight: 0, border: 0, outline: 0, resize: 'none',
                padding: '14px 16px', fontSize: 13, lineHeight: 1.55,
                background: 'var(--surface)', color: 'var(--text-base)',
                fontFamily: 'var(--font-sans)',
              }}
            />
          </div>
          <div style={{ background: 'var(--surface)', padding: 16, overflow: 'auto', display: 'flex', flexDirection: 'column', gap: 14, minHeight: 0 }}>
            <Panel
              title="Providers"
              tight
              actions={
                <Button
                  size="sm"
                  variant={hasConfiguredProvider ? 'ghost' : 'accent'}
                  icon={SettingsIcon}
                  onClick={onOpenProviders}
                  title="Add API keys / endpoints and pick which provider this project uses"
                >
                  {hasConfiguredProvider ? 'Edit' : 'Configure'}
                </Button>
              }
            >
              {aiProviderSettings.length === 0 || !hasConfiguredProvider ? (
                <div style={{ fontSize: 11.5, color: 'var(--text-dim)', lineHeight: 1.5, padding: '4px 0 10px' }}>
                  No provider is configured yet. Click <strong>Configure</strong> to open Settings &rarr; AI providers and add an API key for Claude, OpenAI, or an OpenAI-compatible endpoint. Until then the <em>Run</em> button stays disabled.
                </div>
              ) : null}
              <KV compact data={aiProviderSettings.length
                ? aiProviderSettings.map((p) => [p.label, <Badge tone={p.status === 'configured' ? 'ok' : 'dim'}>{p.status?.toUpperCase() || 'OFF'}</Badge>] as [string, ReactNode])
                : [['none', <span style={{ color: 'var(--text-faint)' }}>no providers configured</span>]]} />
            </Panel>
            <Panel title="Controlled actions" tight>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                {(Object.keys(aiActionKindLabels) as AiSuggestedActionKind[]).map((kind) => {
                  const count = actionCounts.get(kind) ?? 0;
                  return (
                    <div key={kind} style={{
                      fontFamily: 'var(--font-mono)', fontSize: 11.5, color: 'var(--text-dim)',
                      padding: '3px 6px', borderRadius: 3, background: 'var(--surface-2)',
                      display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 6,
                    }}>
                      <span>{aiActionKindLabels[kind]}</span>
                      <span style={{ color: count > 0 ? 'var(--text-base)' : 'var(--text-faint)' }}>{count}</span>
                    </div>
                  );
                })}
              </div>
            </Panel>
          </div>
        </div>
      </div>
    </>
  );
}

// ============ Reports ============

interface ReportsProps {
  reportFullPackages: ReportFullPackage[];
  projectName: string;
  issues: Issue[];
  reportSections: ReportSection[];
  setReportSections: (sections: ReportSection[]) => void;
  reportSectionLabels: Record<ReportSection, string>;
  reportFormat?: ReportFormat;
  setReportFormat?: (format: ReportFormat) => void;
  onExportReport?: (format?: ReportFormat) => void | Promise<void>;
  reportArtifact?: ReportArtifact | null;
  reportStatus?: string;
}

const reportSectionOrder: ReportSection[] = ['executive', 'technical', 'remediation', 'evidence', 'appendix'];

export function ReportsScreen({
  reportFullPackages, projectName, issues, reportSections, setReportSections, reportSectionLabels,
  reportFormat, setReportFormat, onExportReport, reportArtifact, reportStatus,
}: ReportsProps) {
  function exportAs(format: ReportFormat) {
    if (!setReportFormat || !onExportReport) return;
    setReportFormat(format);
    void onExportReport(format);
  }
  const exportReady = !!setReportFormat && !!onExportReport;
  const counts = useMemo(() => {
    const c = { Critical: 0, High: 0, Medium: 0, Low: 0 };
    for (const i of issues) {
      const k = i.severity[0].toUpperCase() + i.severity.slice(1) as keyof typeof c;
      if (k in c) c[k]++;
    }
    return c;
  }, [issues]);
  return (
    <>
      <WorkspaceHeader
        eyebrow="SURFACE"
        title="Reports"
        maturity="alpha"
        maturityHint="Report builder engine (MD / HTML / JSON / PDF / SARIF / JUnit + signed bundle) is wired and Production Ready behind the legacy UI; pfv2 surface for direct render buttons is still being assembled."
        subtitle={`${projectName || 'No project'} · ${issues.length} findings · ${reportFullPackages.length} report packages`}
        actions={
          <>
            <Button
              variant="ghost" icon={Download}
              onClick={() => exportAs('pdf')}
              disabled={!exportReady}
              title={exportReady ? 'Render the report draft as a PDF (current sections + selected template)' : 'Export handler not wired'}
            >
              PDF
            </Button>
            <Button
              variant="ghost" icon={FileText}
              onClick={() => exportAs('markdown')}
              disabled={!exportReady}
              title={exportReady ? 'Render the report draft as Markdown' : 'Export handler not wired'}
            >
              Markdown
            </Button>
            <Button
              icon={FileText}
              onClick={() => exportAs('html')}
              disabled={!exportReady}
              title={exportReady ? 'Render the report draft as a self-contained HTML file' : 'Export handler not wired'}
            >
              HTML
            </Button>
            <Button
              variant="accent" icon={ShieldCheck}
              onClick={() => exportAs('bundle')}
              disabled={!exportReady}
              title={exportReady ? 'Bundle and sign the report + evidence for tamper-evident handoff' : 'Export handler not wired'}
            >
              Signed bundle
            </Button>
          </>
        }
      />
      <div className="ws-body flush" style={{ display: 'flex', flexDirection: 'column', minHeight: 0, flex: 1 }}>
        <div style={{ display: 'grid', gridTemplateColumns: '300px 1fr', flex: 1, minHeight: 0 }}>
          <div style={{ background: 'var(--surface)', display: 'flex', flexDirection: 'column', overflow: 'hidden', borderRight: '1px solid var(--border)' }}>
            <div className="pf-panel-head">
              <div className="pf-panel-title">
                <span className="pf-panel-eyebrow">SECTIONS</span>
                {reportSections.length} included · {reportFullPackages.length} packages
              </div>
            </div>
            <div className="pf-list" style={{ flex: 1, overflow: 'auto', minHeight: 0 }}>
              {reportSectionOrder.map((section) => {
                const included = reportSections.includes(section);
                const toggle = (next: boolean) => {
                  if (next) {
                    if (!reportSections.includes(section)) {
                      setReportSections(reportSectionOrder.filter((s) => s === section || reportSections.includes(s)));
                    }
                  } else {
                    setReportSections(reportSections.filter((s) => s !== section));
                  }
                };
                return (
                  <div key={section} className={`pf-list-item${included ? ' is-active' : ''}`} style={{ paddingTop: 8, paddingBottom: 8 }}>
                    <div className="pf-list-item-mark" />
                    <Toggle on={included} onChange={toggle} />
                    <div className="pf-list-item-main">
                      <div style={{ fontSize: 13 }}>{reportSectionLabels[section]}</div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
          <div style={{ overflow: 'auto', padding: '24px 48px', background: 'var(--bg-base)', minHeight: 0 }}>
            <div style={{
              maxWidth: 760, margin: '0 auto',
              background: 'var(--surface)', border: '1px solid var(--border)',
              borderRadius: 8, padding: 40, minHeight: 600,
            }}>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-faint)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 8 }}>
                REPORT · {projectName || 'untitled project'}
              </div>
              <h1 style={{ fontSize: 26, fontWeight: 500, margin: 0, letterSpacing: '-0.02em' }}>
                Application security assessment
              </h1>
              <div style={{ color: 'var(--text-dim)', fontSize: 13, marginTop: 4 }}>
                prepared by ProxyForge · {issues.length} findings
              </div>
              <div style={{
                marginTop: 22, display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12,
                paddingTop: 16, borderTop: '1px solid var(--border)',
              }}>
                {(['Critical', 'High', 'Medium', 'Low'] as const).map((s) => (
                  <div key={s}>
                    <div style={{ fontSize: 11, color: 'var(--text-faint)', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 500 }}>{s}</div>
                    <div style={{
                      fontFamily: 'var(--font-mono)', fontSize: 26, marginTop: 2,
                      color: s === 'Critical' ? 'var(--critical)' : s === 'High' ? 'var(--accent)' : s === 'Medium' ? 'var(--medium)' : 'var(--text-dim)',
                    }}>
                      {counts[s] ?? 0}
                    </div>
                  </div>
                ))}
              </div>
              <h2 style={{ fontSize: 16, fontWeight: 500, marginTop: 30, paddingTop: 16, borderTop: '1px solid var(--border)' }}>
                Findings
              </h2>
              <div className="pf-list" style={{ margin: 0, marginTop: 8 }}>
                {issues.length === 0 ? (
                  <div style={{ padding: 12, color: 'var(--text-faint)', fontSize: 12.5 }}>
                    No findings to include yet.
                  </div>
                ) : issues.slice(0, 10).map((f) => (
                  <div key={f.id} className="pf-list-item" style={{ padding: '10px 0', borderBottom: '1px solid var(--border-soft)' }}>
                    <SevDot level={f.severity[0].toUpperCase() + f.severity.slice(1)} />
                    <div className="pf-list-item-main">
                      <div style={{ fontSize: 13, color: 'var(--text-base)' }}>{f.title}</div>
                      <div className="pf-list-item-meta">
                        <span>{f.id}</span>
                        <span className="sep">·</span>
                        <span>{f.host}{f.path}</span>
                        <span className="sep">·</span>
                        <span>{f.confidence}</span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
              {reportArtifact || reportStatus ? (
                <div style={{
                  marginTop: 24, padding: '12px 14px', borderTop: '1px solid var(--border)',
                  background: 'var(--surface-2)', borderRadius: 6, fontSize: 12, color: 'var(--text-dim)',
                }}>
                  {reportStatus ? <div style={{ marginBottom: reportArtifact ? 6 : 0 }}>{reportStatus}</div> : null}
                  {reportArtifact ? (
                    <div style={{ display: 'flex', gap: 14, flexWrap: 'wrap', fontFamily: 'var(--font-mono)', fontSize: 11.5 }}>
                      <span>{reportArtifact.format.toUpperCase()}</span>
                      <span>·</span>
                      <span>{reportArtifact.fileName}</span>
                      <span>·</span>
                      <span>{reportArtifact.path}</span>
                    </div>
                  ) : null}
                </div>
              ) : null}
              <div style={{ marginTop: 18, fontSize: 11.5, color: 'var(--text-faint)' }}>
                Current format: <strong>{reportFormat ? reportFormat.toUpperCase() : 'not selected'}</strong> · Sections: {reportSections.length}/{reportSectionOrder.length}
                {reportFullPackages.length ? ` · ${reportFullPackages.length} prior package(s) retained` : ''}
              </div>
            </div>
          </div>
        </div>
      </div>
    </>
  );
}

// ============ Settings ============

interface SettingsProps {
  projectName: string;
  setProjectName: (v: string) => void;
  scopeAllowlist: string[];
  listenerHost: string;
  listenerPort: number;
  listenerRunning: boolean;
  loggerCaptureControls: LoggerCaptureControl[];
  setLoggerToolCapture: (tool: LoggerToolSource, enabled: boolean) => void;
  loggerToolLabels: Record<LoggerToolSource, string>;
  safetyPolicy: ProjectSafetyPolicy;
  aiProviderSettings: AiProviderRuntime[];
  updateAiProvider: (id: AiProviderId, patch: Partial<AiProviderConfig>) => void;
  httpsStatus?: HttpsInspectionStatus;
  onToggleHttpsInspection?: () => void | Promise<void>;
  onUpdateUpstreamTlsMode?: (mode: HttpsInspectionStatus['upstreamTlsMode']) => void | Promise<void>;
  onToggleListener: () => void;
  onOpenWizard: () => void;
  initialTab?: SettingsTab;
  onExportProject?: () => void | Promise<void>;
  onImportProject?: () => void | Promise<void>;
  projectFileStatus?: string;
}

type SettingsTab = 'project' | 'scope' | 'policy' | 'ca' | 'listener' | 'ai';

export function SettingsScreen({
  projectName, setProjectName, scopeAllowlist, listenerHost, listenerPort,
  listenerRunning,
  loggerCaptureControls, setLoggerToolCapture, loggerToolLabels,
  safetyPolicy,
  aiProviderSettings, updateAiProvider,
  httpsStatus, onToggleHttpsInspection, onUpdateUpstreamTlsMode,
  onToggleListener, onOpenWizard, initialTab,
  onExportProject, onImportProject, projectFileStatus,
}: SettingsProps) {
  const [tab, setTab] = useState<SettingsTab>(initialTab ?? 'project');
  return (
    <>
      <WorkspaceHeader
        eyebrow="WORKSPACE"
        title="Settings"
        maturity="alpha"
        maturityHint="Project / scope / policy / CA / listener / AI provider / project file tabs are all wired."
        subtitle="Project · scope · policy · certificates · listener · AI providers"
        actions={
          <>
            <Button
              variant="ghost"
              icon={Download}
              onClick={onExportProject ? () => { void onExportProject(); } : undefined}
              disabled={!onExportProject}
              title="Export the entire project (scope, CA references, settings) as a portable file"
            >
              Export project
            </Button>
            <Button
              variant="ghost"
              icon={Upload}
              onClick={onImportProject ? () => { void onImportProject(); } : undefined}
              disabled={!onImportProject}
              title="Import a previously exported project file (opens a file picker)"
            >
              Import
            </Button>
            <Button variant="accent" onClick={onOpenWizard} title="Re-open the setup wizard (project, scope, CA, listener, browser)">Setup wizard</Button>
          </>
        }
      />
      <Tabs<SettingsTab>
        value={tab}
        onChange={setTab}
        items={[
          { value: 'project', label: 'Project', icon: SettingsIcon },
          { value: 'scope', label: 'Scope', icon: ShieldCheck },
          { value: 'policy', label: 'Policy', icon: Lock },
          { value: 'ca', label: 'Project CA', icon: ShieldCheck },
          { value: 'listener', label: 'Listener', icon: Globe2 },
          { value: 'ai', label: 'AI providers', icon: Bot, count: aiProviderSettings.filter((p) => p.status === 'configured').length },
        ]}
      />
      <div className="ws-body" style={{ maxWidth: 900 }}>
        {tab === 'project' ? (
          <>
            <Panel title="Project">
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
                <Field label="Name">
                  <input value={projectName} onChange={(e) => setProjectName(e.target.value)} style={inputStyle} />
                </Field>
                <Field label="File">
                  <input
                    value={projectName ? `${projectName.toLowerCase().replace(/\s+/g, '-')}.proxyforge.json` : 'unsaved'}
                    readOnly
                    style={{ ...inputStyle, fontFamily: 'var(--font-mono)' }}
                  />
                </Field>
              </div>
              {projectFileStatus ? (
                <div className="dim" style={{ marginTop: 8, fontSize: 12 }}>{projectFileStatus}</div>
              ) : null}
            </Panel>
            <Panel title="Tool capture">
              <KV compact data={loggerCaptureControls.map((c) => [
                loggerToolLabels[c.tool] || c.tool,
                <Toggle on={c.enabled} onChange={(next) => setLoggerToolCapture(c.tool, next)} />,
              ] as [string, ReactNode])} />
            </Panel>
          </>
        ) : tab === 'scope' ? (
          <>
            <Banner tone="warn" icon={ShieldCheck}>
              Active checks, Exploit Lab, and Intruder require an in-scope match.
              Out-of-scope hosts may be observed but never probed.
            </Banner>
            <Panel title={`In scope (${scopeAllowlist.length})`} flush>
              <div className="pf-table-wrap">
                <table className="pf-table">
                  <thead><tr><th>Pattern</th><th style={{ width: 90 }}>Type</th></tr></thead>
                  <tbody>
                    {scopeAllowlist.length === 0 ? (
                      <tr><td colSpan={2} style={emptyRowStyle}>No scope configured. Run the setup wizard.</td></tr>
                    ) : scopeAllowlist.map((p) => (
                      <tr key={p}>
                        <td className="mono">{p}</td>
                        <td className="dim">{p.startsWith('*.') ? 'wildcard' : 'host'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Panel>
          </>
        ) : tab === 'policy' ? (
          <>
            <Panel title="Active safety policy" tight>
              <KV compact data={[
                ['Scope match required', safetyPolicy.requireScopeMatch ? 'yes' : 'no'],
                ['Throttle floor', `${safetyPolicy.minThrottleMs} ms`],
                ['Max requests/run', safetyPolicy.maxRequestsPerRun.toLocaleString()],
                ['Audit logging', safetyPolicy.auditLogging ? 'on' : 'off'],
                ['Redact secrets in audit', safetyPolicy.redactAuditSecrets ? 'yes' : 'no'],
              ]} />
            </Panel>
            <Panel title="Signed governance policy">
              <div style={{ padding: '12px 0', color: 'var(--text-dim)', fontSize: 12.5 }}>
                Import a signed governance policy package to enforce scope, throttles, and approval gates beyond the active project defaults.
              </div>
            </Panel>
          </>
        ) : tab === 'ca' ? (
          <>
            <Banner tone="warn" icon={ShieldCheck}>
              The project root CA is scoped to this project. ProxyForge does not modify your system trust store unless you explicitly import.
            </Banner>
            <Panel title="Project root CA">
              <div style={{ padding: '12px 0', color: 'var(--text-dim)', fontSize: 12.5 }}>
                Use the setup wizard to generate and export the CA.
              </div>
              <Button onClick={onOpenWizard}>Open wizard</Button>
            </Panel>
          </>
        ) : tab === 'listener' ? (
          <>
            <Panel title="Local listener">
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
                <Field label="Bind host">
                  <input value={listenerHost} readOnly style={{ ...inputStyle, fontFamily: 'var(--font-mono)' }} />
                </Field>
                <Field label="Bind port">
                  <input value={listenerPort} readOnly style={{ ...inputStyle, fontFamily: 'var(--font-mono)' }} />
                </Field>
              </div>
              <div style={{ marginTop: 14, display: 'flex', gap: 6 }}>
                <Button
                  variant={listenerRunning ? 'ghost' : 'accent'}
                  icon={listenerRunning ? Pause : Play}
                  onClick={onToggleListener}
                  title={listenerRunning ? 'Stop the local HTTP proxy listener' : 'Start the local HTTP proxy listener'}
                >
                  {listenerRunning ? 'Pause' : 'Start'}
                </Button>
              </div>
            </Panel>
            {httpsStatus ? (
              <Panel title="HTTPS inspection" actions={
                <Badge tone={httpsStatus.enabled ? 'ok' : 'dim'}>
                  {httpsStatus.enabled ? 'CONNECT MITM ON' : 'TUNNEL-ONLY'}
                </Badge>
              }>
                <div style={{ fontSize: 12.5, color: 'var(--text-dim)', lineHeight: 1.5, marginBottom: 12 }}>
                  {httpsStatus.message}
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
                  <Field label="Decrypt HTTPS via project CA">
                    <Toggle
                      on={httpsStatus.enabled}
                      onChange={() => onToggleHttpsInspection?.()}
                      label={httpsStatus.enabled ? 'enabled — host certs minted by project CA' : 'disabled — CONNECT passes through opaque'}
                    />
                  </Field>
                  <Field label="Upstream TLS validation">
                    <select
                      value={httpsStatus.upstreamTlsMode}
                      onChange={(e) => onUpdateUpstreamTlsMode?.(e.target.value as HttpsInspectionStatus['upstreamTlsMode'])}
                      style={inputStyle}
                      title="strict: verify upstream certs. relaxed: ignore upstream cert errors (test only)."
                      disabled={!onUpdateUpstreamTlsMode}
                    >
                      <option value="strict">strict — verify upstream certs</option>
                      <option value="relaxed">relaxed — accept invalid upstream certs</option>
                    </select>
                  </Field>
                </div>
              </Panel>
            ) : null}
          </>
        ) : (
          <AiProvidersTab providers={aiProviderSettings} update={updateAiProvider} />
        )}
      </div>
    </>
  );
}

function AiProvidersTab({ providers, update }: {
  providers: AiProviderRuntime[];
  update: (id: AiProviderId, patch: Partial<AiProviderConfig>) => void;
}) {
  return (
    <>
      <Banner tone="warn" icon={Bot}>
        API keys are read from environment variables ProxyForge sees at launch. Set the variable in your shell (or system env), restart ProxyForge, and the provider will switch to <Badge tone="ok">CONFIGURED</Badge>. ProxyForge never stores raw keys in the project file.
      </Banner>
      {providers.length === 0 ? (
        <Panel title="No providers">
          <div style={{ padding: '12px 0', color: 'var(--text-faint)', fontSize: 12.5 }}>
            No AI provider runtimes loaded.
          </div>
        </Panel>
      ) : providers.map((provider) => (
        <Panel
          key={provider.id}
          title={provider.label}
          eyebrow={provider.id}
          actions={<Badge tone={provider.status === 'configured' ? 'ok' : provider.status === 'needs-key' ? 'accent' : 'dim'}>{provider.status?.toUpperCase() || 'OFF'}</Badge>}
        >
          <div style={{ fontSize: 12, color: 'var(--text-dim)', marginBottom: 12 }}>{provider.message}</div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
            <Field label="Enabled">
              <Toggle on={provider.enabled} onChange={(next) => update(provider.id, { enabled: next })} />
            </Field>
            <Field label="Mode">
              <select
                value={provider.mode}
                onChange={(e) => update(provider.id, { mode: e.target.value as AiProviderConfig['mode'] })}
                style={inputStyle}
                title="cli = run a local binary · http = call an HTTP endpoint"
              >
                <option value="cli">CLI binary</option>
                <option value="http">HTTP endpoint</option>
              </select>
            </Field>
            <Field label="Model">
              <input
                value={provider.model}
                onChange={(e) => update(provider.id, { model: e.target.value })}
                style={inputStyle}
                placeholder="e.g. claude-opus-4-7, gpt-4o"
              />
            </Field>
            <Field label="Timeout (ms)">
              <input
                value={provider.timeoutMs}
                onChange={(e) => update(provider.id, { timeoutMs: Number(e.target.value) || 0 })}
                inputMode="numeric"
                style={inputStyle}
              />
            </Field>
            {provider.mode === 'cli' ? (
              <>
                <Field label="Command">
                  <input
                    value={provider.command ?? ''}
                    onChange={(e) => update(provider.id, { command: e.target.value })}
                    style={{ ...inputStyle, fontFamily: 'var(--font-mono)' }}
                    placeholder="claude"
                  />
                </Field>
                <Field label="Args (one per line)">
                  <textarea
                    value={(provider.args ?? []).join('\n')}
                    onChange={(e) => update(provider.id, { args: e.target.value.split('\n').filter(Boolean) })}
                    rows={3}
                    style={{ ...inputStyle, height: 'auto', fontFamily: 'var(--font-mono)', padding: '6px 9px' }}
                  />
                </Field>
              </>
            ) : (
              <>
                <Field label="Endpoint">
                  <input
                    value={provider.endpoint ?? ''}
                    onChange={(e) => update(provider.id, { endpoint: e.target.value })}
                    style={{ ...inputStyle, fontFamily: 'var(--font-mono)' }}
                    placeholder="https://api.anthropic.com/v1/messages"
                  />
                </Field>
                <Field label="API key env var">
                  <input
                    value={provider.apiKeyEnv ?? ''}
                    onChange={(e) => update(provider.id, { apiKeyEnv: e.target.value })}
                    style={{ ...inputStyle, fontFamily: 'var(--font-mono)' }}
                    placeholder="ANTHROPIC_API_KEY"
                    title={provider.secretPresent ? 'Environment variable is set in ProxyForge\'s process' : 'Set this env var before launching ProxyForge — the value never lives in the project file'}
                  />
                </Field>
              </>
            )}
          </div>
        </Panel>
      ))}
    </>
  );
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
      <div style={{ fontSize: 11.5, color: 'var(--text-dim)', fontWeight: 500 }}>{label}</div>
      {children}
    </div>
  );
}

// ============ Search ============

interface SearchProps {
  exchanges: HttpExchange[];
  searchQuery: string;
  setSearchQuery: (v: string) => void;
}

export function SearchScreen({ exchanges, searchQuery, setSearchQuery }: SearchProps) {
  const q = searchQuery.trim().toLowerCase();
  const results = useMemo(() => {
    if (!q) return [];
    return exchanges.filter((e) =>
      e.url.toLowerCase().includes(q) ||
      e.host.toLowerCase().includes(q) ||
      e.path.toLowerCase().includes(q) ||
      (e.requestRaw || '').toLowerCase().includes(q) ||
      (e.responseRaw || '').toLowerCase().includes(q)
    ).slice(0, 200);
  }, [exchanges, q]);

  return (
    <>
      <WorkspaceHeader
        eyebrow="WORKSPACE"
        title="Search"
        maturity="alpha"
        maturityHint="Live substring search across URL/host/path/request body/response body works. Saved hunts and structured-field operators are coming soon."
        subtitle={`${results.length} matches across ${exchanges.length} exchanges`}
        actions={
          <Button variant="ghost" icon={FolderOpen} comingSoon title="Recall a previously saved search query">Saved hunts</Button>
        }
      />
      <div className="ws-body flush" style={{ display: 'flex', flexDirection: 'column', minHeight: 0, flex: 1 }}>
        <div style={{ padding: '10px 12px', borderBottom: '1px solid var(--border)', background: 'var(--surface)' }}>
          <input
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search bodies, headers, paths…"
            style={{
              width: '100%', height: 32, padding: '0 12px', borderRadius: 4,
              background: 'var(--surface-2)', border: '1px solid var(--border-strong)',
              fontSize: 13, color: 'var(--text-base)', outline: 'none',
              fontFamily: 'var(--font-mono)',
            }}
          />
        </div>
        <div className="pf-table-wrap" style={{ flex: 1, minHeight: 0 }}>
          <table className="pf-table">
            <thead><tr>
              <th style={{ width: 70 }}>Method</th>
              <th>Host + path</th>
              <th style={{ width: 60 }} className="right">Status</th>
              <th style={{ width: 60 }} className="right">Size</th>
            </tr></thead>
            <tbody>
              {!q ? (
                <tr><td colSpan={4} style={emptyRowStyle}>Type to search across all captured traffic.</td></tr>
              ) : results.length === 0 ? (
                <tr><td colSpan={4} style={emptyRowStyle}>No matches.</td></tr>
              ) : results.map((t) => (
                <tr key={t.id}>
                  <td><Badge>{t.method}</Badge></td>
                  <td><span className="dim">{t.host}</span>{t.path}</td>
                  <td className="right"><Status s={t.status} /></td>
                  <td className="right dim">{((t.length || 0) / 1024).toFixed(1)}k</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
}

// ============ Viewer ============

interface ViewerProps {
  selectedExchange: HttpExchange;
}

export function ViewerScreen({ selectedExchange }: ViewerProps) {
  const [view, setView] = useState<'raw' | 'pretty' | 'hex'>('raw');
  return (
    <>
      <WorkspaceHeader
        eyebrow="WORKSPACE"
        title="Viewer"
        maturity="alpha"
        maturityHint="Raw / pretty / hex views for the selected exchange. Multipart, GraphQL, protobuf, and other content-typed views are coming soon."
        subtitle="Selected exchange — raw, pretty, hex, decoded variants"
        actions={
          <SubTabs value={view} onChange={setView} items={[
            { value: 'raw', label: 'Raw' },
            { value: 'pretty', label: 'Pretty' },
            { value: 'hex', label: 'Hex' },
          ]} />
        }
      />
      <div className="ws-body flush" style={{ display: 'flex', flexDirection: 'column', minHeight: 0, flex: 1 }}>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', flex: 1, minHeight: 0 }}>
          <div style={{ display: 'flex', flexDirection: 'column', borderRight: '1px solid var(--border)', minHeight: 0 }}>
            <div className="pf-panel-head" style={{ background: 'var(--surface)' }}>
              <div className="pf-panel-title">REQUEST</div>
            </div>
            <pre style={{
              flex: 1, minHeight: 0, overflow: 'auto', margin: 0,
              padding: '12px 14px', fontFamily: 'var(--font-mono)',
              fontSize: 12.5, lineHeight: 1.55, color: 'var(--text-base)',
              background: 'var(--surface)', whiteSpace: 'pre-wrap', wordBreak: 'break-all',
            }}>{selectedExchange?.requestRaw || '— no request selected —'}</pre>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', minHeight: 0 }}>
            <div className="pf-panel-head" style={{ background: 'var(--surface)' }}>
              <div className="pf-panel-title">RESPONSE</div>
            </div>
            <pre style={{
              flex: 1, minHeight: 0, overflow: 'auto', margin: 0,
              padding: '12px 14px', fontFamily: 'var(--font-mono)',
              fontSize: 12.5, lineHeight: 1.55, color: 'var(--text-base)',
              background: 'var(--surface)', whiteSpace: 'pre-wrap', wordBreak: 'break-all',
            }}>{selectedExchange?.responseRaw || '— no response —'}</pre>
          </div>
        </div>
      </div>
    </>
  );
}

// ============ shared SubTabs ============

function SubTabs<T extends string>({ value, onChange, items }: {
  value: T;
  onChange: (v: T) => void;
  items: Array<{ value: T; label: string }>;
}) {
  return (
    <div style={{
      display: 'inline-flex', gap: 2, padding: 4,
      background: 'var(--surface-2)', border: '1px solid var(--border)', borderRadius: 4,
    }}>
      {items.map((t) => (
        <button
          key={t.value}
          type="button"
          onClick={() => onChange(t.value)}
          style={{
            padding: '4px 11px', fontSize: 11.5,
            color: t.value === value ? 'var(--text-base)' : 'var(--text-dim)',
            background: t.value === value ? 'var(--surface)' : 'transparent',
            borderRadius: 3, border: 0, cursor: 'pointer',
            fontWeight: t.value === value ? 500 : 400,
            boxShadow: t.value === value ? 'var(--shadow-sm)' : 'none',
          }}
        >{t.label}</button>
      ))}
    </div>
  );
}

const inputStyle = {
  display: 'flex', alignItems: 'center', height: 28, padding: '0 9px',
  borderRadius: 4, background: 'var(--surface)', border: '1px solid var(--border-strong)',
  fontSize: 12.5, color: 'var(--text-base)', outline: 'none', width: '100%',
};

const emptyRowStyle = {
  padding: '20px 14px', textAlign: 'center' as const,
  color: 'var(--text-faint)', fontSize: 12.5,
};
