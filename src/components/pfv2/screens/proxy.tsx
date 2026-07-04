import { useMemo, useState } from 'react';
import {
  ArrowLeftRight, Copy, Download, Edit3, FileText, Filter, HelpCircle, Layers,
  Link2, MoreHorizontal, Pause, Pin, Play, RotateCcw, ScanLine, Send,
  Trash2, Upload, X,
} from 'lucide-react';
import type { HttpExchange, InterceptedRequest, InterceptStatus, MatchReplaceRule, WebSocketMessage } from '../../../types';
import { Badge, Button, IconButton, KV, Method, Panel, SevDot, Status, Tabs, Toggle } from '../ui';
import { WorkspaceHeader } from '../shell';

interface ProxyProps {
  exchanges: HttpExchange[];
  selectedExchangeId: string;
  setSelectedExchangeId: (id: string) => void;
  selectedExchange: HttpExchange;
  interceptStatus: InterceptStatus;
  pendingIntercepts: InterceptedRequest[];
  toggleIntercept: () => Promise<void> | void;
  toggleResponseIntercept: () => Promise<void> | void;
  resolvePendingIntercept: (action: 'forward' | 'drop') => Promise<void> | void;
  selectedIntercept?: InterceptedRequest;
  selectedInterceptId: string | null;
  setSelectedInterceptId: (id: string) => void;
  interceptEditorRaw: string;
  setInterceptEditorRaw: (raw: string) => void;
  matchReplaceRules: MatchReplaceRule[];
  addMatchReplaceRule: () => void;
  updateMatchReplaceRule: (id: string, patch: Partial<MatchReplaceRule>) => void;
  removeMatchReplaceRule: (id: string) => void;
  listenerRunning: boolean;
  listenerPort: number;
  onToggleListener: () => Promise<void> | void;
  promoteProxyHistoryToRepeater: () => void;
  promoteProxyHistoryToScanner: () => void;
  webSocketMessages: WebSocketMessage[];
}

export function ProxyScreen(props: ProxyProps) {
  const [tab, setTab] = useState<'history' | 'intercept' | 'ws' | 'rules'>('history');
  const exchangesCount = props.exchanges.length;

  function exportHistoryJson() {
    const payload = JSON.stringify(props.exchanges, null, 2);
    const blob = new Blob([payload], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `proxyforge-history-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  }

  return (
    <>
      <WorkspaceHeader
        eyebrow="CAPTURE"
        title="Proxy"
        maturity="alpha"
        maturityHint="HTTP/HTTPS listener, intercept, match&replace, WebSocket capture are all wired end-to-end. Import, custom view saves, and grouped views are still on the roadmap."
        subtitle={
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
            <span style={{
              display: 'inline-flex', alignItems: 'center', gap: 5,
              color: props.listenerRunning ? 'var(--ok)' : 'var(--text-faint)',
            }}>
              <span style={{
                width: 7, height: 7, borderRadius: '50%',
                background: props.listenerRunning ? 'var(--ok)' : 'var(--text-faint)',
                boxShadow: props.listenerRunning ? '0 0 0 3px color-mix(in oklab, var(--ok) 18%, transparent)' : 'none',
              }} />
              listener {props.listenerRunning ? 'up' : 'down'} · {props.listenerPort}
            </span>
            <span style={{ color: 'var(--text-mute)' }}>·</span>
            <span>{exchangesCount.toLocaleString()} captured</span>
          </span>
        }
        actions={
          <>
            <Button
              variant="ghost"
              icon={Download}
              onClick={exportHistoryJson}
              disabled={exchangesCount === 0}
              title={exchangesCount === 0 ? 'No captured exchanges to export' : `Download all ${exchangesCount} captured exchange(s) as JSON`}
            >
              Export
            </Button>
            <Button variant="ghost" icon={Upload} comingSoon title="Import a previously exported history file">Import</Button>
            <Button
              variant="ghost"
              icon={props.listenerRunning ? Pause : Play}
              onClick={() => props.onToggleListener()}
              title={props.listenerRunning ? `Stop the listener on 127.0.0.1:${props.listenerPort}` : 'Start the local HTTP proxy listener'}
            >
              {props.listenerRunning ? 'Pause' : 'Resume'}
            </Button>
          </>
        }
      />
      <Tabs<'history' | 'intercept' | 'ws' | 'rules'>
        value={tab}
        onChange={setTab}
        items={[
          { value: 'history', label: 'HTTP history', icon: FileText, count: exchangesCount },
          { value: 'intercept', label: 'Intercept', icon: Pause, count: props.pendingIntercepts.length },
          { value: 'ws', label: 'WebSockets', icon: Link2, count: countWsConnections(props.webSocketMessages) },
          { value: 'rules', label: 'Match & replace', icon: Edit3, count: props.matchReplaceRules.length },
        ]}
      />
      {tab === 'history' ? <ProxyHistory {...props} /> : null}
      {tab === 'intercept' ? <ProxyIntercept {...props} /> : null}
      {tab === 'ws' ? <ProxyWs messages={props.webSocketMessages} /> : null}
      {tab === 'rules' ? <ProxyRules rules={props.matchReplaceRules} addRule={props.addMatchReplaceRule} updateRule={props.updateMatchReplaceRule} removeRule={props.removeMatchReplaceRule} /> : null}
    </>
  );
}

function ProxyHistory({
  exchanges, selectedExchangeId, setSelectedExchangeId, selectedExchange,
  promoteProxyHistoryToRepeater, promoteProxyHistoryToScanner,
}: ProxyProps) {
  const [view, setView] = useState<'raw' | 'pretty' | 'hex'>('raw');
  const [respTab, setRespTab] = useState<'req' | 'res'>('res');
  const [query, setQuery] = useState('');
  const [errorChip, setErrorChip] = useState(false);
  const [annotatedChip, setAnnotatedChip] = useState(false);
  const [helpOpen, setHelpOpen] = useState(false);

  const filtered = useMemo(() => {
    const filters = parseHistoryFilter(query);
    let out = exchanges.filter((ex) => matchesFilter(ex, filters));
    if (errorChip) out = out.filter((ex) => ex.status >= 400);
    if (annotatedChip) out = out.filter((ex) => (ex.notes ?? '').trim().length > 0);
    return out;
  }, [exchanges, query, errorChip, annotatedChip]);
  const list = filtered.slice(0, 200);
  const truncated = filtered.length > list.length;

  return (
    <div className="ws-body flush" style={{ display: 'flex', flexDirection: 'column', minHeight: 0, flex: 1 }}>
      <div className="pf-filterbar" style={{ position: 'relative' }}>
        <input
          className="pf-input"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Filter — host:api.example.com status:>=400 method:POST"
          spellCheck={false}
          style={inputStyle}
        />
        <IconButton
          icon={HelpCircle}
          title="Show filter syntax"
          onClick={() => setHelpOpen((v) => !v)}
        />
        <Chip on={errorChip} onClick={() => setErrorChip((v) => !v)}>4xx/5xx</Chip>
        <Chip on={annotatedChip} onClick={() => setAnnotatedChip((v) => !v)}>annotated</Chip>
        <div style={{ flex: 1 }} />
        <span style={{ color: 'var(--text-faint)', fontSize: 11.5 }}>
          {filtered.length.toLocaleString()} match{filtered.length === 1 ? '' : 'es'}
          {truncated ? ` · showing first ${list.length}` : ''}
        </span>
        <Button size="sm" variant="ghost" icon={Layers} comingSoon title="Collapse rows by hostname">Group by host</Button>
        <Button size="sm" variant="ghost" icon={Pin} comingSoon title="Save the current filter as a named view">Save view</Button>
        {helpOpen ? <FilterSyntaxHelp onClose={() => setHelpOpen(false)} /> : null}
      </div>
      <div style={{ display: 'grid', gridTemplateRows: 'minmax(180px, 1fr) minmax(220px, 2fr)', flex: 1, minHeight: 0 }}>
        <div className="pf-table-wrap" style={{ minHeight: 0 }}>
          <table className="pf-table">
            <thead><tr>
              <th style={{ width: 60 }}>#</th>
              <th style={{ width: 78 }}>Time</th>
              <th style={{ width: 56 }}>Meth</th>
              <th style={{ width: 180 }}>Host</th>
              <th>Path</th>
              <th className="right" style={{ width: 60 }}>Status</th>
              <th style={{ width: 60 }}>MIME</th>
              <th className="right" style={{ width: 70 }}>Length</th>
              <th className="right" style={{ width: 56 }}>ms</th>
              <th style={{ width: 56 }}>Source</th>
            </tr></thead>
            <tbody>
              {list.length === 0 ? (
                <tr><td colSpan={10} style={emptyRowStyle}>
                  No traffic captured. Start the listener and configure a browser proxy.
                </td></tr>
              ) : list.map((t) => (
                <tr key={t.id}
                    className={t.id === selectedExchangeId ? 'is-selected' : ''}
                    onClick={() => setSelectedExchangeId(t.id)}>
                  <td className="faint">{t.id.slice(0, 6)}</td>
                  <td className="dim">{(t.time ?? '').slice(11, 19)}</td>
                  <td><Method m={t.method} /></td>
                  <td className="dim">{t.host}</td>
                  <td>{t.path}</td>
                  <td className="right"><Status s={t.status} /></td>
                  <td className="faint">{t.mime}</td>
                  <td className="right dim">{((t.length || 0) / 1024).toFixed(1)}k</td>
                  <td className="right dim">{t.timing}</td>
                  <td className="faint">{t.source}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', borderTop: '1px solid var(--border)', minHeight: 0 }}>
          <div style={{ display: 'flex', flexDirection: 'column', borderRight: '1px solid var(--border)', overflow: 'hidden', minHeight: 0 }}>
            <div className="pf-panel-head" style={{ background: 'var(--surface)', borderRadius: 0 }}>
              <div className="pf-panel-title">
                <SubTabs value={respTab} onChange={setRespTab} items={[{ value: 'req', label: 'Request' }, { value: 'res', label: 'Response' }]} />
              </div>
              <div style={{ display: 'flex', gap: 4 }}>
                <SubTabs value={view} onChange={setView} items={[
                  { value: 'raw', label: 'Raw' },
                  { value: 'pretty', label: 'Pretty' },
                  { value: 'hex', label: 'Hex' },
                ]} />
                <IconButton
                  icon={Copy}
                  title="Copy this request/response block to the clipboard"
                  onClick={() => {
                    const text = respTab === 'req'
                      ? (selectedExchange?.requestRaw || '')
                      : (selectedExchange?.responseRaw || '');
                    if (text && navigator.clipboard) navigator.clipboard.writeText(text);
                  }}
                  disabled={!selectedExchange?.id}
                />
              </div>
            </div>
            <RawBlock content={
              respTab === 'req'
                ? (selectedExchange?.requestRaw || '— no request data —')
                : (selectedExchange?.responseRaw || '— no response data —')
            } />
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', overflow: 'hidden', minHeight: 0 }}>
            <div className="pf-panel-head" style={{ background: 'var(--surface)' }}>
              <div className="pf-panel-title">
                <span className="pf-panel-eyebrow">EXCHANGE</span>
                {selectedExchange?.id ? `#${selectedExchange.id.slice(0, 8)}` : '—'}
              </div>
              <div style={{ display: 'flex', gap: 6 }}>
                <Button
                  size="sm" variant="ghost" icon={RotateCcw}
                  onClick={promoteProxyHistoryToRepeater}
                  disabled={!selectedExchange?.id}
                  title={selectedExchange?.id ? 'Send a copy of this exchange to Repeater' : 'Click a request in the list above first'}
                >
                  Repeater
                </Button>
                <Button
                  size="sm" variant="ghost" icon={ScanLine}
                  onClick={promoteProxyHistoryToScanner}
                  disabled={!selectedExchange?.id}
                  title={selectedExchange?.id ? 'Queue this exchange for active scanning' : 'Click a request in the list above first'}
                >
                  Active scan
                </Button>
              </div>
            </div>
            <div style={{ padding: '12px 14px', overflow: 'auto', flex: 1, background: 'var(--surface)' }}>
              <KV compact data={[
                ['URL', selectedExchange?.url || '—'],
                ['Method', selectedExchange?.method || '—'],
                ['Status', selectedExchange?.status ? <Status s={selectedExchange.status} /> : '—'],
                ['Source', selectedExchange?.source || '—'],
                ['MIME', selectedExchange?.mime || '—'],
                ['Length', selectedExchange?.length ? `${(selectedExchange.length / 1024).toFixed(1)} KB` : '—'],
                ['Timing', selectedExchange?.timing ? `${selectedExchange.timing} ms` : '—'],
                ['Tags', selectedExchange?.tags?.join(', ') || '—'],
                ['Time', selectedExchange?.time || '—'],
              ]} />
              {selectedExchange?.notes ? (
                <>
                  <div style={{ marginTop: 14, fontSize: 11, color: 'var(--text-faint)', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 500 }}>Notes</div>
                  <div style={{ marginTop: 6, fontSize: 12.5, color: 'var(--text-dim)', lineHeight: 1.5 }}>{selectedExchange.notes}</div>
                </>
              ) : null}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function ProxyIntercept({
  interceptStatus, pendingIntercepts, toggleIntercept, toggleResponseIntercept, resolvePendingIntercept,
  selectedInterceptId, setSelectedInterceptId, interceptEditorRaw, setInterceptEditorRaw,
}: ProxyProps) {
  const selected = pendingIntercepts.find((p) => p.id === selectedInterceptId) ?? pendingIntercepts[0];
  return (
    <div className="ws-body flush" style={{ display: 'flex', flexDirection: 'column', minHeight: 0, flex: 1 }}>
      <div className="pf-filterbar">
        <Toggle on={interceptStatus.enabled} onChange={toggleIntercept} label="Intercept requests" />
        <Toggle on={interceptStatus.responseEnabled} onChange={toggleResponseIntercept} label="Intercept responses" />
        <span style={{ color: 'var(--text-dim)', fontSize: 12.5 }}>holding {pendingIntercepts.length} messages</span>
        <div style={{ flex: 1 }} />
        <Button
          variant="accent" icon={Play}
          onClick={() => resolvePendingIntercept('forward')}
          disabled={pendingIntercepts.length === 0}
          title={pendingIntercepts.length === 0 ? 'No pending messages to forward' : 'Forward every held request/response upstream'}
        >
          Forward all
        </Button>
        <Button
          icon={Trash2}
          onClick={() => resolvePendingIntercept('drop')}
          disabled={pendingIntercepts.length === 0}
          title={pendingIntercepts.length === 0 ? 'No pending messages to drop' : 'Drop every held message without forwarding'}
        >
          Drop all
        </Button>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '3fr 2fr', flex: 1, minHeight: 0 }}>
        <div style={{ display: 'flex', flexDirection: 'column', borderRight: '1px solid var(--border)', minHeight: 0 }}>
          <div className="pf-panel-head" style={{ background: 'var(--surface)' }}>
            <div className="pf-panel-title">
              <span className="pf-panel-eyebrow">QUEUE</span>
              {pendingIntercepts.length} messages
            </div>
          </div>
          <div className="pf-table-wrap" style={{ minHeight: 0 }}>
            <table className="pf-table">
              <thead><tr>
                <th style={{ width: 30 }}></th>
                <th style={{ width: 60 }}>#</th>
                <th style={{ width: 60 }}>Meth</th>
                <th>Host + path</th>
                <th style={{ width: 60 }} className="right">Age</th>
              </tr></thead>
              <tbody>
                {pendingIntercepts.length === 0 ? (
                  <tr><td colSpan={5} style={emptyRowStyle}>
                    Intercept is {interceptStatus.enabled ? 'enabled' : 'disabled'}. Queue is empty.
                  </td></tr>
                ) : pendingIntercepts.map((q) => (
                  <tr key={q.id}
                      className={q.id === selectedInterceptId ? 'is-selected' : ''}
                      onClick={() => setSelectedInterceptId(q.id)}>
                    <td style={{ color: 'var(--accent)', fontFamily: 'var(--font-mono)' }}>{q.direction === 'request' ? '→' : '←'}</td>
                    <td className="faint">{q.id.slice(0, 6)}</td>
                    <td><Method m={q.method} /></td>
                    <td><span className="dim">{q.host}</span>{q.path}</td>
                    <td className="right dim">{(q.time || '').slice(11, 19)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', overflow: 'hidden', minHeight: 0 }}>
          <div className="pf-panel-head" style={{ background: 'var(--surface)' }}>
            <div className="pf-panel-title">
              <span className="pf-panel-eyebrow">EDIT</span>
              {selected ? `${selected.method} ${selected.path}` : 'No request selected'}
            </div>
            <div style={{ display: 'flex', gap: 4 }}>
              <Button
                size="sm" variant="ghost"
                onClick={() => resolvePendingIntercept('drop')}
                disabled={!selected}
                title={selected ? 'Drop this message without forwarding' : 'Select a held message from the queue first'}
              >
                Drop
              </Button>
              <Button
                size="sm" variant="accent" icon={Send}
                onClick={() => resolvePendingIntercept('forward')}
                disabled={!selected}
                title={selected ? 'Forward this (possibly edited) message upstream' : 'Select a held message from the queue first'}
              >
                Forward
              </Button>
            </div>
          </div>
          <textarea
            className="mono"
            value={interceptEditorRaw}
            onChange={(e) => setInterceptEditorRaw(e.target.value)}
            style={{
              flex: 1, minHeight: 0, border: 0, outline: 0, resize: 'none',
              padding: '12px 14px', fontSize: 12.5, lineHeight: 1.5,
              background: 'var(--surface)', color: 'var(--text-base)',
              fontFamily: 'var(--font-mono)',
            }}
          />
        </div>
      </div>
    </div>
  );
}

function countWsConnections(messages: WebSocketMessage[]): number | undefined {
  if (!messages.length) return undefined;
  const ids = new Set<string>();
  for (const m of messages) ids.add(m.connectionId);
  return ids.size;
}

function ProxyWs({ messages }: { messages: WebSocketMessage[] }) {
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [filter, setFilter] = useState<'all' | 'client' | 'server'>('all');
  const [typeFilter, setTypeFilter] = useState<'all' | 'text' | 'binary'>('all');

  const filtered = useMemo(() => {
    return messages.filter((m) => {
      if (filter !== 'all' && m.direction !== filter) return false;
      if (typeFilter !== 'all' && m.type !== typeFilter) return false;
      return true;
    });
  }, [messages, filter, typeFilter]);

  const list = filtered.slice(0, 300);
  const selected = list.find((m) => m.id === selectedId) ?? list[0];

  if (messages.length === 0) {
    return (
      <div className="ws-body flush" style={{ display: 'flex', flexDirection: 'column', minHeight: 0, flex: 1 }}>
        <div style={{ padding: '40px 32px', textAlign: 'center', color: 'var(--text-faint)', fontSize: 13 }}>
          No WebSocket traffic captured yet. WebSocket capture is automatic — when an HTTP client upgrades via the listener, frames will stream into this table.
          <div style={{ fontSize: 11.5, marginTop: 8 }}>
            Try a site that uses WebSockets (chat, live dashboards, notifications) through the proxy.
          </div>
        </div>
      </div>
    );
  }

  const decodedPayload = selected
    ? (selected.payloadEncoding === 'hex' || selected.payloadEncoding === 'base64'
        ? `(${selected.payloadEncoding} encoded · ${selected.length} B)\n${selected.payload}`
        : selected.payload)
    : '';

  return (
    <div className="ws-body flush" style={{ display: 'flex', flexDirection: 'column', minHeight: 0, flex: 1 }}>
      <div className="pf-filterbar">
        <span style={{ color: 'var(--text-base)', fontSize: 12.5, fontWeight: 500 }}>Direction</span>
        <Chip on={filter === 'all'} onClick={() => setFilter('all')}>all</Chip>
        <Chip on={filter === 'client'} onClick={() => setFilter('client')}>→ client</Chip>
        <Chip on={filter === 'server'} onClick={() => setFilter('server')}>← server</Chip>
        <span style={{ color: 'var(--text-base)', fontSize: 12.5, fontWeight: 500, marginLeft: 12 }}>Type</span>
        <Chip on={typeFilter === 'all'} onClick={() => setTypeFilter('all')}>all</Chip>
        <Chip on={typeFilter === 'text'} onClick={() => setTypeFilter('text')}>text</Chip>
        <Chip on={typeFilter === 'binary'} onClick={() => setTypeFilter('binary')}>binary</Chip>
        <div style={{ flex: 1 }} />
        <span style={{ color: 'var(--text-faint)', fontSize: 11.5 }}>
          {filtered.length} frame{filtered.length === 1 ? '' : 's'} across {countWsConnections(filtered) ?? 0} connection(s)
        </span>
      </div>
      <div style={{ display: 'grid', gridTemplateRows: 'minmax(180px, 1fr) minmax(160px, 1fr)', flex: 1, minHeight: 0 }}>
        <div className="pf-table-wrap" style={{ minHeight: 0 }}>
          <table className="pf-table">
            <thead><tr>
              <th style={{ width: 30 }}>Dir</th>
              <th style={{ width: 78 }}>Time</th>
              <th style={{ width: 70 }}>Type</th>
              <th style={{ width: 180 }}>Host</th>
              <th>Path</th>
              <th className="right" style={{ width: 70 }}>Size</th>
              <th style={{ width: 100 }}>Connection</th>
            </tr></thead>
            <tbody>
              {list.map((m) => (
                <tr
                  key={m.id}
                  className={m.id === selected?.id ? 'is-selected' : ''}
                  onClick={() => setSelectedId(m.id)}
                >
                  <td style={{ color: m.direction === 'client' ? 'var(--accent)' : 'var(--text-base)', fontFamily: 'var(--font-mono)' }}>
                    {m.direction === 'client' ? '→' : '←'}
                  </td>
                  <td className="dim">{(m.time ?? '').slice(11, 19)}</td>
                  <td><Badge tone={m.type === 'binary' ? 'accent' : m.type === 'close' ? 'crit' : 'dim'}>{m.type}</Badge></td>
                  <td className="dim">{m.host}</td>
                  <td>{m.path}</td>
                  <td className="right dim">{m.length} B</td>
                  <td className="faint">{m.connectionId.slice(0, 8)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', borderTop: '1px solid var(--border)', minHeight: 0, background: 'var(--surface)' }}>
          <div className="pf-panel-head">
            <div className="pf-panel-title">
              <span className="pf-panel-eyebrow">FRAME</span>
              {selected ? `#${selected.id.slice(0, 8)} · ${selected.direction} · ${selected.type}` : '—'}
            </div>
            <div style={{ display: 'flex', gap: 6 }}>
              <IconButton
                icon={Copy}
                title="Copy frame payload"
                onClick={() => { if (selected?.payload && navigator.clipboard) navigator.clipboard.writeText(selected.payload); }}
                disabled={!selected}
              />
            </div>
          </div>
          <pre style={{
            flex: 1, minHeight: 0, overflow: 'auto', margin: 0,
            padding: '12px 14px', fontFamily: 'var(--font-mono)',
            fontSize: 12, lineHeight: 1.55, color: 'var(--text-base)',
            whiteSpace: 'pre-wrap', wordBreak: 'break-all',
          }}>
            {selected ? decodedPayload : '— select a frame above to inspect —'}
          </pre>
        </div>
      </div>
    </div>
  );
}

function ProxyRules({ rules, addRule, updateRule, removeRule }: {
  rules: MatchReplaceRule[];
  addRule: () => void;
  updateRule: (id: string, patch: Partial<MatchReplaceRule>) => void;
  removeRule: (id: string) => void;
}) {
  return (
    <div className="ws-body flush" style={{ display: 'flex', flexDirection: 'column', minHeight: 0, flex: 1 }}>
      <div className="pf-filterbar">
        <input className="pf-input" placeholder="Filter rules…" style={inputStyle} />
        <Chip on>request</Chip>
        <Chip>response</Chip>
        <div style={{ flex: 1 }} />
        <Button icon={Edit3} onClick={addRule} title="Add a new request/response rewrite rule">New rule</Button>
      </div>
      <div className="pf-table-wrap" style={{ flex: 1, minHeight: 0 }}>
        <table className="pf-table">
          <thead><tr>
            <th style={{ width: 40 }}>On</th>
            <th>Name</th>
            <th style={{ width: 110 }}>Applies to</th>
            <th>Match</th>
            <th>Replace</th>
            <th style={{ width: 60 }} className="right">Hits</th>
            <th style={{ width: 40 }}></th>
          </tr></thead>
          <tbody>
            {rules.length === 0 ? (
              <tr><td colSpan={7} style={emptyRowStyle}>
                No rules yet. Add a rule to rewrite requests or responses.
              </td></tr>
            ) : rules.map((r) => (
              <tr key={r.id}>
                <td><Toggle on={r.enabled} onChange={(next) => updateRule(r.id, { enabled: next })} /></td>
                <td>{r.name || '(unnamed)'}</td>
                <td className="dim">{r.direction}</td>
                <td>{r.match}</td>
                <td className="dim">{r.replace}</td>
                <td className="right dim">{r.isRegex ? 'regex' : 'plain'}</td>
                <td><IconButton icon={X} onClick={() => removeRule(r.id)} title="Remove" /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function RawBlock({ content }: { content: string }) {
  return (
    <pre style={{
      flex: 1, minHeight: 0, overflow: 'auto', margin: 0,
      padding: '12px 14px', fontFamily: 'var(--font-mono)',
      fontSize: 12, lineHeight: 1.55, color: 'var(--text-base)',
      background: 'var(--surface)', whiteSpace: 'pre-wrap', wordBreak: 'break-all',
    }}>{content}</pre>
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
    >
      {children}
    </button>
  );
}

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
        >
          {t.label}
        </button>
      ))}
    </div>
  );
}

type HistoryFilter = {
  text: string[];
  exact: Array<{ field: 'method' | 'host' | 'path' | 'url' | 'mime' | 'source' | 'tag' | 'risk'; needle: string; negate: boolean }>;
  status: Array<{ op: '=' | '>=' | '<=' | '>' | '<' | '!='; value: number }>;
};

const TEXT_FIELDS: Record<string, true> = {
  method: true, host: true, path: true, url: true, mime: true, source: true, tag: true, risk: true,
};

function parseHistoryFilter(query: string): HistoryFilter {
  const filter: HistoryFilter = { text: [], exact: [], status: [] };
  const tokens = query.trim().match(/(?:[^\s"]+|"[^"]*")+/g) ?? [];
  for (const rawToken of tokens) {
    const token = rawToken.replace(/^"|"$/g, '');
    const negate = token.startsWith('-') && token.includes(':');
    const body = negate ? token.slice(1) : token;
    const colon = body.indexOf(':');
    if (colon === -1) {
      const t = body.toLowerCase();
      if (t) filter.text.push(t);
      continue;
    }
    const field = body.slice(0, colon).toLowerCase();
    const value = body.slice(colon + 1);
    if (field === 'status') {
      const m = value.match(/^(>=|<=|!=|>|<|=)?\s*(\d{3})$/);
      if (m) filter.status.push({ op: (m[1] as HistoryFilter['status'][number]['op']) || '=', value: Number(m[2]) });
      continue;
    }
    if (TEXT_FIELDS[field] && value) {
      filter.exact.push({ field: field as HistoryFilter['exact'][number]['field'], needle: value.toLowerCase(), negate });
    }
  }
  return filter;
}

function matchesFilter(ex: HttpExchange, f: HistoryFilter): boolean {
  for (const term of f.text) {
    const hay = `${ex.method} ${ex.host} ${ex.path} ${ex.url} ${ex.status} ${ex.mime} ${ex.source} ${(ex.tags || []).join(' ')}`.toLowerCase();
    if (!hay.includes(term)) return false;
  }
  for (const { field, needle, negate } of f.exact) {
    let hay = '';
    if (field === 'tag') hay = (ex.tags || []).join(' ').toLowerCase();
    else if (field === 'risk') hay = String(ex.risk || '').toLowerCase();
    else hay = String((ex as unknown as Record<string, unknown>)[field] ?? '').toLowerCase();
    const hit = matchWithWildcard(hay, needle);
    if (negate ? hit : !hit) return false;
  }
  for (const { op, value } of f.status) {
    const s = ex.status;
    const pass =
      op === '=' ? s === value :
      op === '!=' ? s !== value :
      op === '>=' ? s >= value :
      op === '<=' ? s <= value :
      op === '>' ? s > value :
      op === '<' ? s < value : false;
    if (!pass) return false;
  }
  return true;
}

function matchWithWildcard(haystack: string, needle: string): boolean {
  if (!needle.includes('*')) return haystack.includes(needle);
  const re = new RegExp('^' + needle.split('*').map(escapeRegExp).join('.*') + '$');
  return re.test(haystack);
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function FilterSyntaxHelp({ onClose }: { onClose: () => void }) {
  return (
    <div
      role="dialog"
      style={{
        position: 'absolute', top: 'calc(100% + 6px)', left: 0, zIndex: 30,
        width: 'min(560px, calc(100% - 16px))',
        background: 'var(--surface)', border: '1px solid var(--border-strong)', borderRadius: 6,
        boxShadow: 'var(--shadow-lg, 0 12px 32px rgba(0,0,0,0.35))',
        padding: '12px 14px', fontSize: 12.5, color: 'var(--text-base)',
      }}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', marginBottom: 8 }}>
        <strong style={{ fontSize: 12.5 }}>Filter syntax</strong>
        <button onClick={onClose} style={{ background: 'transparent', border: 0, color: 'var(--text-dim)', cursor: 'pointer', fontSize: 12 }}>Close</button>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '4px 12px', fontFamily: 'var(--font-mono)', fontSize: 11.5, color: 'var(--text-dim)' }}>
        <code>method:POST</code><span>HTTP method (exact, case-insensitive)</span>
        <code>host:api.example.com</code><span>Host substring or wildcard (<code>*</code>)</span>
        <code>host:api.*</code><span>Wildcard host match</span>
        <code>path:/v1/users</code><span>Path substring</span>
        <code>url:foo</code><span>Full URL substring</span>
        <code>status:404</code><span>Exact status code</span>
        <code>status:&gt;=400</code><span>Comparison: <code>&gt;= &lt;= &gt; &lt; = !=</code></span>
        <code>mime:json</code><span>Response MIME substring</span>
        <code>source:proxy</code><span><code>proxy · repeater · scanner · crawler · demo</code></span>
        <code>tag:auth</code><span>Match any tag (substring)</span>
        <code>risk:high</code><span>Risk severity</span>
        <code>-host:cdn.*</code><span>Negate a field with <code>-</code></span>
        <code>login error</code><span>Bare words match anywhere (AND)</span>
      </div>
      <div style={{ marginTop: 8, fontSize: 11.5, color: 'var(--text-faint)' }}>
        Combine fields with spaces (all must match). Chips below combine with the query (AND).
      </div>
    </div>
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
