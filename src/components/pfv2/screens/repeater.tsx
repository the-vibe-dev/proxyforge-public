import { useMemo, useState } from 'react';
import {
  Download, FolderOpen, Layers, Pin, Plus, RotateCcw, Send, Upload, X,
} from 'lucide-react';
import type { HttpExchange, RepeaterWorkspaceTab } from '../../../types';
import { Button, IconButton, Method, Status } from '../ui';
import { WorkspaceHeader } from '../shell';

interface RepeaterProps {
  repeaterTabs: RepeaterWorkspaceTab[];
  selectedRepeaterTabId: string;
  setSelectedRepeaterTabId: (id: string) => void;
  selectedRepeaterTab?: RepeaterWorkspaceTab;
  exchanges: HttpExchange[];
  onSend?: () => void;
  onSendBatch?: () => void;
  onNewRequest?: () => void;
  onCloseTab?: (id: string) => void;
  repeaterStatus: string;
  repeaterRaw: string;
  setRepeaterRaw: (v: string) => void;
  repeaterTargetUrl: string;
  setRepeaterTargetUrl: (v: string) => void;
  repeaterResult: HttpExchange;
  projectName?: string;
}

export function RepeaterScreen({
  repeaterTabs, selectedRepeaterTabId, setSelectedRepeaterTabId, selectedRepeaterTab,
  exchanges, onSend, onSendBatch, onNewRequest, onCloseTab, repeaterStatus,
  repeaterRaw, setRepeaterRaw, repeaterTargetUrl, setRepeaterTargetUrl, repeaterResult,
  projectName,
}: RepeaterProps) {
  function exportRepeaterTabs() {
    if (repeaterTabs.length === 0) return;
    const payload = JSON.stringify({
      exportedAt: new Date().toISOString(),
      project: projectName ?? '',
      tabs: repeaterTabs,
    }, null, 2);
    const blob = new Blob([payload], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `proxyforge-repeater-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  }
  const [reqPane, setReqPane] = useState<'raw' | 'headers' | 'json'>('raw');
  const [resPane, setResPane] = useState<'raw' | 'pretty' | 'hex'>('raw');

  return (
    <>
      <WorkspaceHeader
        eyebrow="TESTING"
        title="Repeater"
        maturity="alpha"
        maturityHint="Manual send, redirect/timeout controls, and desync/race planning are wired. Groups, bulk replay, and saved snapshot diffs are coming soon to the pfv2 UI."
        subtitle={repeaterStatus}
        actions={
          <>
            <Button variant="ghost" icon={FolderOpen} comingSoon title="Organize Repeater tabs into named groups (per-flow / per-endpoint)">Groups</Button>
            <Button variant="ghost" icon={Upload} comingSoon title="Import a previously exported Repeater bundle">Import</Button>
            <Button
              variant="ghost"
              icon={Download}
              onClick={exportRepeaterTabs}
              disabled={repeaterTabs.length === 0}
              title={
                repeaterTabs.length === 0
                  ? 'No Repeater tabs to export — send a request from Proxy first'
                  : 'Export the current set of Repeater tabs as JSON'
              }
            >
              Export
            </Button>
            <Button icon={Plus} onClick={onNewRequest} title="Open a blank Repeater tab to paste / craft a request">New request</Button>
          </>
        }
      />
      <div style={{
        display: 'flex', alignItems: 'stretch', background: 'var(--surface)',
        borderBottom: '1px solid var(--border)', padding: '0 8px', gap: 2,
        overflow: 'auto', flexShrink: 0,
      }}>
        {repeaterTabs.length === 0 ? (
          <div style={{ padding: '8px 12px', color: 'var(--text-faint)', fontSize: 12.5 }}>
            No saved tabs yet. Click <strong style={{ color: 'var(--text-base)' }}>New request</strong> or send from Proxy.
          </div>
        ) : repeaterTabs.map((t) => {
          const active = t.id === selectedRepeaterTabId;
          return (
            <div
              key={t.id}
              onClick={() => setSelectedRepeaterTabId(t.id)}
              style={{
                padding: '8px 12px',
                display: 'flex', alignItems: 'center', gap: 8,
                fontSize: 12.5,
                color: active ? 'var(--text-base)' : 'var(--text-dim)',
                background: active ? 'var(--bg-base)' : 'transparent',
                borderRight: '1px solid var(--border)',
                borderTop: active ? '2px solid var(--accent)' : '2px solid transparent',
                marginTop: -1,
                cursor: 'pointer', whiteSpace: 'nowrap',
              }}
            >
              <Method m={(t.rawRequest.split(' ')[0] || 'GET').toUpperCase()} />
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{t.name}</span>
              {t.dirty ? <span style={{ color: 'var(--accent)', fontSize: 10 }}>●</span> : null}
              <X
                size={12}
                style={{ color: 'var(--text-faint)', marginLeft: 4 }}
                onClick={(e) => { e.stopPropagation(); onCloseTab?.(t.id); }}
              />
            </div>
          );
        })}
        <div onClick={onNewRequest} style={{
          padding: '8px 10px', color: 'var(--text-faint)', display: 'flex',
          alignItems: 'center', cursor: 'pointer',
        }}>
          <Plus size={14} />
        </div>
      </div>
      <div className="ws-body flush" style={{ display: 'flex', flexDirection: 'column', minHeight: 0, flex: 1 }}>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', flex: 1, minHeight: 0 }}>
          <div style={{ display: 'flex', flexDirection: 'column', overflow: 'hidden', minHeight: 0, borderRight: '1px solid var(--border)' }}>
            <div className="pf-panel-head" style={{ background: 'var(--surface)' }}>
              <div className="pf-panel-title"><span className="pf-panel-eyebrow">REQUEST</span></div>
              <SubTabs value={reqPane} onChange={setReqPane} items={[
                { value: 'raw', label: 'Raw' },
                { value: 'headers', label: 'Headers' },
                { value: 'json', label: 'Body' },
              ]} />
            </div>
            <div style={{ padding: '6px 10px', borderBottom: '1px solid var(--border)', background: 'var(--surface-2)', display: 'flex', gap: 6, alignItems: 'center' }}>
              <input
                value={repeaterTargetUrl}
                onChange={(e) => setRepeaterTargetUrl(e.target.value)}
                placeholder="https://api.example.test/path"
                style={{
                  flex: 1, height: 26, padding: '0 9px', borderRadius: 4,
                  background: 'var(--surface)', border: '1px solid var(--border)',
                  fontSize: 12, color: 'var(--text-base)', outline: 'none',
                  fontFamily: 'var(--font-mono)',
                }}
              />
            </div>
            <textarea
              value={repeaterRaw}
              onChange={(e) => setRepeaterRaw(e.target.value)}
              placeholder={'GET /api/v2/me HTTP/1.1\nHost: api.example.test\nAccept: application/json\n\n'}
              style={{
                flex: 1, minHeight: 0, border: 0, outline: 0, resize: 'none',
                padding: '12px 14px', fontSize: 12.5, lineHeight: 1.55,
                background: 'var(--surface)', color: 'var(--text-base)',
                fontFamily: 'var(--font-mono)',
              }}
            />
            <div style={{
              padding: '10px 14px', borderTop: '1px solid var(--border)',
              background: 'var(--surface-2)', display: 'flex', gap: 8, alignItems: 'center',
            }}>
              <Button
                variant="accent" icon={Send}
                onClick={onSend}
                disabled={!repeaterRaw.trim() || !repeaterTargetUrl.trim()}
                title={
                  !repeaterTargetUrl.trim() ? 'Enter a target URL above'
                  : !repeaterRaw.trim() ? 'Type or paste a raw request'
                  : 'Send this request to the target URL once'
                }
              >
                Send
              </Button>
              <Button
                variant="ghost" icon={RotateCcw}
                onClick={onSendBatch}
                disabled={!onSendBatch || !repeaterRaw.trim() || !repeaterTargetUrl.trim()}
                title={
                  !onSendBatch ? 'Bulk replay handler not wired'
                  : !repeaterTargetUrl.trim() ? 'Enter a target URL above'
                  : !repeaterRaw.trim() ? 'Type or paste a raw request'
                  : 'Bulk replay — run this request through the project bulk-replay engine to see timing variability'
                }
              >
                Send batch
              </Button>
              <Button variant="ghost" icon={Layers} comingSoon title="Send this request across every saved Repeater tab in the current group">Group send</Button>
              <div style={{ flex: 1 }} />
              <div className="pf-row-meta">
                <span>{repeaterRaw.length} B</span>
              </div>
            </div>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', overflow: 'hidden', minHeight: 0 }}>
            <div className="pf-panel-head" style={{ background: 'var(--surface)' }}>
              <div className="pf-panel-title">
                <span className="pf-panel-eyebrow">RESPONSE</span>
                {repeaterResult?.status ? <Status s={repeaterResult.status} /> : <span className="dim">—</span>}
                {repeaterResult?.timing ? <span style={{ color: 'var(--text-faint)', fontSize: 11.5 }}>· {repeaterResult.timing}ms</span> : null}
              </div>
              <SubTabs value={resPane} onChange={setResPane} items={[
                { value: 'raw', label: 'Raw' },
                { value: 'pretty', label: 'Pretty' },
                { value: 'hex', label: 'Hex' },
              ]} />
            </div>
            <pre style={{
              flex: 1, minHeight: 0, overflow: 'auto', margin: 0,
              padding: '12px 14px', fontFamily: 'var(--font-mono)',
              fontSize: 12.5, lineHeight: 1.55, color: 'var(--text-base)',
              background: 'var(--surface)', whiteSpace: 'pre-wrap', wordBreak: 'break-all',
            }}>
              {repeaterResult?.responseRaw || '— no response yet — click Send to issue this request —'}
            </pre>
            <div style={{
              padding: '10px 14px', borderTop: '1px solid var(--border)',
              background: 'var(--surface-2)', display: 'flex', gap: 8, alignItems: 'center',
            }}>
              <Button variant="ghost" icon={Pin} comingSoon title="Snapshot this response for later comparison">Pin snapshot</Button>
              <Button variant="ghost" icon={Layers} comingSoon title="Diff this response against a pinned snapshot">Compare</Button>
              <div style={{ flex: 1 }} />
              <Button variant="ghost" comingSoon title="Convert this response into an issue/finding for the report">Promote to finding</Button>
            </div>
          </div>
        </div>
      </div>
    </>
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
        >{t.label}</button>
      ))}
    </div>
  );
}
