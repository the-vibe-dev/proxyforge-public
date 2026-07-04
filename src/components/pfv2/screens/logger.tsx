import { useMemo, useState } from 'react';
import { Download, Edit3, Filter as FilterIcon, Pin, Upload } from 'lucide-react';
import type { HttpExchange } from '../../../types';
import { Method, Panel, Status, Tabs } from '../ui';
import { WorkspaceHeader } from '../shell';
import { Button } from '../ui';

interface LoggerProps {
  exchanges: HttpExchange[];
}

export function LoggerScreen({ exchanges }: LoggerProps) {
  const [tab, setTab] = useState<'combined' | 'presets' | 'imports'>('combined');
  const [sourceFilter, setSourceFilter] = useState<Set<string>>(new Set());
  const [query, setQuery] = useState('');

  const sources = useMemo(() => {
    const m = new Map<string, number>();
    for (const ex of exchanges) {
      const s = ex.source || 'proxy';
      m.set(s, (m.get(s) ?? 0) + 1);
    }
    return Array.from(m.entries()).sort((a, b) => b[1] - a[1]);
  }, [exchanges]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return exchanges.filter((e) => {
      if (sourceFilter.size > 0 && !sourceFilter.has(e.source)) return false;
      if (!q) return true;
      const tokens = q.split(/\s+/).filter(Boolean);
      const hay = `${e.method} ${e.host} ${e.path} ${e.url} ${e.status} ${e.mime} ${e.source} ${(e.tags || []).join(' ')}`.toLowerCase();
      return tokens.every((tok) => {
        const c = tok.indexOf(':');
        if (c > 0) {
          const field = tok.slice(0, c);
          const value = tok.slice(c + 1);
          if (!value) return true;
          if (field === 'tool' || field === 'source') return e.source.toLowerCase().includes(value);
          if (field === 'method') return e.method.toLowerCase() === value;
          if (field === 'host') return e.host.toLowerCase().includes(value);
          if (field === 'path') return e.path.toLowerCase().includes(value);
          if (field === 'mime') return (e.mime || '').toLowerCase().includes(value);
          if (field === 'status') {
            const m = value.match(/^(>=|<=|!=|>|<|=)?\s*(\d{3})$/);
            if (!m) return false;
            const op = m[1] || '=';
            const n = Number(m[2]);
            const s = e.status;
            return op === '=' ? s === n
              : op === '!=' ? s !== n
              : op === '>=' ? s >= n
              : op === '<=' ? s <= n
              : op === '>' ? s > n
              : op === '<' ? s < n
              : false;
          }
          if (field === 'tag') return (e.tags || []).some((t) => t.toLowerCase().includes(value));
        }
        return hay.includes(tok);
      });
    });
  }, [exchanges, sourceFilter, query]);

  const toggleSource = (s: string) => {
    setSourceFilter((prev) => {
      const next = new Set(prev);
      if (next.has(s)) next.delete(s);
      else next.add(s);
      return next;
    });
  };

  function exportLoggerJson() {
    const payload = JSON.stringify(filtered, null, 2);
    const blob = new Blob([payload], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `proxyforge-logger-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  }

  return (
    <>
      <WorkspaceHeader
        eyebrow="CAPTURE"
        title="Logger"
        maturity="alpha"
        maturityHint="Combined source-per-tool view + filter + export are wired. Saved filters, capture presets, and import archives are coming soon."
        subtitle={`All tool-generated HTTP traffic · ${exchanges.length.toLocaleString()} entries`}
        actions={
          <>
            <Button variant="ghost" icon={Upload} comingSoon title="Import a previously exported logger archive">Import archive</Button>
            <Button
              variant="ghost" icon={Download}
              onClick={exportLoggerJson}
              disabled={filtered.length === 0}
              title={filtered.length === 0 ? 'Nothing to export — capture some traffic first' : `Download ${filtered.length} log entries as JSON`}
            >
              Export
            </Button>
            <Button variant="ghost" icon={Edit3} comingSoon title="Pick which columns appear in the logger table">Custom columns</Button>
          </>
        }
      />
      <Tabs<'combined' | 'presets' | 'imports'>
        value={tab}
        onChange={setTab}
        items={[
          { value: 'combined', label: 'Combined', count: exchanges.length },
          { value: 'presets', label: 'Capture presets', icon: Pin },
          { value: 'imports', label: 'Import history', icon: Upload },
        ]}
      />
      {tab === 'combined' ? (
        <div className="ws-body flush" style={{ display: 'flex', flexDirection: 'column', minHeight: 0, flex: 1 }}>
          <div style={{
            padding: '10px 12px', display: 'flex', gap: 8, borderBottom: '1px solid var(--border)',
            background: 'var(--surface)', alignItems: 'center', flexWrap: 'wrap',
          }}>
            <span style={{ color: 'var(--text-base)', fontSize: 12.5, fontWeight: 500 }}>Sources</span>
            {sources.length === 0 ? (
              <span style={{ color: 'var(--text-faint)', fontSize: 12 }}>No traffic yet</span>
            ) : sources.map(([s, count]) => {
              const on = sourceFilter.size === 0 ? true : sourceFilter.has(s);
              return (
                <button
                  key={s}
                  type="button"
                  onClick={() => toggleSource(s)}
                  style={{
                    display: 'inline-flex', alignItems: 'center', gap: 5,
                    height: 24, padding: '0 9px', fontSize: 12, borderRadius: 100,
                    border: on ? '1px solid var(--text-base)' : '1px solid var(--border-strong)',
                    background: on ? 'var(--text-base)' : 'var(--surface)',
                    color: on ? 'var(--bg-base)' : 'var(--text-dim)',
                    cursor: 'pointer',
                  }}
                >
                  {s}
                  <span style={{ opacity: 0.7, fontFamily: 'var(--font-mono)', fontSize: 10.5 }}>
                    {count.toLocaleString()}
                  </span>
                </button>
              );
            })}
            <div style={{ flex: 1 }} />
            <Button size="sm" variant="ghost" icon={FilterIcon} comingSoon title="Recall a previously saved filter expression">Saved filters</Button>
          </div>
          <div style={{
            padding: '8px 12px', borderBottom: '1px solid var(--border)',
            background: 'var(--surface)', display: 'flex', gap: 8, alignItems: 'center',
          }}>
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Filter — tool:scanner status:>=500 path:/api host:api.example.com"
              spellCheck={false}
              title="Field operators: tool: source: method: host: path: mime: status: tag:. Comparisons for status: >= <= > < = !=. Bare words match anywhere (AND)."
              style={{
                flex: 1, maxWidth: 420, height: 28, padding: '0 9px',
                borderRadius: 4, background: 'var(--surface)', border: '1px solid var(--border-strong)',
                fontSize: 12.5, color: 'var(--text-base)', outline: 'none',
              }}
            />
            <span style={{ color: 'var(--text-faint)', fontSize: 11.5, marginLeft: 8 }}>
              {filtered.length.toLocaleString()} match{filtered.length === 1 ? '' : 'es'}
            </span>
          </div>
          <div className="pf-table-wrap" style={{ flex: 1, minHeight: 0 }}>
            <table className="pf-table">
              <thead><tr>
                <th style={{ width: 60 }}>#</th>
                <th style={{ width: 78 }}>Tool</th>
                <th style={{ width: 90 }}>Time</th>
                <th style={{ width: 56 }}>Meth</th>
                <th style={{ width: 180 }}>Host</th>
                <th>Path</th>
                <th style={{ width: 60 }} className="right">Status</th>
                <th style={{ width: 70 }} className="right">Size</th>
                <th style={{ width: 56 }} className="right">ms</th>
              </tr></thead>
              <tbody>
                {filtered.length === 0 ? (
                  <tr><td colSpan={9} style={emptyRowStyle}>No traffic to display.</td></tr>
                ) : filtered.slice(0, 200).map((t) => (
                  <tr key={t.id}>
                    <td className="faint">{t.id.slice(0, 6)}</td>
                    <td className="dim">{t.source}</td>
                    <td className="dim">{(t.time || '').slice(11, 19)}</td>
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
        </div>
      ) : tab === 'presets' ? (
        <div className="ws-body">
          <Panel title="Saved capture presets">
            <div style={{ padding: '20px 0', color: 'var(--text-faint)', fontSize: 12.5, textAlign: 'center' }}>
              Save a current Logger view as a preset to share or schedule.
            </div>
          </Panel>
        </div>
      ) : (
        <div className="ws-body">
          <Panel title="Import history">
            <div style={{ padding: '20px 0', color: 'var(--text-faint)', fontSize: 12.5, textAlign: 'center' }}>
              No archives imported yet. Drag a <code>.proxyforge.json</code> here.
            </div>
          </Panel>
        </div>
      )}
    </>
  );
}

const emptyRowStyle = {
  padding: '20px 14px', textAlign: 'center' as const,
  color: 'var(--text-faint)', fontSize: 12.5,
};
