import { useMemo, useState, type ReactNode } from 'react';
import {
  ChevronDown, ChevronRight, FolderClosed, Globe2, Play,
  RotateCcw, ScanLine, Search as SearchIcon, FileCode2,
  Filter, GitCompareArrows, Crosshair, Layers, Lock, Bug,
  ShieldCheck,
} from 'lucide-react';
import type { HttpExchange, Issue } from '../../../types';
import { Badge, Button, IconButton, Method, Panel, Status, SevDot, Stat, Tabs } from '../ui';
import { WorkspaceHeader } from '../shell';

interface TargetProps {
  exchanges: HttpExchange[];
  issues: Issue[];
  scopeAllowlist: string[];
  onRunCrawl?: () => void;
  onSendNodeToRepeater?: (exchange: HttpExchange) => void;
}

type TreeNode = {
  name: string;
  kind: 'host' | 'dir' | 'page' | 'file';
  children?: TreeNode[];
  count: number;
  lastStatus?: number;
  issueCount: number;
  path: string;
  in: boolean;
};

function buildTree(exchanges: HttpExchange[], issues: Issue[], scopeAllowlist: string[]): TreeNode[] {
  const inScope = new Set(scopeAllowlist.map((s) => s.toLowerCase().replace(/^\*\./, '')));
  const isInScope = (host: string) => {
    if (!scopeAllowlist.length) return true;
    const h = host.toLowerCase();
    return inScope.has(h) || scopeAllowlist.some((p) => {
      const norm = p.toLowerCase();
      if (norm.startsWith('*.')) return h.endsWith(norm.slice(1));
      return h === norm;
    });
  };

  // host -> path segments
  const hosts = new Map<string, Map<string, { count: number; lastStatus: number; issueCount: number; path: string }>>();
  for (const ex of exchanges) {
    if (!ex.host) continue;
    let host = hosts.get(ex.host);
    if (!host) {
      host = new Map();
      hosts.set(ex.host, host);
    }
    const segs = (ex.path || '/').split('/').filter(Boolean);
    let accum = '';
    for (let i = 0; i < Math.max(1, segs.length); i++) {
      accum = '/' + segs.slice(0, i + 1).join('/');
      const entry = host.get(accum) ?? { count: 0, lastStatus: ex.status, issueCount: 0, path: accum };
      if (i === segs.length - 1 || segs.length === 0) {
        entry.count += 1;
        entry.lastStatus = ex.status;
      }
      host.set(accum, entry);
    }
  }
  // overlay issues
  for (const issue of issues) {
    if (!issue.host) continue;
    const host = hosts.get(issue.host);
    if (!host) continue;
    const segs = (issue.path || '/').split('/').filter(Boolean);
    let accum = '';
    for (let i = 0; i < Math.max(1, segs.length); i++) {
      accum = '/' + segs.slice(0, i + 1).join('/');
      const entry = host.get(accum);
      if (entry) entry.issueCount += 1;
    }
  }

  const out: TreeNode[] = [];
  for (const [host, paths] of hosts) {
    const sorted = Array.from(paths.entries()).sort(([a], [b]) => a.localeCompare(b));
    const hostNode: TreeNode = {
      name: host,
      kind: 'host',
      path: host,
      count: Array.from(paths.values()).reduce((s, e) => s + e.count, 0),
      lastStatus: 200,
      issueCount: Array.from(paths.values()).reduce((s, e) => s + e.issueCount, 0),
      in: isInScope(host),
      children: [],
    };
    // build nested
    const dirMap = new Map<string, TreeNode>();
    for (const [path, entry] of sorted) {
      const segs = path.split('/').filter(Boolean);
      const name = segs[segs.length - 1] ?? '/';
      const parentPath = '/' + segs.slice(0, -1).join('/');
      const node: TreeNode = {
        name,
        kind: segs.length === 0 ? 'dir' : (name.includes('.') ? 'file' : entry.count > 0 ? 'page' : 'dir'),
        path,
        count: entry.count,
        lastStatus: entry.lastStatus,
        issueCount: entry.issueCount,
        in: hostNode.in,
        children: [],
      };
      dirMap.set(path, node);
      const parent = parentPath === '/' ? hostNode : dirMap.get(parentPath);
      if (parent) {
        parent.children = parent.children ?? [];
        parent.children.push(node);
      } else {
        hostNode.children?.push(node);
      }
    }
    out.push(hostNode);
  }
  return out.sort((a, b) => b.count - a.count);
}

export function TargetScreen({ exchanges, issues, scopeAllowlist, onRunCrawl, onSendNodeToRepeater }: TargetProps) {
  const tree = useMemo(() => buildTree(exchanges, issues, scopeAllowlist), [exchanges, issues, scopeAllowlist]);
  const [selected, setSelected] = useState<string>('');
  const [view, setView] = useState<'tree' | 'paths' | 'graph'>('tree');
  const [tab, setTab] = useState<'sitemap' | 'scope' | 'issues' | 'tech' | 'authz'>('sitemap');
  const [filter, setFilter] = useState('');

  const totals = useMemo(() => {
    let nodes = 0;
    let reached = 0;
    let issuesCount = 0;
    const walk = (n: TreeNode) => {
      nodes++;
      if (n.count > 0) reached++;
      issuesCount += n.issueCount;
      n.children?.forEach(walk);
    };
    tree.forEach(walk);
    return { nodes, reached, issues: issuesCount };
  }, [tree]);

  const selNodeExchanges = useMemo(() => {
    if (!selected) return [];
    return exchanges.filter((ex) => {
      const full = `${ex.host}${ex.path}`;
      return full === selected || full.startsWith(selected);
    });
  }, [exchanges, selected]);

  const selNodeIssues = useMemo(() => {
    if (!selected) return [];
    return issues.filter((i) => `${i.host}${i.path}`.startsWith(selected));
  }, [issues, selected]);

  return (
    <>
      <WorkspaceHeader
        eyebrow="CAPTURE"
        title="Target Map"
        maturity="alpha"
        maturityHint="Crawler + sitemap + scope + technology/parameter inventory are wired. AuthZ review, sitemap comparison, and filter saving are coming soon."
        subtitle="Site map · scope · access-control review · content discovery"
        actions={
          <>
            <SubTabs value={view} onChange={setView} items={[
              { value: 'tree', label: 'Tree' },
              { value: 'paths', label: 'Paths' },
              { value: 'graph', label: 'Graph' },
            ]} />
            <Button variant="ghost" icon={Filter} comingSoon title="Filter sitemap by path / status / annotation">Filter</Button>
            <Button variant="ghost" icon={GitCompareArrows} comingSoon title="Diff this sitemap against a previously captured one">Compare</Button>
            <Button
              variant="accent" icon={Play}
              onClick={onRunCrawl}
              disabled={!onRunCrawl}
              title={onRunCrawl ? 'Crawl the configured target URL (respects scope allowlist)' : 'Crawl handler is not wired in this build'}
            >
              Crawl
            </Button>
          </>
        }
      />
      <Tabs<'sitemap' | 'scope' | 'issues' | 'tech' | 'authz'>
        value={tab}
        onChange={setTab}
        items={[
          { value: 'sitemap', label: 'Site map', icon: Crosshair, count: totals.nodes },
          { value: 'scope', label: 'Scope', icon: ShieldCheck, count: scopeAllowlist.length },
          { value: 'issues', label: 'Issues', icon: Bug, count: issues.length },
          { value: 'tech', label: 'Tech', icon: Layers },
          { value: 'authz', label: 'AuthZ', icon: Lock },
        ]}
      />
      <div className="ws-body flush" style={{ flexDirection: 'column', minHeight: 0, flex: 1 }}>
        {tab === 'sitemap' ? (
          <div className="pf-hsplit" style={{ display: 'grid', gridTemplateColumns: '320px 1fr', flex: 1, minHeight: 0 }}>
            <div style={{ display: 'flex', flexDirection: 'column', background: 'var(--surface)', borderRight: '1px solid var(--border)', minHeight: 0 }}>
              <div style={{ padding: '8px 10px', borderBottom: '1px solid var(--border)' }}>
                <input
                  className="pf-input"
                  placeholder="Filter map…"
                  value={filter}
                  onChange={(e) => setFilter(e.target.value)}
                  style={inputStyle}
                />
              </div>
              <div style={{ flex: 1, overflow: 'auto', minHeight: 0 }}>
                {tree.length === 0 ? (
                  <div style={emptyStyle}>
                    No hosts captured yet.
                    <div style={{ fontSize: 11.5, marginTop: 4, color: 'var(--text-faint)' }}>
                      Start the listener and configure a browser to populate the map.
                    </div>
                  </div>
                ) : (
                  <TreeView nodes={tree} selected={selected} onSelect={setSelected} filter={filter} />
                )}
              </div>
              <div style={{ padding: '8px 12px', borderTop: '1px solid var(--border)', background: 'var(--surface-2)' }} className="pf-row-meta">
                <span>{totals.nodes} nodes</span>
                <span className="sep">·</span>
                <span>{totals.reached} reached</span>
                <span className="sep">·</span>
                <span>{totals.issues} issues</span>
              </div>
            </div>
            <NodeDetail selected={selected} exchanges={selNodeExchanges} issues={selNodeIssues} onSendToRepeater={onSendNodeToRepeater} />
          </div>
        ) : null}
        {tab === 'scope' ? <ScopeTab scopeAllowlist={scopeAllowlist} /> : null}
        {tab === 'issues' ? <IssuesTab issues={issues} /> : null}
        {tab === 'tech' ? <TechTab exchanges={exchanges} /> : null}
        {tab === 'authz' ? <AuthzPlaceholder /> : null}
      </div>
    </>
  );
}

const inputStyle = {
  display: 'flex', alignItems: 'center', height: 28, padding: '0 9px',
  borderRadius: 4, background: 'var(--surface)', border: '1px solid var(--border-strong)',
  fontSize: 12.5, color: 'var(--text-base)', outline: 'none', width: '100%',
};

const emptyStyle = {
  padding: '40px 20px', textAlign: 'center' as const,
  color: 'var(--text-faint)', fontSize: 13,
};

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
            padding: '4px 11px', fontSize: 11.5, color: t.value === value ? 'var(--text-base)' : 'var(--text-dim)',
            background: t.value === value ? 'var(--surface)' : 'transparent',
            borderRadius: 3, border: 0, cursor: 'pointer', fontWeight: t.value === value ? 500 : 400,
            boxShadow: t.value === value ? 'var(--shadow-sm)' : 'none',
          }}
        >
          {t.label}
        </button>
      ))}
    </div>
  );
}

function TreeView({ nodes, selected, onSelect, filter }: {
  nodes: TreeNode[];
  selected: string;
  onSelect: (p: string) => void;
  filter: string;
}) {
  const lower = filter.toLowerCase().trim();
  const matches = (n: TreeNode): boolean => {
    if (!lower) return true;
    if (n.name.toLowerCase().includes(lower) || n.path.toLowerCase().includes(lower)) return true;
    return Boolean(n.children?.some(matches));
  };
  return (
    <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, padding: '6px 0' }}>
      {nodes.filter(matches).map((n) => <TreeNodeRow key={n.path + n.name} node={n} depth={0} selected={selected} onSelect={onSelect} filterMatches={matches} defaultOpen />)}
    </div>
  );
}

function TreeNodeRow({ node, depth, selected, onSelect, filterMatches, defaultOpen = false }: {
  node: TreeNode;
  depth: number;
  selected: string;
  onSelect: (p: string) => void;
  filterMatches: (n: TreeNode) => boolean;
  defaultOpen?: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);
  const isFolder = node.kind === 'host' || node.kind === 'dir' || (node.children && node.children.length > 0);
  const isActive = selected === node.path;
  const code = node.lastStatus;
  return (
    <>
      <div
        onClick={() => { if (isFolder) setOpen(!open); onSelect(node.kind === 'host' ? node.name : node.path); }}
        style={{
          display: 'flex', alignItems: 'center', gap: 6,
          padding: `2px 12px 2px ${8 + depth * 14}px`, cursor: 'pointer',
          whiteSpace: 'nowrap', background: isActive ? 'var(--selected)' : 'transparent',
          color: isActive ? 'var(--text-base)' : undefined,
        }}
        onMouseEnter={(e) => { if (!isActive) e.currentTarget.style.background = 'var(--hover)'; }}
        onMouseLeave={(e) => { if (!isActive) e.currentTarget.style.background = 'transparent'; }}
      >
        <span style={{ width: 14, height: 14, display: 'grid', placeItems: 'center', color: 'var(--text-faint)', flexShrink: 0 }}>
          {isFolder ? (open ? <ChevronDown size={10} /> : <ChevronRight size={10} />) : <span style={{ width: 10 }} />}
        </span>
        <span style={{ width: 14, color: 'var(--text-faint)', flexShrink: 0 }}>
          {node.kind === 'host' ? <Globe2 size={12} /> :
           node.kind === 'dir' ? <FolderClosed size={12} /> :
           <FileCode2 size={12} />}
        </span>
        <span style={{ color: node.kind === 'host' || node.issueCount > 0 ? 'var(--text-base)' : 'var(--text-dim)' }}>
          {node.name}
        </span>
        {code && code >= 400 ? (
          <span style={{ color: 'var(--accent)', fontSize: 10.5, marginLeft: 6 }}>{code}</span>
        ) : null}
        {node.issueCount > 0 ? <span style={{ marginLeft: 6 }}><SevDot level="High" /></span> : null}
        <span style={{ marginLeft: 'auto', paddingLeft: 12, color: 'var(--text-faint)', fontSize: 10.5 }}>
          {node.count > 0 ? `${node.count} req` : ''}
        </span>
      </div>
      {open && node.children?.filter(filterMatches).map((c) => (
        <TreeNodeRow key={c.path + c.name} node={c} depth={depth + 1} selected={selected} onSelect={onSelect} filterMatches={filterMatches} />
      ))}
    </>
  );
}

function NodeDetail({ selected, exchanges, issues, onSendToRepeater }: {
  selected: string;
  exchanges: HttpExchange[];
  issues: Issue[];
  onSendToRepeater?: (exchange: HttpExchange) => void;
}) {
  if (!selected) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', background: 'var(--bg-base)', overflow: 'hidden', padding: 24 }}>
        <div style={{ color: 'var(--text-faint)', fontSize: 13, margin: 'auto' }}>
          Select a host or path on the left to inspect.
        </div>
      </div>
    );
  }
  const methods = Array.from(new Set(exchanges.map((e) => e.method))).join('·') || '—';
  const avgStatus = exchanges.length ? Math.round(exchanges.reduce((s, e) => s + e.status, 0) / exchanges.length) : 0;
  const representative = exchanges[0];
  const canSendToRepeater = Boolean(onSendToRepeater && representative);
  return (
    <div style={{ display: 'flex', flexDirection: 'column', background: 'var(--bg-base)', overflow: 'hidden', minHeight: 0 }}>
      <div className="pf-panel-head" style={{ background: 'var(--surface)' }}>
        <div className="pf-panel-title">
          <span className="pf-panel-eyebrow">NODE</span>
          <span className="mono" style={{ fontSize: 13 }}>{selected}</span>
        </div>
        <div style={{ display: 'flex', gap: 6 }}>
          <Button
            size="sm"
            variant="ghost"
            icon={RotateCcw}
            onClick={canSendToRepeater ? () => onSendToRepeater?.(representative!) : undefined}
            disabled={!canSendToRepeater}
            title={
              !onSendToRepeater
                ? 'Repeater handler not wired'
                : !representative
                  ? 'No captured requests for this node yet'
                  : `Send ${representative.method} ${representative.path} into the Repeater workspace`
            }
          >
            Repeater
          </Button>
          <Button size="sm" variant="ghost" icon={ScanLine} comingSoon title="Queue this node for active scanning">Active scan</Button>
          <Button size="sm" variant="ghost" icon={SearchIcon} comingSoon title="Run path discovery against this node">Discover</Button>
        </div>
      </div>
      <div style={{ padding: 16, overflow: 'auto', display: 'flex', flexDirection: 'column', gap: 14, minHeight: 0 }}>
        <div className="pf-cards cols-4">
          <Stat label="Requests" value={exchanges.length} />
          <Stat label="Methods" value={methods} />
          <Stat label="Avg status" value={avgStatus || '—'} />
          <Stat label="Issues" value={issues.length} delta={issues.length ? 'review' : 'clean'} accent={issues.length > 0} />
        </div>
        <Panel title="Recent exchanges" flush>
          <div className="pf-table-wrap" style={{ maxHeight: 280 }}>
            <table className="pf-table">
              <thead><tr>
                <th style={{ width: 70 }}>Method</th>
                <th>Host</th>
                <th>Path</th>
                <th className="right" style={{ width: 70 }}>Status</th>
                <th className="right" style={{ width: 70 }}>Size</th>
                <th className="right" style={{ width: 60 }}>ms</th>
              </tr></thead>
              <tbody>
                {exchanges.slice(0, 24).map((t) => (
                  <tr key={t.id}>
                    <td><Method m={t.method} /></td>
                    <td className="dim">{t.host}</td>
                    <td>{t.path}</td>
                    <td className="right"><Status s={t.status} /></td>
                    <td className="right dim">{((t.length || 0) / 1024).toFixed(1)}k</td>
                    <td className="right dim">{t.timing}</td>
                  </tr>
                ))}
                {exchanges.length === 0 ? (
                  <tr><td colSpan={6} style={{ padding: 20, textAlign: 'center', color: 'var(--text-faint)' }}>No exchanges at this node.</td></tr>
                ) : null}
              </tbody>
            </table>
          </div>
        </Panel>
        {issues.length > 0 ? (
          <Panel title="Issues at this node">
            <div className="pf-list" style={{ margin: -12 }}>
              {issues.map((i) => (
                <div key={i.id} className="pf-list-item" style={{ padding: '10px 14px' }}>
                  <div className="pf-list-item-mark" />
                  <SevDot level={(i.severity[0].toUpperCase() + i.severity.slice(1))} />
                  <div className="pf-list-item-main">
                    <div className="pf-list-item-title">{i.title}</div>
                    <div className="pf-list-item-meta">
                      <span>{i.confidence}</span>
                      <span className="sep">·</span>
                      <span>{i.status}</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </Panel>
        ) : null}
      </div>
    </div>
  );
}

function ScopeTab({ scopeAllowlist }: { scopeAllowlist: string[] }) {
  return (
    <div className="ws-body">
      <Panel title="Scope allowlist" flush>
        <div className="pf-table-wrap">
          <table className="pf-table">
            <thead><tr>
              <th>Pattern</th>
              <th style={{ width: 100 }}>Type</th>
              <th style={{ width: 60 }}></th>
            </tr></thead>
            <tbody>
              {scopeAllowlist.length === 0 ? (
                <tr><td colSpan={3} style={{ padding: 20, textAlign: 'center', color: 'var(--text-faint)' }}>
                  No scope configured. Open <strong>Settings → Project Safety</strong>.
                </td></tr>
              ) : scopeAllowlist.map((p) => (
                <tr key={p}>
                  <td className="mono">{p}</td>
                  <td className="dim">{p.startsWith('*.') ? 'wildcard' : 'host'}</td>
                  <td><IconButton icon={ShieldCheck} title="Open in settings" comingSoon /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>
    </div>
  );
}

function IssuesTab({ issues }: { issues: Issue[] }) {
  return (
    <div className="ws-body">
      <Panel title="Issues" flush>
        <div className="pf-table-wrap">
          <table className="pf-table">
            <thead><tr>
              <th style={{ width: 28 }}></th>
              <th>Title</th>
              <th style={{ width: 220 }}>Host</th>
              <th style={{ width: 80 }}>Status</th>
              <th style={{ width: 80 }}>Confidence</th>
            </tr></thead>
            <tbody>
              {issues.length === 0 ? (
                <tr><td colSpan={5} style={{ padding: 20, textAlign: 'center', color: 'var(--text-faint)' }}>No issues yet.</td></tr>
              ) : issues.map((i) => (
                <tr key={i.id}>
                  <td><SevDot level={(i.severity[0].toUpperCase() + i.severity.slice(1))} /></td>
                  <td>{i.title}</td>
                  <td className="dim">{i.host}{i.path}</td>
                  <td>{i.status === 'open' ? <Badge tone="accent">OPEN</Badge> : i.status === 'fixed' ? <Badge tone="ok">FIXED</Badge> : <Badge>{i.status.toUpperCase()}</Badge>}</td>
                  <td className="dim">{i.confidence}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>
    </div>
  );
}

function TechTab({ exchanges }: { exchanges: HttpExchange[] }) {
  const mimes = useMemo(() => {
    const m = new Map<string, number>();
    for (const ex of exchanges) {
      if (!ex.mime) continue;
      m.set(ex.mime, (m.get(ex.mime) ?? 0) + 1);
    }
    return Array.from(m.entries()).sort((a, b) => b[1] - a[1]);
  }, [exchanges]);
  return (
    <div className="ws-body">
      <Panel title="Observed content types">
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
          {mimes.length === 0 ? (
            <span style={{ color: 'var(--text-faint)', fontSize: 12.5 }}>No traffic captured.</span>
          ) : mimes.map(([mime, count]) => (
            <span key={mime} style={{
              padding: '4px 10px', borderRadius: 4, background: 'var(--surface-2)',
              border: '1px solid var(--border)', fontSize: 12, fontFamily: 'var(--font-mono)',
              color: 'var(--text-dim)',
            }}>
              {mime} <span style={{ opacity: 0.7 }}>· {count}</span>
            </span>
          ))}
        </div>
      </Panel>
    </div>
  );
}

function AuthzPlaceholder() {
  return (
    <div className="ws-body">
      <Panel title="Access-control matrix">
        <div style={{ padding: '20px 0', color: 'var(--text-dim)', fontSize: 12.5, textAlign: 'center' }}>
          Build a session profile in <strong>Settings → Team / SSO</strong> and replay through Repeater to populate.
        </div>
      </Panel>
    </div>
  );
}
