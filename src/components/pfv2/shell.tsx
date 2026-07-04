import { type ReactNode } from 'react';
import {
  LayoutGrid, Target as TargetIcon, ArrowLeftRight, FileText, Network,
  RotateCcw, Crosshair, ScanLine, Zap, Folder, ChartLine, Code2, GitCompare,
  Puzzle, Cog, FileBarChart, Bot, Settings as SettingsIcon, Search, Bell, Sun, Moon, Bug,
} from 'lucide-react';
import type { ToolId } from '../../types';
import { IconButton, MaturityBadge, type MaturityLevel } from './ui';

interface NavItem {
  id: ToolId;
  label: string;
  icon: typeof LayoutGrid;
  count?: number | string;
  alert?: boolean;
}

interface NavSection {
  title: string | null;
  items: NavItem[];
}

export function buildNavSections(counts: Partial<Record<ToolId, number | string>>, alerts: Partial<Record<ToolId, boolean>>): NavSection[] {
  const item = (id: ToolId, label: string, icon: typeof LayoutGrid): NavItem => ({
    id,
    label,
    icon,
    count: counts[id],
    alert: alerts[id],
  });
  return [
    { title: null, items: [item('dashboard', 'Dashboard', LayoutGrid)] },
    {
      title: 'Capture',
      items: [
        item('target', 'Target Map', TargetIcon),
        item('proxy', 'Proxy', ArrowLeftRight),
        item('logger', 'Logger', FileText),
        item('collaborator', 'Callbacks', Network),
      ],
    },
    {
      title: 'Testing',
      items: [
        item('repeater', 'Repeater', RotateCcw),
        item('intruder', 'Intruder', Crosshair),
        item('scanner', 'Scanner', ScanLine),
        item('exploit', 'Exploit Lab', Zap),
      ],
    },
    {
      title: 'Analysis',
      items: [
        item('organizer', 'Organizer', Folder),
        item('sequencer', 'Sequencer', ChartLine),
        item('decoder', 'Decoder', Code2),
        item('comparer', 'Comparer', GitCompare),
      ],
    },
    {
      title: 'Surface',
      items: [
        item('automations', 'Automations', Cog),
        item('extensions', 'Extensions', Puzzle),
        item('ai', 'AI / Agent', Bot),
        item('reports', 'Reports', FileBarChart),
      ],
    },
    {
      title: 'Workspace',
      items: [
        item('search', 'Search', Search),
        item('viewer', 'Viewer', FileText),
        item('settings', 'Settings', SettingsIcon),
      ],
    },
  ];
}

interface SidebarProps {
  projectName: string;
  workspaceLabel: string;
  activeTool: ToolId;
  onSelect: (tool: ToolId) => void;
  listenerHost: string;
  listenerPort: number;
  listenerRunning: boolean;
  counts: Partial<Record<ToolId, number | string>>;
  alerts: Partial<Record<ToolId, boolean>>;
}

function BrandMark({ size = 22 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path
        d="M12 1.7l8.4 4.85v8.9L12 20.3 3.6 15.45v-8.9L12 1.7z"
        stroke="currentColor" strokeWidth="1.4" strokeLinejoin="round" fill="none"
      />
      <path
        d="M12 6.6c.5 1.7-.9 2.6-.9 4.1 0 .8.5 1.5 1.2 1.5.6 0 1-.4 1-1.1.7.8 1.2 1.8 1.2 3 0 1.9-1.5 3.4-3.5 3.4S7.5 16 7.5 14.1c0-2.4 1.9-3.3 2.6-5.2.3-.7.5-1.5 1.9-2.3z"
        fill="currentColor"
      />
    </svg>
  );
}

export function Sidebar({
  projectName,
  workspaceLabel,
  activeTool,
  onSelect,
  listenerHost,
  listenerPort,
  listenerRunning,
  counts,
  alerts,
}: SidebarProps) {
  const sections = buildNavSections(counts, alerts);
  return (
    <aside className="rail">
      <div className="rail-brand">
        <span className="rail-brand-mark"><BrandMark /></span>
        <span className="rail-brand-name">
          Proxy<span className="accent">Forge</span>
        </span>
      </div>
      <div className="rail-project">
        <div className="rail-project-label">Project</div>
        <div className="rail-project-name">
          <span style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
            {projectName || 'No project loaded'}
          </span>
        </div>
        {workspaceLabel ? <div className="rail-project-meta">{workspaceLabel}</div> : null}
      </div>
      <nav className="rail-nav">
        {sections.map((sec, i) => (
          <div key={sec.title || `s${i}`}>
            {sec.title ? <div className="rail-section">{sec.title}</div> : null}
            {sec.items.map((it) => {
              const Icon = it.icon;
              return (
                <button
                  key={it.id}
                  type="button"
                  className={[
                    'rail-item',
                    activeTool === it.id ? 'is-active' : '',
                    it.alert ? 'has-alert' : '',
                  ].filter(Boolean).join(' ')}
                  onClick={() => onSelect(it.id)}
                >
                  <span className="rail-item-icon"><Icon size={15} /></span>
                  <span className="rail-item-label">{it.label}</span>
                  {it.count !== undefined ? <span className="rail-item-badge">{it.count}</span> : null}
                </button>
              );
            })}
          </div>
        ))}
      </nav>
      <div className="rail-foot">
        <span className={['rail-foot-dot', listenerRunning ? '' : 'is-down'].filter(Boolean).join(' ')} />
        <span className="rail-foot-meta">listener · {listenerHost}:{listenerPort}</span>
      </div>
    </aside>
  );
}

interface TopBarProps {
  crumbs: string[];
  theme: 'light' | 'dark';
  onToggleTheme: () => void;
  onOpenSettings?: () => void;
  searchQuery: string;
  onSearchChange: (value: string) => void;
}

export function TopBar({ crumbs, theme, onToggleTheme, onOpenSettings, searchQuery, onSearchChange }: TopBarProps) {
  return (
    <div className="pf-topbar">
      <div className="topbar-crumbs">
        {crumbs.map((c, i) => (
          <span key={`${i}-${c}`} style={{ display: 'inline-flex', gap: 6, alignItems: 'center' }}>
            {i > 0 ? <span className="sep">/</span> : null}
            <span className={i === crumbs.length - 1 ? 'here' : ''}>{c}</span>
          </span>
        ))}
      </div>
      <div className="topbar-spacer" />
      <div className="topbar-search">
        <Search size={13} />
        <input
          type="text"
          value={searchQuery}
          onChange={(event) => onSearchChange(event.target.value)}
          placeholder="Search hosts, requests, findings…"
        />
        <span className="topbar-search-kbd">⌘K</span>
      </div>
      <div className="topbar-spacer" />
      <div className="topbar-actions">
        <IconButton icon={Bug} title="Bug report" />
        <IconButton icon={Bell} title="Notifications" />
        <IconButton
          icon={theme === 'dark' ? Sun : Moon}
          title={theme === 'dark' ? 'Switch to light' : 'Switch to dark'}
          onClick={onToggleTheme}
        />
        <IconButton icon={SettingsIcon} title="Settings" onClick={onOpenSettings} />
      </div>
    </div>
  );
}

interface WorkspaceHeaderProps {
  eyebrow?: ReactNode;
  title: ReactNode;
  subtitle?: ReactNode;
  actions?: ReactNode;
  maturity?: MaturityLevel;
  maturityHint?: string;
}

export function WorkspaceHeader({ eyebrow, title, subtitle, actions, maturity, maturityHint }: WorkspaceHeaderProps) {
  return (
    <div className="ws-header">
      <div className="ws-title-block">
        {eyebrow ? <div className="ws-eyebrow">{eyebrow}</div> : null}
        <h1 className="ws-title" style={{ display: 'inline-flex', alignItems: 'center', gap: 10 }}>
          <span>{title}</span>
          {maturity ? <MaturityBadge level={maturity} hint={maturityHint} /> : null}
        </h1>
        {subtitle ? <div className="ws-subtitle">{subtitle}</div> : null}
      </div>
      {actions ? <div className="ws-actions">{actions}</div> : null}
    </div>
  );
}

interface StatusBarProps {
  items: Array<{ icon?: typeof Bell; label: ReactNode }>;
  version?: string;
}

export function StatusBar({ items, version }: StatusBarProps) {
  return (
    <div className="pf-statusbar">
      {items.map((it, i) => (
        <div className="pf-statusbar-item" key={i}>
          {it.icon ? <it.icon size={12} /> : null}
          {it.label}
        </div>
      ))}
      <div className="pf-statusbar-spacer" />
      {version ? <div className="pf-statusbar-item">{version}</div> : null}
    </div>
  );
}
