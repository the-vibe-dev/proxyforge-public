import { useState, type ReactNode, type CSSProperties, type ButtonHTMLAttributes } from 'react';
import { LucideIcon } from 'lucide-react';

export type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';

type ButtonVariant = 'default' | 'primary' | 'accent' | 'ghost';
type ButtonSize = 'default' | 'sm';

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  icon?: LucideIcon;
  iconRight?: LucideIcon;
  children?: ReactNode;
  comingSoon?: boolean;
}

export function Button({
  variant = 'default', size, icon: Icon, iconRight: IconRight, children, className,
  comingSoon, disabled, title, onClick, ...rest
}: ButtonProps) {
  const isDead = !!comingSoon;
  const classes = [
    'btn', variant === 'default' ? '' : variant,
    size === 'sm' ? 'sm' : '',
    !children && Icon ? 'icon' : '',
    isDead ? 'is-coming-soon' : '',
    className,
  ].filter(Boolean).join(' ');
  const effectiveTitle = isDead
    ? (title ? `${title} (coming soon — not yet wired in this build)` : 'Coming soon — not yet wired in this build')
    : title;
  return (
    <button
      className={classes}
      disabled={disabled || isDead}
      title={effectiveTitle}
      aria-disabled={disabled || isDead || undefined}
      onClick={isDead ? undefined : onClick}
      {...rest}
    >
      {Icon ? <Icon size={14} /> : null}
      {children}
      {IconRight ? <IconRight size={14} /> : null}
    </button>
  );
}

interface IconButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  icon: LucideIcon;
  active?: boolean;
  comingSoon?: boolean;
}

export function IconButton({ icon: Icon, active, className, comingSoon, disabled, title, onClick, ...rest }: IconButtonProps) {
  const isDead = !!comingSoon;
  const effectiveTitle = isDead
    ? (title ? `${title} (coming soon — not yet wired in this build)` : 'Coming soon — not yet wired in this build')
    : title;
  return (
    <button
      className={['iconbtn', active ? 'is-active' : '', isDead ? 'is-coming-soon' : '', className].filter(Boolean).join(' ')}
      disabled={disabled || isDead}
      title={effectiveTitle}
      aria-disabled={disabled || isDead || undefined}
      onClick={isDead ? undefined : onClick}
      {...rest}
    >
      <Icon size={15} />
    </button>
  );
}

type BadgeTone = 'default' | 'solid' | 'crit' | 'high' | 'med' | 'low' | 'accent' | 'dim' | 'ok';
export function Badge({ tone = 'default', children }: { tone?: BadgeTone; children: ReactNode }) {
  const toneCls = tone === 'default' ? '' : tone === 'low' ? 'dim' : tone;
  return <span className={['pf-badge', toneCls].filter(Boolean).join(' ')}>{children}</span>;
}

export type MaturityLevel = 'stable' | 'alpha' | 'planned';

const maturityCopy: Record<MaturityLevel, { label: string; tone: BadgeTone; tip: string }> = {
  stable: {
    label: 'STABLE',
    tone: 'ok',
    tip: 'Fully implemented. Backed by Production Ready evidence in the feature matrix — passing CI, packaging, docs, and Linux/Windows verification. Safe to use end-to-end.',
  },
  alpha: {
    label: 'ALPHA',
    tone: 'accent',
    tip: 'Engine works (Parity Candidate). Core flow is wired and tested, but UI polish, edge-case coverage, and cross-platform hardening are still in progress. Expect rough edges.',
  },
  planned: {
    label: 'COMING SOON',
    tone: 'dim',
    tip: 'Surface visible but not yet wired in this build. Controls may be disabled or backed by skeleton placeholders. Tracked in the roadmap.',
  },
};

export function MaturityBadge({ level, hint }: { level: MaturityLevel; hint?: string }) {
  const m = maturityCopy[level];
  const title = hint ? `${m.tip}\n\n${hint}` : m.tip;
  return (
    <span className={`pf-badge ${m.tone} pf-maturity pf-maturity-${level}`} title={title} aria-label={`Maturity: ${m.label}`}>
      <span className={`pf-maturity-dot pf-maturity-dot-${level}`} aria-hidden="true" />
      {m.label}
    </span>
  );
}

interface SectionSkeletonProps {
  title: string;
  description?: ReactNode;
  rows?: number;
  showTable?: boolean;
  actions?: ReactNode;
}

export function SectionSkeleton({ title, description, rows = 4, showTable = true, actions }: SectionSkeletonProps) {
  return (
    <div
      style={{
        display: 'flex', flexDirection: 'column', flex: 1, minHeight: 0,
        padding: '24px 28px', gap: 16, color: 'var(--text-dim)',
      }}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', gap: 12, flexWrap: 'wrap' }}>
        <div>
          <div style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
            <MaturityBadge level="planned" />
            <span style={{ fontSize: 13, fontWeight: 500, color: 'var(--text-base)' }}>{title}</span>
          </div>
          {description ? (
            <div style={{ fontSize: 12.5, color: 'var(--text-dim)', maxWidth: 640, marginTop: 6, lineHeight: 1.5 }}>
              {description}
            </div>
          ) : null}
        </div>
        {actions ? <div style={{ display: 'flex', gap: 8 }}>{actions}</div> : null}
      </div>
      {showTable ? (
        <div
          style={{
            border: '1px dashed var(--border-strong)', borderRadius: 6,
            background: 'var(--surface)', padding: '14px 16px',
            display: 'flex', flexDirection: 'column', gap: 10,
          }}
          aria-label="Section skeleton"
        >
          {Array.from({ length: rows }).map((_, i) => (
            <div key={i} style={{ display: 'grid', gridTemplateColumns: '60px 110px 1fr 70px 70px', gap: 12, alignItems: 'center' }}>
              <SkBar w="100%" />
              <SkBar w="90%" />
              <SkBar w={`${60 + ((i * 17) % 30)}%`} />
              <SkBar w="60%" />
              <SkBar w="40%" />
            </div>
          ))}
          <div style={{ fontSize: 11.5, color: 'var(--text-faint)', marginTop: 4, fontStyle: 'italic' }}>
            This view is not yet wired in pfv2. The underlying engine may already exist — check the feature matrix for status.
          </div>
        </div>
      ) : null}
    </div>
  );
}

function SkBar({ w }: { w: string }) {
  return (
    <span
      style={{
        display: 'block', height: 10, width: w,
        borderRadius: 3,
        background: 'linear-gradient(90deg, var(--surface-2) 0%, var(--surface-3) 50%, var(--surface-2) 100%)',
        backgroundSize: '200% 100%',
        opacity: 0.6,
      }}
    />
  );
}

export function SevDot({ level }: { level: Severity | string }) {
  const k = (level || 'Low').toLowerCase();
  const cls =
    k === 'critical' ? 'crit'
    : k === 'high' ? 'high'
    : k === 'medium' ? 'med'
    : k === 'low' ? 'low'
    : 'info';
  return <span className={`pf-sev-dot ${cls}`} title={level} />;
}

export function Method({ m }: { m: string }) {
  return <span className={`method ${m}`}>{m}</span>;
}

export function Status({ s }: { s: number }) {
  const c = s >= 500 ? 's5' : s >= 400 ? 's4' : s >= 300 ? 's3' : s >= 200 ? 's2' : '';
  return <span className={`pf-status ${c}`}>{s || '—'}</span>;
}

interface PanelProps {
  title?: ReactNode;
  eyebrow?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  flush?: boolean;
  tight?: boolean;
  bodyStyle?: CSSProperties;
  style?: CSSProperties;
  className?: string;
}

export function Panel({ title, eyebrow, actions, children, flush, tight, bodyStyle, style, className }: PanelProps) {
  return (
    <div className={['pf-panel', className].filter(Boolean).join(' ')} style={style}>
      {(title || actions) ? (
        <div className="pf-panel-head">
          <div className="pf-panel-title">
            {eyebrow ? <span className="pf-panel-eyebrow">{eyebrow}</span> : null}
            {title}
          </div>
          {actions ? <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>{actions}</div> : null}
        </div>
      ) : null}
      <div className={['pf-panel-body', flush ? 'flush' : '', tight ? 'tight' : ''].filter(Boolean).join(' ')} style={bodyStyle}>
        {children}
      </div>
    </div>
  );
}

interface StatProps {
  label: string;
  value: ReactNode;
  delta?: ReactNode;
  deltaDir?: 'up' | 'down';
  spark?: number[];
  accent?: boolean;
}

export function Stat({ label, value, delta, deltaDir, spark, accent }: StatProps) {
  return (
    <div className="pf-stat">
      <div className="pf-stat-label">{label}</div>
      <div className="pf-stat-value" style={accent ? { color: 'var(--accent)' } : undefined}>{value}</div>
      {delta ? (
        <div className={['pf-stat-delta', deltaDir === 'up' ? 'up' : ''].filter(Boolean).join(' ')}>
          {deltaDir === 'up' ? '↑' : '·'} {delta}
        </div>
      ) : null}
      {spark && spark.length ? <Sparkline values={spark} hot={accent} /> : null}
    </div>
  );
}

export function Sparkline({ values, hot }: { values: number[]; hot?: boolean }) {
  const max = Math.max(...values, 1);
  return (
    <div className="pf-spark-bars">
      {values.map((v, i) => (
        <div
          key={i}
          className={['pf-spark-bar', hot && v === max ? 'hot' : ''].filter(Boolean).join(' ')}
          style={{ height: `${Math.max(2, (v / max) * 22)}px` }}
        />
      ))}
    </div>
  );
}

interface TabsProps<T extends string> {
  value: T;
  onChange: (value: T) => void;
  items: Array<{ value: T; label: ReactNode; count?: number | string; icon?: LucideIcon }>;
}

export function Tabs<T extends string>({ value, onChange, items }: TabsProps<T>) {
  return (
    <div className="ws-tabs" role="tablist">
      {items.map((t) => (
        <button
          key={t.value}
          type="button"
          role="tab"
          aria-selected={t.value === value}
          className={['ws-tab', t.value === value ? 'is-active' : ''].filter(Boolean).join(' ')}
          onClick={() => onChange(t.value)}
        >
          {t.icon ? <t.icon size={13} /> : null}
          {t.label}
          {t.count !== undefined ? <span className="ws-tab-count">{t.count}</span> : null}
        </button>
      ))}
    </div>
  );
}

export function KV({ data, compact }: { data: Array<[string, ReactNode]>; compact?: boolean }) {
  return (
    <dl
      style={{
        display: 'grid',
        gridTemplateColumns: '130px 1fr',
        gap: compact ? '2px 12px' : '4px 14px',
        fontSize: compact ? 11.5 : 12,
        margin: 0,
      }}
    >
      {data.map(([k, v]) => (
        <div key={k} style={{ display: 'contents' }}>
          <dt style={{ color: 'var(--text-dim)', fontWeight: 400 }}>{k}</dt>
          <dd style={{ margin: 0, color: 'var(--text-base)', fontFamily: 'var(--font-mono)', fontSize: 11.5 }}>{v}</dd>
        </div>
      ))}
    </dl>
  );
}

interface BannerProps {
  tone?: 'warn' | 'crit';
  icon?: LucideIcon;
  children: ReactNode;
  action?: ReactNode;
}

export function Banner({ tone = 'warn', icon: Icon, children, action }: BannerProps) {
  return (
    <div className={['pf-banner', tone === 'crit' ? 'crit' : ''].filter(Boolean).join(' ')}>
      {Icon ? <Icon size={16} className="pf-banner-icon" /> : null}
      <div style={{ flex: 1 }}>{children}</div>
      {action}
    </div>
  );
}

interface EmptyProps {
  icon?: LucideIcon;
  title?: string;
  sub?: string;
  action?: ReactNode;
}

export function Empty({ icon: Icon, title, sub, action }: EmptyProps) {
  return (
    <div
      style={{
        display: 'grid',
        placeItems: 'center',
        padding: '60px 24px',
        textAlign: 'center',
        color: 'var(--text-faint)',
      }}
    >
      {Icon ? (
        <div style={{ color: 'var(--text-mute)', marginBottom: 12 }}>
          <Icon size={28} strokeWidth={1.2} />
        </div>
      ) : null}
      {title ? <div style={{ fontSize: 14, color: 'var(--text-base)', fontWeight: 500, marginBottom: 4 }}>{title}</div> : null}
      {sub ? <div style={{ fontSize: 12.5, color: 'var(--text-dim)', maxWidth: 360 }}>{sub}</div> : null}
      {action ? <div style={{ marginTop: 14 }}>{action}</div> : null}
    </div>
  );
}

export function Toggle({ on, onChange, label }: { on: boolean; onChange?: (next: boolean) => void; label?: ReactNode }) {
  return (
    <span
      role="switch"
      aria-checked={on}
      onClick={() => onChange?.(!on)}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 6,
        cursor: 'pointer',
        fontSize: 12,
        color: 'var(--text-dim)',
        userSelect: 'none',
      }}
    >
      <span
        style={{
          width: 26,
          height: 14,
          background: on ? 'var(--accent)' : 'var(--border-strong)',
          borderRadius: 100,
          position: 'relative',
          transition: 'background 0.12s',
        }}
      >
        <span
          style={{
            position: 'absolute',
            top: 2,
            left: 2,
            width: 10,
            height: 10,
            background: 'var(--bg-base)',
            borderRadius: '50%',
            transform: on ? 'translateX(12px)' : 'translateX(0)',
            transition: 'transform 0.12s',
          }}
        />
      </span>
      {label}
    </span>
  );
}

export { useState };
