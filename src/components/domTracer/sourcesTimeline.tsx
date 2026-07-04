import type { CSSProperties } from 'react';

// ---------------------------------------------------------------------------
// SourcesTimeline
// Vertical list of DOM tracer source events with type badges and click-to-select.
// ---------------------------------------------------------------------------

export interface SourceRow {
  id: string;
  type: string;
  value: string;
  timestamp: string;
}

interface SourcesTimelineProps {
  sources: SourceRow[];
  onSelect?: (id: string) => void;
  selectedId?: string;
}

type SourceCategory = 'hash' | 'url' | 'storage' | 'message' | 'other';

function categoriseSource(type: string): SourceCategory {
  const t = type.toLowerCase();
  if (t.includes('hash')) return 'hash';
  if (t.includes('search') || t.includes('href') || t.includes('referrer') || t.includes('url')) return 'url';
  if (t.includes('storage') || t.includes('cookie') || t.includes('name')) return 'storage';
  if (t.includes('message') || t.includes('opener') || t.includes('postmessage')) return 'message';
  return 'other';
}

const BADGE_STYLES: Record<SourceCategory, CSSProperties> = {
  hash:    { background: 'rgba(147,51,234,0.18)', color: '#c084fc', border: '1px solid rgba(147,51,234,0.35)' },
  url:     { background: 'rgba(59,130,246,0.18)',  color: '#93c5fd', border: '1px solid rgba(59,130,246,0.35)' },
  storage: { background: 'rgba(234,179,8,0.15)',   color: '#fde047', border: '1px solid rgba(234,179,8,0.35)' },
  message: { background: 'rgba(20,184,166,0.15)',  color: '#5eead4', border: '1px solid rgba(20,184,166,0.35)' },
  other:   { background: 'rgba(107,114,128,0.18)', color: '#9ca3af', border: '1px solid rgba(107,114,128,0.35)' },
};

function truncate(s: string, max: number): string {
  return s.length > max ? `${s.slice(0, max)}…` : s;
}

const ROW_BASE: CSSProperties = {
  display: 'grid',
  gridTemplateColumns: '120px 140px 1fr',
  alignItems: 'center',
  gap: 10,
  padding: '6px 12px',
  borderRadius: 4,
  cursor: 'pointer',
  borderLeft: '2px solid transparent',
  transition: 'background 0.1s',
};

export function SourcesTimeline({ sources, onSelect, selectedId }: SourcesTimelineProps) {
  if (sources.length === 0) {
    return (
      <div
        style={{
          padding: '40px 24px',
          textAlign: 'center',
          color: 'var(--text-faint)',
          fontSize: 12.5,
          fontStyle: 'italic',
        }}
      >
        No source events captured yet.
      </div>
    );
  }

  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        gap: 2,
        overflowY: 'auto',
        padding: '4px 0',
      }}
      role="listbox"
      aria-label="Source events"
    >
      {sources.map((src) => {
        const cat = categoriseSource(src.type);
        const isSelected = src.id === selectedId;

        const rowStyle: CSSProperties = {
          ...ROW_BASE,
          background: isSelected ? 'rgba(99,102,241,0.12)' : undefined,
          borderLeftColor: isSelected ? 'var(--accent, #6366f1)' : 'transparent',
        };

        return (
          <div
            key={src.id}
            role="option"
            aria-selected={isSelected}
            style={rowStyle}
            onClick={() => onSelect?.(src.id)}
            onMouseEnter={(e) => {
              if (!isSelected) (e.currentTarget as HTMLDivElement).style.background = 'rgba(255,255,255,0.04)';
            }}
            onMouseLeave={(e) => {
              if (!isSelected) (e.currentTarget as HTMLDivElement).style.background = '';
            }}
          >
            {/* Timestamp */}
            <span
              style={{
                fontFamily: 'var(--font-mono, monospace)',
                fontSize: 11,
                color: 'var(--text-dim, #6b7280)',
                whiteSpace: 'nowrap',
                overflow: 'hidden',
                textOverflow: 'ellipsis',
              }}
              title={src.timestamp}
            >
              {src.timestamp.slice(11, 23)}
            </span>

            {/* Source type badge */}
            <span
              style={{
                ...BADGE_STYLES[cat],
                display: 'inline-block',
                borderRadius: 3,
                padding: '1px 6px',
                fontSize: 10.5,
                fontFamily: 'var(--font-mono, monospace)',
                fontWeight: 600,
                letterSpacing: '0.02em',
                whiteSpace: 'nowrap',
                overflow: 'hidden',
                textOverflow: 'ellipsis',
                maxWidth: 136,
              }}
              title={src.type}
            >
              {src.type}
            </span>

            {/* Value (truncated) */}
            <span
              style={{
                fontFamily: 'var(--font-mono, monospace)',
                fontSize: 11.5,
                color: 'var(--text-base, #d1d5db)',
                overflow: 'hidden',
                textOverflow: 'ellipsis',
                whiteSpace: 'nowrap',
              }}
              title={src.value}
            >
              {truncate(src.value, 80)}
            </span>
          </div>
        );
      })}
    </div>
  );
}
