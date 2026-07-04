import type { CSSProperties } from 'react';

// ---------------------------------------------------------------------------
// SinksTable
// Tabular view of DOM tracer sink events with severity, canary match, and actions.
// ---------------------------------------------------------------------------

export type SinkSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface SinkRow {
  id: string;
  sinkName: string;
  value: string;
  canaryMatched: boolean;
  severity: SinkSeverity;
  timestamp: string;
}

interface SinksTableProps {
  sinks: SinkRow[];
  onInspect?: (id: string) => void;
}

const SEV_STYLES: Record<SinkSeverity, CSSProperties> = {
  critical: { background: 'rgba(220,38,38,0.18)',   color: '#f87171', border: '1px solid rgba(220,38,38,0.4)' },
  high:     { background: 'rgba(234,88,12,0.18)',   color: '#fb923c', border: '1px solid rgba(234,88,12,0.4)' },
  medium:   { background: 'rgba(234,179,8,0.15)',   color: '#fde047', border: '1px solid rgba(234,179,8,0.4)' },
  low:      { background: 'rgba(96,165,250,0.15)',  color: '#93c5fd', border: '1px solid rgba(96,165,250,0.4)' },
  info:     { background: 'rgba(107,114,128,0.15)', color: '#9ca3af', border: '1px solid rgba(107,114,128,0.4)' },
};

const SEV_ORDER: Record<SinkSeverity, number> = {
  critical: 0, high: 1, medium: 2, low: 3, info: 4,
};

function SeverityBadge({ severity }: { severity: SinkSeverity }) {
  return (
    <span
      style={{
        ...SEV_STYLES[severity],
        display: 'inline-block',
        borderRadius: 3,
        padding: '1px 6px',
        fontSize: 10.5,
        fontWeight: 700,
        letterSpacing: '0.05em',
        textTransform: 'uppercase',
        whiteSpace: 'nowrap',
      }}
    >
      {severity}
    </span>
  );
}

function CanaryBadge({ matched }: { matched: boolean }) {
  if (matched) {
    return (
      <span
        style={{
          display: 'inline-block',
          borderRadius: 3,
          padding: '1px 6px',
          fontSize: 10.5,
          fontWeight: 700,
          letterSpacing: '0.05em',
          background: 'rgba(34,197,94,0.18)',
          color: '#86efac',
          border: '1px solid rgba(34,197,94,0.4)',
          whiteSpace: 'nowrap',
        }}
      >
        MATCHED
      </span>
    );
  }
  return <span style={{ color: 'var(--text-faint, #4b5563)', fontSize: 12 }}>—</span>;
}

const TH: CSSProperties = {
  padding: '6px 10px',
  textAlign: 'left',
  fontSize: 11,
  fontWeight: 600,
  letterSpacing: '0.06em',
  textTransform: 'uppercase',
  color: 'var(--text-dim, #6b7280)',
  borderBottom: '1px solid var(--border, rgba(255,255,255,0.08))',
  whiteSpace: 'nowrap',
  userSelect: 'none',
};

const TD: CSSProperties = {
  padding: '7px 10px',
  fontSize: 12,
  color: 'var(--text-base, #d1d5db)',
  borderBottom: '1px solid var(--border, rgba(255,255,255,0.05))',
  verticalAlign: 'middle',
};

export function SinksTable({ sinks, onInspect }: SinksTableProps) {
  if (sinks.length === 0) {
    return (
      <div
        style={{
          padding: '40px 24px',
          textAlign: 'center',
          color: 'var(--text-faint, #4b5563)',
          fontSize: 12.5,
          fontStyle: 'italic',
        }}
      >
        No sink events recorded yet.
      </div>
    );
  }

  const sorted = [...sinks].sort(
    (a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity],
  );

  return (
    <div style={{ overflowX: 'auto', overflowY: 'auto' }}>
      <table
        style={{
          width: '100%',
          borderCollapse: 'collapse',
          fontSize: 12,
          tableLayout: 'fixed',
        }}
        aria-label="Sink events"
      >
        <colgroup>
          <col style={{ width: 90 }} />
          <col style={{ width: 160 }} />
          <col />
          <col style={{ width: 90 }} />
          <col style={{ width: 130 }} />
          <col style={{ width: 80 }} />
        </colgroup>
        <thead>
          <tr>
            <th style={TH}>Severity</th>
            <th style={TH}>Sink</th>
            <th style={TH}>Value</th>
            <th style={TH}>Canary</th>
            <th style={TH}>Timestamp</th>
            <th style={TH}>Actions</th>
          </tr>
        </thead>
        <tbody>
          {sorted.map((sink) => (
            <tr
              key={sink.id}
              style={{ transition: 'background 0.08s' }}
              onMouseEnter={(e) => {
                (e.currentTarget as HTMLTableRowElement).style.background = 'rgba(255,255,255,0.03)';
              }}
              onMouseLeave={(e) => {
                (e.currentTarget as HTMLTableRowElement).style.background = '';
              }}
            >
              <td style={TD}>
                <SeverityBadge severity={sink.severity} />
              </td>
              <td style={{ ...TD, fontFamily: 'var(--font-mono, monospace)', fontSize: 11.5 }}>
                {sink.sinkName}
              </td>
              <td
                style={{
                  ...TD,
                  fontFamily: 'var(--font-mono, monospace)',
                  fontSize: 11,
                  maxWidth: 0,
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  whiteSpace: 'nowrap',
                }}
                title={sink.value}
              >
                {sink.value}
              </td>
              <td style={TD}>
                <CanaryBadge matched={sink.canaryMatched} />
              </td>
              <td
                style={{
                  ...TD,
                  fontFamily: 'var(--font-mono, monospace)',
                  fontSize: 11,
                  color: 'var(--text-dim, #6b7280)',
                  whiteSpace: 'nowrap',
                }}
              >
                {sink.timestamp.slice(11, 23)}
              </td>
              <td style={TD}>
                <button
                  type="button"
                  onClick={() => onInspect?.(sink.id)}
                  style={{
                    background: 'rgba(99,102,241,0.15)',
                    border: '1px solid rgba(99,102,241,0.35)',
                    color: '#a5b4fc',
                    borderRadius: 3,
                    padding: '2px 9px',
                    fontSize: 11,
                    fontWeight: 500,
                    cursor: 'pointer',
                    transition: 'background 0.1s',
                  }}
                  onMouseEnter={(e) => {
                    (e.currentTarget as HTMLButtonElement).style.background = 'rgba(99,102,241,0.28)';
                  }}
                  onMouseLeave={(e) => {
                    (e.currentTarget as HTMLButtonElement).style.background = 'rgba(99,102,241,0.15)';
                  }}
                >
                  Inspect
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
