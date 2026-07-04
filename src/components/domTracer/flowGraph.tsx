import type { CSSProperties } from 'react';

// ---------------------------------------------------------------------------
// FlowGraph
// SVG-free, pure-div flow visualization showing source → transformation → sink chains.
// ---------------------------------------------------------------------------

export interface TraceRow {
  sourceId: string;
  sinkId: string;
  transformation: string;
  sourceType: string;
  sinkName: string;
  sinkSeverity: string;
}

interface FlowGraphProps {
  traces: TraceRow[];
  highlighted?: string;
}

function sinkBorderColor(severity: string): string {
  const s = severity.toLowerCase();
  if (s === 'critical' || s === 'high') return '#ef4444';   // red
  if (s === 'medium') return '#eab308';                      // yellow
  if (s === 'low') return '#60a5fa';                         // blue
  return '#6b7280';                                          // gray for info/unknown
}

function sinkBg(severity: string): string {
  const s = severity.toLowerCase();
  if (s === 'critical' || s === 'high') return 'rgba(239,68,68,0.10)';
  if (s === 'medium') return 'rgba(234,179,8,0.10)';
  if (s === 'low') return 'rgba(96,165,250,0.10)';
  return 'rgba(107,114,128,0.10)';
}

const SOURCE_BOX: CSSProperties = {
  background: 'rgba(59,130,246,0.12)',
  border: '1px solid rgba(59,130,246,0.45)',
  borderRadius: 5,
  padding: '5px 10px',
  fontFamily: 'var(--font-mono, monospace)',
  fontSize: 11,
  color: '#93c5fd',
  whiteSpace: 'nowrap',
  maxWidth: 160,
  overflow: 'hidden',
  textOverflow: 'ellipsis',
};

const ARROW: CSSProperties = {
  display: 'flex',
  alignItems: 'center',
  color: 'var(--text-faint, #4b5563)',
  fontSize: 14,
  userSelect: 'none',
  padding: '0 2px',
};

const XFORM_LABEL: CSSProperties = {
  display: 'flex',
  alignItems: 'center',
  gap: 4,
  padding: '4px 8px',
  background: 'rgba(99,102,241,0.10)',
  border: '1px solid rgba(99,102,241,0.25)',
  borderRadius: 4,
  fontSize: 10.5,
  fontFamily: 'var(--font-mono, monospace)',
  color: '#a5b4fc',
  whiteSpace: 'nowrap',
  maxWidth: 130,
  overflow: 'hidden',
  textOverflow: 'ellipsis',
};

const ROW_WRAP: CSSProperties = {
  display: 'flex',
  alignItems: 'center',
  gap: 6,
  padding: '8px 14px',
  borderRadius: 5,
  transition: 'background 0.1s',
};

export function FlowGraph({ traces, highlighted }: FlowGraphProps) {
  if (traces.length === 0) {
    return (
      <div
        style={{
          padding: '48px 24px',
          textAlign: 'center',
          color: 'var(--text-faint, #4b5563)',
          fontSize: 13,
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          gap: 8,
        }}
      >
        {/* Simple dashed box placeholder */}
        <div
          style={{
            width: 300,
            border: '1px dashed rgba(255,255,255,0.1)',
            borderRadius: 6,
            padding: '20px 0',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: 10,
            opacity: 0.5,
          }}
        >
          <span style={{ fontSize: 11, fontFamily: 'var(--font-mono, monospace)', color: '#60a5fa' }}>source</span>
          <span style={{ color: 'var(--text-faint, #4b5563)' }}>→</span>
          <span style={{ fontSize: 11, fontFamily: 'var(--font-mono, monospace)', color: '#a5b4fc' }}>transform</span>
          <span style={{ color: 'var(--text-faint, #4b5563)' }}>→</span>
          <span style={{ fontSize: 11, fontFamily: 'var(--font-mono, monospace)', color: '#f87171' }}>sink</span>
        </div>
        <span style={{ fontSize: 12, fontStyle: 'italic', marginTop: 4 }}>
          No canary flow detected yet.
        </span>
        <span style={{ fontSize: 11, color: 'var(--text-faint, #374151)', maxWidth: 320, lineHeight: 1.5 }}>
          Inject a canary nonce and interact with the target page — matched flows will appear here.
        </span>
      </div>
    );
  }

  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        gap: 4,
        overflowY: 'auto',
        padding: '6px 0',
      }}
      aria-label="Canary flow graph"
    >
      {/* Column headers */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: '160px 28px 140px 28px 160px 1fr',
          alignItems: 'center',
          padding: '2px 14px 6px',
          borderBottom: '1px solid var(--border, rgba(255,255,255,0.06))',
          marginBottom: 2,
        }}
      >
        {['Source', '', 'Transformation', '', 'Sink', ''].map((h, i) => (
          <span
            key={i}
            style={{
              fontSize: 10,
              fontWeight: 600,
              letterSpacing: '0.06em',
              textTransform: 'uppercase',
              color: h ? 'var(--text-dim, #6b7280)' : 'transparent',
            }}
          >
            {h || '.'}
          </span>
        ))}
      </div>

      {traces.map((trace) => {
        const isHighlighted =
          highlighted === trace.sourceId || highlighted === trace.sinkId;

        const sinkBox: CSSProperties = {
          background: sinkBg(trace.sinkSeverity),
          border: `1px solid ${sinkBorderColor(trace.sinkSeverity)}`,
          borderRadius: 5,
          padding: '5px 10px',
          fontFamily: 'var(--font-mono, monospace)',
          fontSize: 11,
          color: sinkBorderColor(trace.sinkSeverity),
          whiteSpace: 'nowrap',
          maxWidth: 160,
          overflow: 'hidden',
          textOverflow: 'ellipsis',
        };

        return (
          <div
            key={`${trace.sourceId}:${trace.sinkId}`}
            style={{
              ...ROW_WRAP,
              background: isHighlighted ? 'rgba(99,102,241,0.08)' : undefined,
              outline: isHighlighted ? '1px solid rgba(99,102,241,0.25)' : 'none',
            }}
            onMouseEnter={(e) => {
              if (!isHighlighted) (e.currentTarget as HTMLDivElement).style.background = 'rgba(255,255,255,0.03)';
            }}
            onMouseLeave={(e) => {
              if (!isHighlighted) (e.currentTarget as HTMLDivElement).style.background = '';
            }}
          >
            {/* Source box */}
            <div style={SOURCE_BOX} title={`Source: ${trace.sourceType}\nID: ${trace.sourceId}`}>
              {trace.sourceType}
            </div>

            {/* Arrow */}
            <div style={ARROW}>→</div>

            {/* Transformation */}
            <div style={XFORM_LABEL} title={`Transformation: ${trace.transformation}`}>
              <span style={{ opacity: 0.7, fontSize: 10 }}>T:</span>
              {trace.transformation || 'raw'}
            </div>

            {/* Arrow */}
            <div style={ARROW}>→</div>

            {/* Sink box */}
            <div style={sinkBox} title={`Sink: ${trace.sinkName}\nSeverity: ${trace.sinkSeverity}\nID: ${trace.sinkId}`}>
              {trace.sinkName}
            </div>

            {/* Severity label */}
            <div
              style={{
                marginLeft: 8,
                fontSize: 10.5,
                fontWeight: 700,
                letterSpacing: '0.04em',
                textTransform: 'uppercase',
                color: sinkBorderColor(trace.sinkSeverity),
                opacity: 0.85,
              }}
            >
              {trace.sinkSeverity}
            </div>
          </div>
        );
      })}
    </div>
  );
}
