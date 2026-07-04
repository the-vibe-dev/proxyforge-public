import { useState, useEffect, type CSSProperties } from 'react';

// ---------------------------------------------------------------------------
// CanaryComposer
// Panel for configuring and injecting a canary nonce into a tracer session.
// ---------------------------------------------------------------------------

const SINK_TARGETS = [
  'innerHTML',
  'eval',
  'Function',
  'location.href',
  'fetch.url',
  'other',
] as const;

type SinkTarget = typeof SINK_TARGETS[number];

interface CanaryComposerProps {
  sessionId: string;
  onInject: (nonce: string, sinkTarget?: string) => void;
  activeNonce?: string;
}

function generateNonce(): string {
  return `pf-${Math.random().toString(36).slice(2, 10)}`;
}

const LABEL: CSSProperties = {
  display: 'block',
  fontSize: 11,
  fontWeight: 600,
  letterSpacing: '0.05em',
  textTransform: 'uppercase',
  color: 'var(--text-dim, #6b7280)',
  marginBottom: 4,
};

const INPUT: CSSProperties = {
  width: '100%',
  background: 'var(--surface, rgba(255,255,255,0.04))',
  border: '1px solid var(--border, rgba(255,255,255,0.1))',
  borderRadius: 4,
  padding: '5px 9px',
  fontSize: 12,
  fontFamily: 'var(--font-mono, monospace)',
  color: 'var(--text-base, #d1d5db)',
  outline: 'none',
  boxSizing: 'border-box',
};

const SELECT: CSSProperties = {
  ...INPUT,
  cursor: 'pointer',
  appearance: 'none',
};

export function CanaryComposer({ sessionId: _sessionId, onInject, activeNonce }: CanaryComposerProps) {
  const [nonce, setNonce] = useState<string>(() => generateNonce());
  const [sinkTarget, setSinkTarget] = useState<SinkTarget | ''>('');

  // Regenerate nonce when the active nonce is cleared externally
  useEffect(() => {
    if (!activeNonce) {
      setNonce(generateNonce());
    }
  }, [activeNonce]);

  const isActive = !!activeNonce;

  function handleInject() {
    onInject(nonce, sinkTarget || undefined);
  }

  function handleClear() {
    onInject('', undefined);
    setNonce(generateNonce());
    setSinkTarget('');
  }

  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        gap: 12,
        padding: '14px 16px',
        background: 'var(--surface, rgba(255,255,255,0.03))',
        border: '1px solid var(--border, rgba(255,255,255,0.08))',
        borderRadius: 6,
      }}
    >
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <span style={{ fontSize: 12.5, fontWeight: 600, color: 'var(--text-base, #d1d5db)' }}>
          Canary Composer
        </span>
        {isActive && (
          <span
            style={{
              fontSize: 10.5,
              fontWeight: 700,
              letterSpacing: '0.05em',
              textTransform: 'uppercase',
              background: 'rgba(34,197,94,0.15)',
              color: '#86efac',
              border: '1px solid rgba(34,197,94,0.35)',
              borderRadius: 3,
              padding: '1px 6px',
            }}
          >
            ACTIVE
          </span>
        )}
      </div>

      {/* Nonce */}
      <div>
        <label style={LABEL} htmlFor="canary-nonce">
          Canary Nonce
        </label>
        <div style={{ display: 'flex', gap: 6 }}>
          <input
            id="canary-nonce"
            type="text"
            readOnly
            value={isActive ? activeNonce : nonce}
            style={{ ...INPUT, flex: 1, color: 'var(--text-dim, #9ca3af)', cursor: 'default' }}
            aria-label="Canary nonce (auto-generated)"
          />
          {!isActive && (
            <button
              type="button"
              onClick={() => setNonce(generateNonce())}
              title="Regenerate nonce"
              style={{
                background: 'rgba(255,255,255,0.06)',
                border: '1px solid rgba(255,255,255,0.1)',
                borderRadius: 4,
                color: 'var(--text-dim, #9ca3af)',
                padding: '4px 9px',
                fontSize: 11,
                cursor: 'pointer',
                whiteSpace: 'nowrap',
              }}
            >
              Regen
            </button>
          )}
        </div>
      </div>

      {/* Sink target */}
      <div>
        <label style={LABEL} htmlFor="canary-sink-target">
          Sink Target (optional)
        </label>
        <div style={{ position: 'relative' }}>
          <select
            id="canary-sink-target"
            value={sinkTarget}
            onChange={(e) => setSinkTarget(e.target.value as SinkTarget | '')}
            disabled={isActive}
            style={{ ...SELECT, paddingRight: 28 }}
          >
            <option value="">— any sink —</option>
            {SINK_TARGETS.map((t) => (
              <option key={t} value={t}>{t}</option>
            ))}
          </select>
          <span
            style={{
              position: 'absolute',
              right: 9,
              top: '50%',
              transform: 'translateY(-50%)',
              pointerEvents: 'none',
              color: 'var(--text-faint, #4b5563)',
              fontSize: 10,
            }}
          >
            ▾
          </span>
        </div>
      </div>

      {/* Actions */}
      <div style={{ display: 'flex', gap: 8 }}>
        <button
          type="button"
          onClick={handleInject}
          disabled={isActive}
          style={{
            flex: 1,
            background: isActive ? 'rgba(99,102,241,0.08)' : 'rgba(99,102,241,0.22)',
            border: '1px solid rgba(99,102,241,0.4)',
            borderRadius: 4,
            color: isActive ? 'var(--text-faint, #4b5563)' : '#a5b4fc',
            padding: '6px 12px',
            fontSize: 12,
            fontWeight: 500,
            cursor: isActive ? 'not-allowed' : 'pointer',
            transition: 'background 0.1s',
          }}
        >
          Inject Canary
        </button>
        <button
          type="button"
          onClick={handleClear}
          disabled={!isActive}
          style={{
            background: isActive ? 'rgba(239,68,68,0.15)' : 'rgba(255,255,255,0.04)',
            border: `1px solid ${isActive ? 'rgba(239,68,68,0.35)' : 'rgba(255,255,255,0.08)'}`,
            borderRadius: 4,
            color: isActive ? '#fca5a5' : 'var(--text-faint, #4b5563)',
            padding: '6px 14px',
            fontSize: 12,
            fontWeight: 500,
            cursor: isActive ? 'pointer' : 'not-allowed',
            transition: 'background 0.1s',
          }}
        >
          Clear
        </button>
      </div>

      {/* Info note */}
      <p
        style={{
          margin: 0,
          fontSize: 11,
          color: 'var(--text-faint, #4b5563)',
          lineHeight: 1.5,
        }}
      >
        The nonce is injected as a taint source value. Any sink that receives it will be flagged
        as a canary match in the Sinks table.
      </p>
    </div>
  );
}
