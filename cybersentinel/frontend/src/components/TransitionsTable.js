import React, { useState } from 'react';

const STATE_COLORS = {
  Q0: '#22c55e', Q1: '#84cc16', Q2: '#ef4444',
  Q3: '#f97316', Q4: '#f59e0b', Q5: '#eab308',
  Q6: '#f97316', Q7: '#dc2626', Q8: '#7f1d1d',
};

function StateBadge({ state }) {
  return (
    <span style={{
      display: 'inline-block',
      background: STATE_COLORS[state] + '22',
      border: `1px solid ${STATE_COLORS[state]}`,
      borderRadius: 4,
      padding: '1px 6px',
      fontSize: 11,
      fontWeight: 700,
      color: STATE_COLORS[state],
      fontFamily: 'monospace',
    }}>
      {state}
    </span>
  );
}

function WeightBar({ weight, maxWeight = 1.5 }) {
  const pct = Math.min(Math.abs(weight) / maxWeight, 1) * 100;
  const color = weight > 0.5 ? '#ef4444' : weight > 0.2 ? '#f97316' : '#22c55e';
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
      <div style={{
        height: 6, width: `${pct}%`, maxWidth: 60,
        background: color, borderRadius: 3,
        minWidth: 2,
      }} />
      <span style={{ fontFamily: 'monospace', fontSize: 11, color: '#94a3b8' }}>
        {weight > 0 ? '+' : ''}{weight.toFixed(3)}
      </span>
    </div>
  );
}

export default function TransitionsTable({ transitions = [], triggeredPatterns = [] }) {
  const [expanded, setExpanded] = useState(false);

  if (transitions.length === 0) return null;

  const shown = expanded ? transitions : transitions.slice(0, 5);

  return (
    <div>
      <div style={{
        display: 'flex', justifyContent: 'space-between', alignItems: 'center',
        marginBottom: 10,
      }}>
        <div style={{ fontSize: 13, color: '#94a3b8' }}>
          WFA Transitions Taken ({transitions.length} steps)
        </div>
        {transitions.length > 5 && (
          <button
            onClick={() => setExpanded(!expanded)}
            style={{
              background: 'transparent', border: 'none',
              color: '#3b82f6', cursor: 'pointer', fontSize: 12,
            }}
          >
            {expanded ? 'Show less ▲' : `Show all ${transitions.length} ▼`}
          </button>
        )}
      </div>

      <div style={{ overflowX: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
          <thead>
            <tr style={{ borderBottom: '1px solid #1e293b' }}>
              {['Step', 'From', 'To', 'Symbol', 'Weight', 'Description'].map(h => (
                <th key={h} style={{
                  textAlign: 'left', padding: '6px 8px',
                  color: '#475569', fontWeight: 600, fontSize: 11,
                }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {shown.map((t, i) => (
              <tr key={i} style={{
                borderBottom: '1px solid #0f172a',
                background: t.weight > 0.5 ? '#1a0a00' : 'transparent',
              }}>
                <td style={{ padding: '5px 8px', color: '#475569', fontFamily: 'monospace' }}>
                  {i + 1}
                </td>
                <td style={{ padding: '5px 8px' }}><StateBadge state={t.from} /></td>
                <td style={{ padding: '5px 8px' }}><StateBadge state={t.to} /></td>
                <td style={{ padding: '5px 8px', color: '#64748b', fontFamily: 'monospace', fontSize: 10 }}>
                  {t.symbol}
                </td>
                <td style={{ padding: '5px 8px' }}>
                  <WeightBar weight={t.weight} />
                </td>
                <td style={{ padding: '5px 8px', color: '#64748b', fontSize: 11 }}>
                  {t.description}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Triggered patterns */}
      {triggeredPatterns.length > 0 && (
        <div style={{ marginTop: 12 }}>
          <div style={{ fontSize: 12, color: '#94a3b8', marginBottom: 6 }}>
            ⚠️ Triggered Risk Patterns:
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
            {triggeredPatterns.map((p, i) => (
              <span key={i} style={{
                background: '#450a0a',
                border: '1px solid #991b1b',
                color: '#fca5a5',
                borderRadius: 6,
                padding: '3px 8px',
                fontSize: 11,
              }}>
                🔴 {p}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
