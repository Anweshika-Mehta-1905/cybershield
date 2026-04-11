import React, { useMemo } from 'react';

const STATE_POSITIONS = {
  Q0: { x: 60, y: 150 },
  Q1: { x: 160, y: 150 },
  Q2: { x: 240, y: 70 },
  Q3: { x: 240, y: 150 },
  Q4: { x: 320, y: 90 },
  Q5: { x: 320, y: 210 },
  Q6: { x: 420, y: 150 },
  Q7: { x: 510, y: 90 },
  Q8: { x: 510, y: 210 },
};

const RISK_COLORS = {
  Q0: '#22c55e', Q1: '#84cc16', Q2: '#ef4444',
  Q3: '#f97316', Q4: '#f59e0b', Q5: '#eab308',
  Q6: '#f97316', Q7: '#dc2626', Q8: '#7f1d1d',
};

function CurvedArrow({ from, to, label, active, weight }) {
  const dx = to.x - from.x;
  const dy = to.y - from.y;
  const mx = (from.x + to.x) / 2;
  const my = (from.y + to.y) / 2 - 25;

  const color = active ? '#f59e0b' : '#334155';
  const strokeW = active ? 2.5 : 1;

  return (
    <g>
      <defs>
        <marker id={`arr-${active ? 'a' : 'i'}`} markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
          <path d="M0,0 L0,6 L8,3 z" fill={color} />
        </marker>
      </defs>
      <path
        d={`M${from.x},${from.y} Q${mx},${my} ${to.x},${to.y}`}
        fill="none"
        stroke={color}
        strokeWidth={strokeW}
        markerEnd={`url(#arr-${active ? 'a' : 'i'})`}
        strokeDasharray={active ? 'none' : '4,3'}
        style={{ filter: active ? 'drop-shadow(0 0 3px #f59e0b)' : 'none' }}
      />
      {active && label && (
        <text x={mx} y={my - 5} fontSize="8" fill="#fbbf24" textAnchor="middle">
          {label.length > 14 ? label.slice(0, 12) + '…' : label}
        </text>
      )}
    </g>
  );
}

export default function WFADiagram({ path = [], transitions = [] }) {
  const activeEdges = useMemo(() => {
    const set = new Set();
    for (let i = 0; i < path.length - 1; i++) {
      set.add(`${path[i]}->${path[i + 1]}`);
    }
    return set;
  }, [path]);

  const transitionMap = useMemo(() => {
    const m = {};
    transitions.forEach(t => { m[`${t.from}->${t.to}`] = t; });
    return m;
  }, [transitions]);

  // Static edges to draw (representative subset)
  const edges = [
    ['Q0', 'Q1'], ['Q1', 'Q2'], ['Q1', 'Q3'], ['Q1', 'Q5'], ['Q1', 'Q4'],
    ['Q2', 'Q8'], ['Q3', 'Q4'], ['Q3', 'Q6'], ['Q3', 'Q5'],
    ['Q4', 'Q7'], ['Q4', 'Q5'],
    ['Q5', 'Q6'], ['Q5', 'Q7'], ['Q6', 'Q8'], ['Q6', 'Q7'],
    ['Q7', 'Q8'],
  ];

  return (
    <div style={{ background: '#0f172a', borderRadius: 12, padding: 16, border: '1px solid #1e293b' }}>
      <div style={{ fontSize: 12, color: '#64748b', marginBottom: 8 }}>
        WFA State Transition Path {path.length > 0 && (
          <span style={{ color: '#f59e0b' }}>→ {path.join(' → ')}</span>
        )}
      </div>
      <svg viewBox="0 0 590 300" style={{ width: '100%' }}>
        {/* Edges */}
        {edges.map(([f, t]) => {
          const key = `${f}->${t}`;
          const active = activeEdges.has(key);
          const tr = transitionMap[key];
          return (
            <CurvedArrow
              key={key}
              from={STATE_POSITIONS[f]}
              to={STATE_POSITIONS[t]}
              label={tr?.symbol || ''}
              active={active}
              weight={tr?.weight}
            />
          );
        })}

        {/* State nodes */}
        {Object.entries(STATE_POSITIONS).map(([state, pos]) => {
          const inPath = path.includes(state);
          const isCurrent = path[path.length - 1] === state;
          const color = RISK_COLORS[state];
          const isAccepting = state === 'Q7' || state === 'Q8';

          return (
            <g key={state}>
              {isAccepting && (
                <circle cx={pos.x} cy={pos.y} r={24} fill="none"
                  stroke={color} strokeWidth={1.5} strokeDasharray="3,2" opacity={0.5} />
              )}
              <circle
                cx={pos.x} cy={pos.y} r={20}
                fill={inPath ? color : '#1e293b'}
                stroke={inPath ? color : '#334155'}
                strokeWidth={isCurrent ? 3 : 1.5}
                style={{ filter: isCurrent ? `drop-shadow(0 0 6px ${color})` : 'none' }}
              />
              <text x={pos.x} y={pos.y + 1} textAnchor="middle" dominantBaseline="middle"
                fontSize="11" fontWeight="bold"
                fill={inPath ? '#fff' : '#64748b'}>
                {state}
              </text>
              <text x={pos.x} y={pos.y + 34} textAnchor="middle" fontSize="8" fill="#475569">
                {['CLEAN', 'PROTO', 'IP!', 'SUB', 'ENC', 'PATH', 'CRED', 'ANOM', 'MAL'][parseInt(state[1])]}
              </text>
            </g>
          );
        })}
      </svg>

      {/* Legend */}
      <div style={{ display: 'flex', gap: 16, fontSize: 11, color: '#64748b', marginTop: 8 }}>
        <span>⬤ <span style={{ color: '#22c55e' }}>Q0</span> Safe</span>
        <span>⬤ <span style={{ color: '#ef4444' }}>Q2</span> IP Host</span>
        <span>⬤ <span style={{ color: '#dc2626' }}>Q7-Q8</span> Malicious</span>
        <span style={{ marginLeft: 'auto' }}>
          <span style={{ color: '#f59e0b' }}>━</span> Active path
          <span style={{ color: '#334155', marginLeft: 8 }}>╌</span> Inactive
        </span>
      </div>
    </div>
  );
}
