import React from 'react';

const COLORS = {
  SAFE: { fill: '#22c55e', glow: '#16a34a', text: '#bbf7d0' },
  LOW: { fill: '#84cc16', glow: '#65a30d', text: '#d9f99d' },
  MEDIUM: { fill: '#eab308', glow: '#ca8a04', text: '#fef08a' },
  HIGH: { fill: '#f97316', glow: '#ea580c', text: '#fed7aa' },
  CRITICAL: { fill: '#ef4444', glow: '#dc2626', text: '#fecaca' },
};

export default function RiskMeter({ score = 0, riskLevel = 'SAFE', label = '' }) {
  const pct = Math.min(Math.max(score, 0), 1);
  const angle = -135 + pct * 270; // -135° to +135°
  const colors = COLORS[riskLevel] || COLORS.SAFE;

  // SVG arc path for gauge
  const polarToCartesian = (cx, cy, r, deg) => {
    const rad = ((deg - 90) * Math.PI) / 180;
    return { x: cx + r * Math.cos(rad), y: cy + r * Math.sin(rad) };
  };

  const describeArc = (cx, cy, r, startDeg, endDeg) => {
    const s = polarToCartesian(cx, cy, r, startDeg);
    const e = polarToCartesian(cx, cy, r, endDeg);
    const large = endDeg - startDeg > 180 ? 1 : 0;
    return `M ${s.x} ${s.y} A ${r} ${r} 0 ${large} 1 ${e.x} ${e.y}`;
  };

  const cx = 100, cy = 100, r = 70;
  const bgArc = describeArc(cx, cy, r, -135, 135);
  const fillEnd = -135 + pct * 270;
  const fillArc = pct > 0 ? describeArc(cx, cy, r, -135, Math.min(fillEnd, 134.9)) : '';

  const needle = polarToCartesian(cx, cy, r - 10, angle);

  return (
    <div style={{ textAlign: 'center' }}>
      <svg viewBox="0 0 200 140" style={{ width: '100%', maxWidth: 280, filter: `drop-shadow(0 0 8px ${colors.glow}44)` }}>
        <defs>
          <linearGradient id={`grad-${riskLevel}`} gradientUnits="userSpaceOnUse" x1="30" y1="100" x2="170" y2="100">
            <stop offset="0%" stopColor="#22c55e" />
            <stop offset="33%" stopColor="#eab308" />
            <stop offset="66%" stopColor="#f97316" />
            <stop offset="100%" stopColor="#ef4444" />
          </linearGradient>
        </defs>

        {/* Background track */}
        <path d={bgArc} fill="none" stroke="#1e293b" strokeWidth="14" strokeLinecap="round" />

        {/* Filled arc */}
        {fillArc && (
          <path
            d={fillArc}
            fill="none"
            stroke={`url(#grad-${riskLevel})`}
            strokeWidth="14"
            strokeLinecap="round"
          />
        )}

        {/* Needle */}
        <line
          x1={cx} y1={cy}
          x2={needle.x} y2={needle.y}
          stroke={colors.fill}
          strokeWidth="3"
          strokeLinecap="round"
          style={{ filter: `drop-shadow(0 0 4px ${colors.fill})` }}
        />
        <circle cx={cx} cy={cy} r="5" fill={colors.fill} />

        {/* Score text */}
        <text x={cx} y={cy + 25} textAnchor="middle" fontSize="22" fontWeight="bold" fill={colors.text}>
          {(pct * 100).toFixed(1)}%
        </text>
        <text x={cx} y={cy + 40} textAnchor="middle" fontSize="11" fill={colors.text} opacity="0.8">
          {riskLevel}
        </text>

        {/* Scale labels */}
        <text x="28" y="125" fontSize="9" fill="#64748b">0</text>
        <text x="165" y="125" fontSize="9" fill="#64748b">100</text>
      </svg>
      {label && (
        <div style={{ marginTop: 4, fontSize: 12, color: '#64748b' }}>{label}</div>
      )}
    </div>
  );
}
