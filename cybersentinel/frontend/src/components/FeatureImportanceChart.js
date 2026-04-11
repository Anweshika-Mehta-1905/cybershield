import React from 'react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';

const FEATURE_LABELS = {
  url_length: 'URL Length',
  hostname_length: 'Hostname Length',
  path_length: 'Path Length',
  query_length: 'Query Length',
  subdomain_depth: 'Subdomain Depth',
  has_ip_host: 'IP as Host',
  has_at_sign: '@ Sign',
  has_double_slash: 'Double Slash',
  has_dash_in_domain: 'Dash in Domain',
  has_port: 'Non-std Port',
  digit_ratio: 'Digit Ratio',
  special_char_count: 'Special Chars',
  dot_count: 'Dot Count',
  slash_count: 'Slash Count',
  has_https: 'HTTPS',
  has_encoding: 'URL Encoding',
  has_unicode: 'Unicode',
  path_depth: 'Path Depth',
  has_suspicious_tld: 'Suspicious TLD',
  has_credential_keyword: 'Cred Keyword',
  query_param_count: 'Query Params',
  has_fragment: 'Fragment',
  entropy: 'Entropy',
  consecutive_digits: 'Consec. Digits',
  subdomain_contains_ip_pattern: 'IP in Subdomain',
};

const CustomTooltip = ({ active, payload }) => {
  if (active && payload?.length) {
    const d = payload[0].payload;
    return (
      <div style={{
        background: '#1e293b', border: '1px solid #334155',
        borderRadius: 8, padding: '8px 12px', fontSize: 12,
      }}>
        <div style={{ color: '#94a3b8' }}>{FEATURE_LABELS[d.feature] || d.feature}</div>
        <div style={{ color: d.weight >= 0 ? '#ef4444' : '#22c55e', fontWeight: 'bold' }}>
          Weight: {d.weight.toFixed(4)}
        </div>
      </div>
    );
  }
  return null;
};

export default function FeatureImportanceChart({ importance = [], featureValues = {} }) {
  const data = importance
    .slice(0, 10)
    .map(f => ({
      ...f,
      label: (FEATURE_LABELS[f.feature] || f.feature).slice(0, 16),
      value: featureValues[f.feature] ?? null,
    }));

  return (
    <div>
      <div style={{ fontSize: 13, color: '#94a3b8', marginBottom: 12 }}>
        Top Feature Weights (Logistic Regression)
      </div>
      <ResponsiveContainer width="100%" height={220}>
        <BarChart data={data} layout="vertical" margin={{ left: 0, right: 20 }}>
          <XAxis type="number" tick={{ fontSize: 10, fill: '#64748b' }} domain={['auto', 'auto']} />
          <YAxis
            type="category"
            dataKey="label"
            tick={{ fontSize: 10, fill: '#94a3b8' }}
            width={110}
          />
          <Tooltip content={<CustomTooltip />} cursor={{ fill: '#1e293b' }} />
          <Bar dataKey="weight" radius={[0, 4, 4, 0]}>
            {data.map((entry, i) => (
              <Cell
                key={i}
                fill={entry.weight >= 0 ? `hsl(${10 + entry.abs_weight * 20},80%,55%)` : '#22c55e'}
              />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>

      {/* Feature values table */}
      {Object.keys(featureValues).length > 0 && (
        <div style={{ marginTop: 12, maxHeight: 160, overflowY: 'auto' }}>
          <table style={{ width: '100%', fontSize: 11, borderCollapse: 'collapse' }}>
            <thead>
              <tr>
                <th style={{ textAlign: 'left', color: '#475569', padding: '4px 8px', borderBottom: '1px solid #1e293b' }}>Feature</th>
                <th style={{ textAlign: 'right', color: '#475569', padding: '4px 8px', borderBottom: '1px solid #1e293b' }}>Value</th>
              </tr>
            </thead>
            <tbody>
              {importance.slice(0, 10).map(f => (
                <tr key={f.feature} style={{ borderBottom: '1px solid #0f172a' }}>
                  <td style={{ padding: '3px 8px', color: '#94a3b8' }}>
                    {FEATURE_LABELS[f.feature] || f.feature}
                  </td>
                  <td style={{
                    padding: '3px 8px', textAlign: 'right',
                    color: featureValues[f.feature] > 0.5 ? '#f97316' : '#64748b',
                    fontFamily: 'monospace',
                  }}>
                    {typeof featureValues[f.feature] === 'number'
                      ? featureValues[f.feature].toFixed(3)
                      : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
