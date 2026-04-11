import React from 'react';
import RiskMeter from './RiskMeter';

const RISK_BG = {
  SAFE: '#052e16', LOW: '#1a2e05', MEDIUM: '#1c1a00',
  HIGH: '#1c0a00', CRITICAL: '#1a0000',
};
const RISK_BORDER = {
  SAFE: '#166534', LOW: '#365314', MEDIUM: '#713f12',
  HIGH: '#9a3412', CRITICAL: '#991b1b',
};

function ScoreCard({ title, subtitle, score, riskLevel, details = [], icon }) {
  return (
    <div style={{
      background: RISK_BG[riskLevel] || '#0f172a',
      border: `1px solid ${RISK_BORDER[riskLevel] || '#1e293b'}`,
      borderRadius: 12, padding: 20, flex: 1,
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
        <span style={{ fontSize: 20 }}>{icon}</span>
        <div>
          <div style={{ fontSize: 14, fontWeight: 700, color: '#e2e8f0' }}>{title}</div>
          <div style={{ fontSize: 11, color: '#64748b' }}>{subtitle}</div>
        </div>
      </div>
      <RiskMeter score={score} riskLevel={riskLevel} />
      <div style={{ marginTop: 12 }}>
        {details.map((d, i) => (
          <div key={i} style={{
            display: 'flex', justifyContent: 'space-between',
            padding: '4px 0', borderBottom: '1px solid #1e293b',
            fontSize: 11,
          }}>
            <span style={{ color: '#64748b' }}>{d.label}</span>
            <span style={{ color: '#94a3b8', fontFamily: 'monospace' }}>{d.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function getRiskLevel(score) {
  if (score >= 0.80) return 'CRITICAL';
  if (score >= 0.60) return 'HIGH';
  if (score >= 0.40) return 'MEDIUM';
  if (score >= 0.20) return 'LOW';
  return 'SAFE';
}

export default function ScoreComparison({ mlResult, wfaResult, hybridResult }) {
  if (!mlResult && !wfaResult && !hybridResult) return null;

  const mlScore = mlResult?.ml_score ?? mlResult?.score ?? 0;
  const wfaScore = wfaResult?.wfa_score ?? wfaResult?.score ?? 0;
  const hybridScore = hybridResult?.final_score ?? 0;

  return (
    <div>
      <div style={{ fontSize: 13, fontWeight: 600, color: '#94a3b8', marginBottom: 16 }}>
        🔬 Model Comparison
      </div>

      <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap' }}>
        {/* ML Model */}
        {mlResult && (
          <ScoreCard
            title="ML Model"
            subtitle="Logistic Regression · URL Features"
            score={mlScore}
            riskLevel={mlResult.risk_level || getRiskLevel(mlScore)}
            icon="🤖"
            details={[
              { label: 'Score', value: mlScore.toFixed(4) },
              { label: 'Model', value: 'Logistic Regression' },
              { label: 'Features', value: '25 URL features' },
              { label: 'Decision', value: mlScore > 0.5 ? '🔴 Malicious' : '🟢 Benign' },
            ]}
          />
        )}

        {/* WFA Rule-based */}
        {wfaResult && (
          <ScoreCard
            title="Rule-based WFA"
            subtitle="Weighted Finite Automaton · TOC"
            score={wfaScore}
            riskLevel={wfaResult.risk_level || getRiskLevel(wfaScore)}
            icon="🔵"
            details={[
              { label: 'Score', value: wfaScore.toFixed(4) },
              { label: 'Final State', value: wfaResult.final_state || wfaResult.wfa_final_state || '—' },
              { label: 'States', value: 'Q0 → Q8' },
              { label: 'Decision', value: wfaScore > 0.5 ? '🔴 Malicious' : '🟢 Benign' },
            ]}
          />
        )}

        {/* Hybrid */}
        {hybridResult && (
          <ScoreCard
            title="Hybrid Final"
            subtitle="0.25·Anomaly + 0.40·ML + 0.35·WFA"
            score={hybridScore}
            riskLevel={hybridResult.risk_level || getRiskLevel(hybridScore)}
            icon="⚡"
            details={[
              { label: 'Final Score', value: hybridScore.toFixed(4) },
              { label: 'Threshold', value: '0.50' },
              { label: 'Anomaly', value: (hybridResult.anomaly_score ?? 0).toFixed(4) },
              { label: 'Decision', value: hybridResult.is_malicious ? '🔴 MALICIOUS' : '🟢 BENIGN' },
            ]}
          />
        )}
      </div>

      {/* Verdict banner */}
      {hybridResult && (
        <div style={{
          marginTop: 16,
          background: hybridResult.is_malicious ? '#450a0a' : '#052e16',
          border: `2px solid ${hybridResult.is_malicious ? '#dc2626' : '#16a34a'}`,
          borderRadius: 10,
          padding: '14px 20px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: 8,
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <span style={{ fontSize: 32 }}>{hybridResult.is_malicious ? '🚨' : '✅'}</span>
            <div>
              <div style={{
                fontSize: 18, fontWeight: 800,
                color: hybridResult.is_malicious ? '#fca5a5' : '#86efac',
              }}>
                {hybridResult.is_malicious ? 'THREAT DETECTED' : 'URL IS SAFE'}
              </div>
              <div style={{ fontSize: 12, color: '#94a3b8' }}>
                Risk Level: <strong style={{ color: hybridResult.is_malicious ? '#f87171' : '#4ade80' }}>
                  {hybridResult.risk_level}
                </strong>
                {' · '}Final Score: {hybridScore.toFixed(4)}
              </div>
            </div>
          </div>

          {/* Layer weight breakdown */}
          {hybridResult.explanation?.layer_scores && (
            <div style={{ display: 'flex', gap: 12, fontSize: 11 }}>
              {Object.entries(hybridResult.explanation.layer_scores).map(([k, v]) => (
                <div key={k} style={{ textAlign: 'center' }}>
                  <div style={{ color: '#64748b' }}>
                    {k === 'anomaly_layer' ? '🌐 Net' : k === 'ml_layer' ? '🤖 ML' : '🔵 WFA'}
                  </div>
                  <div style={{ color: '#e2e8f0', fontFamily: 'monospace', fontWeight: 700 }}>
                    {v.toFixed(3)}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
