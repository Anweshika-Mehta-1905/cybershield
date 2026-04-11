import React, { useState, useCallback } from 'react';
import { predictURL, predictMLOnly, predictWFAOnly } from './utils/api';
import RiskMeter from './components/RiskMeter';
import WFADiagram from './components/WFADiagram';
import FeatureImportanceChart from './components/FeatureImportanceChart';
import ScoreComparison from './components/ScoreComparison';
import TransitionsTable from './components/TransitionsTable';
import NetworkUploader from './components/NetworkUploader';

/* ─── Styles ─── */
const S = {
  app: {
    minHeight: '100vh',
    background: 'linear-gradient(135deg, #0a0e1a 0%, #0d1117 50%, #0a0e1a 100%)',
    color: '#e2e8f0',
    fontFamily: "'Segoe UI', system-ui, sans-serif",
    padding: '0 0 60px',
  },
  header: {
    background: 'linear-gradient(90deg, #0f172a, #1e293b)',
    borderBottom: '1px solid #1e293b',
    padding: '18px 32px',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    position: 'sticky', top: 0, zIndex: 100,
  },
  logo: { display: 'flex', alignItems: 'center', gap: 12 },
  container: { maxWidth: 1200, margin: '0 auto', padding: '32px 24px' },
  card: {
    background: '#0f172a',
    border: '1px solid #1e293b',
    borderRadius: 14,
    padding: 24,
    marginBottom: 20,
  },
  input: {
    width: '100%',
    background: '#0a0e1a',
    border: '1px solid #334155',
    borderRadius: 10,
    color: '#e2e8f0',
    fontSize: 15,
    padding: '14px 18px',
    outline: 'none',
    fontFamily: 'monospace',
    boxSizing: 'border-box',
    transition: 'border-color 0.2s',
  },
  btn: (variant = 'primary', disabled = false) => ({
    background: disabled
      ? '#1e293b'
      : variant === 'primary'
        ? 'linear-gradient(135deg, #1d4ed8, #3b82f6)'
        : variant === 'wfa'
          ? 'linear-gradient(135deg, #7c3aed, #a78bfa)'
          : 'linear-gradient(135deg, #0f766e, #14b8a6)',
    border: 'none',
    borderRadius: 10,
    color: disabled ? '#475569' : '#fff',
    cursor: disabled ? 'not-allowed' : 'pointer',
    fontSize: 14,
    fontWeight: 600,
    padding: '12px 24px',
    transition: 'all 0.2s',
    whiteSpace: 'nowrap',
  }),
  tab: (active) => ({
    background: active ? '#1e293b' : 'transparent',
    border: `1px solid ${active ? '#334155' : 'transparent'}`,
    borderRadius: 8,
    color: active ? '#e2e8f0' : '#64748b',
    cursor: 'pointer',
    fontSize: 13,
    fontWeight: active ? 600 : 400,
    padding: '8px 16px',
    transition: 'all 0.2s',
  }),
};

const SAMPLE_URLS = [
  { label: '✅ Benign (GitHub)', url: 'https://github.com/torvalds/linux' },
  { label: '🔴 IP Host', url: 'http://192.168.1.1/admin/login?redirect=paypal' },
  { label: '🔴 Phishing', url: 'http://paypal-secure-update.tk/account/verify?token=abc123' },
  { label: '🔴 Unicode', url: 'https://www.pаypal.com/signin' },
  { label: '⚠️ Suspicious', url: 'http://login.account.verify.amazon-support.xyz/update' },
];

function TabBar({ tabs, active, onChange }) {
  return (
    <div style={{ display: 'flex', gap: 6, marginBottom: 20, flexWrap: 'wrap' }}>
      {tabs.map(t => (
        <button key={t.id} style={S.tab(active === t.id)} onClick={() => onChange(t.id)}>
          {t.icon} {t.label}
        </button>
      ))}
    </div>
  );
}

function Spinner() {
  return (
    <div style={{ display: 'inline-block', width: 18, height: 18 }}>
      <svg viewBox="0 0 24 24" style={{ animation: 'spin 1s linear infinite', width: 18, height: 18 }}>
        <circle cx="12" cy="12" r="10" stroke="#3b82f6" strokeWidth="3" fill="none" strokeDasharray="31.4" strokeDashoffset="10" />
      </svg>
      <style>{`@keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }`}</style>
    </div>
  );
}

export default function App() {
  const [url, setUrl] = useState('');
  const [networkFeatures, setNetworkFeatures] = useState(null);
  const [loading, setLoading] = useState({ hybrid: false, ml: false, wfa: false });
  const [results, setResults] = useState({ hybrid: null, ml: null, wfa: null });
  const [error, setError] = useState('');
  const [activeTab, setActiveTab] = useState('comparison');

  const isLoading = Object.values(loading).some(Boolean);

  const runHybrid = useCallback(async () => {
    if (!url.trim()) return;
    setLoading(l => ({ ...l, hybrid: true }));
    setError('');
    try {
      const data = await predictURL(url.trim(), networkFeatures);
      setResults(r => ({ ...r, hybrid: data }));
    } catch (e) {
      setError(e.response?.data?.detail || e.message || 'Request failed. Is the backend running?');
    } finally {
      setLoading(l => ({ ...l, hybrid: false }));
    }
  }, [url, networkFeatures]);

  const runML = useCallback(async () => {
    if (!url.trim()) return;
    setLoading(l => ({ ...l, ml: true }));
    setError('');
    try {
      const data = await predictMLOnly(url.trim());
      setResults(r => ({ ...r, ml: data }));
    } catch (e) {
      setError(e.response?.data?.detail || e.message || 'Request failed.');
    } finally {
      setLoading(l => ({ ...l, ml: false }));
    }
  }, [url]);

  const runWFA = useCallback(async () => {
    if (!url.trim()) return;
    setLoading(l => ({ ...l, wfa: true }));
    setError('');
    try {
      const data = await predictWFAOnly(url.trim());
      setResults(r => ({ ...r, wfa: data }));
    } catch (e) {
      setError(e.response?.data?.detail || e.message || 'Request failed.');
    } finally {
      setLoading(l => ({ ...l, wfa: false }));
    }
  }, [url]);

  const runAll = useCallback(async () => {
    if (!url.trim()) return;
    setLoading({ hybrid: true, ml: true, wfa: true });
    setError('');
    try {
      const [h, m, w] = await Promise.all([
        predictURL(url.trim(), networkFeatures),
        predictMLOnly(url.trim()),
        predictWFAOnly(url.trim()),
      ]);
      setResults({ hybrid: h, ml: m, wfa: w });
    } catch (e) {
      setError(e.response?.data?.detail || e.message || 'Request failed. Is the backend running on port 8000?');
    } finally {
      setLoading({ hybrid: false, ml: false, wfa: false });
    }
  }, [url, networkFeatures]);

  const hasAnyResult = results.hybrid || results.ml || results.wfa;
  const mainResult = results.hybrid || results.ml || results.wfa;

  const tabs = [
    { id: 'comparison', icon: '⚖️', label: 'ML vs WFA' },
    { id: 'wfa', icon: '🔵', label: 'WFA Diagram' },
    { id: 'features', icon: '📊', label: 'Feature Analysis' },
    { id: 'transitions', icon: '📋', label: 'Transitions' },
  ];

  /* ─── WFA data (from wfa or hybrid) ─── */
  const wfaData = results.wfa || (results.hybrid ? {
    wfa_score: results.hybrid.wfa_score,
    risk_level: results.hybrid.risk_level,
    final_state: results.hybrid.explanation?.wfa_final_state,
    path: results.hybrid.wfa_path,
    transitions: results.hybrid.wfa_transitions,
    triggered_patterns: results.hybrid.triggered_features,
  } : null);

  /* ─── ML data (from ml or hybrid) ─── */
  const mlData = results.ml || (results.hybrid ? {
    ml_score: results.hybrid.ml_score,
    risk_level: results.hybrid.risk_level,
    features: results.hybrid.ml_features,
    feature_importance: results.hybrid.feature_importance,
    triggered_features: results.hybrid.triggered_features,
  } : null);

  return (
    <div style={S.app}>
      {/* Header */}
      <div style={S.header}>
        <div style={S.logo}>
          <span style={{ fontSize: 28 }}>🛡️</span>
          <div>
            <div style={{ fontSize: 18, fontWeight: 800, letterSpacing: '-0.5px' }}>
              CyberShield
            </div>
            <div style={{ fontSize: 11, color: '#64748b' }}>
              Hybrid Threat Detection · WFA + ML + Anomaly
            </div>
          </div>
        </div>
        <div style={{ display: 'flex', gap: 16, fontSize: 12, color: '#475569' }}>
          <span>Layer 1: Autoencoder</span>
          <span style={{ color: '#1e293b' }}>|</span>
          <span>Layer 2: LogReg</span>
          <span style={{ color: '#1e293b' }}>|</span>
          <span>Layer 3: WFA</span>
        </div>
      </div>

      <div style={S.container}>

        {/* Input card */}
        <div style={S.card}>
          <div style={{ fontSize: 15, fontWeight: 700, color: '#94a3b8', marginBottom: 16 }}>
            🔍 Analyze URL
          </div>

          {/* URL input */}
          <div style={{ position: 'relative', marginBottom: 12 }}>
            <input
              style={S.input}
              placeholder="Enter URL to analyze  e.g. http://suspicious-paypal.tk/login"
              value={url}
              onChange={e => setUrl(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && runAll()}
            />
          </div>

          {/* Sample URLs */}
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginBottom: 16 }}>
            <span style={{ fontSize: 11, color: '#475569', alignSelf: 'center' }}>Samples:</span>
            {SAMPLE_URLS.map(s => (
              <button
                key={s.url}
                onClick={() => setUrl(s.url)}
                style={{
                  background: '#1e293b', border: '1px solid #334155',
                  borderRadius: 6, color: '#94a3b8',
                  cursor: 'pointer', fontSize: 11, padding: '4px 10px',
                }}
              >
                {s.label}
              </button>
            ))}
          </div>

          {/* Network uploader */}
          <NetworkUploader onFeaturesLoaded={setNetworkFeatures} />

          {/* Action buttons */}
          <div style={{ display: 'flex', gap: 10, marginTop: 16, flexWrap: 'wrap' }}>
            <button
              style={S.btn('primary', isLoading || !url.trim())}
              disabled={isLoading || !url.trim()}
              onClick={runAll}
            >
              {isLoading ? <><Spinner /> &nbsp;Analyzing…</> : '⚡ Analyze All (ML + WFA + Hybrid)'}
            </button>
            <button
              style={S.btn('ml', isLoading || !url.trim())}
              disabled={isLoading || !url.trim()}
              onClick={runML}
            >
              🤖 ML Only
            </button>
            <button
              style={S.btn('wfa', isLoading || !url.trim())}
              disabled={isLoading || !url.trim()}
              onClick={runWFA}
            >
              🔵 WFA Only
            </button>
          </div>

          {error && (
            <div style={{
              marginTop: 12, padding: '10px 14px', borderRadius: 8,
              background: '#450a0a', border: '1px solid #991b1b',
              color: '#fca5a5', fontSize: 12,
            }}>
              ❌ {error}
            </div>
          )}
        </div>

        {/* Results */}
        {hasAnyResult && (
          <>
            <TabBar tabs={tabs} active={activeTab} onChange={setActiveTab} />

            {/* Comparison tab */}
            {activeTab === 'comparison' && (
              <div style={S.card}>
                <ScoreComparison
                  mlResult={mlData ? { ...mlData, ml_score: mlData.ml_score } : null}
                  wfaResult={wfaData ? {
                    ...wfaData,
                    wfa_score: wfaData.wfa_score,
                    final_state: wfaData.final_state,
                  } : null}
                  hybridResult={results.hybrid}
                />
              </div>
            )}

            {/* WFA Diagram tab */}
            {activeTab === 'wfa' && (
              <div style={S.card}>
                <div style={{ fontSize: 14, fontWeight: 700, color: '#94a3b8', marginBottom: 16 }}>
                  🔵 Weighted Finite Automaton State Diagram
                </div>
                {wfaData ? (
                  <>
                    <WFADiagram
                      path={wfaData.path || []}
                      transitions={wfaData.transitions || wfaData.wfa_transitions || []}
                    />
                    <div style={{
                      marginTop: 16, display: 'grid',
                      gridTemplateColumns: 'repeat(auto-fill, minmax(160px, 1fr))',
                      gap: 10,
                    }}>
                      {[
                        { label: 'WFA Score', val: (wfaData.wfa_score || 0).toFixed(4), icon: '📊' },
                        { label: 'Final State', val: wfaData.final_state || '—', icon: '🏁' },
                        { label: 'Path Length', val: (wfaData.path || []).length, icon: '🔗' },
                        { label: 'Risk Level', val: wfaData.risk_level || '—', icon: '⚠️' },
                      ].map(item => (
                        <div key={item.label} style={{
                          background: '#1e293b', borderRadius: 8,
                          padding: '10px 14px', textAlign: 'center',
                        }}>
                          <div style={{ fontSize: 18 }}>{item.icon}</div>
                          <div style={{ fontSize: 16, fontWeight: 700, color: '#e2e8f0', fontFamily: 'monospace' }}>
                            {item.val}
                          </div>
                          <div style={{ fontSize: 10, color: '#64748b' }}>{item.label}</div>
                        </div>
                      ))}
                    </div>
                  </>
                ) : (
                  <div style={{ color: '#475569', textAlign: 'center', padding: 40 }}>
                    Run WFA or All analysis to see the state diagram
                  </div>
                )}
              </div>
            )}

            {/* Feature Analysis tab */}
            {activeTab === 'features' && (
              <div style={S.card}>
                <div style={{ fontSize: 14, fontWeight: 700, color: '#94a3b8', marginBottom: 16 }}>
                  📊 ML Feature Analysis
                </div>
                {mlData ? (
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 24 }}>
                    <div>
                      <FeatureImportanceChart
                        importance={mlData.feature_importance || []}
                        featureValues={mlData.features || mlData.ml_features || {}}
                      />
                    </div>
                    <div>
                      <div style={{ fontSize: 13, color: '#94a3b8', marginBottom: 12 }}>
                        Triggered Risk Indicators
                      </div>
                      {(mlData.triggered_features || []).length === 0 ? (
                        <div style={{
                          background: '#052e16', border: '1px solid #166534',
                          borderRadius: 8, padding: 16, textAlign: 'center',
                          color: '#4ade80', fontSize: 13,
                        }}>
                          ✅ No suspicious features detected
                        </div>
                      ) : (
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                          {(mlData.triggered_features || []).map((f, i) => (
                            <div key={i} style={{
                              background: '#450a0a',
                              border: '1px solid #991b1b',
                              borderRadius: 6,
                              padding: '6px 12px',
                              fontSize: 12,
                              color: '#fca5a5',
                              display: 'flex',
                              alignItems: 'center',
                              gap: 8,
                            }}>
                              <span>⚠️</span> {f}
                            </div>
                          ))}
                        </div>
                      )}

                      <div style={{ marginTop: 20 }}>
                        <div style={{ fontSize: 13, color: '#94a3b8', marginBottom: 10 }}>
                          ML Score Breakdown
                        </div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                          <RiskMeter
                            score={mlData.ml_score || 0}
                            riskLevel={mlData.risk_level || 'SAFE'}
                          />
                        </div>
                      </div>
                    </div>
                  </div>
                ) : (
                  <div style={{ color: '#475569', textAlign: 'center', padding: 40 }}>
                    Run ML or All analysis to see feature breakdown
                  </div>
                )}
              </div>
            )}

            {/* Transitions tab */}
            {activeTab === 'transitions' && (
              <div style={S.card}>
                <div style={{ fontSize: 14, fontWeight: 700, color: '#94a3b8', marginBottom: 16 }}>
                  📋 WFA Transition Log
                </div>
                {wfaData ? (
                  <TransitionsTable
                    transitions={wfaData.transitions || wfaData.wfa_transitions || []}
                    triggeredPatterns={wfaData.triggered_patterns || wfaData.triggered_features || []}
                  />
                ) : (
                  <div style={{ color: '#475569', textAlign: 'center', padding: 40 }}>
                    Run WFA or All analysis to see transitions
                  </div>
                )}
              </div>
            )}

            {/* Always show raw JSON toggle */}
            <details style={{ marginTop: 12 }}>
              <summary style={{ cursor: 'pointer', color: '#475569', fontSize: 12, padding: '8px 0' }}>
                🔧 Raw API Response (debug)
              </summary>
              <pre style={{
                background: '#0a0e1a', border: '1px solid #1e293b',
                borderRadius: 8, padding: 16,
                fontSize: 11, color: '#64748b',
                overflow: 'auto', maxHeight: 300, marginTop: 8,
              }}>
                {JSON.stringify({ hybrid: results.hybrid, ml: results.ml, wfa: results.wfa }, null, 2)}
              </pre>
            </details>
          </>
        )}

        {/* Empty state */}
        {!hasAnyResult && !isLoading && (
          <div style={{
            textAlign: 'center', padding: '60px 24px',
            color: '#334155',
          }}>
            <div style={{ fontSize: 64, marginBottom: 16 }}>🛡️</div>
            <div style={{ fontSize: 20, fontWeight: 700, marginBottom: 8, color: '#475569' }}>
              3-Layer Hybrid Detection System
            </div>
            <div style={{ fontSize: 14, color: '#334155', maxWidth: 500, margin: '0 auto' }}>
              Enter a URL above and click <strong style={{ color: '#3b82f6' }}>Analyze All</strong> to run all three layers:
              Autoencoder anomaly detection, Logistic Regression URL analysis, and Weighted Finite Automaton scoring.
            </div>
            <div style={{ marginTop: 24, display: 'flex', justifyContent: 'center', gap: 20, fontSize: 13 }}>
              <span style={{ color: '#1d4ed8' }}>🌐 Layer 1: Autoencoder</span>
              <span style={{ color: '#7c3aed' }}>🤖 Layer 2: Logistic Regression</span>
              <span style={{ color: '#0f766e' }}>🔵 Layer 3: WFA (TOC)</span>
            </div>
          </div>
        )}

      </div>
    </div>
  );
}
