import React, { useRef, useState } from 'react';
import { uploadNetworkCSV } from '../utils/api';

export default function NetworkUploader({ onFeaturesLoaded }) {
  const fileRef = useRef(null);
  const [status, setStatus] = useState(null); // null | 'loading' | 'ok' | 'error'
  const [info, setInfo] = useState(null);
  const [error, setError] = useState('');

  const handleFile = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setStatus('loading');
    setError('');
    setInfo(null);

    try {
      const result = await uploadNetworkCSV(file);
      setInfo(result);
      setStatus('ok');
      onFeaturesLoaded(result.features);
    } catch (err) {
      const msg = err.response?.data?.detail || err.message || 'Upload failed';
      setError(msg);
      setStatus('error');
    }

    // Reset so same file can be re-uploaded
    e.target.value = '';
  };

  const handleClear = () => {
    setStatus(null);
    setInfo(null);
    setError('');
    onFeaturesLoaded(null);
  };

  return (
    <div style={{
      background: '#0f172a',
      border: `1px dashed ${status === 'ok' ? '#16a34a' : status === 'error' ? '#dc2626' : '#334155'}`,
      borderRadius: 10,
      padding: 16,
      transition: 'border-color 0.3s',
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10 }}>
        <span style={{ fontSize: 18 }}>🌐</span>
        <div>
          <div style={{ fontSize: 13, fontWeight: 600, color: '#e2e8f0' }}>
            Network Features (Optional)
          </div>
          <div style={{ fontSize: 11, color: '#64748b' }}>
            Upload a CSV row from N-BaIoT / IoT traffic capture (115 features)
          </div>
        </div>
      </div>

      {status !== 'ok' ? (
        <button
          onClick={() => fileRef.current?.click()}
          disabled={status === 'loading'}
          style={{
            background: '#1e293b',
            border: '1px solid #334155',
            borderRadius: 8,
            color: '#94a3b8',
            cursor: 'pointer',
            padding: '8px 16px',
            fontSize: 12,
            display: 'flex',
            alignItems: 'center',
            gap: 8,
            width: '100%',
            justifyContent: 'center',
          }}
        >
          {status === 'loading' ? (
            <>⏳ Parsing CSV...</>
          ) : (
            <>📁 Choose CSV File</>
          )}
        </button>
      ) : (
        <div style={{
          background: '#052e16',
          border: '1px solid #166534',
          borderRadius: 8,
          padding: '8px 12px',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
        }}>
          <div>
            <div style={{ fontSize: 12, color: '#86efac' }}>
              ✅ {info?.n_features} features loaded
            </div>
            <div style={{ fontSize: 10, color: '#4ade80', fontFamily: 'monospace' }}>
              [{info?.features?.slice(0, 4).map(v => v.toFixed(2)).join(', ')}…]
            </div>
          </div>
          <button
            onClick={handleClear}
            style={{
              background: 'transparent',
              border: 'none',
              color: '#64748b',
              cursor: 'pointer',
              fontSize: 16,
            }}
            title="Remove network features"
          >✕</button>
        </div>
      )}

      {status === 'error' && (
        <div style={{
          marginTop: 8, fontSize: 11,
          color: '#fca5a5', background: '#450a0a',
          border: '1px solid #991b1b',
          borderRadius: 6, padding: '6px 10px',
        }}>
          ❌ {error}
        </div>
      )}

      <input
        ref={fileRef}
        type="file"
        accept=".csv,.txt"
        style={{ display: 'none' }}
        onChange={handleFile}
      />

      <div style={{ marginTop: 8, fontSize: 10, color: '#475569' }}>
        💡 CSV should have one row of numeric values (e.g., exported from Wireshark + feature extractor).
        Enables Layer 1 (Autoencoder anomaly detection).
      </div>
    </div>
  );
}
