import React, { useState } from 'react';
import { Search, ShieldAlert, CheckCircle, AlertTriangle, ArrowRight, RefreshCw } from 'lucide-react';

export default function UrlScanner({ onScanComplete }) {
  const [targetUrl, setTargetUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const quickSamples = [
    { label: 'Known Safe (Google)', url: 'https://www.google.com/search?q=cybersecurity' },
    { label: 'Brand Spoof (Paypa1)', url: 'http://paypa1-security-verification.xyz/account/login' },
    { label: 'Blacklisted Target', url: 'http://evil-phishing-test.com/login.php' },
    { label: 'Homoglyph (G00gle)', url: 'http://g00gle-security-alert.click' },
  ];

  async function handleScan(urlToScan) {
    const url = urlToScan || targetUrl;
    if (!url.trim()) return;

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const res = await fetch('http://localhost:8000/api/v1/scan/url', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: url.trim(), source: 'dashboard_manual_scanner' }),
      });

      if (!res.ok) {
        throw new Error(`Scan failed with status ${res.status}`);
      }

      const data = await res.json();
      setResult(data);
      if (onScanComplete) onScanComplete();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="card">
      <div className="card-header">
        <div>
          <h2 className="card-title">Threat Intelligence & Deep URL Scanner</h2>
          <p style={{ color: 'var(--text-muted)', fontSize: '13px', marginTop: '2px' }}>
            Inspect URLs and domains in real time against deterministic heuristics, brand spoofing models, and threat feeds.
          </p>
        </div>
      </div>

      <div style={{ display: 'flex', gap: '10px' }}>
        <input
          type="text"
          className="input-text"
          placeholder="Enter URL or domain (e.g. http://paypa1-security-alert.top/verify)..."
          value={targetUrl}
          onChange={(e) => setTargetUrl(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && handleScan()}
        />
        <button
          className="btn-cyber btn-cyan"
          onClick={() => handleScan()}
          disabled={loading}
          style={{ minWidth: '130px' }}
        >
          {loading ? <RefreshCw className="spin" size={16} /> : <Search size={16} />}
          <span>{loading ? 'Analyzing...' : 'Analyze URL'}</span>
        </button>
      </div>

      {/* Quick Test Samples */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
        <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Quick Test Samples:</span>
        {quickSamples.map((s, idx) => (
          <button
            key={idx}
            className="btn-cyber btn-ghost"
            style={{ fontSize: '11px', padding: '4px 10px' }}
            onClick={() => {
              setTargetUrl(s.url);
              handleScan(s.url);
            }}
          >
            {s.label}
          </button>
        ))}
      </div>

      {error && (
        <div style={{ padding: '12px', background: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.3)', borderRadius: '6px', color: '#f87171' }}>
          {error}
        </div>
      )}

      {result && (
        <div className="scan-result-card">
          <div className="scan-result-top">
            <div>
              <span style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.6px' }}>Scan Verdict</span>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginTop: '4px' }}>
                <span className={`badge ${result.decision === 'BLOCK' ? 'badge-block' : (result.decision === 'WARN' ? 'badge-warn' : 'badge-allow')}`} style={{ fontSize: '13px', padding: '4px 12px' }}>
                  {result.decision}
                </span>
                <span style={{ fontSize: '14px', fontWeight: '700', color: 'var(--text-primary)' }}>
                  {result.threat_type || 'NONE'}
                </span>
              </div>
            </div>

            <div style={{ textAlign: 'right' }}>
              <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Execution Latency</span>
              <div style={{ fontSize: '16px', fontWeight: '700', color: 'var(--cyan-primary)' }}>
                {result.latency_ms} ms
              </div>
            </div>
          </div>

          <div className="scan-meta-grid">
            <div className="scan-meta-item">
              <div className="label">Normalized Domain</div>
              <div className="val code-cell">{result.domain}</div>
            </div>
            <div className="scan-meta-item">
              <div className="label">Registered Root Domain</div>
              <div className="val code-cell">{result.registered_domain}</div>
            </div>
            <div className="scan-meta-item">
              <div className="label">Calculated Risk Score</div>
              <div className="val" style={{ color: result.risk_score >= 75 ? 'var(--crimson-threat)' : (result.risk_score >= 40 ? 'var(--amber-warn)' : 'var(--emerald-safe)') }}>
                {result.risk_score} / 100
              </div>
            </div>
            <div className="scan-meta-item">
              <div className="label">Confidence Score</div>
              <div className="val">{result.confidence}%</div>
            </div>
            {result.matched_brand && (
              <div className="scan-meta-item">
                <div className="label">Impersonated Brand</div>
                <div className="val" style={{ color: '#f43f5e' }}>{result.matched_brand}</div>
              </div>
            )}
          </div>

          <div>
            <h4 style={{ fontSize: '13px', fontWeight: '600', marginBottom: '8px' }}>Security Explainability & Findings:</h4>
            <ul style={{ paddingLeft: '20px', display: 'flex', flexDirection: 'column', gap: '4px', fontSize: '13px', color: 'var(--text-secondary)' }}>
              {result.reasons && result.reasons.length > 0 ? (
                result.reasons.map((r, idx) => <li key={idx}>{r}</li>)
              ) : (
                <li>No suspicious signatures found</li>
              )}
            </ul>
          </div>
        </div>
      )}
    </div>
  );
}
