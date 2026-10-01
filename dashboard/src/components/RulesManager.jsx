import React, { useState, useEffect } from 'react';
import { Sliders, Check, Shield } from 'lucide-react';

export default function RulesManager() {
  const [rules, setRules] = useState([]);

  useEffect(() => {
    fetchRules();
  }, []);

  async function fetchRules() {
    try {
      const res = await fetch('http://localhost:8000/api/v1/rules');
      if (res.ok) {
        setRules(await res.json());
      }
    } catch (e) {}
  }

  async function handleToggle(ruleCode) {
    try {
      const res = await fetch(`http://localhost:8000/api/v1/rules/${ruleCode}/toggle`, {
        method: 'POST',
      });
      if (res.ok) {
        fetchRules();
      }
    } catch (e) {}
  }

  return (
    <div className="card">
      <div className="card-header">
        <div>
          <h2 className="card-title">Adaptive Threat Rules & Heuristic Shields</h2>
          <p style={{ color: 'var(--text-muted)', fontSize: '13px', marginTop: '2px' }}>
            Enable or disable specific threat detection engines and heuristic policies in real time.
          </p>
        </div>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
        {rules.map((rule) => (
          <div
            key={rule.rule_code}
            style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              padding: '16px 20px',
              background: 'var(--bg-card-inner)',
              border: '1px solid var(--border-subtle)',
              borderRadius: '8px',
            }}
          >
            <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span className="badge badge-cyan">{rule.rule_code}</span>
                <strong style={{ fontSize: '14px', color: 'var(--text-primary)' }}>{rule.rule_name}</strong>
                <span className={`badge ${rule.severity === 'CRITICAL' ? 'badge-block' : 'badge-warn'}`}>
                  {rule.severity}
                </span>
              </div>
              <p style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>{rule.description}</p>
            </div>

            <label className="toggle-switch">
              <input
                type="checkbox"
                checked={rule.is_enabled}
                onChange={() => handleToggle(rule.rule_code)}
              />
              <span className="toggle-slider"></span>
            </label>
          </div>
        ))}
      </div>
    </div>
  );
}
