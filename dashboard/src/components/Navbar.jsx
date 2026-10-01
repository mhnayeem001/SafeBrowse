import React from 'react';
import { ShieldAlert, Bell, ExternalLink } from 'lucide-react';

export default function Navbar({ activeTab, apiOnline }) {
  const titles = {
    overview: 'Security Operations Overview',
    live: 'Real-Time Threat & Navigation Stream',
    scanner: 'Multi-Signal URL & Domain Scanner',
    lists: 'Global Whitelist & Blacklist Controls',
    rules: 'Adaptive Threat Engine Security Rules',
    reports: 'False Positive & User Feedback Queue',
    health: 'Infrastructure & Service Health Status',
  };

  return (
    <header className="top-navbar">
      <div className="page-title-group">
        <h1>{titles[activeTab] || 'Security Center'}</h1>
      </div>

      <div className="top-actions">
        <span className={`badge ${apiOnline ? 'badge-allow' : 'badge-block'}`}>
          {apiOnline ? 'API Connected' : 'API Offline'}
        </span>
        <a
          href="http://localhost:8000/docs"
          target="_blank"
          rel="noreferrer"
          className="btn-cyber btn-ghost"
          style={{ padding: '6px 12px', fontSize: '12px' }}
        >
          <span>FastAPI Docs</span>
          <ExternalLink size={14} />
        </a>
      </div>
    </header>
  );
}
