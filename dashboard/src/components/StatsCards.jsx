import React from 'react';
import { ShieldCheck, ShieldAlert, AlertTriangle, Zap, CheckCircle2, Flag } from 'lucide-react';

export default function StatsCards({ stats }) {
  const cards = [
    {
      title: 'Total Scans',
      value: stats?.total_scans ?? 0,
      sub: 'Pre-navigation & DOM checks',
      icon: Zap,
      color: 'var(--cyan-primary)',
    },
    {
      title: 'Threats Blocked',
      value: stats?.threats_blocked ?? 0,
      sub: 'Phishing, spoofing, & malware',
      icon: ShieldAlert,
      color: 'var(--crimson-threat)',
    },
    {
      title: 'Warnings Issued',
      value: stats?.warnings_issued ?? 0,
      sub: 'Elevated risk websites',
      icon: AlertTriangle,
      color: 'var(--amber-warn)',
    },
    {
      title: 'Safe Requests',
      value: stats?.safe_requests ?? 0,
      sub: 'Clean navigational traffic',
      icon: CheckCircle2,
      color: 'var(--emerald-safe)',
    },
    {
      title: 'Average Latency',
      value: `${stats?.avg_latency_ms ? stats.avg_latency_ms.toFixed(1) : '0.0'} ms`,
      sub: 'Sub-second real-time scoring',
      icon: ShieldCheck,
      color: 'var(--blue-primary)',
    },
    {
      title: 'User Reports',
      value: stats?.false_positive_reports ?? 0,
      sub: 'False-positive feedback queue',
      icon: Flag,
      color: 'var(--purple-accent)',
    },
  ];

  return (
    <div className="kpi-grid">
      {cards.map((c, i) => {
        const Icon = c.icon;
        return (
          <div key={i} className="kpi-card">
            <div className="kpi-top">
              <span>{c.title}</span>
              <Icon size={18} style={{ color: c.color }} />
            </div>
            <div className="kpi-value">{c.value}</div>
            <div className="kpi-sub">{c.sub}</div>
          </div>
        );
      })}
    </div>
  );
}
