import React from 'react';
import { 
  Shield, Activity, Radio, Search, ListFilter, Sliders, AlertTriangle, Cpu 
} from 'lucide-react';

export default function Sidebar({ activeTab, setActiveTab }) {
  const menuItems = [
    { id: 'overview', label: 'Overview', icon: Shield },
    { id: 'live', label: 'Live Monitor', icon: Radio },
    { id: 'scanner', label: 'Threat Scanner', icon: Search },
    { id: 'lists', label: 'Whitelist & Blacklist', icon: ListFilter },
    { id: 'rules', label: 'Security Rules', icon: Sliders },
    { id: 'reports', label: 'False Positives', icon: AlertTriangle },
    { id: 'health', label: 'System Health', icon: Cpu },
  ];

  return (
    <aside className="sidebar">
      <div className="sidebar-header">
        <img src="/icon48.png" alt="SafeBrowse X" className="brand-logo" />
        <div>
          <div className="brand-title">SafeBrowse <span>X</span></div>
          <div className="brand-subtitle">Security Operations</div>
        </div>
      </div>

      <ul className="nav-links">
        {menuItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <li
              key={item.id}
              className={`nav-item ${isActive ? 'active' : ''}`}
              onClick={() => setActiveTab(item.id)}
            >
              <Icon size={18} />
              <span>{item.label}</span>
            </li>
          );
        })}
      </ul>

      <div className="sidebar-footer">
        <div>
          <span className="status-dot"></span>
          <span>Engine v1.0.0</span>
        </div>
        <span className="badge badge-cyan">ONLINE</span>
      </div>
    </aside>
  );
}
