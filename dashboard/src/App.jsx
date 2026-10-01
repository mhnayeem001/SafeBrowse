import React, { useState, useEffect } from 'react';
import Sidebar from './components/Sidebar';
import Navbar from './components/Navbar';
import StatsCards from './components/StatsCards';
import LiveFeed from './components/LiveFeed';
import UrlScanner from './components/UrlScanner';
import ListsManager from './components/ListsManager';
import RulesManager from './components/RulesManager';
import ReportsManager from './components/ReportsManager';
import SystemHealth from './components/SystemHealth';

export default function App() {
  const [activeTab, setActiveTab] = useState('overview');
  const [stats, setStats] = useState(null);
  const [apiOnline, setApiOnline] = useState(false);

  useEffect(() => {
    fetchStats();
    const interval = setInterval(fetchStats, 5000);
    return () => clearInterval(interval);
  }, []);

  async function fetchStats() {
    try {
      const res = await fetch('http://localhost:8000/api/v1/stats');
      if (res.ok) {
        const data = await res.json();
        setStats(data);
        setApiOnline(true);
      } else {
        setApiOnline(false);
      }
    } catch (e) {
      setApiOnline(false);
    }
  }

  return (
    <div className="app-container">
      <Sidebar activeTab={activeTab} setActiveTab={setActiveTab} />
      
      <div className="main-wrapper">
        <Navbar activeTab={activeTab} apiOnline={apiOnline} />

        <main className="content-body">
          {/* Always render KPI summary on Overview */}
          {activeTab === 'overview' && (
            <>
              <StatsCards stats={stats} />
              <UrlScanner onScanComplete={fetchStats} />
              <LiveFeed />
            </>
          )}

          {activeTab === 'live' && <LiveFeed />}
          {activeTab === 'scanner' && <UrlScanner onScanComplete={fetchStats} />}
          {activeTab === 'lists' && <ListsManager />}
          {activeTab === 'rules' && <RulesManager />}
          {activeTab === 'reports' && <ReportsManager />}
          {activeTab === 'health' && <SystemHealth />}
        </main>
      </div>
    </div>
  );
}
