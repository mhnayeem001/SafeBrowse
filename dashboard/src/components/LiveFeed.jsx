import React, { useState, useEffect, useRef } from 'react';
import { Radio, Filter, Pause, Play, Trash2 } from 'lucide-react';

export default function LiveFeed({ initialEvents = [] }) {
  const [events, setEvents] = useState(initialEvents);
  const [filter, setFilter] = useState('ALL');
  const [isPaused, setIsPaused] = useState(false);
  const [wsConnected, setWsConnected] = useState(false);
  const wsRef = useRef(null);

  useEffect(() => {
    // Initial fetch of recent events
    fetch('http://localhost:8000/api/v1/events?limit=30')
      .then((res) => res.json())
      .then((data) => {
        if (Array.isArray(data)) {
          setEvents(data);
        }
      })
      .catch(() => {});

    // WebSocket connection
    function connectWs() {
      try {
        const ws = new WebSocket('ws://localhost:8000/api/v1/events/ws');
        wsRef.current = ws;

        ws.onopen = () => {
          setWsConnected(true);
        };

        ws.onmessage = (msg) => {
          if (isPaused) return;
          try {
            const data = JSON.parse(msg.data);
            if (data.type === 'SCAN_EVENT') {
              setEvents((prev) => [data, ...prev.slice(0, 99)]);
            }
          } catch (e) {}
        };

        ws.onclose = () => {
          setWsConnected(false);
          // Reconnect after 3s
          setTimeout(connectWs, 3000);
        };

        ws.onerror = () => {
          setWsConnected(false);
        };
      } catch (e) {
        setWsConnected(false);
      }
    }

    connectWs();

    return () => {
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, [isPaused]);

  const filteredEvents = events.filter((ev) => {
    if (filter === 'ALL') return true;
    return ev.decision === filter;
  });

  return (
    <div className="card">
      <div className="card-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <Radio size={18} style={{ color: wsConnected ? 'var(--emerald-safe)' : 'var(--crimson-threat)' }} />
          <h2 className="card-title">Live Security Telemetry Stream</h2>
          <span className={`badge ${wsConnected ? 'badge-allow' : 'badge-warn'}`}>
            {wsConnected ? 'LIVE STREAM' : 'RECONNECTING'}
          </span>
        </div>

        <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
          <select
            className="input-text"
            style={{ width: '130px', padding: '6px 10px', fontSize: '12px' }}
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
          >
            <option value="ALL">All Events</option>
            <option value="BLOCK">Blocked Only</option>
            <option value="WARN">Warnings Only</option>
            <option value="ALLOW">Allowed Only</option>
          </select>

          <button
            className="btn-cyber btn-ghost"
            style={{ padding: '6px 12px' }}
            onClick={() => setIsPaused(!isPaused)}
          >
            {isPaused ? <Play size={14} /> : <Pause size={14} />}
            <span>{isPaused ? 'Resume' : 'Pause'}</span>
          </button>

          <button
            className="btn-cyber btn-ghost"
            style={{ padding: '6px 12px' }}
            onClick={() => setEvents([])}
            title="Clear Feed"
          >
            <Trash2 size={14} />
          </button>
        </div>
      </div>

      <div className="data-table-container" style={{ maxHeight: '500px' }}>
        <table className="data-table">
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Verdict</th>
              <th>Domain</th>
              <th>Threat Type</th>
              <th>Risk Score</th>
              <th>Latency</th>
              <th>Reason</th>
            </tr>
          </thead>
          <tbody>
            {filteredEvents.length === 0 ? (
              <tr>
                <td colSpan="7" style={{ textAlign: 'center', padding: '32px', color: 'var(--text-muted)' }}>
                  No telemetry events received yet. Active extension scans will appear here in real time.
                </td>
              </tr>
            ) : (
              filteredEvents.map((ev, i) => {
                const isBlock = ev.decision === 'BLOCK';
                const isWarn = ev.decision === 'WARN';
                const badgeClass = isBlock ? 'badge-block' : (isWarn ? 'badge-warn' : 'badge-allow');
                const timeStr = ev.timestamp ? new Date(ev.timestamp).toLocaleTimeString() : 'Just now';

                return (
                  <tr key={i}>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '11px' }}>{timeStr}</td>
                    <td>
                      <span className={`badge ${badgeClass}`}>{ev.decision}</span>
                    </td>
                    <td className="code-cell" style={{ maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                      {ev.domain}
                    </td>
                    <td>{ev.threat_type || 'NONE'}</td>
                    <td style={{ fontWeight: '600' }}>{ev.risk_score}/100</td>
                    <td style={{ color: 'var(--text-muted)' }}>{ev.latency_ms ? `${ev.latency_ms} ms` : '<10ms'}</td>
                    <td style={{ maxWidth: '300px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {ev.reasons && ev.reasons.length > 0 ? ev.reasons[0] : 'Clean request'}
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
