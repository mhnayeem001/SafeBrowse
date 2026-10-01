import React, { useState, useEffect } from 'react';
import { AlertCircle, CheckCircle2, XCircle } from 'lucide-react';

export default function ReportsManager() {
  const [reports, setReports] = useState([]);

  useEffect(() => {
    fetchReports();
  }, []);

  async function fetchReports() {
    try {
      const res = await fetch('http://localhost:8000/api/v1/reports');
      if (res.ok) {
        setReports(await res.json());
      }
    } catch (e) {}
  }

  return (
    <div className="card">
      <div className="card-header">
        <div>
          <h2 className="card-title">False Positive & User Report Review Queue</h2>
          <p style={{ color: 'var(--text-muted)', fontSize: '13px', marginTop: '2px' }}>
            Review sites flagged incorrectly by heuristic engines to prevent false positives and refine models.
          </p>
        </div>
      </div>

      <div className="data-table-container">
        <table className="data-table">
          <thead>
            <tr>
              <th>Report ID</th>
              <th>Reported URL / Domain</th>
              <th>Original Verdict</th>
              <th>Threat Type</th>
              <th>User Notes</th>
              <th>Status</th>
              <th>Timestamp</th>
            </tr>
          </thead>
          <tbody>
            {reports.length === 0 ? (
              <tr>
                <td colSpan="7" style={{ textAlign: 'center', padding: '32px', color: 'var(--text-muted)' }}>
                  No false-positive reports submitted yet. Clean accuracy baseline maintained.
                </td>
              </tr>
            ) : (
              reports.map((r) => (
                <tr key={r.id}>
                  <td className="code-cell">{r.report_id}</td>
                  <td className="code-cell">{r.domain || r.url}</td>
                  <td><span className="badge badge-block">{r.original_verdict}</span></td>
                  <td>{r.threat_type || 'N/A'}</td>
                  <td>{r.user_notes || 'No comments provided'}</td>
                  <td><span className="badge badge-warn">{r.status}</span></td>
                  <td style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                    {new Date(r.created_at).toLocaleString()}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
