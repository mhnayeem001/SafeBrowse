import React, { useState, useEffect } from 'react';
import { Plus, Trash2, ShieldCheck, ShieldBan } from 'lucide-react';

export default function ListsManager() {
  const [activeTab, setActiveTab] = useState('whitelist');
  const [whitelist, setWhitelist] = useState([]);
  const [blacklist, setBlacklist] = useState([]);
  const [newTarget, setNewTarget] = useState('');
  const [newReason, setNewReason] = useState('');
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    fetchLists();
  }, []);

  async function fetchLists() {
    try {
      const [wlRes, blRes] = await Promise.all([
        fetch('http://localhost:8000/api/v1/whitelist'),
        fetch('http://localhost:8000/api/v1/blacklist'),
      ]);
      if (wlRes.ok) setWhitelist(await wlRes.json());
      if (blRes.ok) setBlacklist(await blRes.json());
    } catch (e) {}
  }

  async function handleAdd() {
    if (!newTarget.trim()) return;
    setLoading(true);

    try {
      if (activeTab === 'whitelist') {
        const res = await fetch('http://localhost:8000/api/v1/whitelist', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ domain_or_url: newTarget.trim(), reason: newReason.trim() || 'Added from Dashboard' }),
        });
        if (res.ok) {
          setNewTarget('');
          setNewReason('');
          fetchLists();
        }
      } else {
        const res = await fetch('http://localhost:8000/api/v1/blacklist', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ domain_or_url: newTarget.trim(), reason: newReason.trim() || 'Added from Dashboard', threat_type: 'MALICIOUS' }),
        });
        if (res.ok) {
          setNewTarget('');
          setNewReason('');
          fetchLists();
        }
      }
    } catch (e) {
    } finally {
      setLoading(false);
    }
  }

  async function handleDelete(id, type) {
    try {
      await fetch(`http://localhost:8000/api/v1/${type}/${id}`, { method: 'DELETE' });
      fetchLists();
    } catch (e) {}
  }

  return (
    <div className="card">
      <div className="card-header">
        <div style={{ display: 'flex', gap: '8px' }}>
          <button
            className={`btn-cyber ${activeTab === 'whitelist' ? 'btn-cyan' : 'btn-ghost'}`}
            onClick={() => setActiveTab('whitelist')}
          >
            <ShieldCheck size={16} />
            <span>Global Whitelist ({whitelist.length})</span>
          </button>
          <button
            className={`btn-cyber ${activeTab === 'blacklist' ? 'btn-danger' : 'btn-ghost'}`}
            onClick={() => setActiveTab('blacklist')}
          >
            <ShieldBan size={16} />
            <span>Global Blacklist ({blacklist.length})</span>
          </button>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr auto', gap: '10px' }}>
        <input
          type="text"
          className="input-text"
          placeholder={activeTab === 'whitelist' ? 'Domain or URL to trust (e.g. portal.company.com)' : 'Domain or URL to block (e.g. evil-phish.net)'}
          value={newTarget}
          onChange={(e) => setNewTarget(e.target.value)}
        />
        <input
          type="text"
          className="input-text"
          placeholder="Reason / justification notes..."
          value={newReason}
          onChange={(e) => setNewReason(e.target.value)}
        />
        <button className="btn-cyber btn-cyan" onClick={handleAdd} disabled={loading}>
          <Plus size={16} />
          <span>Add Target</span>
        </button>
      </div>

      <div className="data-table-container">
        <table className="data-table">
          <thead>
            <tr>
              <th>Target Pattern</th>
              <th>Match Type</th>
              <th>Reason</th>
              <th>Added By</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {(activeTab === 'whitelist' ? whitelist : blacklist).length === 0 ? (
              <tr>
                <td colSpan="5" style={{ textAlign: 'center', padding: '24px', color: 'var(--text-muted)' }}>
                  No entries in this list.
                </td>
              </tr>
            ) : (
              (activeTab === 'whitelist' ? whitelist : blacklist).map((item) => (
                <tr key={item.id}>
                  <td className="code-cell">{item.domain_or_url}</td>
                  <td><span className="badge badge-cyan">{item.match_type || 'domain'}</span></td>
                  <td>{item.reason || 'N/A'}</td>
                  <td style={{ fontSize: '12px', color: 'var(--text-muted)' }}>{item.added_by || 'admin'}</td>
                  <td>
                    <button
                      className="btn-cyber btn-ghost"
                      style={{ padding: '4px 8px', color: 'var(--crimson-threat)' }}
                      onClick={() => handleDelete(item.id, activeTab)}
                      title="Delete Entry"
                    >
                      <Trash2 size={14} />
                    </button>
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
