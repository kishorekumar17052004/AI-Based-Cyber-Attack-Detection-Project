import React, { useState, useEffect } from 'react';
import { AlertTriangle } from 'lucide-react';
import { getAlerts } from '../api';

const ATTACK_CSS = {
  'DDoS': 'ddos', 'DoS': 'dos', 'Brute Force': 'brute-force', 'SQL Injection': 'sql-injection',
  'PortScan': 'portscan', 'Port Scan': 'portscan', 'Probe': 'portscan', 'Web Attack': 'web-attack',
  'Bot': 'bot', 'Infiltration': 'infiltration', 'BENIGN': 'benign'
};

export default function ThreatAlerts() {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);

  const fetchAlerts = async () => {
    try {
      const data = await getAlerts(100);
      setAlerts(data?.alerts || []);
    } catch (err) {
      console.error('Alerts fetch error:', err);
    }
    setLoading(false);
  };

  useEffect(() => {
    const initial = setTimeout(fetchAlerts, 0);
    const interval = setInterval(fetchAlerts, 5000);
    return () => { clearTimeout(initial); clearInterval(interval); };
  }, []);

  const highCount = alerts.filter(a => a.severity === 'High').length;
  const mediumCount = alerts.filter(a => a.severity === 'Medium').length;

  return (
    <div className="animate-in">
      <div className="page-header">
        <div>
          <h1>Attack Logs</h1>
          <p>Complete log of detected threats and security events.</p>
        </div>
        <div className="header-right">
          <div style={{ display: 'flex', gap: '12px' }}>
            <div className="status-badge" style={{ background: 'rgba(239,68,68,0.1)', borderColor: 'rgba(239,68,68,0.2)', color: '#ef4444' }}>
              <AlertTriangle size={14} /> {highCount} High
            </div>
            <div className="status-badge" style={{ background: 'rgba(245,158,11,0.1)', borderColor: 'rgba(245,158,11,0.2)', color: '#f59e0b' }}>
              {mediumCount} Medium
            </div>
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <h2>All Alerts ({alerts.length})</h2>
        </div>
        <div className="card-body">
          {loading ? (
            <div className="empty-state"><p>Loading alerts...</p></div>
          ) : alerts.length === 0 ? (
            <div className="empty-state">
              <AlertTriangle size={40} style={{ opacity: 0.3 }} />
              <p style={{ marginTop: '12px' }}>No alerts yet. Start an authorized capture or run a simulation to generate data.</p>
            </div>
          ) : (
            <table className="data-table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Type</th>
                  <th>Severity</th>
                  <th>Source IP</th>
                  <th>Destination IP</th>
                  <th>Message</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map((alert, i) => (
                  <tr key={alert.id || i}>
                    <td style={{ fontFamily: "'JetBrains Mono'", fontSize: '11px', whiteSpace: 'nowrap' }}>
                      {new Date(alert.timestamp).toLocaleString()}
                    </td>
                    <td>
                      <span className={`alert-badge ${ATTACK_CSS[alert.alert_type] || 'benign'}`}>
                        {alert.alert_type}
                      </span>
                    </td>
                    <td>
                      <span className={`threat-level ${alert.severity?.toLowerCase()}`}>
                        <span className="threat-dot"></span>
                        {alert.severity}
                      </span>
                    </td>
                    <td style={{ fontFamily: "'JetBrains Mono'", fontSize: '12px' }}>{alert.source_ip}</td>
                    <td style={{ fontFamily: "'JetBrains Mono'", fontSize: '12px' }}>{alert.destination_ip}</td>
                    <td style={{ fontSize: '12px', color: 'var(--text-secondary)', maxWidth: '300px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {alert.message}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
}
