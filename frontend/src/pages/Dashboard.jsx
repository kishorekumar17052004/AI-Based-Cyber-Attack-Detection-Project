import React, { useState, useEffect, useCallback } from 'react';
import { Trash2 } from 'lucide-react';
import {
  Chart as ChartJS, CategoryScale, LinearScale, PointElement,
  LineElement, Title, Tooltip, Legend, ArcElement, BarElement
} from 'chart.js';
import { Line, Doughnut, Bar } from 'react-chartjs-2';
import { getStats, getModelInfo, clearData } from '../api';
import { useToast } from '../context/ToastContext';

ChartJS.register(
  CategoryScale, LinearScale, PointElement, LineElement,
  Title, Tooltip, Legend, ArcElement, BarElement
);
ChartJS.defaults.color = '#cbd5e1';
ChartJS.defaults.borderColor = 'rgba(59,130,246,0.10)';
ChartJS.defaults.font.family = "'Inter', sans-serif";

const ATTACK_COLORS = {
  'BENIGN': '#10b981',
  'DDoS': '#ef4444',
  'DoS': '#fb7185',
  'Brute Force': '#f59e0b',
  'SQL Injection': '#c084fc',
  'PortScan': '#3b82f6', 'Port Scan': '#3b82f6', 'Probe': '#06b6d4',
  'Bot': '#f472b6',
  'Web Attack': '#e11d48',
  'Infiltration': '#f97316'
};

const ATTACK_CSS = {
  'DDoS': 'ddos', 'DoS': 'dos', 'Brute Force': 'brute-force', 'SQL Injection': 'sql-injection',
  'PortScan': 'portscan', 'Port Scan': 'portscan', 'Probe': 'portscan', 'Web Attack': 'web-attack',
  'Bot': 'bot', 'Infiltration': 'infiltration', 'BENIGN': 'benign'
};

export default function Dashboard() {
  const [stats, setStats] = useState(null);
  const [modelAccuracy, setModelAccuracy] = useState(null);
  const [hours, setHours] = useState(24);
  const { showToast } = useToast();

  const fetchData = useCallback(async () => {
    try {
      const data = await getStats(hours);
      setStats(data);
    } catch (err) {
      console.error('Stats fetch error:', err);
    }
  }, [hours]);

  useEffect(() => {
    const initial = setTimeout(fetchData, 0);
    getModelInfo().then(info => setModelAccuracy(info.accuracy)).catch(() => {});
    const interval = setInterval(fetchData, 10000);
    return () => { clearTimeout(initial); clearInterval(interval); };
  }, [fetchData]);

  const handleClear = async () => {
    if (window.confirm('Clear all prediction and alert data?')) {
      await clearData();
      showToast('All data cleared', 'success');
      fetchData();
    }
  };

  // Doughnut
  const donutData = stats?.attack_breakdown && Object.keys(stats.attack_breakdown).length > 0
    ? {
        labels: Object.keys(stats.attack_breakdown),
        datasets: [{
          data: Object.values(stats.attack_breakdown),
          backgroundColor: Object.keys(stats.attack_breakdown).map(l => ATTACK_COLORS[l] || '#94a3b8'),
          borderWidth: 0, spacing: 3
        }]
      }
    : { labels: ['No Data'], datasets: [{ data: [1], backgroundColor: ['#1f2937'], borderWidth: 0 }] };

  // Timeline
  const timelineData = {
    labels: (stats?.timeline || []).map(t => {
      const parts = t.hour.split('T');
      return parts.length > 1 ? parts[1] + ':00' : t.hour;
    }),
    datasets: [
      {
        label: 'Attacks', data: (stats?.timeline || []).map(t => t.attacks),
        borderColor: '#ef4444', backgroundColor: 'rgba(239,68,68,0.08)',
        fill: true, tension: 0.4, borderWidth: 2, pointRadius: 3, pointBackgroundColor: '#ef4444'
      },
      {
        label: 'Benign', data: (stats?.timeline || []).map(t => t.benign),
        borderColor: '#10b981', backgroundColor: 'rgba(16,185,129,0.08)',
        fill: true, tension: 0.4, borderWidth: 2, pointRadius: 3, pointBackgroundColor: '#10b981'
      }
    ]
  };

  // Severity bar
  const sevData = {
    labels: ['Critical', 'High', 'Medium', 'Low'],
    datasets: [{
      data: [
        stats?.severity_breakdown?.Critical || 0,
        stats?.severity_breakdown?.High || 0,
        stats?.severity_breakdown?.Medium || 0,
        stats?.severity_breakdown?.Low || 0
      ],
      backgroundColor: ['rgba(139,92,246,0.7)', 'rgba(244,63,94,0.7)', 'rgba(245,158,11,0.7)', 'rgba(34,197,94,0.7)'],
      borderColor: ['#8b5cf6', '#f43f5e', '#f59e0b', '#22c55e'],
      borderWidth: 1, borderRadius: 6, barPercentage: 0.6
    }]
  };

  const chartOpts = {
    responsive: true, maintainAspectRatio: false,
    plugins: { legend: { position: 'bottom', labels: { padding: 12, usePointStyle: true, pointStyle: 'circle', font: { size: 10 } } } }
  };

  const lineOpts = {
    ...chartOpts,
    interaction: { mode: 'index', intersect: false },
    scales: {
      x: { grid: { display: false }, ticks: { maxTicksLimit: 8, font: { size: 9 } } },
      y: { beginAtZero: true, grid: { color: 'rgba(59,130,246,0.08)' }, ticks: { font: { size: 10 } } }
    },
    plugins: { legend: { position: 'top', align: 'end', labels: { padding: 15, usePointStyle: true, pointStyle: 'circle', font: { size: 10, weight: 500 } } } }
  };

  const barOpts = {
    ...chartOpts, indexAxis: 'y',
    scales: {
      x: { beginAtZero: true, grid: { color: 'rgba(59,130,246,0.08)' }, ticks: { font: { size: 10 } } },
      y: { grid: { display: false }, ticks: { font: { size: 11, weight: 600 } } }
    },
    plugins: { legend: { display: false } }
  };

  const donutOpts = { ...chartOpts, cutout: '65%' };

  return (
    <div className="animate-in">
      {/* Header */}
      <div className="page-header">
        <div>
          <h1>Security Overview</h1>
          <p>Real-time AI-powered network traffic analysis and threat detection.</p>
        </div>
        <div className="header-right">
          <div className="model-badge">
            <span className="badge-label">Model Accuracy</span>
            <span className="badge-value">
              {modelAccuracy ? `${(modelAccuracy * 100).toFixed(1)}%` : 'N/A'}
            </span>
          </div>
          <div className="status-badge">
            <div className="status-dot"></div>
            System Active
          </div>
          <button className="btn-icon" onClick={handleClear} title="Clear Data">
            <Trash2 size={16} />
          </button>
        </div>
      </div>

      {/* Stats Cards */}
      <section className="stats-grid">
        <div className="card stat-card">
          <div className="stat-icon total">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="20" height="20">
              <path d="M22 12h-4l-3 9L9 3l-3 9H2"/>
            </svg>
          </div>
          <span className="stat-value">{(stats?.total_analyzed || 0).toLocaleString()}</span>
          <span className="stat-label">Total Analyzed</span>
        </div>
        <div className="card stat-card">
          <div className="stat-icon attacks">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="20" height="20">
              <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
              <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
            </svg>
          </div>
          <span className="stat-value">{(stats?.attacks_detected || 0).toLocaleString()}</span>
          <span className="stat-label">Attacks Detected</span>
        </div>
        <div className="card stat-card">
          <div className="stat-icon benign">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="20" height="20">
              <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
              <polyline points="22 4 12 14.01 9 11.01"/>
            </svg>
          </div>
          <span className="stat-value">{(stats?.benign_traffic || 0).toLocaleString()}</span>
          <span className="stat-label">Benign Traffic</span>
        </div>
        <div className="card stat-card">
          <div className="stat-icon rate">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="20" height="20">
              <circle cx="12" cy="12" r="10"/>
              <polyline points="12 6 12 12 16 14"/>
            </svg>
          </div>
          <span className="stat-value">{(stats?.high_severity_count || 0).toLocaleString()}</span>
          <span className="stat-label">High / Critical Severity</span>
        </div>
      </section>

      {/* Charts */}
      <section className="charts-grid">
        <div className="card">
          <div className="card-header">
            <h2>Attack Distribution</h2>
            <select className="select-control" value={hours} onChange={e => setHours(Number(e.target.value))}>
              <option value={1}>Last 1 Hour</option>
              <option value={6}>Last 6 Hours</option>
              <option value={24}>Last 24 Hours</option>
              <option value={168}>Last 7 Days</option>
            </select>
          </div>
          <div className="card-body chart-container">
            <Doughnut data={donutData} options={donutOpts} />
          </div>
        </div>
        <div className="card">
          <div className="card-header"><h2>Traffic Timeline</h2></div>
          <div className="card-body chart-container">
            <Line data={timelineData} options={lineOpts} />
          </div>
        </div>
        <div className="card">
          <div className="card-header"><h2>Severity Breakdown</h2></div>
          <div className="card-body chart-container">
            <Bar data={sevData} options={barOpts} />
          </div>
        </div>
      </section>

      {/* Alerts + Top Attackers */}
      <section style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
        {/* Recent Alerts */}
        <div className="card alerts-card">
          <div className="card-header">
            <h2>Live Alerts</h2>
            <span className="alert-count">{stats?.recent_alerts?.length || 0}</span>
          </div>
          <div className="card-body">
            <div className="alerts-list">
              {(!stats?.recent_alerts || stats.recent_alerts.length === 0) ? (
                <div className="empty-state">
                  <p>No alerts yet. Run a simulation to detect threats.</p>
                </div>
              ) : stats.recent_alerts.slice(0, 15).map((alert, i) => (
                <div key={alert.id || i} className="alert-item">
                  <span className={`alert-severity-dot ${alert.severity?.toLowerCase()}`}></span>
                  <div className="alert-content">
                    <div className="alert-message">{alert.message}</div>
                    <div className="alert-meta">{new Date(alert.timestamp).toLocaleTimeString()}</div>
                  </div>
                  <span className={`alert-badge ${ATTACK_CSS[alert.alert_type] || 'benign'}`}>
                    {alert.alert_type}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Top Attackers */}
        <div className="card">
          <div className="card-header"><h2>Top Threat Sources</h2></div>
          <div className="card-body">
            <table className="data-table">
              <thead>
                <tr><th>Rank</th><th>Source IP</th><th>Attacks</th><th>Threat Level</th></tr>
              </thead>
              <tbody>
                {(!stats?.top_attackers || stats.top_attackers.length === 0) ? (
                  <tr><td colSpan="4" style={{ textAlign: 'center', color: 'var(--text-muted)' }}>No threat data available</td></tr>
                ) : stats.top_attackers.map((attacker, idx) => {
                  const maxCount = stats.top_attackers[0].count;
                  const ratio = attacker.count / maxCount;
                  let level, levelClass;
                  if (ratio > 0.75) { level = 'Critical'; levelClass = 'critical'; }
                  else if (ratio > 0.5) { level = 'High'; levelClass = 'high'; }
                  else if (ratio > 0.25) { level = 'Medium'; levelClass = 'medium'; }
                  else { level = 'Low'; levelClass = 'low'; }
                  return (
                    <tr key={idx}>
                      <td style={{ fontWeight: 700, color: 'var(--text-muted)' }}>#{idx + 1}</td>
                      <td style={{ fontFamily: "'JetBrains Mono'", fontWeight: 500 }}>{attacker.ip}</td>
                      <td style={{ fontFamily: "'JetBrains Mono'", fontWeight: 600 }}>{attacker.count}</td>
                      <td>
                        <span className={`threat-level ${levelClass}`}>
                          <span className="threat-dot"></span>
                          {level}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      </section>
    </div>
  );
}
