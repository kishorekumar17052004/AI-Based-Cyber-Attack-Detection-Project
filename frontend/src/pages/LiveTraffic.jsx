import React, { useState, useEffect, useRef, useCallback } from 'react';
import { Play, Pause, Upload } from 'lucide-react';
import { simulate, predict, getFeatureNames, predictBatchCSV } from '../api';
import { useToast } from '../context/ToastContext';

const ATTACK_COLORS_MAP = {
  'BENIGN': '#10b981', 'DDoS': '#ef4444', 'Brute Force': '#f59e0b',
  'DoS': '#fb7185', 'SQL Injection': '#8b5cf6', 'PortScan': '#3b82f6',
  'Port Scan': '#3b82f6', 'Probe': '#06b6d4', 'Web Attack': '#e11d48',
  'Bot': '#f472b6', 'Infiltration': '#f97316'
};

export default function LiveTraffic() {
  const [attackType, setAttackType] = useState('');
  const [count, setCount] = useState(5);
  const [simStatus, setSimStatus] = useState({ status: 'idle', text: 'Awaiting simulation...' });
  const [isAutoSim, setIsAutoSim] = useState(false);
  const [results, setResults] = useState([]);
  const [latestResult, setLatestResult] = useState(null);
  const [featureNames, setFeatureNames] = useState([]);
  const [activeTab, setActiveTab] = useState('form');
  const [csvFile, setCsvFile] = useState(null);
  const autoRef = useRef(null);
  const { showToast } = useToast();

  useEffect(() => {
    getFeatureNames().then(data => {
      if (data?.feature_names) setFeatureNames(data.feature_names);
    }).catch(() => {});
  }, []);

  const runSimulation = useCallback(async () => {
    setSimStatus({ status: 'running', text: 'Analyzing traffic...' });
    try {
      const data = await simulate(count, attackType || null);
      if (!data || data.error) {
        setSimStatus({ status: 'error', text: 'Simulation failed' });
        showToast('Simulation failed. Is the backend running?', 'error');
        return;
      }
      const attacks = data.results.filter(r => r.is_attack);
      setResults(prev => [...data.results, ...prev].slice(0, 200));
      setLatestResult(data.results[data.results.length - 1]);
      setSimStatus({ status: 'idle', text: `Analyzed ${data.count} packets — ${attacks.length} threats detected` });

      if (attacks.length > 0) {
        showToast(`⚠️ ${attacks.length} attack(s) detected!`, 'warning');
      } else {
        showToast(`✅ ${data.count} packets — all clear`, 'success');
      }
    } catch {
      setSimStatus({ status: 'error', text: 'Simulation failed' });
      showToast('Simulation failed', 'error');
    }
  }, [count, attackType, showToast]);

  const toggleAutoSim = () => {
    if (isAutoSim) {
      clearInterval(autoRef.current);
      autoRef.current = null;
      setIsAutoSim(false);
      setSimStatus({ status: 'idle', text: 'Auto-simulation stopped' });
      showToast('Auto-simulation stopped', 'info');
    } else {
      setIsAutoSim(true);
      setSimStatus({ status: 'running', text: 'Auto-simulating traffic...' });
      showToast('Auto-simulation started', 'info');
      runSimulation();
      autoRef.current = setInterval(runSimulation, 3000);
    }
  };

  useEffect(() => {
    return () => { if (autoRef.current) clearInterval(autoRef.current); };
  }, []);

  // Manual form submission
  const handleManualSubmit = async (e) => {
    e.preventDefault();
    const formData = new FormData(e.target);
    const features = {};
    featureNames.forEach(name => { features[name] = parseFloat(formData.get(name)) || 0; });

    try {
      const data = await predict(features);
      if (data && !data.error) {
        setLatestResult(data);
        setResults(prev => [data, ...prev].slice(0, 200));
        if (data.is_attack) {
          showToast(`🚨 ${data.predicted_label} detected! (${data.confidence}%)`, 'warning');
        } else {
          showToast(`✅ BENIGN (${data.confidence}%)`, 'success');
        }
      }
    } catch {
      showToast('Analysis failed', 'error');
    }
  };

  const randomFill = () => {
    featureNames.forEach((name, i) => {
      const input = document.getElementById(`feat-${i}`);
      if (input) {
        if (name.includes('psh_flag')) input.value = Math.round(Math.random());
        else if (name.includes('rate')) input.value = Math.round(Math.random() * 1000000);
        else if (name.includes('IAT') || name === 'duration') input.value = Math.round(Math.random() * 30000000);
        else if (name.includes('packets')) input.value = Math.round(Math.random() * 500);
        else input.value = Math.round(Math.random() * 50000);
      }
    });
    showToast('Form filled with random values', 'info');
  };

  // CSV Upload
  const handleCSV = async () => {
    if (!csvFile) return;
    showToast('Analyzing CSV...', 'info');
    try {
      const data = await predictBatchCSV(csvFile);
      if (data) {
        showToast(`Analyzed ${data.total_analyzed} — ${data.attacks_detected} attacks`, data.attacks_detected > 0 ? 'warning' : 'success');
        setResults(prev => [...(data.results || []), ...prev].slice(0, 200));
      }
    } catch {
      showToast('CSV analysis failed', 'error');
    }
    setCsvFile(null);
  };

  // Confidence ring
  const circumference = 2 * Math.PI * 42;
  const confidence = latestResult?.confidence || 0;
  const offset = circumference - (confidence / 100) * circumference;
  const ringColor = latestResult?.is_attack ? '#ef4444' : '#10b981';

  return (
    <div className="animate-in">
      <div className="page-header">
        <div>
          <h1>Model Prediction Result</h1>
          <p>Generate and analyze simulated network traffic in real-time.</p>
        </div>
        <div className="status-badge">
          <div className="status-dot"></div>
          System Active
        </div>
      </div>

      <section className="action-grid">
        {/* Simulation Controls */}
        <div className="card">
          <div className="card-header"><h2><Play size={16} /> Live Simulation</h2></div>
          <div className="card-body">
            <div className="sim-controls">
              <div className="form-group">
                <label>Attack Type</label>
                <select className="select-control" value={attackType} onChange={e => setAttackType(e.target.value)}>
                  <option value="">Random Mix</option>
                  <option value="BENIGN">BENIGN</option>
                  <option value="DDoS">DDoS</option>
                  <option value="DoS">DoS</option>
                  <option value="Brute Force">Brute Force</option>
                  <option value="SQL Injection">SQL Injection</option>
                  <option value="PortScan">PortScan</option>
                  <option value="Probe">Probe</option>
                  <option value="Web Attack">Web Attack</option>
                  <option value="Bot">Bot</option>
                  <option value="Infiltration">Infiltration</option>
                </select>
              </div>
              <div className="form-group">
                <label>Samples</label>
                <input type="number" className="input-control" value={count} min={1} max={50} onChange={e => setCount(Number(e.target.value))} />
              </div>
              <div className="sim-buttons">
                <button className="btn btn-primary" onClick={runSimulation}>
                  <Play size={14} /> Simulate
                </button>
                <button className={`btn btn-accent ${isAutoSim ? 'active' : ''}`} onClick={toggleAutoSim}>
                  {isAutoSim ? <><Pause size={14} /> Stop</> : <><Play size={14} /> Auto</>}
                </button>
              </div>
              <div className="sim-status">
                <span className={`status-indicator ${simStatus.status}`}></span>
                <span>{simStatus.text}</span>
              </div>
            </div>
          </div>
        </div>

        {/* Manual Input */}
        <div className="card">
          <div className="card-header"><h2>Manual Analysis</h2></div>
          <div className="card-body">
            <div className="manual-tabs">
              <button className={`tab-btn ${activeTab === 'form' ? 'active' : ''}`} onClick={() => setActiveTab('form')}>Form Input</button>
              <button className={`tab-btn ${activeTab === 'csv' ? 'active' : ''}`} onClick={() => setActiveTab('csv')}>CSV Upload</button>
            </div>

            <div className={`tab-content ${activeTab === 'form' ? 'active' : ''}`}>
              <form onSubmit={handleManualSubmit}>
                <div className="feature-grid">
                  {featureNames.map((name, i) => (
                    <div className="feature-input" key={i}>
                      <label htmlFor={`feat-${i}`} title={name}>{name}</label>
                      <input type="number" id={`feat-${i}`} name={name} step="any" defaultValue="0" />
                    </div>
                  ))}
                </div>
                <div className="form-actions">
                  <button type="button" className="btn btn-secondary" onClick={randomFill}>Random Fill</button>
                  <button type="submit" className="btn btn-primary">Analyze</button>
                </div>
              </form>
            </div>

            <div className={`tab-content ${activeTab === 'csv' ? 'active' : ''}`}>
              <div
                className={`upload-area ${csvFile ? 'has-file' : ''}`}
                onClick={() => document.getElementById('csv-input').click()}
                onDragOver={e => { e.preventDefault(); e.currentTarget.classList.add('dragover'); }}
                onDragLeave={e => e.currentTarget.classList.remove('dragover')}
                onDrop={e => { e.preventDefault(); e.currentTarget.classList.remove('dragover'); if (e.dataTransfer.files[0]) setCsvFile(e.dataTransfer.files[0]); }}
              >
                <Upload size={32} />
                <p>{csvFile ? `📄 ${csvFile.name}` : <>Drag & drop CSV or <span className="link">browse</span></>}</p>
                <input type="file" id="csv-input" accept=".csv" hidden onChange={e => setCsvFile(e.target.files[0])} />
              </div>
              <button className="btn btn-primary" disabled={!csvFile} onClick={handleCSV}>Analyze CSV</button>
            </div>
          </div>
        </div>

        {/* Latest Result */}
        <div className="card">
          <div className="card-header"><h2>Latest Detection</h2></div>
          <div className="card-body">
            {!latestResult ? (
              <div className="empty-state"><p>Run a simulation to see results.</p></div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '16px' }}>
                <div className={`result-label-wrapper ${latestResult.is_attack ? 'attack' : 'benign'}`}>
                  <span className="result-label-text">{latestResult.predicted_label}</span>
                  <span className={`result-severity ${latestResult.severity?.toLowerCase()}`}>{latestResult.severity}</span>
                </div>
                <div className="confidence-ring">
                  <svg viewBox="0 0 100 100">
                    <circle className="ring-bg" cx="50" cy="50" r="42" />
                    <circle className="ring-fill" cx="50" cy="50" r="42"
                      style={{ strokeDasharray: circumference, strokeDashoffset: offset, stroke: ringColor }} />
                  </svg>
                  <span className="confidence-value" style={{ color: ringColor }}>{confidence.toFixed(1)}%</span>
                </div>
                <span className="confidence-label">Confidence</span>
                <div style={{ width: '100%', fontSize: '12px' }}>
                  <div className="detail-row"><span className="detail-label">Source</span><span className="detail-value">{latestResult.source_ip || 'N/A'}</span></div>
                  <div className="detail-row"><span className="detail-label">Dest</span><span className="detail-value">{latestResult.destination_ip || 'N/A'}</span></div>
                  <div className="detail-row"><span className="detail-label">Protocol</span><span className="detail-value">{latestResult.protocol || 'N/A'}</span></div>
                </div>

                {latestResult.class_probabilities && (
                  <div className="prob-bars" style={{ width: '100%' }}>
                    {Object.entries(latestResult.class_probabilities).sort((a, b) => b[1] - a[1]).map(([label, prob]) => (
                      <div className="prob-bar-item" key={label}>
                        <span className="prob-bar-label">{label}</span>
                        <div className="prob-bar-track">
                          <div className="prob-bar-fill" style={{ width: `${prob}%`, background: ATTACK_COLORS_MAP[label] || '#94a3b8' }}></div>
                        </div>
                        <span className="prob-bar-value">{prob.toFixed(1)}%</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </section>

      {/* Traffic Log */}
      {results.length > 0 && (
        <section style={{ marginTop: '24px' }}>
          <div className="card">
            <div className="card-header"><h2>Traffic Log ({results.length})</h2></div>
            <div className="card-body">
              <table className="data-table">
                <thead>
                  <tr><th>Time</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Prediction</th><th>Confidence</th><th>Severity</th></tr>
                </thead>
                <tbody>
                  {results.slice(0, 50).map((r, i) => (
                    <tr key={i}>
                      <td style={{ fontFamily: "'JetBrains Mono'", fontSize: '11px' }}>{new Date(r.timestamp).toLocaleTimeString()}</td>
                      <td style={{ fontFamily: "'JetBrains Mono'", fontSize: '11px' }}>{r.source_ip || 'N/A'}</td>
                      <td style={{ fontFamily: "'JetBrains Mono'", fontSize: '11px' }}>{r.destination_ip || 'N/A'}</td>
                      <td>{r.protocol || 'TCP'}</td>
                      <td>
                        <span style={{ color: ATTACK_COLORS_MAP[r.predicted_label] || '#cbd5e1', fontWeight: 600 }}>
                          {r.predicted_label}
                        </span>
                      </td>
                      <td style={{ fontFamily: "'JetBrains Mono'" }}>{r.confidence?.toFixed(1)}%</td>
                      <td>
                        <span className={`threat-level ${r.severity?.toLowerCase()}`}>
                          <span className="threat-dot"></span>
                          {r.severity}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </section>
      )}
    </div>
  );
}
