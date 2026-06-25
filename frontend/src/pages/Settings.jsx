import React, { useState, useEffect } from 'react';
import { Settings as SettingsIcon, CheckCircle, XCircle } from 'lucide-react';
import { getHealth, getModelInfo } from '../api';

export default function SettingsPage() {
  const [health, setHealth] = useState(null);
  const [modelInfo, setModelInfo] = useState(null);

  useEffect(() => {
    getHealth().then(setHealth).catch(() => setHealth({ status: 'error' }));
    getModelInfo().then(setModelInfo).catch(() => setModelInfo(null));
  }, []);

  return (
    <div className="animate-in">
      <div className="page-header">
        <div>
          <h1>System Settings</h1>
          <p>Monitor service health and system configuration.</p>
        </div>
      </div>

      <section style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', marginBottom: '24px' }}>
        {/* Service Status */}
        <div className="card">
          <div className="card-header"><h2>Service Status</h2></div>
          <div className="card-body">
            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              <div className="detail-row">
                <span className="detail-label">Express Backend</span>
                <span className="detail-value" style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                  {health?.status === 'ok'
                    ? <><CheckCircle size={14} color="#10b981" /> Running</>
                    : <><XCircle size={14} color="#ef4444" /> Offline</>
                  }
                </span>
              </div>
              <div className="detail-row">
                <span className="detail-label">MongoDB</span>
                <span className="detail-value" style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                  {health?.database === 'connected'
                    ? <><CheckCircle size={14} color="#10b981" /> Connected</>
                    : <><XCircle size={14} color="#ef4444" /> Disconnected</>
                  }
                </span>
              </div>
              <div className="detail-row">
                <span className="detail-label">ML Microservice (Python)</span>
                <span className="detail-value" style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                  {health?.model_loaded
                    ? <><CheckCircle size={14} color="#10b981" /> Model Loaded</>
                    : <><XCircle size={14} color="#f59e0b" /> Not Running</>
                  }
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* Model Info */}
        <div className="card">
          <div className="card-header"><h2>Model Information</h2></div>
          <div className="card-body">
            {modelInfo ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                <div className="detail-row">
                  <span className="detail-label">Model Type</span>
                  <span className="detail-value">{modelInfo.model_type}</span>
                </div>
                <div className="detail-row">
                  <span className="detail-label">Features</span>
                  <span className="detail-value">{modelInfo.n_features}</span>
                </div>
                <div className="detail-row">
                  <span className="detail-label">Classes</span>
                  <span className="detail-value">{modelInfo.n_classes} ({modelInfo.classes?.join(', ')})</span>
                </div>
                <div className="detail-row">
                  <span className="detail-label">Accuracy</span>
                  <span className="detail-value" style={{ color: '#10b981' }}>{(modelInfo.accuracy * 100).toFixed(2)}%</span>
                </div>
                <div className="detail-row">
                  <span className="detail-label">F1 Score</span>
                  <span className="detail-value">{(modelInfo.f1_score * 100).toFixed(2)}%</span>
                </div>
              </div>
            ) : (
              <div className="empty-state">
                <p>ML service not available. Start the Python microservice to see model info.</p>
              </div>
            )}
          </div>
        </div>
      </section>

      {/* Architecture Info */}
      <div className="card">
        <div className="card-header"><h2>Architecture</h2></div>
        <div className="card-body" style={{ lineHeight: 1.8 }}>
          <table className="data-table">
            <thead>
              <tr><th>Service</th><th>Technology</th><th>Port</th><th>Description</th></tr>
            </thead>
            <tbody>
              <tr>
                <td style={{ fontWeight: 600 }}>Frontend</td>
                <td>React + Vite</td>
                <td style={{ fontFamily: "'JetBrains Mono'" }}>5173</td>
                <td style={{ color: 'var(--text-secondary)' }}>Dashboard UI with Chart.js</td>
              </tr>
              <tr>
                <td style={{ fontWeight: 600 }}>Backend API</td>
                <td>Express.js + MongoDB</td>
                <td style={{ fontFamily: "'JetBrains Mono'" }}>5000</td>
                <td style={{ color: 'var(--text-secondary)' }}>REST API, traffic simulation, data storage</td>
              </tr>
              <tr>
                <td style={{ fontWeight: 600 }}>ML Service</td>
                <td>Flask + scikit-learn</td>
                <td style={{ fontFamily: "'JetBrains Mono'" }}>5001</td>
                <td style={{ color: 'var(--text-secondary)' }}>Random Forest model inference</td>
              </tr>
              <tr>
                <td style={{ fontWeight: 600 }}>Database</td>
                <td>MongoDB</td>
                <td style={{ fontFamily: "'JetBrains Mono'" }}>27017</td>
                <td style={{ color: 'var(--text-secondary)' }}>Predictions & alerts storage</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
