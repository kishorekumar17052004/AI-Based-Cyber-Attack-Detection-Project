import React, { useEffect, useState } from 'react';
import { Activity, Radio } from 'lucide-react';
import { getCaptureStatus, getPackets } from '../api';

const badgeClass = label => ({ 'DDoS': 'ddos', 'DoS': 'ddos', 'Brute Force': 'brute-force',
  'SQL Injection': 'sql-injection', 'Port Scan': 'portscan', 'Probe': 'portscan', 'Bot': 'bot', 'BENIGN': 'benign' }[label] || 'brute-force');

export default function PacketMonitor() {
  const [packets, setPackets] = useState([]);
  const [status, setStatus] = useState({ running: false });
  const [filter, setFilter] = useState('');

  useEffect(() => {
    const refresh = () => {
      getPackets(200, filter).then(data => setPackets(data.packets || [])).catch(() => {});
      getCaptureStatus().then(setStatus).catch(() => {});
    };
    refresh();
    const timer = setInterval(refresh, 2000);
    return () => clearInterval(timer);
  }, [filter]);

  return (
    <div className="animate-in">
      <div className="page-header">
        <div><h1>Live Packet Monitor</h1><p>Metadata and detection results, refreshed every two seconds.</p></div>
        <div className="header-right">
          <select className="select-control" value={filter} onChange={event => setFilter(event.target.value)}>
            <option value="">All traffic</option><option>BENIGN</option><option>DDoS</option><option>DoS</option>
            <option>Port Scan</option><option>Brute Force</option><option>SQL Injection</option><option>Web Attack</option>
            <option>Bot</option><option>Infiltration</option><option>Probe</option>
          </select>
          <div className={`status-badge ${status.running ? '' : 'status-off'}`}><Radio size={14} /> {status.running ? 'Live' : 'Capture off'}</div>
        </div>
      </div>
      <div className="card">
        <div className="card-header"><h2><Activity size={17} /> Recent packets ({packets.length})</h2></div>
        <div className="card-body table-scroll">
          <table className="data-table">
            <thead><tr><th>Time</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Size</th><th>Detection</th><th>Severity</th><th>Confidence</th></tr></thead>
            <tbody>
              {packets.length === 0 ? <tr><td colSpan="8" className="empty-cell">No packet records yet. Start an authorized capture or run a simulation.</td></tr> : packets.map(packet => (
                <tr key={packet.packet_id || packet._id}>
                  <td className="mono-cell">{new Date(packet.timestamp).toLocaleTimeString()}</td>
                  <td className="mono-cell">{packet.source_ip}{packet.source_port ? `:${packet.source_port}` : ''}</td>
                  <td className="mono-cell">{packet.destination_ip}{packet.destination_port ? `:${packet.destination_port}` : ''}</td>
                  <td>{packet.protocol}</td><td>{packet.packet_size || 0} B</td>
                  <td><span className={`alert-badge ${badgeClass(packet.attack_type || packet.predicted_label)}`}>{packet.attack_type || packet.predicted_label}</span></td>
                  <td><span className={`threat-level ${packet.severity?.toLowerCase()}`}><span className="threat-dot" />{packet.severity}</span></td>
                  <td>{Number(packet.confidence_score ?? packet.confidence ?? 0).toFixed(1)}%</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
