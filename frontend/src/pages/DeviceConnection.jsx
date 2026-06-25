import React, { useEffect, useState } from 'react';
import { Link2, Play, Square, ShieldCheck } from 'lucide-react';
import { getCaptureInterfaces, getCaptureStatus, startCapture, stopCapture } from '../api';
import { useToast } from '../context/ToastContext';

export default function DeviceConnection() {
  const [targetIp, setTargetIp] = useState('');
  const [interfaceName, setInterfaceName] = useState('');
  const [interfaces, setInterfaces] = useState([]);
  const [authorized, setAuthorized] = useState(false);
  const [status, setStatus] = useState({ running: false });
  const [busy, setBusy] = useState(false);
  const { showToast } = useToast();

  const refresh = async () => {
    try { setStatus(await getCaptureStatus()); } catch { setStatus({ running: false, unavailable: true }); }
  };

  useEffect(() => {
    getCaptureInterfaces().then(data => setInterfaces(data.interfaces || [])).catch(() => {});
    refresh();
    const timer = setInterval(refresh, 2500);
    return () => clearInterval(timer);
  }, []);

  const start = async (event) => {
    event.preventDefault();
    setBusy(true);
    try {
      const result = await startCapture(targetIp.trim(), interfaceName, authorized);
      setStatus(result.capture);
      showToast('Authorized packet capture started', 'success');
    } catch (error) {
      showToast(error.response?.data?.error || 'Could not start capture', 'error');
    } finally { setBusy(false); }
  };

  const stop = async () => {
    setBusy(true);
    try {
      const result = await stopCapture();
      setStatus(result.capture);
      showToast('Capture stopped', 'info');
    } catch { showToast('Could not stop capture', 'error'); }
    finally { setBusy(false); }
  };

  return (
    <div className="animate-in">
      <div className="page-header">
        <div><h1>Device / IP Connection</h1><p>Start a host-filtered capture for a device you are authorized to monitor.</p></div>
        <div className={`status-badge ${status.running ? '' : 'status-off'}`}>
          <span className="status-dot" /> {status.running ? 'Capturing' : 'Stopped'}
        </div>
      </div>

      <div className="connection-layout">
        <form className="card" onSubmit={start}>
          <div className="card-header"><h2><Link2 size={17} /> Capture target</h2></div>
          <div className="card-body capture-form">
            <div className="form-group">
              <label>Private device IP address</label>
              <input className="input-control" required placeholder="192.168.1.10" value={targetIp}
                onChange={event => setTargetIp(event.target.value)} disabled={status.running} />
              <small>Public, multicast, link-local, and unspecified addresses are rejected by Flask.</small>
            </div>
            <div className="form-group">
              <label>Network interface (optional)</label>
              <select className="select-control" value={interfaceName} onChange={event => setInterfaceName(event.target.value)} disabled={status.running}>
                <option value="">Automatic</option>
                {interfaces.map(name => <option key={name} value={name}>{name}</option>)}
              </select>
            </div>
            <label className="consent-row">
              <input type="checkbox" checked={authorized} onChange={event => setAuthorized(event.target.checked)} disabled={status.running} />
              <span>I own this device/network or have explicit permission to monitor it.</span>
            </label>
            <div className="sim-buttons">
              <button className="btn btn-primary" disabled={busy || status.running || !authorized}><Play size={15} /> Start capture</button>
              <button type="button" className="btn btn-danger" disabled={busy || !status.running} onClick={stop}><Square size={15} /> Stop</button>
            </div>
          </div>
        </form>

        <div className="card">
          <div className="card-header"><h2>Session status</h2></div>
          <div className="card-body result-details">
            <div className="detail-row"><span className="detail-label">Target</span><span className="detail-value">{status.target_ip || '—'}</span></div>
            <div className="detail-row"><span className="detail-label">Interface</span><span className="detail-value">{status.interface || 'Automatic'}</span></div>
            <div className="detail-row"><span className="detail-label">Packets forwarded</span><span className="detail-value">{status.packets_captured || 0}</span></div>
            <div className="detail-row"><span className="detail-label">Started</span><span className="detail-value">{status.started_at ? new Date(status.started_at).toLocaleString() : '—'}</span></div>
            {status.last_error && <div className="safety-note error-note">{status.last_error}</div>}
          </div>
        </div>
      </div>

      <div className="safety-note"><ShieldCheck size={20} /><div><strong>Metadata only.</strong> The service does not persist packet payloads. Windows capture requires Npcap and an elevated terminal. Capturing a hotspot gateway does not magically expose another phone's traffic; the capture host must be able to observe that traffic.</div></div>
    </div>
  );
}
