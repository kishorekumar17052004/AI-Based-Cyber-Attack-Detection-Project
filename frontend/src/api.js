import axios from 'axios';

const API_BASE = 'http://localhost:5000/api';

const api = axios.create({ baseURL: API_BASE, timeout: 15000 });

export async function getHealth() {
  const res = await api.get('/health');
  return res.data;
}

export async function getModelInfo() {
  const res = await api.get('/model-info');
  return res.data;
}

export async function getFeatureNames() {
  const res = await api.get('/feature-names');
  return res.data;
}

export async function getStats(hours = 24) {
  const res = await api.get(`/stats?hours=${hours}`);
  return res.data;
}

export async function getAlerts(limit = 50) {
  const res = await api.get(`/alerts?limit=${limit}`);
  return res.data;
}

export async function simulate(count = 5, attackType = null) {
  let url = `/simulate?count=${count}`;
  if (attackType) url += `&attack_type=${encodeURIComponent(attackType)}`;
  const res = await api.get(url);
  return res.data;
}

export async function predict(features, metadata = {}) {
  const res = await api.post('/predict', { features, metadata });
  return res.data;
}

export async function predictBatchCSV(file) {
  const formData = new FormData();
  formData.append('file', file);
  const res = await api.post('/predict-batch', formData, {
    headers: { 'Content-Type': 'multipart/form-data' }
  });
  return res.data;
}

export async function clearData() {
  const res = await api.post('/clear-data');
  return res.data;
}

export async function getCaptureStatus() {
  const res = await api.get('/capture/status');
  return res.data;
}

export async function getCaptureInterfaces() {
  const res = await api.get('/capture/interfaces');
  return res.data;
}

export async function startCapture(target_ip, interfaceName, authorized) {
  const res = await api.post('/capture/start', { target_ip, interface: interfaceName, authorized });
  return res.data;
}

export async function stopCapture() {
  const res = await api.post('/capture/stop');
  return res.data;
}

export async function getPackets(limit = 100, attackType = '') {
  const params = new URLSearchParams({ limit: String(limit) });
  if (attackType) params.set('attack_type', attackType);
  const res = await api.get(`/packets?${params}`);
  return res.data;
}

export async function getPacket(packetId) {
  const res = await api.get(`/packets/${packetId}`);
  return res.data;
}

export default api;
