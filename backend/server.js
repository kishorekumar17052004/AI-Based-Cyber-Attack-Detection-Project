const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const axios = require('axios');
const multer = require('multer');
const csv = require('csv-parser');
const fs = require('fs');
const path = require('path');
require('dotenv').config();

const { generateTrafficSample, generateTrafficBatch, FEATURE_NAMES } = require('./trafficSimulator');
const Prediction = require('./models/Prediction');
const Alert = require('./models/Alert');

const app = express();
const PORT = process.env.PORT || 5000;
const HOST = process.env.HOST || '127.0.0.1';
const ML_SERVICE_URL = process.env.ML_SERVICE_URL || 'http://127.0.0.1:5001';

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' }));

// Multer for CSV upload
const upload = multer({ dest: process.env.VERCEL ? '/tmp' : path.join(__dirname, 'uploads/') });

// ============================================================
// MongoDB Connection
// ============================================================
const MONGO_URI = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/cybershield';
mongoose.connect(MONGO_URI)
    .then(() => console.log('[*] MongoDB connected:', MONGO_URI))
    .catch(err => {
        console.log('[!] MongoDB connection error:', err.message);
        console.log('[*] Running without database — data will not persist.');
    });

// ============================================================
// Helper: Call ML Microservice
// ============================================================
async function predictWithML(features, metadata = {}) {
    try {
        const res = await axios.post(`${ML_SERVICE_URL}/predict`, { features, metadata }, { timeout: 5000 });
        return res.data;
    } catch (err) {
        console.error('[!] ML service error:', err.message);
        return null;
    }
}

async function predictBatchWithML(samples) {
    try {
        const res = await axios.post(`${ML_SERVICE_URL}/predict-batch`, { samples }, { timeout: 15000 });
        return res.data;
    } catch (err) {
        console.error('[!] ML service batch error:', err.message);
        return null;
    }
}

// ============================================================
// Helper: Save prediction and alert to DB
// ============================================================
async function savePrediction(predData) {
    try {
        const attackType = predData.attack_type || predData.predicted_label;
        const confidenceScore = predData.confidence_score ?? predData.confidence;
        const prediction = new Prediction({
            packet_id: predData.packet_id || new mongoose.Types.ObjectId().toString(),
            timestamp: predData.timestamp || new Date(),
            source_ip: predData.source_ip || 'N/A',
            destination_ip: predData.destination_ip || 'N/A',
            source_port: predData.source_port || 0,
            destination_port: predData.destination_port || 0,
            protocol: predData.protocol || 'TCP',
            packet_size: predData.packet_size || predData.features?.packet_size || 0,
            predicted_label: attackType,
            attack_type: attackType,
            confidence: confidenceScore,
            confidence_score: confidenceScore,
            severity: predData.severity,
            is_attack: (predData.attack_type || predData.predicted_label) !== 'BENIGN',
            features: predData.features || {}
        });
        await prediction.save();

        // Create alert for attacks
        if (attackType !== 'BENIGN') {
            const alert = new Alert({
                timestamp: predData.timestamp || new Date(),
                alert_type: attackType,
                message: `${attackType} detected from ${predData.source_ip || 'unknown'} to ${predData.destination_ip || 'unknown'} (confidence: ${(confidenceScore ?? 0).toFixed(1)}%)`,
                severity: predData.severity,
                source_ip: predData.source_ip || 'N/A',
                destination_ip: predData.destination_ip || 'N/A'
            });
            await alert.save();
        }
        return prediction;
    } catch (err) {
        console.error('[!] DB save error:', err.message);
    }
}

// ============================================================
// API: Health Check
// ============================================================
app.get('/api/health', async (req, res) => {
    let mlStatus = false;
    try {
        const mlRes = await axios.get(`${ML_SERVICE_URL}/health`, { timeout: 2000 });
        mlStatus = mlRes.data?.model_loaded || false;
    } catch (e) { /* ML service not running */ }

    res.json({
        status: 'ok',
        model_loaded: mlStatus,
        database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
        timestamp: new Date().toISOString()
    });
});

// Authorized collector lifecycle. Flask owns the privileged capture worker.
app.get('/api/capture/status', async (req, res) => {
    try {
        const result = await axios.get(`${ML_SERVICE_URL}/capture/status`, { timeout: 3000 });
        res.json(result.data);
    } catch (err) { res.status(503).json({ error: 'Collector service unavailable' }); }
});

app.get('/api/capture/interfaces', async (req, res) => {
    try {
        const result = await axios.get(`${ML_SERVICE_URL}/capture/interfaces`, { timeout: 3000 });
        res.json(result.data);
    } catch (err) { res.status(503).json({ error: 'Collector service unavailable' }); }
});

app.post('/api/capture/start', async (req, res) => {
    try {
        const result = await axios.post(`${ML_SERVICE_URL}/capture/start`, req.body, { timeout: 5000 });
        res.status(result.status).json(result.data);
    } catch (err) {
        res.status(err.response?.status || 503).json(err.response?.data || { error: 'Collector service unavailable' });
    }
});

app.post('/api/capture/stop', async (req, res) => {
    try {
        const result = await axios.post(`${ML_SERVICE_URL}/capture/stop`, {}, { timeout: 3000 });
        res.json(result.data);
    } catch (err) { res.status(503).json({ error: 'Collector service unavailable' }); }
});

// Metadata-only packet ingestion from the local collector. Payload bytes are never accepted.
app.post('/api/packets/ingest', async (req, res) => {
    const remote = req.socket.remoteAddress || '';
    if (!['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(remote)) {
        return res.status(403).json({ error: 'Collector ingestion is restricted to localhost' });
    }
    const data = req.body || {};
    if (!data.source_ip || !data.destination_ip || !data.attack_type) {
        return res.status(400).json({ error: 'source_ip, destination_ip, and attack_type are required' });
    }
    const saved = await savePrediction(data);
    if (!saved) return res.status(500).json({ error: 'Packet could not be persisted' });
    res.status(201).json({ packet_id: saved.packet_id, status: 'stored' });
});

app.get('/api/packets', async (req, res) => {
    const limit = Math.min(Math.max(parseInt(req.query.limit) || 100, 1), 500);
    const filter = req.query.attack_type ? { predicted_label: req.query.attack_type } : {};
    try {
        const packets = await Prediction.find(filter).sort({ timestamp: -1 }).limit(limit).lean({ virtuals: true });
        res.json({ packets, count: packets.length });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/packets/:packetId', async (req, res) => {
    try {
        const packet = await Prediction.findOne({ packet_id: req.params.packetId }).lean({ virtuals: true });
        if (!packet) return res.status(404).json({ error: 'Packet not found' });
        res.json(packet);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// ============================================================
// API: Model Info
// ============================================================
app.get('/api/model-info', async (req, res) => {
    try {
        const mlRes = await axios.get(`${ML_SERVICE_URL}/model-info`, { timeout: 3000 });
        res.json(mlRes.data);
    } catch (err) {
        res.status(503).json({ error: 'ML service unavailable. Start the Python ML microservice.' });
    }
});

// ============================================================
// API: Feature Names
// ============================================================
app.get('/api/feature-names', async (req, res) => {
    try {
        const mlRes = await axios.get(`${ML_SERVICE_URL}/feature-names`, { timeout: 3000 });
        res.json(mlRes.data);
    } catch (err) {
        // Fallback to built-in feature names
        res.json({ feature_names: FEATURE_NAMES, count: FEATURE_NAMES.length });
    }
});

// ============================================================
// API: Single Prediction
// ============================================================
app.post('/api/predict', async (req, res) => {
    const { features, metadata } = req.body;
    if (!features) return res.status(400).json({ error: 'Missing features' });

    const mlResult = await predictWithML(features, metadata);
    if (!mlResult || mlResult.error) {
        return res.status(503).json({ error: 'ML prediction failed. Is the Python service running?' });
    }

    const result = {
        ...mlResult,
        timestamp: new Date().toISOString(),
        source_ip: metadata?.source_ip || 'N/A',
        destination_ip: metadata?.destination_ip || 'N/A',
        source_port: metadata?.source_port || 0,
        destination_port: metadata?.destination_port || 0,
        protocol: metadata?.protocol || 'TCP',
        features
    };

    await savePrediction(result);
    res.json(result);
});

// ============================================================
// API: Batch Prediction (CSV Upload)
// ============================================================
app.post('/api/predict-batch', upload.single('file'), async (req, res) => {
    const results = [];

    if (req.file) {
        // CSV file uploaded
        const rows = [];
        await new Promise((resolve, reject) => {
            fs.createReadStream(req.file.path)
                .pipe(csv())
                .on('data', (row) => rows.push(row))
                .on('end', resolve)
                .on('error', reject);
        });

        // Clean up temp file
        fs.unlinkSync(req.file.path);

        for (const row of rows) {
            const features = {};
            FEATURE_NAMES.forEach(fname => {
                const key = Object.keys(row).find(k => k.trim() === fname);
                features[fname] = key ? parseFloat(row[key]) || 0 : 0;
            });

            const mlResult = await predictWithML(features);
            if (mlResult && !mlResult.error) {
                const result = {
                    ...mlResult,
                    timestamp: new Date().toISOString(),
                    features
                };
                await savePrediction(result);
                results.push(result);
            }
        }
    } else if (req.body.samples) {
        // JSON batch
        for (const sample of req.body.samples) {
            const feats = sample.features || sample;
            const mlResult = await predictWithML(feats);
            if (mlResult && !mlResult.error) {
                const result = { ...mlResult, timestamp: new Date().toISOString(), features: feats };
                await savePrediction(result);
                results.push(result);
            }
        }
    } else {
        return res.status(400).json({ error: 'Send CSV file or JSON samples' });
    }

    const attackCount = results.filter(r => r.is_attack).length;
    const attackBreakdown = {};
    results.forEach(r => {
        attackBreakdown[r.predicted_label] = (attackBreakdown[r.predicted_label] || 0) + 1;
    });

    res.json({
        total_analyzed: results.length,
        attacks_detected: attackCount,
        benign_traffic: results.length - attackCount,
        attack_breakdown: attackBreakdown,
        results
    });
});

// ============================================================
// API: Simulate Traffic
// ============================================================
app.get('/api/simulate', async (req, res) => {
    const count = Math.min(parseInt(req.query.count) || 1, 50);
    const attackType = req.query.attack_type || null;

    const results = [];
    for (let i = 0; i < count; i++) {
        const sample = generateTrafficSample(attackType);

        const mlResult = await predictWithML(sample.features, sample.metadata);

        if (mlResult && !mlResult.error) {
            const result = {
                ...mlResult,
                timestamp: new Date().toISOString(),
                source_ip: sample.metadata.source_ip,
                destination_ip: sample.metadata.destination_ip,
                source_port: sample.metadata.source_port,
                destination_port: sample.metadata.destination_port,
                protocol: sample.metadata.protocol,
                actual_label: sample.metadata.actual_label,
                features: sample.features
            };
            await savePrediction(result);
            results.push(result);
        } else {
            // If ML service is down, return simulated data with the actual label
            const fallback = {
                predicted_label: sample.metadata.actual_label,
                confidence: 85 + Math.random() * 15,
                severity: {
                    'BENIGN': 'Low',
                    'DDoS': 'High',
                    'DoS': 'High',
                    'Brute Force': 'High',
                    'PortScan': 'Medium',
                    'Probe': 'Medium',
                    'SQL Injection': 'High',
                    'Web Attack': 'High',
                    'Bot': 'Medium',
                    'Infiltration': 'Critical'
                }[sample.metadata.actual_label] || 'Medium',
                is_attack: sample.metadata.actual_label !== 'BENIGN',
                class_probabilities: {},
                timestamp: new Date().toISOString(),
                source_ip: sample.metadata.source_ip,
                destination_ip: sample.metadata.destination_ip,
                source_port: sample.metadata.source_port,
                destination_port: sample.metadata.destination_port,
                protocol: sample.metadata.protocol,
                actual_label: sample.metadata.actual_label,
                features: sample.features,
                _fallback: true
            };
            await savePrediction(fallback);
            results.push(fallback);
        }
    }

    res.json({ count: results.length, results });
});

// ============================================================
// API: Dashboard Stats
// ============================================================
app.get('/api/stats', async (req, res) => {
    const hours = parseInt(req.query.hours) || 24;
    const since = new Date(Date.now() - hours * 60 * 60 * 1000);

    try {
        // Total predictions
        const total = await Prediction.countDocuments({ timestamp: { $gte: since } });

        // Attacks
        const attacks = await Prediction.countDocuments({ timestamp: { $gte: since }, is_attack: true });
        const highSeverity = await Prediction.countDocuments({ timestamp: { $gte: since }, severity: { $in: ['High', 'Critical'] } });

        // Attack breakdown
        const breakdownAgg = await Prediction.aggregate([
            { $match: { timestamp: { $gte: since } } },
            { $group: { _id: '$predicted_label', count: { $sum: 1 } } }
        ]);
        const attack_breakdown = {};
        breakdownAgg.forEach(b => { attack_breakdown[b._id] = b.count; });

        // Severity breakdown
        const severityAgg = await Prediction.aggregate([
            { $match: { timestamp: { $gte: since }, is_attack: true } },
            { $group: { _id: '$severity', count: { $sum: 1 } } }
        ]);
        const severity_breakdown = {};
        severityAgg.forEach(s => { severity_breakdown[s._id] = s.count; });

        // Recent alerts
        const alerts = await Alert.find({ timestamp: { $gte: since } })
            .sort({ timestamp: -1 })
            .limit(50)
            .lean();

        // Timeline (group by hour)
        const timelineAgg = await Prediction.aggregate([
            { $match: { timestamp: { $gte: since } } },
            {
                $group: {
                    _id: { $dateToString: { format: '%Y-%m-%dT%H', date: '$timestamp' } },
                    attacks: { $sum: { $cond: ['$is_attack', 1, 0] } },
                    benign: { $sum: { $cond: ['$is_attack', 0, 1] } }
                }
            },
            { $sort: { _id: 1 } }
        ]);
        const timeline = timelineAgg.map(t => ({ hour: t._id, attacks: t.attacks, benign: t.benign }));

        // Top attackers
        const attackerAgg = await Prediction.aggregate([
            { $match: { timestamp: { $gte: since }, is_attack: true } },
            { $group: { _id: '$source_ip', count: { $sum: 1 } } },
            { $sort: { count: -1 } },
            { $limit: 10 }
        ]);
        const top_attackers = attackerAgg.map(a => ({ ip: a._id, count: a.count }));

        // Model accuracy
        let model_accuracy = 0;
        try {
            const mlInfo = await axios.get(`${ML_SERVICE_URL}/model-info`, { timeout: 2000 });
            model_accuracy = (mlInfo.data.accuracy || 0) * 100;
        } catch (e) { /* ML service not available */ }

        res.json({
            time_window_hours: hours,
            total_analyzed: total,
            attacks_detected: attacks,
            high_severity_count: highSeverity,
            benign_traffic: total - attacks,
            attack_rate: total > 0 ? parseFloat((attacks / total * 100).toFixed(2)) : 0,
            attack_breakdown,
            severity_breakdown,
            recent_alerts: alerts.map(a => ({
                id: a._id,
                timestamp: a.timestamp,
                alert_type: a.alert_type,
                message: a.message,
                severity: a.severity,
                source_ip: a.source_ip,
                destination_ip: a.destination_ip
            })),
            timeline,
            top_attackers,
            model_accuracy
        });
    } catch (err) {
        console.error('[!] Stats error:', err.message);
        res.status(500).json({ error: err.message });
    }
});

// ============================================================
// API: Alerts
// ============================================================
app.get('/api/alerts', async (req, res) => {
    const limit = Math.min(parseInt(req.query.limit) || 20, 100);
    try {
        const alerts = await Alert.find().sort({ timestamp: -1 }).limit(limit).lean();
        res.json({
            alerts: alerts.map(a => ({
                id: a._id,
                timestamp: a.timestamp,
                alert_type: a.alert_type,
                message: a.message,
                severity: a.severity,
                source_ip: a.source_ip,
                destination_ip: a.destination_ip,
                acknowledged: a.acknowledged || false
            }))
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ============================================================
// API: Clear Data
// ============================================================
app.post('/api/clear-data', async (req, res) => {
    try {
        await Prediction.deleteMany({});
        await Alert.deleteMany({});
        res.json({ status: 'ok', message: 'All data cleared' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ============================================================
// Start Server
// ============================================================
if (require.main === module) {
    app.listen(PORT, HOST, () => {
    console.log('\n' + '='.repeat(55));
    console.log('  CyberShield AI — MERN Backend (Express)');
    console.log('='.repeat(55));
    console.log(`[*] Express server running on http://${HOST}:${PORT}`);
    console.log(`[*] ML microservice expected at ${ML_SERVICE_URL}`);
    console.log('[*] MongoDB:', MONGO_URI);
    console.log('');
    });
}

module.exports = app;
