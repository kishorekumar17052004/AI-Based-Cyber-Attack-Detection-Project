const mongoose = require('mongoose');

const predictionSchema = new mongoose.Schema({
    packet_id: { type: String, unique: true, sparse: true, index: true },
    timestamp: { type: Date, default: Date.now, index: true },
    source_ip: { type: String, default: 'N/A' },
    destination_ip: { type: String, default: 'N/A' },
    source_port: { type: Number, default: 0 },
    destination_port: { type: Number, default: 0 },
    protocol: { type: String, default: 'TCP' },
    packet_size: { type: Number, default: 0 },
    predicted_label: { type: String, required: true, index: true },
    attack_type: { type: String, required: true, index: true },
    confidence: { type: Number, required: true },
    confidence_score: { type: Number, required: true },
    severity: { type: String, required: true },
    is_attack: { type: Boolean, default: false, index: true },
    features: { type: mongoose.Schema.Types.Mixed, default: {} }
});

module.exports = mongoose.model('Prediction', predictionSchema);
