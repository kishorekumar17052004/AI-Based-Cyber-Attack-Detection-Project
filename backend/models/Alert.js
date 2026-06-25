const mongoose = require('mongoose');

const alertSchema = new mongoose.Schema({
    timestamp: { type: Date, default: Date.now, index: true },
    alert_type: { type: String, required: true },
    message: { type: String, required: true },
    severity: { type: String, required: true },
    source_ip: { type: String, default: 'N/A' },
    destination_ip: { type: String, default: 'N/A' },
    acknowledged: { type: Boolean, default: false }
});

module.exports = mongoose.model('Alert', alertSchema);
