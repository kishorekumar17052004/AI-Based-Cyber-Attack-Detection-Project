const mongoose = require('mongoose');

const memoryAlerts = [];

const alertSchema = new mongoose.Schema({
    timestamp: { type: Date, default: Date.now, index: true },
    alert_type: { type: String, required: true },
    message: { type: String, required: true },
    severity: { type: String, required: true },
    source_ip: { type: String, default: 'N/A' },
    destination_ip: { type: String, default: 'N/A' },
    acknowledged: { type: Boolean, default: false }
});

const MongooseAlert = mongoose.model('Alert', alertSchema);

function mongoReady() {
    return mongoose.connection.readyState === 1;
}

function sortRecords(records, sortSpec = {}) {
    const [[key, direction] = []] = Object.entries(sortSpec);
    if (!key) return records;
    return [...records].sort((a, b) => {
        const av = a[key] instanceof Date ? a[key].getTime() : a[key];
        const bv = b[key] instanceof Date ? b[key].getTime() : b[key];
        if (typeof av === 'string' && typeof bv === 'string') {
            return direction < 0 ? bv.localeCompare(av) : av.localeCompare(bv);
        }
        return direction < 0 ? bv - av : av - bv;
    });
}

function query(records) {
    let output = [...records];
    return {
        sort(sortSpec) {
            output = sortRecords(output, sortSpec);
            return this;
        },
        limit(count) {
            output = output.slice(0, count);
            return this;
        },
        lean() {
            return Promise.resolve(output.map((item) => ({ ...item })));
        },
    };
}

class Alert {
    constructor(data) {
        Object.assign(this, data);
        this._id = this._id || new mongoose.Types.ObjectId().toString();
        this.timestamp = this.timestamp ? new Date(this.timestamp) : new Date();
    }

    async save() {
        if (mongoReady()) {
            const saved = await new MongooseAlert(this).save();
            Object.assign(this, saved.toObject());
            return this;
        }
        const record = { ...this };
        memoryAlerts.unshift(record);
        memoryAlerts.splice(500);
        return this;
    }

    static find(filter = {}) {
        if (mongoReady()) return MongooseAlert.find(filter);
        const records = memoryAlerts.filter((record) => Object.entries(filter).every(([key, value]) => record[key] === value));
        return query(records);
    }

    static async deleteMany(filter = {}) {
        if (mongoReady()) return MongooseAlert.deleteMany(filter);
        const before = memoryAlerts.length;
        for (let index = memoryAlerts.length - 1; index >= 0; index -= 1) {
            const matched = Object.entries(filter).every(([key, value]) => memoryAlerts[index][key] === value);
            if (matched) memoryAlerts.splice(index, 1);
        }
        return { deletedCount: before - memoryAlerts.length };
    }
}

module.exports = Alert;
