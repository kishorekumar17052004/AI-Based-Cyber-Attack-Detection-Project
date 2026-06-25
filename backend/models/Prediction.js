const mongoose = require('mongoose');

const memoryPredictions = [];

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

const MongoosePrediction = mongoose.model('Prediction', predictionSchema);

function mongoReady() {
    return mongoose.connection.readyState === 1;
}

function matchesFilter(record, filter = {}) {
    return Object.entries(filter).every(([key, value]) => {
        if (value && typeof value === 'object' && '$gte' in value) {
            return new Date(record[key]) >= new Date(value.$gte);
        }
        if (value && typeof value === 'object' && '$in' in value) {
            return value.$in.includes(record[key]);
        }
        return record[key] === value;
    });
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

class Prediction {
    constructor(data) {
        Object.assign(this, data);
        this._id = this._id || new mongoose.Types.ObjectId().toString();
        this.timestamp = this.timestamp ? new Date(this.timestamp) : new Date();
    }

    async save() {
        if (mongoReady()) {
            const saved = await new MongoosePrediction(this).save();
            Object.assign(this, saved.toObject());
            return this;
        }
        const record = { ...this };
        memoryPredictions.unshift(record);
        memoryPredictions.splice(500);
        return this;
    }

    static find(filter = {}) {
        if (mongoReady()) return MongoosePrediction.find(filter);
        return query(memoryPredictions.filter((record) => matchesFilter(record, filter)));
    }

    static findOne(filter = {}) {
        if (mongoReady()) return MongoosePrediction.findOne(filter);
        const record = memoryPredictions.find((item) => matchesFilter(item, filter));
        return {
            lean() {
                return Promise.resolve(record ? { ...record } : null);
            },
        };
    }

    static async countDocuments(filter = {}) {
        if (mongoReady()) return MongoosePrediction.countDocuments(filter);
        return memoryPredictions.filter((record) => matchesFilter(record, filter)).length;
    }

    static async aggregate(pipeline = []) {
        if (mongoReady()) return MongoosePrediction.aggregate(pipeline);
        const matchStage = pipeline.find((stage) => stage.$match)?.$match || {};
        const groupStage = pipeline.find((stage) => stage.$group)?.$group;
        const sortStage = pipeline.find((stage) => stage.$sort)?.$sort;
        const limitStage = pipeline.find((stage) => stage.$limit)?.$limit;
        let records = memoryPredictions.filter((record) => matchesFilter(record, matchStage));

        if (groupStage?._id === '$predicted_label') {
            const grouped = {};
            records.forEach((record) => { grouped[record.predicted_label] = (grouped[record.predicted_label] || 0) + 1; });
            records = Object.entries(grouped).map(([_id, count]) => ({ _id, count }));
        } else if (groupStage?._id === '$severity') {
            const grouped = {};
            records.forEach((record) => { grouped[record.severity] = (grouped[record.severity] || 0) + 1; });
            records = Object.entries(grouped).map(([_id, count]) => ({ _id, count }));
        } else if (groupStage?._id === '$source_ip') {
            const grouped = {};
            records.forEach((record) => { grouped[record.source_ip] = (grouped[record.source_ip] || 0) + 1; });
            records = Object.entries(grouped).map(([_id, count]) => ({ _id, count }));
        } else if (groupStage?._id?.$dateToString) {
            const grouped = {};
            records.forEach((record) => {
                const hour = new Date(record.timestamp).toISOString().slice(0, 13);
                grouped[hour] = grouped[hour] || { _id: hour, attacks: 0, benign: 0 };
                grouped[hour][record.is_attack ? 'attacks' : 'benign'] += 1;
            });
            records = Object.values(grouped);
        }

        if (sortStage) records = sortRecords(records, sortStage);
        if (limitStage) records = records.slice(0, limitStage);
        return records;
    }

    static async deleteMany(filter = {}) {
        if (mongoReady()) return MongoosePrediction.deleteMany(filter);
        const before = memoryPredictions.length;
        for (let index = memoryPredictions.length - 1; index >= 0; index -= 1) {
            if (matchesFilter(memoryPredictions[index], filter)) memoryPredictions.splice(index, 1);
        }
        return { deletedCount: before - memoryPredictions.length };
    }
}

module.exports = Prediction;
