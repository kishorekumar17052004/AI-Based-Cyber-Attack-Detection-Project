/**
 * Traffic Simulator — JavaScript port of simulate_traffic.py
 * Generates realistic CICIDS 2017–style network traffic for live demos
 */

// Feature names matching the trained model
const FEATURE_NAMES = [
    'duration',
    'fwd_packets_count',
    'bwd_packets_count',
    'fwd_total_payload_bytes',
    'bwd_total_payload_bytes',
    'fwd_payload_bytes_max',
    'fwd_payload_bytes_mean',
    'bwd_payload_bytes_max',
    'bwd_payload_bytes_mean',
    'bytes_rate',
    'packets_rate',
    'packets_IAT_mean',
    'packet_IAT_max',
    'fwd_packets_IAT_total',
    'fwd_packets_IAT_mean',
    'bwd_packets_IAT_total',
    'bwd_packets_IAT_mean',
    'fwd_psh_flag_counts',
    'fwd_packets_rate',
    'bwd_packets_rate'
];

// Feature ranges (global bounds)
const FEATURE_RANGES = {
    duration: [0, 120000000],
    fwd_packets_count: [1, 5000],
    bwd_packets_count: [0, 5000],
    fwd_total_payload_bytes: [0, 1000000],
    bwd_total_payload_bytes: [0, 1000000],
    fwd_payload_bytes_max: [0, 65535],
    fwd_payload_bytes_mean: [0, 10000],
    bwd_payload_bytes_max: [0, 65535],
    bwd_payload_bytes_mean: [0, 10000],
    bytes_rate: [0, 500000000],
    packets_rate: [0, 4000000],
    packets_IAT_mean: [0, 120000000],
    packet_IAT_max: [0, 120000000],
    fwd_packets_IAT_total: [0, 120000000],
    fwd_packets_IAT_mean: [0, 60000000],
    bwd_packets_IAT_total: [0, 120000000],
    bwd_packets_IAT_mean: [0, 60000000],
    fwd_psh_flag_counts: [0, 1],
    fwd_packets_rate: [0, 2000000],
    bwd_packets_rate: [0, 2000000]
};

// Traffic profiles per attack type
const TRAFFIC_PROFILES = {
    'BENIGN': {
        duration: [10000, 30000000],
        fwd_packets_count: [1, 50],
        bwd_packets_count: [1, 40],
        fwd_total_payload_bytes: [50, 50000],
        bwd_total_payload_bytes: [50, 40000],
        fwd_payload_bytes_max: [40, 1500],
        fwd_payload_bytes_mean: [20, 800],
        bwd_payload_bytes_max: [40, 1500],
        bwd_payload_bytes_mean: [20, 600],
        bytes_rate: [100, 500000],
        packets_rate: [1, 1000],
        packets_IAT_mean: [1000, 5000000],
        packet_IAT_max: [5000, 30000000],
        fwd_packets_IAT_total: [1000, 30000000],
        fwd_packets_IAT_mean: [500, 5000000],
        bwd_packets_IAT_total: [1000, 30000000],
        bwd_packets_IAT_mean: [500, 5000000],
        fwd_psh_flag_counts: [0, 1],
        fwd_packets_rate: [1, 500],
        bwd_packets_rate: [1, 400]
    },
    'DDoS': {
        duration: [0, 500000],
        fwd_packets_count: [100, 5000],
        bwd_packets_count: [0, 10],
        fwd_total_payload_bytes: [5000, 1000000],
        bwd_total_payload_bytes: [0, 1000],
        fwd_payload_bytes_max: [40, 1500],
        fwd_payload_bytes_mean: [40, 200],
        bwd_payload_bytes_max: [0, 100],
        bwd_payload_bytes_mean: [0, 50],
        bytes_rate: [1000000, 500000000],
        packets_rate: [10000, 4000000],
        packets_IAT_mean: [0, 1000],
        packet_IAT_max: [0, 5000],
        fwd_packets_IAT_total: [0, 500000],
        fwd_packets_IAT_mean: [0, 500],
        bwd_packets_IAT_total: [0, 100000],
        bwd_packets_IAT_mean: [0, 100],
        fwd_psh_flag_counts: [0, 1],
        fwd_packets_rate: [10000, 2000000],
        bwd_packets_rate: [0, 100]
    },
    'Brute Force': {
        duration: [1000000, 60000000],
        fwd_packets_count: [5, 200],
        bwd_packets_count: [5, 200],
        fwd_total_payload_bytes: [500, 50000],
        bwd_total_payload_bytes: [200, 40000],
        fwd_payload_bytes_max: [100, 1000],
        fwd_payload_bytes_mean: [50, 300],
        bwd_payload_bytes_max: [100, 500],
        bwd_payload_bytes_mean: [50, 200],
        bytes_rate: [100, 100000],
        packets_rate: [1, 500],
        packets_IAT_mean: [100000, 10000000],
        packet_IAT_max: [500000, 30000000],
        fwd_packets_IAT_total: [1000000, 60000000],
        fwd_packets_IAT_mean: [100000, 10000000],
        bwd_packets_IAT_total: [1000000, 60000000],
        bwd_packets_IAT_mean: [100000, 10000000],
        fwd_psh_flag_counts: [1, 1],
        fwd_packets_rate: [1, 200],
        bwd_packets_rate: [1, 200]
    },
    'SQL Injection': {
        duration: [500000, 30000000],
        fwd_packets_count: [3, 100],
        bwd_packets_count: [2, 80],
        fwd_total_payload_bytes: [200, 100000],
        bwd_total_payload_bytes: [100, 50000],
        fwd_payload_bytes_max: [200, 5000],
        fwd_payload_bytes_mean: [100, 2000],
        bwd_payload_bytes_max: [100, 3000],
        bwd_payload_bytes_mean: [50, 1000],
        bytes_rate: [100, 200000],
        packets_rate: [1, 100],
        packets_IAT_mean: [500000, 15000000],
        packet_IAT_max: [1000000, 30000000],
        fwd_packets_IAT_total: [500000, 30000000],
        fwd_packets_IAT_mean: [200000, 10000000],
        bwd_packets_IAT_total: [500000, 30000000],
        bwd_packets_IAT_mean: [200000, 10000000],
        fwd_psh_flag_counts: [1, 1],
        fwd_packets_rate: [1, 50],
        bwd_packets_rate: [1, 40]
    },
    'PortScan': {
        duration: [0, 100000],
        fwd_packets_count: [1, 5],
        bwd_packets_count: [0, 3],
        fwd_total_payload_bytes: [40, 500],
        bwd_total_payload_bytes: [0, 300],
        fwd_payload_bytes_max: [40, 100],
        fwd_payload_bytes_mean: [40, 80],
        bwd_payload_bytes_max: [0, 80],
        bwd_payload_bytes_mean: [0, 60],
        bytes_rate: [1000, 5000000],
        packets_rate: [100, 1000000],
        packets_IAT_mean: [0, 100000],
        packet_IAT_max: [0, 100000],
        fwd_packets_IAT_total: [0, 100000],
        fwd_packets_IAT_mean: [0, 50000],
        bwd_packets_IAT_total: [0, 100000],
        bwd_packets_IAT_mean: [0, 50000],
        fwd_psh_flag_counts: [0, 0],
        fwd_packets_rate: [100, 500000],
        bwd_packets_rate: [0, 100000]
    },
    'DoS': {
        duration: [100000, 1000000],
        fwd_packets_count: [300, 2000],
        bwd_packets_count: [0, 30],
        fwd_total_payload_bytes: [20000, 900000],
        bwd_total_payload_bytes: [0, 5000],
        fwd_payload_bytes_max: [40, 1500],
        fwd_payload_bytes_mean: [80, 700],
        bwd_payload_bytes_max: [0, 500],
        bwd_payload_bytes_mean: [0, 120],
        bytes_rate: [400000, 12000000],
        packets_rate: [700, 1400],
        packets_IAT_mean: [100, 4000],
        packet_IAT_max: [1000, 50000],
        fwd_packets_IAT_total: [10000, 1000000],
        fwd_packets_IAT_mean: [100, 4000],
        bwd_packets_IAT_total: [0, 200000],
        bwd_packets_IAT_mean: [0, 3000],
        fwd_psh_flag_counts: [0, 1],
        fwd_packets_rate: [600, 1200],
        bwd_packets_rate: [0, 100]
    },
    'Probe': {
        duration: [0, 300000],
        fwd_packets_count: [8, 60],
        bwd_packets_count: [0, 10],
        fwd_total_payload_bytes: [400, 6000],
        bwd_total_payload_bytes: [0, 1500],
        fwd_payload_bytes_max: [40, 300],
        fwd_payload_bytes_mean: [40, 160],
        bwd_payload_bytes_max: [0, 200],
        bwd_payload_bytes_mean: [0, 120],
        bytes_rate: [1000, 3000000],
        packets_rate: [50, 500],
        packets_IAT_mean: [1000, 200000],
        packet_IAT_max: [2000, 300000],
        fwd_packets_IAT_total: [1000, 300000],
        fwd_packets_IAT_mean: [1000, 150000],
        bwd_packets_IAT_total: [0, 250000],
        bwd_packets_IAT_mean: [0, 120000],
        fwd_psh_flag_counts: [0, 0],
        fwd_packets_rate: [50, 400],
        bwd_packets_rate: [0, 100]
    },
    'Web Attack': {
        duration: [500000, 30000000],
        fwd_packets_count: [4, 120],
        bwd_packets_count: [2, 100],
        fwd_total_payload_bytes: [300, 150000],
        bwd_total_payload_bytes: [200, 90000],
        fwd_payload_bytes_max: [300, 8000],
        fwd_payload_bytes_mean: [120, 2500],
        bwd_payload_bytes_max: [100, 4000],
        bwd_payload_bytes_mean: [50, 1200],
        bytes_rate: [200, 250000],
        packets_rate: [1, 120],
        packets_IAT_mean: [300000, 12000000],
        packet_IAT_max: [800000, 25000000],
        fwd_packets_IAT_total: [500000, 30000000],
        fwd_packets_IAT_mean: [200000, 9000000],
        bwd_packets_IAT_total: [500000, 30000000],
        bwd_packets_IAT_mean: [200000, 9000000],
        fwd_psh_flag_counts: [1, 1],
        fwd_packets_rate: [1, 60],
        bwd_packets_rate: [1, 50]
    },
    'Bot': {
        duration: [1000000, 60000000],
        fwd_packets_count: [5, 250],
        bwd_packets_count: [0, 80],
        fwd_total_payload_bytes: [500, 80000],
        bwd_total_payload_bytes: [0, 30000],
        fwd_payload_bytes_max: [50, 1200],
        fwd_payload_bytes_mean: [40, 400],
        bwd_payload_bytes_max: [0, 800],
        bwd_payload_bytes_mean: [0, 300],
        bytes_rate: [100, 150000],
        packets_rate: [1, 300],
        packets_IAT_mean: [500000, 15000000],
        packet_IAT_max: [1000000, 30000000],
        fwd_packets_IAT_total: [1000000, 60000000],
        fwd_packets_IAT_mean: [300000, 12000000],
        bwd_packets_IAT_total: [0, 40000000],
        bwd_packets_IAT_mean: [0, 10000000],
        fwd_psh_flag_counts: [0, 1],
        fwd_packets_rate: [1, 150],
        bwd_packets_rate: [0, 80]
    },
    'Infiltration': {
        duration: [1000000, 60000000],
        fwd_packets_count: [60, 700],
        bwd_packets_count: [20, 300],
        fwd_total_payload_bytes: [50000, 1000000],
        bwd_total_payload_bytes: [5000, 200000],
        fwd_payload_bytes_max: [500, 10000],
        fwd_payload_bytes_mean: [200, 4000],
        bwd_payload_bytes_max: [100, 3000],
        bwd_payload_bytes_mean: [50, 1200],
        bytes_rate: [1500000, 12000000],
        packets_rate: [30, 500],
        packets_IAT_mean: [200000, 8000000],
        packet_IAT_max: [500000, 20000000],
        fwd_packets_IAT_total: [1000000, 60000000],
        fwd_packets_IAT_mean: [100000, 6000000],
        bwd_packets_IAT_total: [1000000, 50000000],
        bwd_packets_IAT_mean: [100000, 6000000],
        fwd_psh_flag_counts: [1, 1],
        fwd_packets_rate: [20, 300],
        bwd_packets_rate: [5, 150]
    }
};

// Realism config
const REALISM_CONFIG = {
    benign_burst_probability: 0.20,
    cross_profile_blend_probability: 0.15,
    range_expansion_ratio: 0.12,
    outlier_probability: 0.05
};

const BENIGN_BURST_OVERRIDES = {
    fwd_packets_count: [80, 1500],
    bwd_packets_count: [0, 20],
    fwd_total_payload_bytes: [8000, 500000],
    bytes_rate: [500000, 60000000],
    packets_rate: [2000, 600000],
    packets_IAT_mean: [50, 20000],
    packet_IAT_max: [1000, 200000],
    fwd_packets_IAT_mean: [20, 12000],
    fwd_packets_rate: [1500, 300000]
};

const OVERLAP_ATTACK_TYPES = ['DDoS', 'PortScan'];

const SRC_IPS = [
    '192.168.1.100', '192.168.1.101', '10.0.0.50', '172.16.0.5',
    '192.168.2.200', '10.10.10.10', '203.0.113.50', '198.51.100.25',
    '192.168.1.1', '10.0.0.1'
];

const DST_IPS = [
    '192.168.10.50', '10.0.0.100', '172.16.0.1', '192.168.1.200',
    '10.10.10.1', '203.0.113.1', '198.51.100.1', '192.168.10.100'
];

const PROTOCOLS = ['TCP', 'UDP', 'ICMP'];

const ATTACK_PORTS = {
    'BENIGN': [80, 443, 8080, 53, 25, 110, 993],
    'DDoS': [80, 443, 53, 8080],
    'DoS': [80, 443, 8080],
    'Brute Force': [21, 22, 3389, 23],
    'SQL Injection': [80, 443, 8080, 3306, 5432],
    'PortScan': Array.from({ length: 1023 }, (_, i) => i + 1),
    'Probe': Array.from({ length: 1023 }, (_, i) => i + 1),
    'Web Attack': [80, 443, 8080],
    'Bot': [4444, 5555, 6667, 1337],
    'Infiltration': [445, 3389]
};

// Normal distribution approximation (Box-Muller)
function randomNormal(mean, std) {
    const u1 = Math.random();
    const u2 = Math.random();
    const z = Math.sqrt(-2 * Math.log(u1)) * Math.cos(2 * Math.PI * u2);
    return mean + z * std;
}

function randomChoice(arr) {
    return arr[Math.floor(Math.random() * arr.length)];
}

function generateTrafficSample(attackType = null) {
    if (!attackType) {
        attackType = Math.random() < 0.55 ? 'BENIGN' : randomChoice(['DDoS', 'DoS', 'Brute Force', 'SQL Injection', 'PortScan', 'Probe', 'Web Attack', 'Bot', 'Infiltration']);
    }

    const profile = TRAFFIC_PROFILES[attackType] || TRAFFIC_PROFILES['BENIGN'];

    const isBurstyBenign = attackType === 'BENIGN' && Math.random() < REALISM_CONFIG.benign_burst_probability;
    let overlapProfileName = null;
    let overlapProfile = null;

    if (attackType === 'BENIGN' && Math.random() < REALISM_CONFIG.cross_profile_blend_probability) {
        overlapProfileName = randomChoice(OVERLAP_ATTACK_TYPES);
        overlapProfile = TRAFFIC_PROFILES[overlapProfileName];
    }

    const features = {};
    for (const featureName of Object.keys(FEATURE_RANGES)) {
        let [low, high] = profile[featureName] || FEATURE_RANGES[featureName];
        const [baseLow, baseHigh] = FEATURE_RANGES[featureName];

        if (isBurstyBenign && BENIGN_BURST_OVERRIDES[featureName]) {
            [low, high] = BENIGN_BURST_OVERRIDES[featureName];
        } else if (overlapProfile && overlapProfile[featureName] && Math.random() < 0.35) {
            [low, high] = overlapProfile[featureName];
        }

        if (featureName !== 'fwd_psh_flag_counts') {
            const span = Math.max(1.0, high - low);
            const jitter = span * REALISM_CONFIG.range_expansion_ratio;
            low = Math.max(baseLow, low - jitter);
            high = Math.min(baseHigh, high + jitter);
        }

        if (featureName === 'fwd_psh_flag_counts') {
            features[featureName] = Math.round(Math.random() * (high - low) + low);
        } else {
            if (high >= low) {
                const mid = (low + high) / 2;
                const std = Math.max((high - low) / 4, 1e-9);
                let value = randomNormal(mid, std);

                // Rare outliers
                if (Math.random() < REALISM_CONFIG.outlier_probability) {
                    value = Math.random() * (baseHigh - baseLow) + baseLow;
                }

                value = Math.max(baseLow, Math.min(baseHigh, value));
                features[featureName] = parseFloat(value.toFixed(2));
            } else {
                features[featureName] = 0.0;
            }
        }
    }

    const protocolChoice = attackType === 'BENIGN'
        ? randomChoice(PROTOCOLS)
        : ['Brute Force', 'SQL Injection', 'PortScan', 'Probe', 'Web Attack', 'Bot', 'Infiltration'].includes(attackType)
            ? 'TCP'
            : randomChoice(['TCP', 'UDP']);

    const ports = ATTACK_PORTS[attackType] || [80];
    const destinationPort = randomChoice(ports);
    const payloadHints = {
        'SQL Injection': "' OR 1=1 UNION SELECT password FROM users",
        'Web Attack': "<script>alert(1)</script>?cmd=whoami",
    };
    const uniquePorts = {
        'PortScan': Math.floor(Math.random() * 40) + 20,
        'Probe': Math.floor(Math.random() * 10) + 8,
    }[attackType] || 1;
    const connectionAttempts = {
        'Brute Force': Math.floor(Math.random() * 45) + 12,
        'Infiltration': Math.floor(Math.random() * 90) + 50,
    }[attackType] || 0;
    const packetCount = Math.round((features.fwd_packets_count || 0) + (features.bwd_packets_count || 0));

    const metadata = {
        source_ip: randomChoice(SRC_IPS),
        destination_ip: randomChoice(DST_IPS),
        source_port: Math.floor(Math.random() * (65535 - 1024)) + 1024,
        destination_port: destinationPort,
        protocol: protocolChoice,
        timestamp: new Date().toISOString(),
        actual_label: attackType,
        traffic_mode: isBurstyBenign ? 'bursty_benign' : overlapProfileName ? 'blended_benign' : 'standard',
        overlap_profile: overlapProfileName,
        payload_hint: payloadHints[attackType] || ''
    };
    features.packet_count = packetCount;
    features.unique_destination_ports = uniquePorts;
    features.connection_attempts = connectionAttempts;

    return { features, metadata };
}

function generateTrafficBatch(nSamples = 10, attackDistribution = null) {
    const samples = [];

    if (attackDistribution) {
        for (const [type, count] of Object.entries(attackDistribution)) {
            for (let i = 0; i < count; i++) {
                samples.push(generateTrafficSample(type));
            }
        }
    } else {
        for (let i = 0; i < nSamples; i++) {
            samples.push(generateTrafficSample());
        }
    }

    // Shuffle
    for (let i = samples.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [samples[i], samples[j]] = [samples[j], samples[i]];
    }

    return samples;
}

module.exports = { generateTrafficSample, generateTrafficBatch, FEATURE_NAMES, FEATURE_RANGES };
