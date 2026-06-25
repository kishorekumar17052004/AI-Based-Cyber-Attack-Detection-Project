"""Authorized packet collection and ML inference service.

Only packet metadata is retained. Capture requires a private/loopback target and an
explicit authorization acknowledgement. Run elevated and install Npcap on Windows.
"""

import ipaddress
import json
import os
import socket
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone

import joblib
import numpy as np
import requests
from flask import Flask, jsonify, request
from flask_cors import CORS

try:
    from scapy.all import IP, IPv6, TCP, UDP, Raw, conf, get_if_list, sniff
    SCAPY_AVAILABLE = True
    PCAP_AVAILABLE = os.name != "nt" or bool(conf.use_pcap)
except ImportError:
    SCAPY_AVAILABLE = False
    PCAP_AVAILABLE = False

app = Flask(__name__)
CORS(app)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(BASE_DIR, "models")
EXPRESS_INGEST_URL = os.getenv("EXPRESS_INGEST_URL", "http://127.0.0.1:5000/api/packets/ingest")

SEVERITY_MAPPING = {
    "BENIGN": "Low", "Port Scan": "Medium", "Probe": "Medium", "Bot": "Medium",
    "Brute Force": "High", "DDoS": "High", "DoS": "High",
    "SQL Injection": "High", "Web Attack": "High", "Infiltration": "Critical",
}

model = scaler = label_encoder = model_metadata = None
feature_names = ["duration", "fwd_packets_count", "bwd_packets_count",
                 "fwd_total_payload_bytes", "bwd_total_payload_bytes"]

capture_lock = threading.Lock()
capture_stop = threading.Event()
capture_thread = None
capture_state = {
    "running": False, "target_ip": None, "interface": None, "started_at": None,
    "packets_captured": 0, "last_error": None,
}
flows = {}
source_events = defaultdict(lambda: deque(maxlen=500))


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def load_model():
    global model, scaler, label_encoder, model_metadata, feature_names
    try:
        model = joblib.load(os.path.join(MODELS_DIR, "rf_model.pkl"))
        scaler = joblib.load(os.path.join(MODELS_DIR, "scaler.pkl"))
        label_encoder = joblib.load(os.path.join(MODELS_DIR, "label_encoder.pkl"))
        with open(os.path.join(MODELS_DIR, "model_metadata.json"), encoding="utf-8") as handle:
            model_metadata = json.load(handle)
        feature_names = model_metadata.get("feature_names", feature_names)
        print(f"[*] Loaded {model_metadata.get('model_type', 'model')}")
        return True
    except Exception as exc:
        print(f"[!] Model unavailable: {exc}")
        return False


def is_authorized_local_ip(value):
    """Reject unspecified, multicast, link-local and every public Internet target."""
    try:
        address = ipaddress.ip_address(value)
        return (address.is_private or address.is_loopback) and not (
            address.is_multicast or address.is_unspecified or address.is_link_local
        )
    except ValueError:
        return False


def normalize_features(features):
    vector = []
    for name in feature_names:
        try:
            vector.append(float(features.get(name, 0) or 0))
        except (TypeError, ValueError):
            vector.append(0.0)
    return vector


def model_prediction(features):
    if model is None or label_encoder is None:
        return None
    try:
        values = np.array(normalize_features(features)).reshape(1, -1)
        values = scaler.transform(values) if scaler is not None else values
        prediction = model.predict(values)[0]
        probabilities = model.predict_proba(values)[0]
        label = str(label_encoder.inverse_transform([prediction])[0]).replace("PortScan", "Port Scan")
        return label, float(np.max(probabilities) * 100), {
            str(name).replace("PortScan", "Port Scan"): round(float(probabilities[i] * 100), 2)
            for i, name in enumerate(label_encoder.classes_)
        }
    except Exception as exc:
        print(f"[!] Inference error: {exc}")
        return None


def classify(features, metadata=None):
    """Conservative detector layered over the supplied limited-class RF artifact."""
    metadata = metadata or {}
    packet_rate = float(features.get("packets_rate", 0) or 0)
    bytes_rate = float(features.get("bytes_rate", 0) or 0)
    packet_count = int(features.get("packet_count", 1) or 1)
    destination_port = int(metadata.get("destination_port", 0) or 0)
    unique_ports = int(features.get("unique_destination_ports", 1) or 1)
    failed_attempts = int(features.get("connection_attempts", 0) or 0)
    payload_hint = str(metadata.get("payload_hint", "")).lower()

    label, confidence, source = "BENIGN", 82.0, "baseline"
    if any(token in payload_hint for token in ("union select", "or 1=1", "drop table")):
        label, confidence, source = "SQL Injection", 94.0, "signature"
    elif any(token in payload_hint for token in ("<script", "../", "cmd=", "wp-admin")):
        label, confidence, source = "Web Attack", 91.0, "signature"
    elif unique_ports >= 20:
        label, confidence, source = "Port Scan", min(98.0, 75 + unique_ports / 2), "flow-heuristic"
    elif failed_attempts >= 50 and destination_port in (445, 3389) and bytes_rate > 1_000_000:
        label, confidence, source = "Infiltration", 88.0, "flow-heuristic"
    elif failed_attempts >= 12 and destination_port in (21, 22, 23, 25, 3389):
        label, confidence, source = "Brute Force", min(97.0, 78 + failed_attempts / 3), "flow-heuristic"
    elif packet_rate > 1500 or bytes_rate > 15_000_000:
        label, confidence, source = "DDoS", 95.0, "flow-heuristic"
    elif packet_rate > 600 or (packet_count > 300 and packet_rate > 200):
        label, confidence, source = "DoS", 90.0, "flow-heuristic"
    elif unique_ports >= 8:
        label, confidence, source = "Probe", 78.0, "flow-heuristic"
    elif destination_port in (4444, 5555, 6667, 1337) and packet_count >= 5:
        label, confidence, source = "Bot", 76.0, "flow-heuristic"

    rf = model_prediction(features)
    probabilities = rf[2] if rf else {label: confidence}
    if rf and label in ("DDoS", "Brute Force") and rf[0] == label:
        confidence, source = max(confidence, rf[1]), "random-forest+flow"

    return {
        "attack_type": label,
        "predicted_label": label,
        "severity": SEVERITY_MAPPING[label],
        "confidence_score": round(confidence, 2),
        "confidence": round(confidence, 2),
        "is_attack": label != "BENIGN",
        "class_probabilities": probabilities,
        "detector": source,
    }


def packet_metadata(packet, target_ip):
    network = packet.getlayer(IP) or packet.getlayer(IPv6)
    if network is None:
        return None
    src, dst = str(network.src), str(network.dst)
    transport = packet.getlayer(TCP) or packet.getlayer(UDP)
    protocol = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else str(network.nh if packet.haslayer(IPv6) else network.proto)
    sport = int(getattr(transport, "sport", 0))
    dport = int(getattr(transport, "dport", 0))
    now = time.time()
    key = (src, dst, sport, dport, protocol)
    reverse_key = (dst, src, dport, sport, protocol)
    flow = flows.get(key) or flows.get(reverse_key)
    if flow is None:
        flow = {"start": now, "count": 0, "bytes": 0, "fwd_count": 0, "bwd_count": 0,
                "fwd_bytes": 0, "bwd_bytes": 0}
        flows[key] = flow
    size = len(packet)
    forward = src == key[0] if key in flows else src == reverse_key[0]
    flow["count"] += 1
    flow["bytes"] += size
    flow["fwd_count" if forward else "bwd_count"] += 1
    flow["fwd_bytes" if forward else "bwd_bytes"] += size
    duration = max(now - flow["start"], 0.001)

    events = source_events[(src, dst)]
    tcp_flags = int(getattr(transport, "flags", 0)) if packet.haslayer(TCP) else 0
    is_connection_attempt = packet.haslayer(UDP) or (tcp_flags & 0x02 and not tcp_flags & 0x10)
    if is_connection_attempt:
        events.append((now, dport))
    while events and events[0][0] < now - 10:
        events.popleft()
    unique_ports = len({port for _, port in events if port})
    payload_hint = ""
    if packet.haslayer(Raw):
        payload_hint = bytes(packet[Raw].load[:256]).decode("utf-8", errors="ignore")

    features = {
        "duration": round(duration, 6), "packet_count": flow["count"],
        "bytes_rate": round(flow["bytes"] / duration, 2),
        "packets_rate": round(flow["count"] / duration, 2),
        "fwd_packets_count": flow["fwd_count"], "bwd_packets_count": flow["bwd_count"],
        "fwd_total_payload_bytes": flow["fwd_bytes"], "bwd_total_payload_bytes": flow["bwd_bytes"],
        "unique_destination_ports": unique_ports, "connection_attempts": len(events),
    }
    return features, {
        "source_ip": src, "destination_ip": dst, "source_port": sport,
        "destination_port": dport, "protocol": protocol, "packet_size": size,
        "payload_hint": payload_hint, "target_ip": target_ip,
    }


def forward_packet(packet, target_ip):
    extracted = packet_metadata(packet, target_ip)
    if not extracted:
        return
    features, metadata = extracted
    result = classify(features, metadata)
    record = {**result, **{k: v for k, v in metadata.items() if k != "payload_hint"},
              "features": features, "timestamp": utc_now()}
    try:
        requests.post(EXPRESS_INGEST_URL, json=record, timeout=2).raise_for_status()
        with capture_lock:
            capture_state["packets_captured"] += 1
    except requests.RequestException as exc:
        with capture_lock:
            capture_state["last_error"] = f"Express ingestion failed: {exc}"


def capture_worker(target_ip, interface):
    try:
        while not capture_stop.is_set():
            sniff(iface=interface or None, filter=f"host {target_ip}",
                  prn=lambda packet: forward_packet(packet, target_ip),
                  store=False, timeout=1)
    except Exception as exc:
        with capture_lock:
            capture_state["last_error"] = str(exc)
    finally:
        with capture_lock:
            capture_state["running"] = False


@app.get("/health")
def health():
    return jsonify(status="ok", model_loaded=model is not None,
                   scapy_available=SCAPY_AVAILABLE, pcap_available=PCAP_AVAILABLE,
                   capture_ready=SCAPY_AVAILABLE and PCAP_AVAILABLE,
                   capture=capture_state, timestamp=utc_now())


@app.get("/model-info")
def model_info():
    metadata = model_metadata or {}
    metrics = metadata.get("metrics", {})
    return jsonify(model_type=metadata.get("model_type", "Heuristic fallback"),
                   n_features=len(feature_names), feature_names=feature_names,
                   classes=list(SEVERITY_MAPPING), n_classes=len(SEVERITY_MAPPING),
                   trained_classes=metadata.get("classes", []), accuracy=metrics.get("accuracy", 0),
                   f1_score=metrics.get("f1_score", 0))


@app.get("/feature-names")
def get_feature_names():
    return jsonify(feature_names=feature_names, count=len(feature_names))


@app.post("/predict")
def predict():
    data = request.get_json(silent=True) or {}
    if "features" not in data:
        return jsonify(error="Missing features"), 400
    result = classify(data["features"], data.get("metadata"))
    return jsonify(**result, source_ip=data.get("metadata", {}).get("source_ip", "N/A"),
                   destination_ip=data.get("metadata", {}).get("destination_ip", "N/A"), timestamp=utc_now())


@app.post("/predict-batch")
def predict_batch():
    data = request.get_json(silent=True) or {}
    if not isinstance(data.get("samples"), list):
        return jsonify(error="Missing samples"), 400
    return jsonify(results=[classify(item.get("features", item), item.get("metadata")) for item in data["samples"]])


@app.get("/capture/interfaces")
def interfaces():
    return jsonify(interfaces=get_if_list() if SCAPY_AVAILABLE else [], hostname=socket.gethostname())


@app.get("/capture/status")
def capture_status():
    return jsonify(capture_state)


@app.post("/capture/start")
def start_capture():
    global capture_thread
    data = request.get_json(silent=True) or {}
    target_ip = str(data.get("target_ip", "")).strip()
    interface = str(data.get("interface", "")).strip() or None
    if data.get("authorized") is not True:
        return jsonify(error="You must confirm that you own or are authorized to monitor this device/network."), 403
    if not is_authorized_local_ip(target_ip):
        return jsonify(error="Only private or loopback IP addresses are allowed."), 400
    if not SCAPY_AVAILABLE:
        return jsonify(error="Scapy is not installed. Install requirements.txt first."), 503
    if not PCAP_AVAILABLE:
        return jsonify(error="Npcap is required for packet capture on Windows. Install Npcap in WinPcap API-compatible mode, then restart Flask."), 503
    with capture_lock:
        if capture_state["running"]:
            return jsonify(error="A capture session is already running."), 409
        capture_stop.clear()
        capture_state.update(running=True, target_ip=target_ip, interface=interface,
                             started_at=utc_now(), packets_captured=0, last_error=None)
        capture_thread = threading.Thread(target=capture_worker, args=(target_ip, interface), daemon=True)
        capture_thread.start()
    return jsonify(message="Authorized capture started", capture=capture_state), 202


@app.post("/capture/stop")
def stop_capture():
    capture_stop.set()
    with capture_lock:
        capture_state["running"] = False
    return jsonify(message="Capture stop requested", capture=capture_state)


if __name__ == "__main__":
    load_model()
    app.run(host=os.getenv("FLASK_HOST", "127.0.0.1"), port=int(os.getenv("FLASK_PORT", "5001")),
            debug=os.getenv("FLASK_DEBUG", "false").lower() == "true", threaded=True)
