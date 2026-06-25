# CyberShield AI

An authorized-network monitoring dashboard built with React, Express, MongoDB, and a Python Flask/Scapy detection service.

## Safety boundary

This project is defensive monitoring software. Capture starts only when the operator confirms authorization, and Flask accepts only private or loopback target IPs. Scapy receives a `host <target_ip>` capture filter. Packet payloads are inspected only in memory for a few detection indicators and are never forwarded or stored; MongoDB receives metadata and derived features only.

Do not use this application on devices or networks you do not own or have explicit permission to monitor.

## Architecture

| Service | Port | Purpose |
| --- | ---: | --- |
| React + Vite | 5173 | Dashboard, live monitor, logs, connection and prediction pages |
| Express API | 5000 | Collector proxy, REST API, MongoDB persistence and statistics |
| Flask + Scapy + scikit-learn | 5001 | Authorized packet capture, feature extraction and inference |
| MongoDB | 27017 | Packet and alert storage |

```text
Project-MERN/
├── backend/
│   ├── server.js
│   ├── trafficSimulator.js
│   ├── models/
│   │   ├── Prediction.js
│   │   └── Alert.js
│   └── ml-service/
│       ├── app.py
│       ├── requirements.txt
│       └── models/               # Random Forest, scaler, encoder, metadata
├── frontend/
│   └── src/
│       ├── pages/                # Dashboard, monitor, logs, connection, prediction
│       ├── components/
│       ├── context/
│       ├── api.js
│       └── App.jsx
├── package.json
└── README.md
```

The supplied Random Forest artifact was trained for only `Brute Force` and `DDoS`. The Flask service therefore layers conservative stateful flow/signature rules over that model for BENIGN, DoS, Port Scan, SQL Injection, Web Attack, Bot, Infiltration, and Probe. This makes every requested label available, but it is a development baseline—not a production IDS or a claim of validated accuracy for those additional classes. Retrain with representative labeled data before relying on it operationally.

## Stored packet schema

```js
{
  packet_id,
  source_ip,
  destination_ip,
  source_port,
  destination_port,
  protocol,
  packet_size,
  attack_type,       // virtual alias of predicted_label
  severity,
  confidence_score, // virtual alias of confidence
  timestamp,
  features
}
```

Severity mapping: BENIGN=Low; Port Scan, Probe and Bot=Medium; Brute Force, DDoS, DoS, SQL Injection and Web Attack=High; Infiltration=Critical.

## Setup on Windows

Prerequisites: Node.js 18+, Python 3.10+, MongoDB, and [Npcap](https://npcap.com/) in WinPcap-compatible mode. Open Command Prompt as Administrator for live packet capture.

Step 1: Open Command Prompt as Administrator and go to the project folder:

```bat
cd C:\Users\kisho\Documents\Project-MERN
```

Step 2: Install Node packages:

```bat
npm install
npm install --prefix backend
npm install --prefix frontend
```

Step 3: Create the Python environment:

```bat
py -m venv .venv
```

Step 4: Install Python packages:

```bat
.venv\Scripts\python.exe -m pip install -r backend\ml-service\requirements.txt
```

Step 5: Create the backend `.env` file:

```bat
copy backend\.env.example backend\.env
```

Step 6: Start MongoDB in another Command Prompt window:

```bat
mongod
```

Keep this MongoDB window open.

Step 7: Start the project from the project Command Prompt window:

```bat
npm run dev
```

If you are using PowerShell instead of Command Prompt, use:

```powershell
npm.cmd run dev
```

Step 8: Open the app:

```text
http://localhost:5173
```

If Flask does not start with `npm run dev`, run Flask directly:

```bat
.venv\Scripts\python.exe backend\ml-service\app.py
```

Run Express and React in separate terminals with `npm run server` and `npm run client` when using that direct Flask command.

## Setup on macOS/Linux

Install libpcap using your OS package manager, then:

```bash
npm install
npm install --prefix backend
npm install --prefix frontend
python3 -m venv .venv
source .venv/bin/activate
pip install -r backend/ml-service/requirements.txt
cp backend/.env.example backend/.env
mongod
```

Start Flask with elevated capture permission, Express, and React in separate terminals:

```bash
sudo .venv/bin/python backend/ml-service/app.py
npm run server
npm run client
```

## Using live capture

1. Open **Device Connection**.
2. Enter the private IP of your laptop/authorized device and select an interface if automatic selection is insufficient.
3. Confirm the authorization checkbox, then start capture.
4. Generate ordinary traffic on that device and open **Live Packets**. Records refresh every two seconds.
5. Stop capture when finished.

Important: entering a mobile or hotspot IP does not remotely connect to that phone. Scapy can analyze only traffic visible to the computer/interface where Flask is running. Modern switched/Wi-Fi networks usually do not expose another client's unicast traffic to your laptop.

## API routes

| Method | Route | Description |
| --- | --- | --- |
| GET | `/api/health` | Express, MongoDB and model status |
| GET | `/api/stats?hours=24` | Dashboard counters, charts and recent alerts |
| GET | `/api/packets?limit=100` | Recent packet records |
| GET | `/api/packets/:packetId` | One prediction result |
| POST | `/api/packets/ingest` | Metadata ingestion from local Flask collector |
| GET | `/api/capture/interfaces` | Scapy interfaces |
| GET | `/api/capture/status` | Capture state |
| POST | `/api/capture/start` | Start allowlisted capture (`target_ip`, `interface`, `authorized`) |
| POST | `/api/capture/stop` | Stop capture |
| POST | `/api/predict` | Predict one feature object |
| POST | `/api/predict-batch` | Predict JSON or CSV batch |
| GET | `/api/alerts?limit=50` | Attack logs |
| GET | `/api/simulate?count=5` | Safe synthetic development traffic |
| POST | `/api/clear-data` | Delete stored packets and alerts |

Example prediction body:

```json
{
  "features": {
    "duration": 2.5,
    "fwd_packets_count": 20,
    "bwd_packets_count": 12,
    "fwd_total_payload_bytes": 14000,
    "bwd_total_payload_bytes": 7000
  },
  "metadata": {
    "source_ip": "192.168.1.10",
    "destination_ip": "192.168.1.1",
    "protocol": "TCP"
  }
}
```

## Troubleshooting

- **Windows says `Permission denied` for `.venv\Scripts\python.exe`:** close any running project terminals, then recreate the virtual environment:
  ```bat
  rmdir /s /q .venv
  py -m venv .venv
  .venv\Scripts\python.exe -m pip install -r backend\ml-service\requirements.txt
  ```
- **Flask says permission denied:** use an elevated terminal and verify Npcap/libpcap installation.
- **No packets appear:** choose the correct active interface and make sure the target traffic is visible on the capture host.
- **MongoDB disconnected:** start `mongod` and verify `backend/.env`.
- **The dashboard loads but has no data:** start a capture or use the safe simulator on Model Prediction.
- **Capture stop takes a moment:** the collector checks its stop event at least once per second.
