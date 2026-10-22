# Intelligent Network Threat Detection & Security Analytics Platform (NetShield)

A modular, interactive network security monitoring platform that analyses actual network traffic (PCAP), generates bidirectional network flows, detects suspicious activity using configurable rule-based algorithms and AI anomaly detection (Isolation Forest), assigns explainable 0–100 risk scores, and visualises findings through a dark-themed Security Operations Center (SOC) dashboard.

---

## 1. Architecture Overview

NetShield is built with a clean separation of concerns to allow swapping packet ingestion (e.g., from PCAP replay to live interface capture) without altering the downstream flow aggregator, detection rules, or scoring engines.

```
                              ┌────────────────────────────────────────┐
                              │            PCAP Ingestion              │
                              │ (Scapy Metadata & 5-Tuple Extraction)  │
                              └───────────────────┬────────────────────┘
                                                  │
                                                  ▼
                              ┌────────────────────────────────────────┐
                              │        Flow Aggregation Engine         │
                              │ (Bidirectional metrics, timeouts, TCP) │
                              └─────────┬────────────────────┬─────────┘
                                        │                    │
                   ┌────────────────────┴─────┐        ┌─────┴───────────────────┐
                   ▼                          ▼        ▼                         ▼
        ┌───────────────────────┐   ┌───────────────────────┐   ┌────────────────────────┐
        │  Rule-Based Engine    │   │  AI Anomaly Engine    │   │ SQLite Storage         │
        │ - Port Scan           │   │ - Isolation Forest    │   │ - PcapFiles            │
        │ - Excessive Conn Rate │   │ - Flow-level features │   │ - NetworkFlows         │
        │ - DNS Tunnel/Bursts   │   │ - Feature attribution │   │ - ThreatAlerts         │
        └──────────┬────────────┘   └───────────┬───────────┘   └────────────────────────┘
                   │                            │
                   └─────────────┬──────────────┘
                                 ▼
                    ┌─────────────────────────┐
                    │ Explainable Risk Scorer │
                    │ (0 - 100 risk scale)    │
                    └────────────┬────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │       FastAPI API       │
                    │ REST Endpoints & CORS   │
                    └────────────┬────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │ React + TS SOC Frontend │
                    │ Dashboard & Triage      │
                    └─────────────────────────┘
```

---

## 2. Repository Layout

```
.
├── backend/
│   ├── app/
│   │   ├── api/                 # API routers (/health, /pcaps, /flows, /alerts, /stats)
│   │   ├── models/              # SQLAlchemy ORM models (PcapFile, NetworkFlow, ThreatAlert)
│   │   ├── schemas/             # Pydantic schemas for data validation and API serialization
│   │   ├── pipeline/            # Parsing, flow aggregation, detection rules, and ML models
│   │   │   ├── rules/           # Port scan, connection rate, and DNS detection rules
│   │   │   └── ml/              # Isolation Forest model and feature extraction
│   │   ├── config.py            # Platform configuration and threshold tunables
│   │   ├── database.py          # SQLite engine and session lifecycle
│   │   └── main.py              # FastAPI application bootstrap and lifespan
│   ├── tests/                   # Pytest test suite (health, models, pipeline)
│   └── requirements.txt         # Pinned backend dependencies
├── frontend/
│   ├── src/
│   │   ├── components/          # Navbar, StatCard, StatusBadge, EmptyState
│   │   ├── views/               # Overview, TrafficAnalytics, FlowExplorer, Alerts, Upload
│   │   ├── services/            # Fetch-based API client
│   │   ├── types/               # TypeScript interfaces matching backend models
│   │   ├── App.tsx              # Root application layout and state management
│   │   ├── index.css            # Dark SOC styling and component styles
│   │   └── main.tsx             # React entrypoint
│   ├── package.json             # Frontend dependencies
│   ├── tsconfig.json            # Strict TypeScript configuration
│   └── vite.config.ts           # Vite dev server with /api proxy
├── data/
│   ├── uploads/                 # Storage for uploaded PCAP captures
│   └── models/                  # Serialized ML model artifacts (.joblib)
├── .gitignore
└── README.md
```

---

## 3. Technology Stack

- **Backend**: Python 3.14+, FastAPI, Scapy, SQLAlchemy, SQLite, scikit-learn, pytest
- **Frontend**: React 19, TypeScript, Vite, Lucide Icons, Custom SOC Dark Theme
- **Data Stores**: SQLite database (`data/threat_detection.db`)

---

## 4. Getting Started

### Prerequisites
- Python 3.10+ (Tested on Python 3.14)
- Node.js 18+ (Tested on Node.js v26.8)
- npm 9+

### Backend Setup

1. Create and activate a Python virtual environment:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

2. Install dependencies:
   ```bash
   pip install -r backend/requirements.txt
   ```

3. Run the automated test suite:
   ```bash
   PYTHONPATH=. pytest backend/tests/ -v
   ```

4. Start the backend API server:
   ```bash
   source .venv/bin/activate
   uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
   ```
   Interactive Swagger docs are available at: `http://127.0.0.1:8000/docs`

### Frontend Setup

1. Navigate to the frontend directory and install dependencies:
   ```bash
   cd frontend
   npm install
   ```

2. Build for production to verify compilation:
   ```bash
   npm run build
   ```

3. Launch the development server:
   ```bash
   npm run dev
   ```
   Access the dashboard at: `http://localhost:5173`

---

## 5. API Contracts & Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/health` | Service health status, DB connectivity, model readiness |
| `GET` | `/api/pcaps` | List uploaded PCAP captures and metadata |
| `GET` | `/api/pcaps/{id}` | Inspect a single capture |
| `POST` | `/api/pcaps/upload` | Upload PCAP/PCAPNG file, enforce size limits, calculate SHA-256, deduplicate, and run streaming ingestion |
| `POST` | `/api/pcaps/{id}/detect` | Re-run rule-based threat detection deterministically on an existing capture |
| `DELETE` | `/api/pcaps/{id}` | Remove capture and cascade delete associated flows/alerts |
| `GET` | `/api/flows` | Query paginated bidirectional flows (filterable by IP, proto, anomalies) |
| `GET` | `/api/flows/{id}` | Single flow inspection |
| `GET` | `/api/alerts` | Query paginated threat alerts (filterable by severity, rule, status) |
| `GET` | `/api/alerts/{id}` | Alert detail with triggering evidence and flow associations |
| `PATCH` | `/api/alerts/{id}/status` | Update incident response status (`OPEN`, `INVESTIGATING`, `RESOLVED`) |
| `GET` | `/api/stats/overview` | High-level metrics (packet counts, flows, active incidents, avg risk) |
| `GET` | `/api/stats/analytics` | Protocol distribution, top sources/destinations, and timeline |

---

## 6. Packet Parsing & Byte Count Semantics

The packet parser (`backend/app/pipeline/parser.py`) extracts metadata from packets while strictly preserving protocol boundaries and layer byte semantics:
- **Captured Frame Length (`frame_len`)**: Total raw wire bytes recorded in the capture file (`len(bytes(pkt))`).
- **IP Packet Length (`ip_len`)**: Network layer octet count (IP header + payload) as defined by **RFC 7011 / IPFIX (`octetDeltaCount`)**. This represents the canonical flow byte metric stored in `NetworkFlow` (`forward_bytes`, `backward_bytes`, `total_bytes`).
- **Transport Payload Length (`payload_len`)**: Application layer payload bytes (excluding TCP/UDP transport headers).
- **Protocols Supported**: IPv4, IPv6, TCP, UDP, ICMP, ICMPv6, and DNS (over UDP and TCP). Non-IP packets (e.g. ARP, spanning-tree) and malformed frames are safely bypassed without crashing.

---

## 7. Bidirectional Flow Aggregation Semantics

The flow aggregator (`backend/app/pipeline/flow_aggregator.py`) maintains session state using the following rules:
- **Canonical Flow Key**: A direction-independent 5-tuple key:
  `min(ep1, ep2)[0]:min(ep1, ep2)[1]-max(ep1, ep2)[0]:max(ep1, ep2)[1]-protocol`
  Packets in forward and reverse directions map to the same flow record while directional packet and byte counters are incremented separately.
- **Directional Accounting**:
  - `src_ip`, `src_port`: The flow initiator (sender of the first observed packet).
  - `dst_ip`, `dst_port`: The responder endpoint.
  - `forward_packets`, `forward_bytes`: Traffic from initiator to responder.
  - `backward_packets`, `backward_bytes`: Traffic from responder to initiator.
- **TCP Connection State Tracking**:
  - Evaluates `SYN`, `SYN-ACK`, `ACK`, `FIN`, and `RST` flags across both directions.
  - States: `SYN_SENT`, `SYN_ACK_RECEIVED`, `ESTABLISHED`, `CLOSING`, `CLOSED`, `RESET`.
  - Mid-stream captures without full handshakes default to `ESTABLISHED` upon observing ACK/data traffic.
- **Idle Timeouts & Session Expiration**:
  - If the gap between a new packet and the flow's last seen timestamp exceeds `FLOW_TIMEOUT_SECONDS` (default: 60s), the current session is retired and a new flow is instantiated.
- **Connection Termination Handling**:
  - If a TCP flow is in `CLOSED` or `RESET` state and a new `SYN` handshake packet arrives on the same 5-tuple, the old flow is finalized to prevent merging unrelated connections.

---

## 8. Rule-Based Threat Detection Engine

The detection package (`backend/app/pipeline/rules/`) provides modular, deterministic rules with explainable risk scoring:

### Configured Rules & Default Thresholds
1. **Vertical Port Scanning (`RULE_PORT_SCAN_VERTICAL`)**:
   - Triggers when a source IP probes $\ge$ `PORT_SCAN_UNIQUE_PORTS` (default: 15) unique destination ports on a single host within `PORT_SCAN_WINDOW_SECONDS` (default: 10.0s).
   - Severity: `HIGH`. Base risk score: 70 + intensity bonus (up to 95).
2. **Horizontal Host Sweeping (`RULE_PORT_SCAN_HORIZONTAL`)**:
   - Triggers when a source IP probes $\ge$ `PORT_SCAN_HORIZONTAL_HOSTS` (default: 10) unique destination hosts within `PORT_SCAN_WINDOW_SECONDS` (default: 10.0s).
   - Severity: `HIGH`. Base risk score: 70 + intensity bonus (up to 95).
3. **Excessive Connection Attempts (`RULE_EXCESSIVE_CONN_RATE`)**:
   - Triggers when a source IP initiates $\ge$ `EXCESSIVE_CONN_RATE` (default: 40) connections against a target service/port within `EXCESSIVE_CONN_WINDOW_SECONDS` (default: 5.0s).
   - Severity: `MEDIUM`/`HIGH`. Base risk score: 55 + intensity bonus (up to 90).
   - Explanation notes potential service stress, rapid polling, or connection exhaustion; metadata does not claim authentication failure.
4. **Suspicious DNS Tunneling / Exfiltration (`RULE_DNS_TUNNELING_LONG_NAME`)**:
   - Triggers when a DNS query name length $\ge$ `DNS_LONG_NAME_LENGTH` (default: 50 characters).
   - Severity: `HIGH`. Base risk score: 70 + intensity bonus (up to 95).
5. **Excessive DNS Query Volume (`RULE_DNS_HIGH_VOLUME`)**:
   - Triggers when a source IP generates $\ge$ `DNS_BURST_QUERY_COUNT` (default: 25) DNS queries within `DNS_BURST_WINDOW_SECONDS` (default: 5.0s).
   - Severity: `MEDIUM`. Base risk score: 50 + intensity bonus (up to 85).
6. **DNS Domain Generation / Enumeration (`RULE_DNS_HIGH_DIVERSITY`)**:
   - Triggers when a source IP queries $\ge$ `DNS_UNIQUE_DOMAINS_THRESHOLD` (default: 15) unique domain names within a capture.
   - Severity: `MEDIUM`/`HIGH`. Base risk score: 60 + intensity bonus (up to 85).

### Risk-Scoring Methodology (0–100 Scale)
Every alert calculates an explainable score:
$$\text{Risk Score} = \min(100, \text{Base Severity} + \text{Behavioral Intensity Modifier})$$
- Base Severity: `CRITICAL` (85), `HIGH` (70), `MEDIUM` (50–60), `LOW` (25).
- Intensity Modifier: Calculated deterministically from the ratio/magnitude by which observed measurements exceed the configured threshold.
- The human-readable `explanation` breaks down both components clearly.

### Idempotence & Deduplication
- Ingestion automatically runs the rule engine and persists findings to `ThreatAlert`.
- Re-running detection via `POST /api/pcaps/{id}/detect` clears previous alerts for that capture and regenerates fresh alerts deterministically, avoiding duplicate alerts.

---

## 9. Machine Learning Anomaly Detection (Isolation Forest)

NetShield incorporates an **Isolation Forest** unsupervised statistical anomaly detector for network flows (`backend/app/pipeline/ml/`):

### Feature Extraction Schema
Each bidirectional flow is mapped into a fixed 15-dimensional numerical feature vector:
1. `forward_packets`: Total packets sent from initiator to responder.
2. `backward_packets`: Total packets sent from responder to initiator.
3. `forward_bytes`: Total IP-layer bytes sent from initiator to responder.
4. `backward_bytes`: Total IP-layer bytes sent from responder to initiator.
5. `duration`: Flow duration in seconds.
6. `packet_ratio`: Forward packets to total packets ($\frac{\text{fwd}}{\text{total}} \in [0.0, 1.0]$).
7. `byte_ratio`: Forward bytes to total bytes ($\frac{\text{fwd\_bytes}}{\text{total\_bytes}} \in [0.0, 1.0]$).
8. `forward_packet_rate`: Forward packets per second (packets/s).
9. `backward_packet_rate`: Backward packets per second (packets/s).
10. `forward_byte_rate`: Forward bytes per second (bytes/s).
11. `backward_byte_rate`: Backward bytes per second (bytes/s).
12. `is_tcp`: Binary protocol flag (1 for TCP, 0 otherwise).
13. `is_udp`: Binary protocol flag (1 for UDP/DNS, 0 otherwise).
14. `is_icmp`: Binary protocol flag (1 for ICMP, 0 otherwise).
15. `avg_packet_size`: Mean byte size per packet ($\frac{\text{total\_bytes}}{\text{total\_pkts}}$).

*Edge cases:* Sub-millisecond and zero-duration flows are bounded by an epsilon floor ($10^{-3}$s) to safely compute rates without zero-division errors. Missing or non-finite values are sanitized to 0.0. No IP addresses or port numbers are used as numerical inputs.

### Anomaly Scoring & Attribution
- **Model Output & Normalization**:
  $$\text{normalized\_score} = \operatorname{clip}(0.5 - \text{decision\_function}(X), 0.0, 1.0)$$
  - Normal inliers produce normalized scores $< 0.50$ (`is_anomaly = 0`).
  - Statistical outliers produce normalized scores $\ge 0.50$ (`is_anomaly = 1`).
- **Explainable Feature Attribution**:
  For anomalous flows, z-score deviations against baseline training means and standard deviations are computed and stored in `flow.anomaly_features_json`, identifying the exact features that drove the outlier score (e.g. extreme forward packet rate or extreme packet asymmetry).
- **Graceful Degradation**:
  If the model file is not found or fails to load, flows are persisted with default scores (`0.0`), a warning is logged, and the rule-based detection engine continues uninterrupted.

### Training & Evaluation Workflow
- **Train the Model**:
  ```bash
  source .venv/bin/activate
  python3 scripts/train_model.py
  ```
  Generates a synthetic baseline dataset ($N = 2,000$ flows across HTTP, DNS, API, Bulk, and ICMP profiles with fixed seed `42`), trains the Isolation Forest, and serializes the model and metadata to `data/models/`.
- **Evaluate the Detector**:
  ```bash
  source .venv/bin/activate
  python3 scripts/evaluate_model.py
  ```
  Scores a separate validation set (seed `999`) containing 100 benign flows and 50 designed outlier patterns (port scan probes, volumetric floods, exfiltration bursts).

---

## 10. Milestones

- [x] **Milestone 1 — Foundation**: Repository structure, Git initialization, database models, schemas, health check, modular API routers, full React/TS dashboard skeleton, automated tests, and production build verification.
- [x] **Milestone 2 — Packet and flow pipeline**: PCAP upload, Scapy streaming reader, IPv4/IPv6, TCP/UDP/ICMP/DNS parsing, bidirectional flow aggregation with timeouts and TCP state, SHA-256 deduplication, and automated unit/integration test suite.
- [x] **Milestone 3 — Rule-based detections**: Port scan, excessive connection rate, and suspicious DNS behavior detection rules with explainable risk scores and API integration.
- [x] **Milestone 4 — AI and risk scoring**: Isolation Forest training, feature extraction, explainable 0–100 risk scoring, flow attribution, and API/UI integration.
- [ ] **Milestone 5 — Dashboard integration**: End-to-end integration with live alerts, flow explorer, incident triage.
- [ ] **Milestone 6 — Validation and demonstration**: Verification PCAP test, documentation, demo instructions.
