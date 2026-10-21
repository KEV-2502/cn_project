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
| `POST` | `/api/pcaps/upload` | Upload PCAP file, check deduplication, trigger analysis |
| `DELETE` | `/api/pcaps/{id}` | Remove capture and cascade delete associated flows/alerts |
| `GET` | `/api/flows` | Query paginated bidirectional flows (filterable by IP, proto, anomalies) |
| `GET` | `/api/flows/{id}` | Single flow inspection |
| `GET` | `/api/alerts` | Query paginated threat alerts (filterable by severity, rule, status) |
| `GET` | `/api/alerts/{id}` | Alert detail with triggering evidence and flow associations |
| `PATCH` | `/api/alerts/{id}/status` | Update incident response status (`OPEN`, `INVESTIGATING`, `RESOLVED`) |
| `GET` | `/api/stats/overview` | High-level metrics (packet counts, flows, active incidents, avg risk) |
| `GET` | `/api/stats/analytics` | Protocol distribution, top sources/destinations, and timeline |

---

## 6. Milestones

- [x] **Milestone 1 — Foundation**: Repository structure, Git initialization, database models, schemas, health check, modular API routers, full React/TS dashboard skeleton, automated tests, and production build verification.
- [ ] **Milestone 2 — Packet and flow pipeline**: PCAP upload, Scapy metadata parsing, bidirectional flow aggregation with timeouts and TCP state.
- [ ] **Milestone 3 — Rule-based detections**: Port scan, excessive connection rate, and suspicious DNS behavior detection rules.
- [ ] **Milestone 4 — AI and risk scoring**: Isolation Forest training, feature extraction, explainable 0–100 risk scoring.
- [ ] **Milestone 5 — Dashboard integration**: End-to-end integration with live alerts, flow explorer, incident triage.
- [ ] **Milestone 6 — Validation and demonstration**: Verification PCAP test, documentation, demo instructions.
