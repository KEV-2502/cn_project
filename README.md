# NetShield — Intelligent Network Threat Detection & Security Analytics

NetShield is a network security monitoring and analytics project that analyzes uploaded PCAP/PCAPNG captures, aggregates packets into bidirectional network flows, detects suspicious activity with deterministic rules and an Isolation Forest anomaly detector, and presents results through a React-based Security Operations Center (SOC) dashboard.

The project combines packet parsing, flow lifecycle management, explainable alerts, ML-based anomaly scoring, SQLite persistence, REST APIs, and experimental evaluation tooling for comparing detection behavior on network traffic.

> **Project status:** Active development. The core packet/flow pipeline, rule engine, ML integration, API, and dashboard are implemented. End-to-end validation, model quality, false-positive behavior, edge cases, and UI polish still require ongoing work.
>
> **Scope:** The current application analyzes uploaded capture files. Do not assume that live network-interface capture is implemented. A detection or anomaly score is an investigation signal, not proof that traffic is malicious.

---

## Contents

- [Features](#features)
- [Architecture](#architecture)
- [Technology stack](#technology-stack)
- [Repository layout](#repository-layout)
- [Setup and local development](#setup-and-local-development)
- [Running the application](#running-the-application)
- [Using the application](#using-the-application)
- [API overview](#api-overview)
- [Packet parsing and byte semantics](#packet-parsing-and-byte-semantics)
- [Bidirectional flow aggregation](#bidirectional-flow-aggregation)
- [Rule-based detection](#rule-based-detection)
- [Machine-learning anomaly detection](#machine-learning-anomaly-detection)
- [CIC-IDS2017 experiments](#cic-ids2017-experiments)
- [Datasets and generated artifacts](#datasets-and-generated-artifacts)
- [Testing and validation](#testing-and-validation)
- [Current limitations and work remaining](#current-limitations-and-work-remaining)
- [Contributing](#contributing)

---

## Features

### Traffic ingestion and analysis

- Upload PCAP and PCAPNG capture files through the API/UI.
- Extract packet metadata and supported network/transport/application-layer fields.
- Parse IPv4, IPv6, TCP, UDP, ICMP, ICMPv6, and DNS over UDP/TCP.
- Aggregate packets into bidirectional flows with directional packet/byte counters.
- Track TCP connection state and retire stale or terminated flow sessions.
- Calculate a SHA-256 digest for uploaded captures and detect duplicate uploads.
- Persist capture metadata, flows, and alerts in SQLite.

### Detection and triage

- Detect vertical port scans and horizontal host sweeps.
- Detect excessive connection attempts and suspicious DNS patterns.
- Apply explainable risk scoring on a 0–100 scale to rule-generated alerts.
- Run Isolation Forest anomaly scoring on flow-level numerical features.
- Store anomaly feature-attribution information for investigation.
- Re-run detection for an existing capture through an API endpoint.
- Browse flows, alerts, overview statistics, and traffic analytics in the dashboard.

### Experimentation

- Train and evaluate the baseline Isolation Forest using synthetic flow profiles.
- Maintain separate CIC-IDS2017-oriented candidate models and evaluation scripts.
- Evaluate candidate behavior on capture-derived traffic, including transfer/evaluation workflows.
- Produce JSON/Markdown reports and plots for rule evaluation, model evaluation, validation, and investigation.
- Keep experimental candidate models separate from the default application model.

---

## Architecture

```text
PCAP / PCAPNG upload
        |
        v
Packet parser (Scapy)
        |
        v
Bidirectional flow aggregation
        |
        +---------------------------+
        |                           |
        v                           v
Rule-based detection          ML anomaly detection
        |                     (Isolation Forest)
        |                           |
        +-------------+-------------+
                      |
                      v
             Persisted findings
       (captures, flows, threat alerts)
                      |
                      v
                FastAPI REST API
                      |
                      v
              React + TypeScript UI
        (overview, analytics, flows, alerts,
                    capture upload)
```

The backend is organized so packet parsing, flow aggregation, rule evaluation, and ML scoring are separate components. This makes those components easier to test independently, but does not imply that a live capture source is currently available.

### Main backend modules

- `backend/app/pipeline/parser.py` — packet-level metadata extraction.
- `backend/app/pipeline/flow_aggregator.py` — bidirectional flow state and counters.
- `backend/app/pipeline/ingestion.py` — capture ingestion orchestration.
- `backend/app/pipeline/rules/` — deterministic detection rules and rule engine.
- `backend/app/pipeline/ml/features.py` — flow feature extraction.
- `backend/app/pipeline/ml/model.py` — loading/scoring with the Isolation Forest.
- `backend/app/api/` — HTTP API routers.
- `backend/app/models/` and `backend/app/database.py` — persistence models and SQLite session setup.

---

## Technology stack

| Area | Technologies |
|---|---|
| Backend/API | Python, FastAPI, Uvicorn, Pydantic |
| Packet processing | Scapy |
| Persistence | SQLAlchemy, SQLite |
| ML | scikit-learn Isolation Forest, joblib |
| Backend tests | pytest |
| Frontend | React, TypeScript, Vite |
| Icons | Lucide React |
| UI | Custom dark SOC dashboard |

The README has previously been exercised in a Python 3.14 and Node.js 26 environment. Other compatible versions may work, but the exact supported version range has not been comprehensively validated. Use the project's dependency files as the source of truth.

---

## Repository layout

```text
.
├── backend/
│   ├── app/
│   │   ├── api/                  # health, PCAP, flow, alert, and stats endpoints
│   │   ├── models/               # SQLAlchemy persistence models
│   │   ├── schemas/              # request/response schemas
│   │   ├── pipeline/
│   │   │   ├── ml/               # feature extraction, model scoring, training
│   │   │   └── rules/            # port scan, connection rate, DNS rules
│   │   ├── config.py             # configuration and thresholds
│   │   ├── database.py           # database/session lifecycle
│   │   └── main.py               # FastAPI application
│   ├── tests/                    # backend tests
│   └── requirements.txt
├── data/
│   ├── models/                   # default model, metadata, candidate model
│   ├── uploads/                  # runtime capture uploads; not committed
│   ├── generate_test_pcap.py     # synthetic test capture generator
│   └── generate_bidirectional_test_pcap.py
├── experiments/
│   └── cic_ids2017/
│       ├── artifacts/            # capture-derived candidate artifacts
│       ├── models/               # experimental candidate models
│       ├── reports/              # evaluation outputs and plots
│       ├── data_loader.py
│       ├── features.py
│       ├── model.py
│       ├── partitioner.py
│       ├── rule_evaluation_harness.py
│       ├── run_experiment.py
│       ├── run_investigation.py
│       ├── run_validation_experiment.py
│       ├── train_pcap_model.py
│       ├── evaluate*.py
│       └── test_*.py
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   ├── services/             # frontend API client
│   │   ├── types/                # TypeScript API/data types
│   │   └── views/                # overview, analytics, flows, alerts, upload
│   ├── package.json
│   ├── package-lock.json
│   ├── tsconfig.json
│   └── vite.config.ts
├── scripts/
│   ├── train_model.py
│   └── evaluate_model.py
├── .gitignore
└── README.md
```

Some experiment scripts generate additional artifacts and reports at runtime. Large raw datasets and local/generated runtime state are intentionally excluded from Git.

---

## Setup and local development

### Prerequisites

- Python and `venv`
- Node.js and npm
- Git
- Network access for installing dependencies

Python 3.10+ and Node.js 18+ are listed as baseline prerequisites in the original project notes. The project has also been used with Python 3.14 and Node.js 26.8. Dependency compatibility should be checked if using a substantially different environment.

### 1. Clone the repository

```bash
git clone https://github.com/KEV-2502/cn_project.git
cd cn_project
```

### 2. Set up the backend

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r backend/requirements.txt
```

Run the backend tests:

```bash
PYTHONPATH=. pytest backend/tests/ -v
```

Start the API server from the repository root:

```bash
uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
```

- API base URL: `http://127.0.0.1:8000`
- Interactive Swagger UI: `http://127.0.0.1:8000/docs`
- OpenAPI schema: `http://127.0.0.1:8000/openapi.json`

Keep the virtual environment activated in the terminal running the backend.

### 3. Set up the frontend

Open a second terminal:

```bash
cd frontend
npm ci
```

Start the development server:

```bash
npm run dev
```

Vite normally serves the frontend at `http://localhost:5173`. Open the URL printed by Vite if it chooses a different port.

Build the frontend:

```bash
npm run build
```

The Vite configuration includes an API proxy for local development. If frontend requests fail, check that the backend is running and review `frontend/vite.config.ts` and the browser's network console.

### 4. Runtime data

The backend uses SQLite and local directories for runtime data and serialized models. Runtime databases and uploaded capture files may be created during normal use. Do not commit local databases, uploaded traffic captures, credentials, or generated caches.

The default model artifacts are stored under `data/models/`. If a required model is absent or incompatible, inspect the backend logs and health endpoint. The rule engine is designed to continue operating if ML model loading fails, but anomaly scores may fall back to default values.

---

## Running the application

1. Start the backend from the repository root.
2. Start the frontend from `frontend/`.
3. Open the frontend URL reported by Vite.
4. Upload a PCAP/PCAPNG capture using the upload view.
5. Inspect the capture, flows, alerts, and analytics views.
6. Use the API documentation at `/docs` to inspect endpoints and request/response schemas.

Use test captures or traffic that you are authorized to analyze. Capture contents can include sensitive IP addresses, hostnames, DNS queries, and other metadata.

---

## API overview

The API is served by FastAPI. The routes documented in the current project include:

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/api/health` | Service health, database connectivity, model readiness |
| `GET` | `/api/pcaps` | List captures and metadata |
| `GET` | `/api/pcaps/{id}` | Inspect one capture |
| `POST` | `/api/pcaps/upload` | Upload a PCAP/PCAPNG, calculate SHA-256, deduplicate, and ingest |
| `POST` | `/api/pcaps/{id}/detect` | Re-run detection on an existing capture |
| `DELETE` | `/api/pcaps/{id}` | Delete a capture and associated records |
| `GET` | `/api/flows` | Query paginated flows and supported filters |
| `GET` | `/api/flows/{id}` | Inspect one flow |
| `GET` | `/api/alerts` | Query paginated alerts and supported filters |
| `GET` | `/api/alerts/{id}` | Inspect alert evidence and flow associations |
| `PATCH` | `/api/alerts/{id}/status` | Update incident status |
| `GET` | `/api/stats/overview` | Summary statistics |
| `GET` | `/api/stats/analytics` | Protocol distribution, top sources/destinations, timeline |

Consult `/docs` for the actual request parameters, response schemas, and validation behavior of the checked-out version.

---

## Packet parsing and byte semantics

The packet parser extracts packet metadata while distinguishing several byte counts:

- **Captured frame length (`frame_len`)** — the length of the serialized captured packet.
- **IP packet length (`ip_len`)** — the network-layer packet length used for flow byte counters where available.
- **Transport payload length (`payload_len`)** — application payload bytes excluding TCP/UDP headers.

The parser supports IPv4, IPv6, TCP, UDP, ICMP, ICMPv6, and DNS over UDP/TCP. Non-IP packets and malformed frames should be skipped safely rather than crashing ingestion. Verify these semantics against the parser and tests when modifying packet accounting.

---

## Bidirectional flow aggregation

The flow aggregator groups traffic in both directions into a shared flow record while maintaining directional counters.

### Directional accounting

- `src_ip`, `src_port` — initiator endpoint, based on the first observed packet.
- `dst_ip`, `dst_port` — responder endpoint.
- `forward_packets`, `forward_bytes` — initiator-to-responder traffic.
- `backward_packets`, `backward_bytes` — responder-to-initiator traffic.

### TCP lifecycle

The aggregator tracks TCP flags and connection state, including SYN, SYN-ACK, ACK, FIN, and RST behavior. States represented in the existing design include `SYN_SENT`, `SYN_ACK_RECEIVED`, `ESTABLISHED`, `CLOSING`, `CLOSED`, and `RESET`.

Mid-stream captures may not include a full handshake. Idle flows are retired after the configured timeout (the documented default is 60 seconds). A new SYN after a closed/reset connection is intended to start a separate session rather than merge unrelated connections sharing the same 5-tuple.

These are implementation semantics, not a guarantee that every unusual TCP sequence is fully reconstructed. Keep edge-case tests in place when changing flow lifecycle behavior.

---

## Rule-based detection

Rules are located in `backend/app/pipeline/rules/`. The engine generates deterministic findings from observed packet/flow behavior and assigns explainable risk scores.

The documented rule families and default thresholds are:

| Detection | Default trigger | Documented severity/risk behavior |
|---|---|---|
| Vertical port scan | At least 15 unique destination ports on one host within 10 seconds | High; base risk 70 plus intensity adjustment |
| Horizontal host sweep | At least 10 unique destination hosts within 10 seconds | High; base risk 70 plus intensity adjustment |
| Excessive connection attempts | At least 40 attempts against a target service/port within 5 seconds | Medium/high; base risk 55 plus intensity adjustment |
| Long DNS query name | DNS query name length at least 50 characters | High; base risk 70 plus intensity adjustment |
| DNS query burst | At least 25 DNS queries within 5 seconds | Medium; base risk 50 plus intensity adjustment |
| DNS domain diversity | At least 15 unique domains in a capture | Medium/high; base risk 60 plus intensity adjustment |

Thresholds are configurable; check `backend/app/config.py` and the relevant rule implementations for the current source of truth.

### Risk scores

Rule-generated alerts use a 0–100 risk scale. The documented design combines a base severity score with a deterministic behavioral-intensity modifier, capped at 100. The alert explanation should communicate why the rule fired and how the score was derived.

A risk score is not a calibrated probability of compromise. Thresholds require validation against benign and malicious examples, and rules such as long DNS names can produce false positives in legitimate environments.

### Re-running detection

The `POST /api/pcaps/{id}/detect` endpoint is intended to regenerate detection results for an existing capture without accumulating duplicate alerts. Tests should cover repeat execution, deletion, and consistency of associated flows/alerts.

---

## Machine-learning anomaly detection

The application uses an unsupervised Isolation Forest model to score flow-level numerical features. Implementation lives in `backend/app/pipeline/ml/`.

### Baseline feature vector

The documented feature schema has 15 values:

1. `forward_packets`
2. `backward_packets`
3. `forward_bytes`
4. `backward_bytes`
5. `duration`
6. `packet_ratio`
7. `byte_ratio`
8. `forward_packet_rate`
9. `backward_packet_rate`
10. `forward_byte_rate`
11. `backward_byte_rate`
12. `is_tcp`
13. `is_udp`
14. `is_icmp`
15. `avg_packet_size`

The features describe flow volume, duration, directional asymmetry, rates, protocol indicators, and average packet size. IP addresses and port numbers are not used as direct numerical inputs in this baseline feature schema.

Zero or very short durations require safeguards when calculating rates. Missing and non-finite values should be handled consistently with the feature-extraction implementation.

### Scores and attribution

The documented score normalization is based on the Isolation Forest decision function and is clipped to `[0, 1]`. The current baseline design treats normalized scores below `0.50` as inliers and scores at or above `0.50` as anomalies. Verify the implementation before interpreting score values, particularly when models or feature transformations change.

For anomalous flows, the application can store feature-deviation information in `anomaly_features_json` to help explain which flow measurements differ from the training baseline.

If the model cannot be loaded, the application is designed to log a warning and continue rule-based detection. In that case, ML results should not be interpreted as valid model predictions.

### Baseline training and evaluation

Train the baseline model:

```bash
source .venv/bin/activate
python scripts/train_model.py
```

Evaluate the baseline detector:

```bash
source .venv/bin/activate
python scripts/evaluate_model.py
```

The documented baseline training workflow uses synthetic flow profiles with a fixed seed, and the evaluation script generates a separate synthetic validation set containing benign flows and designed outlier patterns. These tests help validate pipeline behavior but are **not equivalent to a representative real-world security benchmark**.

---

## CIC-IDS2017 experiments

The `experiments/cic_ids2017/` directory contains a separate experimental workflow for evaluating detection behavior with CIC-IDS2017-oriented traffic. It is not the same thing as the baseline synthetic-model training workflow, and experimental candidates should not automatically replace the application's default model.

### Main experiment components

| Component | Purpose |
|---|---|
| `data_loader.py` | Load/prepare data for experiments |
| `features.py` | Experimental feature extraction |
| `partitioner.py` | Partition traffic/data for evaluation workflows |
| `sampler.py` | Sampling helpers used by experiments |
| `model.py` | Candidate model wrapper |
| `run_experiment.py` | Run the candidate-model experiment workflow |
| `run_validation_experiment.py` | Run validation workflow |
| `run_investigation.py` | Generate investigation-oriented outputs |
| `rule_evaluation_harness.py` | Evaluate rule-based detection behavior |
| `train_pcap_model.py` | Train/evaluate a capture-derived candidate model |
| `evaluate.py` | Candidate model evaluation |
| `evaluate_pcap_transfer.py` | Candidate-model transfer evaluation |
| `evaluate_friday_traffic.py` | Evaluation on Friday capture traffic |
| `audit_friday_evaluation.py` | Audit the Friday evaluation workflow/results |
| `pcap_pipeline_validator.py` | Validate capture-to-pipeline behavior |
| `plot_results.py` | Generate experiment plots |
| `demo_model.py` | Demo/inference using the experimental candidate model |
| `compare_ml_candidates.py` | Compare candidate-model outputs/results |

The exact command-line arguments and expected input files can vary by script. Inspect each script's module docstring and argument parser before running it.

### Evaluation and investigation artifacts

The repository contains Markdown and JSON reports, including:

- `reports/evaluation_report.md` and `.json`
- `reports/validation_report.md` and `.json`
- `reports/investigation_report.md` and `.json`
- `reports/rule_evaluation_report.md` and `.json`
- `reports/pcap_model_evaluation.md` and `.json`
- `reports/pcap_transfer_evaluation.md` and `.json`
- `reports/friday_evaluation_report.md` and `.json`
- `reports/friday_evaluation_audit.md` and `.json`
- `reports/monday_pcap_pipeline_validation.md` and `.json`
- `reports/horizontal_scan_refinement_report.md`
- `reports/figures/` — evaluation plots such as confusion matrices, per-attack detection rates, anomaly score distributions, validation/test curves, and recall-versus-false-positive-rate curves.

Treat these as records of particular experiment runs, not universal performance guarantees. Always read the report's dataset, split, labels, thresholds, and metric definitions before quoting a result. A plot or aggregate metric by itself is not sufficient to establish generalization.

### Candidate models and artifacts

Experimental model artifacts may include:

- `data/models/candidate_isolation_forest_cic.joblib`
- `experiments/cic_ids2017/models/candidate_isolation_forest_log1p.joblib`
- `experiments/cic_ids2017/artifacts/pcap_model/candidate_pcap_isolation_forest.joblib`
- partitioning or intermediate artifacts produced by experiment scripts.

The default application model remains `data/models/isolation_forest.joblib`. Candidate artifacts are for controlled evaluation and comparison. Before promoting a candidate, verify compatibility with the production feature schema, repeatable inference, validation methodology, false-positive rate, recall, and regression tests.

### Reproducibility cautions

- The raw capture dataset is not included in the repository.
- Experiment scripts may require the separately obtained dataset at specific local paths.
- Reports can contain paths or other metadata from the machine that generated them.
- Generated SQLite databases, raw flow dumps, caches, and large intermediate artifacts should remain local unless there is a clear, documented reason to version them.
- Record dataset provenance, preprocessing, train/validation/test split, random seed, thresholds, and model hash when comparing runs.
- Avoid tuning on the final test set; keep validation and test data separate to reduce leakage.

---

## Datasets and generated artifacts

The repository intentionally excludes the large raw PCAP dataset files and associated large archives. The local development copy has included multi-gigabyte CIC-IDS2017 captures; these are not suitable for ordinary Git commits.

To reproduce dataset-backed experiments:

1. Obtain the dataset from its legitimate source and follow its terms of use.
2. Check the selected script's expected input path and filename.
3. Place the dataset locally without committing it.
4. Run the script and review its output paths and report.
5. Do not commit raw captures, generated flow databases, or derived traffic data unless the team has explicitly reviewed the size, provenance, licensing, and privacy implications.

`.gitignore` excludes local environments, dependency directories, build outputs, runtime uploads, model outputs not explicitly allowed, and the raw dataset directory. If a file is already tracked, adding it to `.gitignore` does not remove it from Git history; untrack it explicitly if needed.

Small generated test captures may be retained if they are needed by automated tests and do not contain sensitive traffic.

---

## Testing and validation

### Backend

Run the main backend test suite:

```bash
source .venv/bin/activate
PYTHONPATH=. pytest backend/tests/ -v
```

Tests cover core areas such as packet parsing, flow aggregation, database models, health checks, PCAP ingestion, rule detection, ML anomaly behavior, horizontal scan refinement, and PCAP re-analysis. The exact set may grow as the project evolves.

Run an individual test module:

```bash
PYTHONPATH=. pytest backend/tests/test_packet_parser.py -v
```

### Frontend

From the `frontend/` directory:

```bash
npm ci
npm run build
```

The production build is a useful compile-time check, but it does not replace browser-based end-to-end testing.

### Experimental tests

Experiment-specific tests live under `experiments/cic_ids2017/` and may require extra datasets or candidate artifacts. Inspect dependencies before running the entire experiment suite:

```bash
source .venv/bin/activate
PYTHONPATH=. pytest experiments/cic_ids2017/ -v
```

If a test expects raw CIC-IDS2017 data that you do not have locally, document that dependency rather than interpreting the skipped/failed data-dependent test as a product regression.

### Before merging changes

- Run relevant unit/integration tests.
- Build the frontend if frontend code or shared API types changed.
- Add regression tests for bug fixes.
- Verify that model feature order and preprocessing remain compatible.
- Check for accidental generated artifacts or datasets in the staged diff.
- Document any test that could not be run and why.

---

## Current limitations and work remaining

The project is under active development. The following should be treated as ongoing work rather than already solved:

- Validate the entire upload-to-dashboard path with multiple real capture files.
- Improve UI consistency and usability across the dashboard.
- Continue reviewing API error handling, pagination, and frontend/backend contracts.
- Validate vertical/horizontal scan behavior and repeated detection edge cases.
- Measure false-positive and false-negative behavior on appropriately separated datasets.
- Ensure experiment reports are reproducible and clearly state dataset/split/metric definitions.
- Review generated artifact policy and keep the repository lightweight.
- Add further end-to-end tests and concise demo instructions.
- Document exact dataset acquisition and experiment commands once paths and requirements are finalized.

Do not describe the model as production-grade or claim a specific real-world detection rate unless a reproducible evaluation report supports that claim.

---

## Contributing

Contributions from project teammates are welcome, especially in code cleanup, tests, API/frontend integration, and evaluation methodology.

1. Clone the repository and follow the setup instructions.
2. Create a branch for your work rather than committing directly to `main`.
3. Identify the files and behavior your change will affect.
4. Preserve current behavior unless the change is intentional and documented.
5. Add or update regression tests.
6. Run the relevant backend tests and frontend build.
7. Open a pull request or share the branch for review.

### Suggested areas to pick up

- Backend maintainability and duplicated logic.
- PCAP ingestion and packet-parser edge cases.
- Bidirectional flow lifecycle and TCP state transitions.
- Detection thresholds and false-positive analysis.
- ML candidate evaluation and model promotion criteria.
- Dashboard polish and API integration.
- Test coverage and reproducible experiment documentation.

**Coordinate changes to detection rules and the default model with the team.** Avoid sweeping rewrites of the pipeline without tests and a clear explanation of the behavior change.

---

## Security and responsible use

- Analyze only traffic you are authorized to inspect.
- Capture files and reports can contain sensitive network metadata; do not publish them without review.
- Never commit API keys, credentials, private capture data, or local databases.
- Treat alerts and ML anomalies as leads for investigation, not as conclusive attribution.
- Keep experimental model artifacts separate until their evaluation and compatibility have been reviewed.

---

## License

No license has been specified in this repository yet. Until a license is added, do not assume that the code is available for unrestricted reuse or redistribution.
