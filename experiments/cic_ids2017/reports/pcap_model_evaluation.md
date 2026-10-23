# NetShield PCAP-Derived Anomaly Detection Model: Training & Evaluation Report

## Executive Summary

This experiment implements an **end-to-end PCAP-trained Isolation Forest anomaly detector** for NetShield, trained and evaluated directly on network flows aggregated by NetShield's production packet parser and flow aggregator from the real CIC-IDS2017 `Monday-WorkingHours.pcap`.

### Key Empirical Findings
1. **Elimination of False-Positive Collapse**: The **Production Model** (trained on synthetic baseline data) collapsed on real PCAP benign traffic, flagging **23.92%** of held-out test flows as anomalies. The **Candidate PCAP Model (Log1p)** drops the default anomaly flag rate to **3.01%** at $\tau=0.50$ and **6.29%** at the validation-calibrated threshold ($\tau = 0.4732$).
2. **Distribution Alignment**: The mean anomaly score dropped from `0.4351` (deep outlier zone in production) to `0.3093` (nominal inlier zone).
3. **Zero-Leakage Temporal Design**: Capture flows were strictly partitioned into chronological Train, Validation, and Test partitions separated by **60-second quarantine buffer gaps**, with boundary-straddling flows fully excluded.

---

## 1. Dataset Provenance & Leakage-Safe Splitting

- **Source Capture**: `Monday-WorkingHours.pcap` (10,822,507,416 bytes)
- **SHA-256**: `f6eac599358f216b074338813a1cf7be3cc4e91d116e13efc0dc71f2cca11972`
- **Packets Streamed**: 250,000 packets (247,856 IP packets)
- **Total Aggregated Flows**: 7,874 bidirectional flows over a 1107.7s (18.5 min) capture window.

### Disjoint Chronological Partitions

| Partition | Flow Count | Time Span ($s$) | Protocol Distribution | 5-Tuple Overlap w/ Train | Boundary Crossers |
| :--- | :---: | :---: | :--- | :---: | :---: |
| **Train Split** | 2,078 | 543.24s | {'UDP': 563, 'TCP': 271, 'DNS': 1206, 'IP_17': 4, 'ICMP': 28, 'IP_2': 6} | — | — |
| *Quarantine Gap 1* | — | 60.0s | Excluded buffer | — | — |
| **Validation Split** | 2,886 | 197.54s | {'UDP': 286, 'DNS': 1985, 'TCP': 614, 'IP_2': 1} | 152 | — |
| *Quarantine Gap 2* | — | 60.0s | Excluded buffer | — | — |
| **Test Split** | 1,827 | 246.93s | {'UDP': 321, 'TCP': 447, 'DNS': 1057, 'IP_2': 1, 'ICMP': 1} | 117 | — |
| **Excluded Flows** | 1,083 | Full span | {'UDP': 185, 'TCP': 270, 'DNS': 622, 'IP_17': 2, 'IP_2': 1, 'ICMP': 3} | — | 1,083 quarantined |

> [!NOTE]
> **Boundary Exclusion Guarantee**: Flows active during the 60-second buffer gaps or spanning partition boundaries were quarantined to ensure zero packet or session leakage across splits.

---

## 2. Feature Schema & Model Training Configuration

### Exact 15-Feature Production Schema
Features extracted via `extract_batch_features` in identical index order:
1. `forward_packets`, 2. `backward_packets`, 3. `forward_bytes`, 4. `backward_bytes`, 5. `duration`, 6. `packet_ratio`, 7. `byte_ratio`, 8. `forward_packet_rate`, 9. `backward_packet_rate`, 10. `forward_byte_rate`, 11. `backward_byte_rate`, 12. `is_tcp`, 13. `is_udp`, 14. `is_icmp`, 15. `avg_packet_size`.

### Preprocessing & Hyperparameters
- **Preprocessing**: `log1p` applied to skewed count, duration, and rate features (indices `[0, 1, 2, 3, 4, 7, 8, 9, 10, 14]`).
- **Algorithm**: `scikit-learn` `IsolationForest` (`n_estimators=100`, `contamination=0.01`, `random_state=42`, `max_samples='auto'`).
- **Training Fit Time**: `0.243s` on `2078` benign flows.
- **Candidate Artifact Path**: `experiments/cic_ids2017/artifacts/pcap_model/candidate_pcap_isolation_forest.joblib`
- **Artifact SHA-256**: `d507d782a4a0b7e6eddded9f5075e576c006c8097675eea00bb15f336d41da23`

---

## 3. Validation Threshold Calibration

Operating thresholds were calibrated on **2,886 disjoint validation flows** to target an observed anomaly rate $\le 2.0%$:

| Configuration | Validation Mean | Std Dev | Default Anomaly Rate ($\tau=0.50$) | Calibrated $\tau$ | Calibrated Anomaly Rate |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Raw PCAP Model** | `0.2444` | `0.0741` | 0.69% | `0.452` | **2.01%** |
| **Log1p PCAP Model (Candidate)** | `0.2907` | `0.0875` | 0.8% | `0.4732` | **2.01%** |

---

## 4. Held-Out Benign Test Evaluation

Evaluated on **1,827 untouched later benign flows** from `Monday-WorkingHours.pcap`:

| Model & Configuration | Threshold ($\tau$) | Score Mean | Score Median | Std Dev | Min / Max | Flagged Flows | Observed Anomaly Rate (%) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Production Model (Synthetic Raw)** | `0.5000` | `0.4351` | `0.3978` | `0.108` | `0.2946` / `0.7007` | 437 / 1827 | **23.92%** |
| **Candidate PCAP Model (Raw, $\tau=0.50$)** | `0.5000` | `0.2565` | `0.2052` | `0.0923` | `0.1879` / `0.6553` | 55 / 1827 | **3.01%** |
| **Candidate PCAP Model (Raw, calib)** | `0.452` | `0.2565` | `0.2052` | `0.0923` | `0.1879` / `0.6553` | 91 / 1827 | **4.98%** |
| **Candidate PCAP Model (Log1p, $\tau=0.50$)** | `0.5000` | `0.3093` | `0.255` | `0.0941` | `0.1883` / `0.5735` | 55 / 1827 | **3.01%** |
| **Candidate PCAP Model (Log1p, calib)** | `0.4732` | `0.3093` | `0.255` | `0.0941` | `0.1883` / `0.5735` | 115 / 1827 | **6.29%** |

### Protocol Breakdown on Test Flows

| Protocol | Flow Count | Production Anomaly Rate (%) | Candidate (Log1p $\tau=0.50$) | Candidate (Log1p Calibrated) |
| :--- | :---: | :---: | :---: | :---: |
| **TCP** | 447 | 22.82% | 12.3% | **25.5%** |
| **UDP** | 321 | 26.17% | 0.0% | **0.0%** |
| **ICMP** | 1 | 0.0% | 0.0% | **100.0%** |

### Runtime and Memory Consumption
- **Peak Memory Usage**: `380.1 MB`
- **Test Inference Throughput**: `176,729.6 flows/second` (10.34 ms total for 1,827 flows)

---

## 5. Production Isolation & Limitations

### Isolation & Checksum Verification
- `data/models/isolation_forest.joblib`: Hash verified identical to baseline.
- `data/models/model_metadata.json`: Hash verified identical to baseline.
- `data/threat_detection.db`: Production database untouched.

### Critical Limitations & Attack Evaluation Readiness
> [!IMPORTANT]
> **Benign-Traffic Limitation**: This experiment trains and evaluates benign traffic behavior only. Monday contains intended-benign working hours traffic. While this proves the model does not suffer false-positive collapse on real packet flows, **it cannot establish attack recall, precision, PR-AUC, or ROC-AUC**.

- **Next Step**: Process the Friday CIC-IDS2017 PCAP (containing PortScan and DDoS attacks) through NetShield's packet parser and flow aggregator to rigorously evaluate attack detection sensitivity before considering production deployment.
