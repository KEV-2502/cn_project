# Isolated CIC-IDS2017 Anomaly Detection Evaluation Report

## 1. Executive Summary
- **Model Evaluated:** Candidate Isolation Forest (`candidate_isolation_forest_cic.joblib`)
- **Training Set:** Monday Benign Traffic only ($N = 15000$, seed=42)
- **Evaluation Set:** $N = 23693$ flows (10000 Benign, 13693 Attack)
- **Decision Threshold:** $\tau = 0.5$ (Outlier if normalized score $\ge 0.50$)

### Key Performance Indicators
- **Precision:** `0.6094`
- **Recall (Overall Detection Rate):** `0.0132`
- **$F_1$-Score:** `0.0259`
- **PR-AUC:** `0.6419`
- **ROC-AUC:** `0.5932`

---

## 2. Confusion Matrix & False Positive Analysis

| Metric | Count | Rate |
| :--- | :--- | :--- |
| **True Positives (TP)** | 181 | Recall: 1.3% |
| **False Positives (FP)** | 116 | Total FPR: 1.16% |
| **True Negatives (TN)** | 9884 | Specificity: 98.84% |
| **False Negatives (FN)** | 13512 | Miss Rate: 98.7% |

### In-Day Holdout vs. Multi-Day Drift FPR
- **Monday In-Day Holdout:** 45 / 5000 (**0.90% FPR**)
- **Tue–Fri Benign Drift:** 71 / 5000 (**1.42% FPR**)

> [!NOTE]
> The difference between Monday in-day FPR and Tuesday–Friday drift FPR demonstrates natural background traffic drift over time.

---

## 3. Per-Attack Class Detection Rates

| Attack Category | Evaluated Samples | Detected (Flagged) | Detection Rate (%) | Mean Anomaly Score |
| :--- | :--- | :--- | :--- | :--- |
| **Bot** | 1966 | 44 | 2.2% | 0.2263 |
| **DDoS** | 1500 | 0 | 0.0% | 0.3186 |
| **DoS GoldenEye** | 1000 | 0 | 0.0% | 0.2881 |
| **DoS Hulk** | 1500 | 3 | 0.2% | 0.3140 |
| **DoS Slowhttptest** | 1000 | 25 | 2.5% | 0.3189 |
| **DoS slowloris** | 1000 | 0 | 0.0% | 0.2930 |
| **FTP-Patator** | 1000 | 0 | 0.0% | 0.2525 |
| **Heartbleed** | 11 | 11 | 100.0% | 0.5951 |
| **Infiltration** | 36 | 11 | 30.6% | 0.4207 |
| **PortScan** | 1500 | 0 | 0.0% | 0.2245 |
| **SSH-Patator** | 1000 | 0 | 0.0% | 0.2548 |
| **Web Attack - Brute Force** | 1507 | 71 | 4.7% | 0.2405 |
| **Web Attack - SQL Injection** | 21 | 0 | 0.0% | 0.2256 |
| **Web Attack - XSS** | 652 | 16 | 2.5% | 0.2363 |

---

## 4. Methodological Limitations & Safety Note
- **Evaluation Set Re-balancing:** Attack classes were stratified and high-volume classes (e.g. DoS Hulk, DDoS) were capped to avoid swamping the evaluation set. Consequently, overall accuracy is not representative of live wild traffic.
- **Feature Semantics:** Directional bytes represent L4 transport payloads, not NetShield's IP-layer total length. The candidate model must not be directly used with NetShield's Scapy PCAP pipeline without feature extractor versioning.
- **Isolation Confirmation:** Production model artifacts (`isolation_forest.joblib`, `model_metadata.json`), database records, and PCAP regression tests remain 100% unaltered.
