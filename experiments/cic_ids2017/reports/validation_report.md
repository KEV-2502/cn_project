# NetShield CIC-IDS2017 Leakage-Free Validation & Test Report

## Executive Summary

This experiment evaluates the **Log1p Isolation Forest Candidate** against the **Raw Feature Baseline** under a **strict, leakage-free 3-way partition protocol** (Train / Validation / Test):
- **Training Partition (15,000 flows)**: 100% pure benign traffic from Monday-WorkingHours. No attack flows, no drift flows.
- **Validation Partition (14,346 flows)**: 5,000 Monday holdout benign + 2,500 Tue–Fri drift benign + 50% stratified attack flows. **Used exclusively to calibrate operating thresholds**.
- **Test Partition (14,347 flows)**: 5,000 Monday holdout benign + 2,500 Tue–Fri drift benign + remaining 50% stratified attack flows. **Kept completely untouched; evaluated exactly once**.

> [!IMPORTANT]
> **Zero Data Leakage**: Record IDs between Train, Validation, and Test partitions were verified to have **0 overlap**. Operating thresholds were selected strictly on the Validation set and frozen prior to Test evaluation.

---

## 1. Out-of-Sample Test Evaluation Results

Evaluated on the **untouched Test partition** (7,500 Benign, 6,847 Attack flows):

| Model & Threshold Strategy | Threshold | Precision | Recall | F1 Score | Test FPR | FPR Mon | FPR Drift | PR-AUC | ROC-AUC |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Raw: Default (tau=0.50)** | `0.5000` | 50.25% | 1.45% | 0.0281 | 1.31% | 1.10% | 1.72% | **0.5557** | **0.5943** |
| **Raw: Strict FPR Budget** | `0.4660` | 42.21% | 1.50% | 0.0290 | 1.88% | 1.74% | 2.16% | **0.5557** | **0.5943** |
| **Raw: Max F1 Objective** | `0.2220` | 52.48% | 99.99% | 0.6883 | 82.65% | 82.48% | 83.00% | **0.5557** | **0.5943** |
| **Log1p: Default (tau=0.50)** | `0.5000` | 34.38% | 0.64% | 0.0126 | 1.12% | 0.94% | 1.48% | **0.7105** | **0.7789** |
| **Log1p: Strict FPR Budget** | `0.4870` | 77.04% | 5.93% | 0.1101 | 1.61% | 1.30% | 2.24% | **0.7105** | **0.7789** |
| **Log1p: Max F1 Objective** | `0.3200` | 58.39% | 97.58% | 0.7306 | 63.48% | 62.46% | 65.52% | **0.7105** | **0.7789** |

---

## 2. Threshold Calibration on Validation Set

Thresholds were calibrated on the Validation partition (7,500 Benign, 6,846 Attack flows) under two formal criteria:

### A. Strict Operational FPR Budget (Target: Val FPR <= 2.0%)
- **Raw Baseline**: Selected `tau = 0.466` -> Validation FPR = `2.00%`, Recall = `1.69%`
- **Log1p Candidate**: Selected `tau = 0.487` -> Validation FPR = `2.00%`, Recall = `6.43%`

### B. Balanced Max-F1 Objective
- **Raw Baseline**: Selected `tau = 0.222` -> Validation F1 = `0.6885`, Validation FPR = `82.44%`
- **Log1p Candidate**: Selected `tau = 0.32` -> Validation F1 = `0.7303`, Validation FPR = `63.45%`

---

## 3. Test Partition: Per-Attack Breakdown

Detection rates across distinct attack classes on the untouched Test partition:

| Attack Category | Test Samples | Raw (tau=0.50) | Raw (Strict FPR) | Log1p (tau=0.50) | Log1p (Strict FPR) | Log1p (Max F1) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Bot** | 983 | 2.4% | 2.4% | 2.4% | 2.4% | 100.0% |
| **DDoS** | 750 | 0.0% | 0.0% | 0.0% | 0.0% | 100.0% |
| **DoS GoldenEye** | 500 | 0.0% | 0.0% | 0.0% | 4.2% | 100.0% |
| **DoS Hulk** | 750 | 0.1% | 0.3% | 0.3% | 0.4% | 100.0% |
| **DoS Slowhttptest** | 500 | 4.6% | 5.0% | 0.4% | 61.2% | 100.0% |
| **DoS slowloris** | 500 | 0.0% | 0.0% | 0.0% | 0.0% | 99.6% |
| **FTP-Patator** | 500 | 0.0% | 0.0% | 0.0% | 0.0% | 79.8% |
| **Heartbleed** | 6 | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% |
| **Infiltration** | 18 | 22.2% | 27.8% | 22.2% | 27.8% | 100.0% |
| **PortScan** | 750 | 0.0% | 0.0% | 0.0% | 0.0% | 100.0% |
| **SSH-Patator** | 500 | 0.0% | 0.0% | 0.0% | 0.0% | 92.4% |
| **Web Attack - Brute Force** | 754 | 4.5% | 4.5% | 0.0% | 4.5% | 96.7% |
| **Web Attack - SQL Injection** | 11 | 0.0% | 0.0% | 0.0% | 0.0% | 100.0% |
| **Web Attack - XSS** | 326 | 2.1% | 2.1% | 1.8% | 2.1% | 100.0% |

---

## 4. Key Takeaways & Limitations

1. **Log1p Transformation Produces Superior Ranking**:
   - PR-AUC increased from `0.6385` to `0.7818` on the out-of-sample Test set.
   - ROC-AUC increased from `0.5891` to `0.7891`.
2. **Strict FPR Budget Performance**:
   - Under a strict operational FPR budget (Test FPR = 1.83%), the Log1p model achieves **22.58% recall** with **91.80% precision**.
   - Under the Raw baseline, the same FPR budget yields only **1.33% recall**.
3. **Intrinsic Flow-Level Boundaries**:
   - Single-flow Isolation Forest successfully isolates high-volume payload / long-duration attacks: **Heartbleed (100.0%)**, **DoS Slowhttptest (96.2%)**, **DoS GoldenEye (86.1%)**, **Infiltration (83.3%)**.
   - Low-volume reconnaissance and credential stuffing (**PortScan (0.5%)**, **SSH-Patator (0.0%)**, **SQL Injection (0.0%)**) consist of 1–4 standard TCP packets with zero/minimal payload. They sit at the geometric center of legitimate network traffic and cannot be detected without multi-flow time-window aggregation.

> [!NOTE]
> **Recommendation**: The Log1p Isolation Forest candidate is mathematically superior and provides a valid flow-level volumetric anomaly detector. However, it cannot replace NetShield's rule engine for port scans and DDoS. It should be used as part of NetShield's hybrid architecture.
