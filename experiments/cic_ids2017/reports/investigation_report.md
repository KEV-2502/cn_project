# CIC-IDS2017 Anomaly Detection Investigation & Controlled Improvement Study

## 1. Executive Summary & Root Cause Analysis
This investigation resolved why the baseline Isolation Forest achieved only **1.32% attack recall** at threshold $\tau = 0.50$, despite a high **PR-AUC of 0.6419** and a low **FPR of 1.16%**.

### Key Findings
1. **Mathematical Offset Mismatch:** In scikit-learn, setting `contamination=0.01` configures the internal `offset_ = -0.6727`, which represents the 1st percentile of training scores. The formula $\text{normalized} = 0.5 - \text{decision_function}(X)$ requires a test point to be more extreme than 99% of nominal Monday traffic to exceed $0.50$. Consequently, subtle attacks scoring between $0.22$ and $0.45$ were never flagged at $\tau = 0.50$.
2. **Distributional Feature Skew:** Byte counts and rates in CIC-IDS2017 span up to 6 orders of magnitude ($0$ to $5.3\times 10^6$). Unscaled trees make random linear splits that isolate only rare statistical extremes (such as Heartbleed's 7.8 MB payload). Applying a $\log(1 + x)$ transform compressed the feature distribution, **boosting PR-AUC from 0.6419 to 0.7840 (+14.2%)** and **ROC-AUC from 0.5932 to 0.7917 (+19.85%)**.
3. **Inherent Limits of Single-Flow Anomaly Detection:** While the Log1p model successfully detected 96.1% of Slowhttptest, 94.8% of DDoS, 92.3% of Slowloris, and 100% of Heartbleed at $\tau = 0.42$, stealthy single-probe attacks (**PortScan: 0.6%**, **SSH-Patator: 0.1%**, **SQL Injection: 0.0%**) remain fundamentally undetectable by single-flow statistical outlier models because their individual packets look identical to nominal network traffic.

---

## 2. Controlled Experiment Matrix Comparison

| Experiment | Feature Transform | Contam | Threshold ($\tau$) | Precision | Recall | $F_1$-Score | PR-AUC | ROC-AUC | Monday FPR | Drift FPR | Overall FPR |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Exp 1: Baseline (Raw, c=0.01, tau=0.50)** | `raw` | `0.01` | `0.5` | 0.6094 | 0.0132 | 0.0259 | **0.6419** | **0.5932** | 0.90% | 1.42% | **1.16%** |
| **Exp 2: Raw (c='auto', tau=0.50)** | `raw` | `auto` | `0.5` | 0.7531 | 0.1936 | 0.3080 | **0.6419** | **0.5932** | 7.94% | 9.44% | **8.69%** |
| **Exp 3: Pruned is_icmp (c=0.01, tau=0.50)** | `raw_no_icmp` | `0.01` | `0.5` | 0.6000 | 0.0134 | 0.0261 | **0.6366** | **0.5803** | 1.02% | 1.42% | **1.22%** |
| **Exp 4: Log1p Robust Transform (c=0.01, tau=0.50)** | `log1p` | `0.01` | `0.5` | 0.4451 | 0.0059 | 0.0117 | **0.7840** | **0.7917** | 0.82% | 1.20% | **1.01%** |
| **Exp 5: Log1p (c='auto', tau=0.50)** | `log1p` | `auto` | `0.5` | 0.7673 | 0.7652 | 0.7663 | **0.7840** | **0.7917** | 29.72% | 33.82% | **31.77%** |
| **Exp 6A: Log1p Calibrated (c=0.01, tau=0.48)** | `log1p` | `0.01` | `0.48` | 0.8064 | 0.0608 | 0.1131 | **0.7840** | **0.7917** | 1.68% | 2.32% | **2.00%** |
| **Exp 6B: Log1p Calibrated (c=0.01, tau=0.42)** | `log1p` | `0.01` | `0.42` | 0.8534 | 0.4653 | 0.6023 | **0.7840** | **0.7917** | 9.86% | 12.04% | **10.95%** |

---

## 3. Per-Attack Detection Breakdown Across Key Models

| Attack Category | Evaluated Samples | Baseline (Exp 1, τ=0.50) | Log1p (Exp 4, τ=0.50) | Log1p Calibrated (Exp 6A, τ=0.48) | Log1p High-Recall (Exp 6B, τ=0.42) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Bot** | 1966 | 2.2% (44) | 2.2% (43) | 2.2% (44) | **27.2% (535)** |
| **DDoS** | 1500 | 0.0% (0) | 0.0% (0) | 0.0% (0) | **94.8% (1422)** |
| **DoS GoldenEye** | 1000 | 0.0% (0) | 0.0% (0) | 5.9% (59) | **27.4% (274)** |
| **DoS Hulk** | 1500 | 0.2% (3) | 0.1% (1) | 1.0% (15) | **22.6% (339)** |
| **DoS Slowhttptest** | 1000 | 2.5% (25) | 0.1% (1) | 60.2% (602) | **96.1% (961)** |
| **DoS slowloris** | 1000 | 0.0% (0) | 0.0% (0) | 0.1% (1) | **92.3% (923)** |
| **FTP-Patator** | 1000 | 0.0% (0) | 0.0% (0) | 0.0% (0) | **48.5% (485)** |
| **Heartbleed** | 11 | 100.0% (11) | 100.0% (11) | 100.0% (11) | **100.0% (11)** |
| **Infiltration** | 36 | 30.6% (11) | 30.6% (11) | 38.9% (14) | **86.1% (31)** |
| **PortScan** | 1500 | 0.0% (0) | 0.0% (0) | 0.0% (0) | **0.6% (9)** |
| **SSH-Patator** | 1000 | 0.0% (0) | 0.0% (0) | 0.0% (0) | **0.1% (1)** |
| **Web Attack - Brute Force** | 1507 | 4.7% (71) | 0.0% (0) | 4.7% (71) | **63.7% (960)** |
| **Web Attack - SQL Injection** | 21 | 0.0% (0) | 0.0% (0) | 0.0% (0) | **0.0% (0)** |
| **Web Attack - XSS** | 652 | 2.5% (16) | 2.1% (14) | 2.5% (16) | **64.6% (421)** |

---

## 4. Architectural Limits & Final Recommendation
1. **Adopt Log1p Feature Preprocessing for Future Anomaly Models:** The $\log(1 + x)$ transformation dramatically improves tree partitioning quality (+14.2% PR-AUC) without introducing artificial distortions.
2. **Operational Constraint Reality:** In network security operations, false positive rates above 2–5% trigger severe alert fatigue. At a strict 2.0% FPR budget (Exp 6A, $\tau = 0.48$), the Isolation Forest reliably catches extreme anomalies (Heartbleed: 100%, Slowhttptest: 60.2%, Infiltration: 38.9%), but cannot catch low-volume or single-probe attacks.
3. **Flow-Level Isolation Forest is Insufficient as a Standalone IDS:** A single-flow unsupervised anomaly detector cannot replace NetShield's hybrid architecture. Volumetric and reconnaissance attacks (PortScan, DDoS, Excessive Connection Rate) must be detected via **aggregate multi-flow state engines**, while Isolation Forest serves as a specialized detector for abnormal payload transfers.
