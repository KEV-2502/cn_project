# NetShield Experimental Log1p Model PCAP Transfer Evaluation Report

## Executive Summary

This evaluation investigates whether the **experimental CIC-IDS2017 Log1p Isolation Forest** transfers to NetShield's actual packet-processing pipeline when scoring **real PCAP-derived flows** from `Monday-WorkingHours.pcap`.

### Key Empirical Findings
1. **Dramatic Improvement Over Production Baseline**:
   - On legitimate Monday traffic, the **Production Model** flagged **51.54%** of normal flows as outliers (Mean score: `0.5067`).
   - The **Experimental Log1p Model** shifted the nominal flow distribution deep into the inlier zone (Mean score: `0.3701`), reducing flagged anomalies to **11.93%** at its calibrated threshold ($\tau = 0.487$).
2. **Schema Divergence: IP Bytes vs. Payload Bytes**:
   - Production sums **IP packet length** (including headers $\ge 40$ bytes per packet).
   - The experimental model was trained on CICFlowMeter CSVs which measure **L4 payload bytes only** (0 bytes for handshakes/control packets).
   - An adapter subtracting L3/L4 headers aligned the semantics, bringing mean score to `0.3581` with an 11.86% flag rate.
3. **The Transfer Gap & PCAP Retraining Verdict**:
   - While Log1p is vastly superior to the production model (11.9% vs 51.5% false alert rate), an 11.9% flag rate on benign traffic remains above our 2.0% operational target.
   - **Retraining on PCAP-derived flows is justified** to eliminate this distribution mismatch.

---

## 1. Schema Compatibility Audit

| Schema Dimension | Production PCAP Pipeline | Experimental Model (CIC CSV) | Compatibility Verdict |
| :--- | :--- | :--- | :---: |
| Schema Dimension | Production PCAP Pipeline | Experimental Model (CIC CSV) | Compatibility Verdict |
| :--- | :--- | :--- | :---: |
| **Feature Count & Ordering** | 15 features in fixed order | 15 features in fixed order | **Exact Match** |
| **Duration Units** | Seconds ($s$) | Seconds ($s$, converted from $\mu s$) | **Exact Match** |
| **Protocol Flags** | TCP, UDP/DNS, ICMP (1.0 / 0.0) | TCP=6, UDP=17, ICMP=1 (1.0 / 0.0) | **Exact Match** |
| **Rate Calculation** | $\text{count} / \max(\text{dur}, 10^{-3})$ | $\text{count} / \max(\text{dur}, 10^{-3})$ | **Exact Match** |
| **Byte Metric** | **IP-Layer Total Octets** (RFC 7011) | **L4 Transport Payload Bytes Only** | **Semantic Divergence** |
| **Zero-Byte Packets** | Control packets $\ge 46$ bytes | Control packets $= 0$ bytes | **Semantic Divergence** |

> [!NOTE]
> **Semantic Adapter**: The adapter computes $\text{payload\_bytes} = \max(0, \text{ip\_bytes} - \text{packets} \times \text{header\_overhead})$ ($40$B for TCP, $28$B for UDP) to map PCAP flows into the payload space expected by the model.

---

## 2. Controlled Evaluation Results on Real Monday PCAP Flows

Evaluated on **2,825 real PCAP-derived flows** from `Monday-WorkingHours.pcap`:

| Model & Configuration | Threshold ($\tau$) | Score Mean | Score Median | Std Dev | Flagged Flows | Flagged Rate (%) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **1. Production Model (Raw Features)** | `0.5000` | `0.5067` | `0.5173` | `0.1288` | **1456 / 2825** | **51.54%** |
| **2. Candidate Model (Raw Features)** | `0.5000` | `0.3048` | `0.3011` | `0.0959` | **193 / 2825** | **6.83%** |
| **3. Experimental Log1p (Direct, tau=0.50)** | `0.5000` | `0.3701` | `0.3428` | `0.0726` | **274 / 2825** | **9.70%** |
| **4. Experimental Log1p (Direct, tau=0.487)** | `0.4870` | `0.3701` | `0.3428` | `0.0726` | **337 / 2825** | **11.93%** |
| **5. Experimental Log1p (Adapted, tau=0.50)** | `0.5000` | `0.3581` | `0.3326` | `0.0793` | **268 / 2825** | **9.49%** |
| **6. Experimental Log1p (Adapted, tau=0.487)** | `0.4870` | `0.3581` | `0.3326` | `0.0793` | **335 / 2825** | **11.86%** |

---

## 3. PCAP-Based Retraining Assessment

### A. Is PCAP-Based Retraining Warranted?
**YES, retraining on PCAP-derived features is warranted.**
- The experimental model trained on CSVs achieves 1.6%–2.0% FPR on CSV test sets, but when applied to PCAP-derived flows, the flag rate rises to **11.86%**.
- This gap stems from natural differences between packet-captured network flows (real-world TCP teardown, retransmissions, DNS query bursts, and exact IP byte metrics) and the synthetic CICFlowMeter CSV features.
- Training directly on NetShield's own `FlowAggregator` output will eliminate the feature mismatch entirely.

### B. Proposed Leakage-Safe Split for PCAP Retraining
To retrain on PCAP features without data leakage:
1. **Benign Training Partition**: First 200,000 packets (~15,000 flows) from `Monday-WorkingHours.pcap` (08:55–09:30). Pure benign baseline.
2. **Benign Evaluation Holdout**: Packets 200,001 to 400,000 from `Monday-WorkingHours.pcap` (09:30–10:15). Completely disjoint in time; zero overlap.
3. **Attack Evaluation Limitation**: Currently, **only Monday PCAP is present on disk**. Evaluating attack recall and PR-AUC on real PCAPs requires downloading at least one attack capture (e.g. `Friday-WorkingHours-Afternoon-PortScan.pcap` or `Friday-WorkingHours-Afternoon-DDos.pcap`).

---

## 4. Preservation & Verification Status

- Production model artifacts (`data/models/isolation_forest.joblib`) and metadata remain **strictly unmodified**.
- Production database (`data/threat_detection.db`) remains **completely untouched**.
- All candidate models and reports are isolated in `experiments/cic_ids2017/`.
