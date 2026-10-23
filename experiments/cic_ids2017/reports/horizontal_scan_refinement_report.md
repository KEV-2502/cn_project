# NetShield: Refinement of `RULE_PORT_SCAN_HORIZONTAL` Evaluation Report

## 1. Overview & Objectives

Based on the findings from `friday_evaluation_audit.md` and `friday_evaluation_audit.json`, NetShield's `PortScanRule` horizontal sweep detector was audited and refined to eliminate false-positive alerts triggered by normal outbound client web browsing while preserving strict detection of genuine horizontal port sweeps and host discovery activity.

### Strict Design Constraints Enforced
1. **No Port Whitelisting**: Neither port 443 (HTTPS) nor port 53 (DNS) were whitelisted. Horizontal scans targeting ports 443 or 53 remain fully detectable.
2. **Schema & Field Integrity**: The refinement uses exclusively existing `NetworkFlow` fields (`forward_packets`, `backward_packets`, `forward_bytes`, `backward_bytes`, `total_packets`, `tcp_state`, `start_time`). No synthetic packet attributes were introduced.
3. **Production Model Immutability**: Production ML model artifacts (`data/models/isolation_forest.joblib` and `model_metadata.json`) and database (`data/threat_detection.db`) remained strictly untouched.

---

## 2. Root Cause Analysis

### Defect 1: Temporal Window Chaining
In `backend/app/pipeline/rules/port_scan.py`, temporal clustering previously evaluated:
```python
elif f.start_time - cur[-1].start_time <= self.window_seconds:
    cur.append(f)
```
This compared each flow's start time to the *preceding flow* (`cur[-1]`) rather than the *cluster start* (`cur[0]`). Consequently, normal workstation web browsing with inter-request intervals $< 10.0$ seconds chained flows continuously for several minutes, accumulating over 60 distinct destination IPs and firing false sweep alerts for windows claiming to be 10 seconds.

### Defect 2: Blind Destination Counting without Probe Qualification
The rule counted every flow to distinct destination IPs regardless of whether the flow was an active, established, bidirectional application session transferring kilobytes of data (e.g., loading web resources across CDN edge nodes) or an unanswered / rejected probe.

---

## 3. Implemented Refinement

The refinement was implemented in `backend/app/pipeline/rules/port_scan.py`:

### A. Probe vs. Established Session Classification (`PortScanRule.is_scan_probe`)
A flow is classified as a scanning probe if:
1. **Unanswered / Unresponsive**: `backward_packets == 0` or `backward_bytes == 0` (unanswered TCP SYN, UDP probe, or ICMP echo request).
2. **Connection Rejected**: `tcp_state == 'RESET'` with minimal backward data (`backward_bytes <= 60` or `backward_packets <= 1`).
3. **Handshake Incomplete**: `tcp_state in ('SYN_SENT', 'INCOMPLETE')`.
4. **Embryonic Connect Probe**: Handshake initiated but terminated without application payload (`total_packets <= 3`, `forward_bytes <= 120`, and `backward_bytes <= 80`).

Normal browsing (exchanging TLS handshakes and application data: `forward_bytes > 120`, `backward_bytes > 80`, `backward_packets >= 2`) is recognized as established sessions and excluded from probe counting.

### B. Bounded Sliding Window Evaluation
Horizontal scan evaluation operates as a sliding window across probe flows only:
- For each probe flow, finds all probe flows within `[start_time, start_time + window_seconds]`.
- Checks if `unique_probe_hosts >= horizontal_host_threshold` (10 hosts).
- If triggered, records earliest timestamp, attaches **only probe flow IDs** (preventing pollution of benign background flows into the alert record), and advances past the window to prevent alert spam.

---

## 4. Empirical Performance Comparison on Friday Traffic (14,351 Flows)

Evaluation executed against the exact 14,351 Friday flows across all 3 capture slices (Morning Benign, PortScan attack, DDoS attack):

### A. Rule Engine Alone

| Metric | Before Refinement | After Refinement | Net Change |
| :--- | :---: | :---: | :---: |
| **Total Alerts Generated** | 65 | **53** | **-12 alerts (-100% false horizontal alerts)** |
| — *Vertical Port Scan Detected* | 2 | 2 | 0 |
| — *Horizontal Network Sweep Detected* | 12 | **0** | **-12 (-100% false alerts eliminated)** |
| — *Excessive Connection Attempts* | 6 | 6 | 0 |
| — *DNS Threat Alerts (Tunneling / Rate / DGA)* | 45 | 45 | 0 |
| **Total Flagged Flows** | 13,532 | **12,855** | **-677 falsely flagged flows** |
| **True Negatives (TN)** | 757 | **1,434** | **+677 clean benign flows** |
| **False Positives (FP)** | 984 | **307** | **-677 false positives (-68.8% reduction)** |
| **False Negatives (FN)** | 62 | **62** | 0 |
| **True Positives (TP)** | 12,548 | **12,548** | 0 |
| **Benign False Positive Rate (FPR)** | 56.52% | **17.63%** | **-38.89 percentage points** |
| **Benign Specificity** | 43.48% | **82.37%** | **+38.89 percentage points** |
| **Attack Recall** | 99.51% | **99.51%** | 0 (100% DDoS, 99.40% PortScan) |
| **Precision** | 0.9273 | **0.9761** | **+4.88 percentage points** |
| **F1-Score** | 0.9600 | **0.9855** | **+0.0255** |

### B. Combined Defense (Candidate PCAP Model Log1p $\tau=0.4732 \lor$ Rule Engine)

| Metric | Before Refinement | After Refinement | Net Change |
| :--- | :---: | :---: | :---: |
| **True Negatives (TN)** | 710 | **1,257** | **+547 clean benign flows** |
| **False Positives (FP)** | 1,031 | **484** | **-547 false positives (-53.1% reduction)** |
| **False Negatives (FN)** | 0 | **0** | **0 (Zero missed attacks)** |
| **True Positives (TP)** | 12,610 | **12,610** | **0 (100% Attack Recall)** |
| **Benign False Positive Rate (FPR)** | 59.22% | **27.80%** | **-31.42 percentage points** |
| **Benign Specificity** | 40.78% | **72.20%** | **+31.42 percentage points** |
| **Attack Recall** | 100.00% | **100.00%** | **Maintained at 100%** |
| **Precision** | 0.9244 | **0.9630** | **+3.86 percentage points** |
| **F1-Score** | 0.9607 | **0.9812** | **+0.0205** |

---

## 5. Test Suite Verification

Comprehensive regression test suite created in `backend/tests/test_horizontal_scan_refinement.py`:
1. `test_normal_client_https_browsing_no_alert`: 15 parallel HTTPS connections across distinct IPs $\to$ 0 alerts.
2. `test_benign_dns_activity_no_alert`: 12 DNS query/responses across distinct IPs $\to$ 0 alerts.
3. `test_genuine_horizontal_syn_scan_detected`: 15 unanswered TCP SYN probes $\to$ 1 alert, 15 targets observed.
4. `test_genuine_horizontal_rst_scan_detected`: 12 TCP RST rejected probes $\to$ 1 alert, 12 targets observed.
5. `test_genuine_horizontal_embryonic_connect_scan_detected`: 14 embryonic handshakes without data $\to$ 1 alert.
6. `test_no_port_whitelisting_scan_on_443_detected`: 12 unanswered SYN probes to port 443 $\to$ 1 alert (verifies 443 is not whitelisted).
7. `test_no_port_whitelisting_scan_on_53_detected`: 12 unanswered UDP probes to port 53 $\to$ 1 alert (verifies 53 is not whitelisted).
8. `test_genuine_vertical_scan_unaffected`: 18 ports on single target $\to$ vertical alert triggered, 0 horizontal alerts.
9. `test_ddos_excessive_connection_rate_unaffected`: 45 connections to target service $\to$ DDoS alert triggered, 0 horizontal alerts.
10. `test_boundary_threshold_behavior`: 9 targets $\to$ 0 alerts; 10 targets $\to$ 1 alert.
11. `test_boundary_timing_behavior`: 15 probes spread over 30s $\to$ 0 alerts; 15 probes within 7s $\to$ 1 alert.
12. `test_mixed_traffic_preserves_flow_ids`: 5 established HTTPS sessions + 12 scan probes $\to$ alert `flow_ids` contains only the 12 probes, completely excluding the 5 established flows.

### Global Test Execution
- Total Tests: **115 passed** in 4.48s (`backend/tests/` + `experiments/cic_ids2017/`).
- Failures: 0.

---

## 6. Production Integrity Verification

All production artifacts verified unchanged:
- `data/models/isolation_forest.joblib`: `404dd5d8bc1cb714f14f7a49bddc6dc50a00a3edc29164e5767f2d69982d2da9` (MATCH)
- `data/models/model_metadata.json`: `2341207c4c0c785a3d0faaabe72f57c046f10081392301e855b6bb473a79110f` (MATCH)
- `data/threat_detection.db`: Untouched.
