#!/usr/bin/env python3
"""Evaluation script for the Isolation Forest network flow anomaly detector.

Evaluates the detector on a separate synthetic evaluation dataset (seed=999)
comprising known benign flows and deliberately unusual network flows (e.g.,
unidirectional port probes, volumetric bursts).

Note on Methodology & Limitations:
----------------------------------
This evaluation is performed on synthetic test distributions to verify that the
detector produces statistically distinguishable scores for abnormal flow patterns.
It demonstrates model behavior and feature sensitivity, but does NOT represent
empirically validated real-world precision, recall, or false-positive benchmarks.
"""

import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

import numpy as np
from backend.app.pipeline.ml.model import AnomalyDetector
from backend.app.pipeline.ml.trainer import generate_synthetic_benign_flows


def generate_evaluation_dataset(seed: int = 999):
    """Generate separate evaluation flows with ground-truth synthetic labels."""
    rng = np.random.default_rng(seed)

    # 1. 100 Benign test flows
    benign_flows = generate_synthetic_benign_flows(num_samples=100, seed=seed)

    # 2. 50 Deliberately unusual / outlier flows
    unusual_flows = []

    # Category A: Unidirectional single-packet port probes (0 duration, 0 reverse traffic)
    for _ in range(20):
        unusual_flows.append({
            "forward_packets": 1,
            "backward_packets": 0,
            "forward_bytes": int(rng.choice([40, 60])),
            "backward_bytes": 0,
            "duration": 0.0,
            "protocol": "TCP",
            "scenario": "port_probe",
        })

    # Category B: Massive volumetric flood (extreme packet count & rate)
    for _ in range(15):
        duration = float(rng.uniform(0.01, 0.1))
        pkts = int(rng.integers(1000, 5000))
        unusual_flows.append({
            "forward_packets": pkts,
            "backward_packets": int(rng.integers(0, 5)),
            "forward_bytes": pkts * int(rng.integers(500, 1400)),
            "backward_bytes": int(rng.integers(0, 300)),
            "duration": duration,
            "protocol": "TCP",
            "scenario": "volumetric_flood",
        })

    # Category C: Asymmetric exfiltration (client pushes huge payload with minimal server response)
    for _ in range(15):
        duration = float(rng.uniform(0.5, 3.0))
        unusual_flows.append({
            "forward_packets": int(rng.integers(100, 300)),
            "backward_packets": int(rng.integers(1, 5)),
            "forward_bytes": int(rng.integers(200000, 800000)),
            "backward_bytes": int(rng.integers(100, 400)),
            "duration": duration,
            "protocol": "TCP",
            "scenario": "asymmetric_exfiltration",
        })

    return benign_flows, unusual_flows


def evaluate():
    detector = AnomalyDetector()
    if not detector.is_ready:
        print("ERROR: Isolation Forest model is not ready! Run scripts/train_model.py first.")
        sys.exit(1)

    benign_flows, unusual_flows = generate_evaluation_dataset(seed=999)

    print("=" * 65)
    print("NetShield Isolation Forest Anomaly Detector — Evaluation Report")
    print("=" * 65)
    print(f"Evaluation Dataset Source: Synthetic Evaluation Set (RNG Seed: 999)")
    print(f"Benign Flow Samples: {len(benign_flows)}")
    print(f"Unusual Flow Samples: {len(unusual_flows)}")
    print("-" * 65)

    # Score benign flows
    benign_scores = [detector.score_flow(f)[0] for f in benign_flows]
    benign_anomalies = sum(1 for f in benign_flows if detector.score_flow(f)[1] == 1)

    # Score unusual flows
    unusual_results = [detector.score_flow(f) for f in unusual_flows]
    unusual_scores = [r[0] for r in unusual_results]
    unusual_anomalies = sum(1 for r in unusual_results if r[1] == 1)

    print(f"Benign Flows:")
    print(f"  Mean Anomaly Score: {np.mean(benign_scores):.4f} (Std: {np.std(benign_scores):.4f})")
    print(f"  Min / Max Score:    {np.min(benign_scores):.4f} / {np.max(benign_scores):.4f}")
    print(f"  Flagged as Anomaly (>= 0.50): {benign_anomalies}/{len(benign_flows)} ({(benign_anomalies/len(benign_flows))*100:.1f}%)")
    print()
    print(f"Unusual Flows (Designed Outliers):")
    print(f"  Mean Anomaly Score: {np.mean(unusual_scores):.4f} (Std: {np.std(unusual_scores):.4f})")
    print(f"  Min / Max Score:    {np.min(unusual_scores):.4f} / {np.max(unusual_scores):.4f}")
    print(f"  Flagged as Anomaly (>= 0.50): {unusual_anomalies}/{len(unusual_flows)} ({(unusual_anomalies/len(unusual_flows))*100:.1f}%)")
    print("-" * 65)
    print("Sample Outlier Feature Attributions:")
    for idx, f in enumerate(unusual_flows[:3]):
        score, is_anom, attrib = detector.score_flow(f)
        scenario = f.get("scenario", "unusual")
        print(f"  [{scenario}] Score: {score:.4f} | Anomaly: {bool(is_anom)}")
        print(f"    Attributions: {attrib.get('top_deviations', {})}")

    print("=" * 65)
    print("Methodological Disclaimer:")
    print("This synthetic test confirms statistical score separation between normal and")
    print("outlier flows. It does not imply real-world production accuracy on live malware.")
    print("=" * 65)


if __name__ == "__main__":
    evaluate()
