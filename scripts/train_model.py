#!/usr/bin/env python3
"""CLI utility to train and save the Isolation Forest flow anomaly detection model."""

import sys
from pathlib import Path

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from backend.app.pipeline.ml.trainer import train_isolation_forest_model
from backend.app.pipeline.ml.model import AnomalyDetector


def main():
    print("=" * 60)
    print("Training NetShield Isolation Forest Anomaly Detection Model")
    print("=" * 60)

    model, metadata = train_isolation_forest_model()

    print(f"Model saved to: {metadata['model_name']}")
    print(f"Training samples: {metadata['training_data']['sample_count']}")
    print(f"Features: {len(metadata['feature_schema'])}")
    print(f"Random seed: {metadata['random_seed']}")

    # Validate that AnomalyDetector can load and score
    detector = AnomalyDetector()
    if detector.is_ready:
        print("Verification: AnomalyDetector successfully loaded serialized model artifact.")
        test_flow = {
            "forward_packets": 5,
            "backward_packets": 10,
            "forward_bytes": 450,
            "backward_bytes": 5000,
            "duration": 1.2,
            "protocol": "TCP",
        }
        score, is_anomaly, attrib = detector.score_flow(test_flow)
        print(f"Sample test flow score: {score} (is_anomaly={is_anomaly})")
    else:
        print("ERROR: AnomalyDetector failed to load model!")
        sys.exit(1)


if __name__ == "__main__":
    main()
