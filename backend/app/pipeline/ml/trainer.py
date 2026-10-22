"""Reproducible Model Training and Baseline Generation Pipeline.

Generates diverse synthetic benign network flow data, fits an Isolation Forest
anomaly detection model with a fixed random seed, records feature attribution
statistics, and serializes artifacts to data/models/.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Tuple
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from backend.app.config import settings
from backend.app.pipeline.ml.features import (
    FEATURE_NAMES,
    extract_batch_features,
)

DEFAULT_MODEL_PATH = settings.MODEL_DIR / "isolation_forest.joblib"
DEFAULT_METADATA_PATH = settings.MODEL_DIR / "model_metadata.json"


def generate_synthetic_benign_flows(num_samples: int = 2000, seed: int = 42) -> List[Dict[str, Any]]:
    """Generate a diverse dataset of plausible benign network flows.

    Covers 5 common application profiles:
    1. HTTP/HTTPS Web Browsing
    2. DNS Queries
    3. Microservice/API RPC Calls
    4. Streaming & Bulk Data Transfers
    5. ICMP Diagnostics
    """
    rng = np.random.default_rng(seed)
    flows: List[Dict[str, Any]] = []

    for _ in range(num_samples):
        profile = rng.choice(["http", "dns", "api", "bulk", "icmp"], p=[0.40, 0.25, 0.20, 0.10, 0.05])

        if profile == "http":
            fwd_pkts = int(rng.integers(3, 15))
            bwd_pkts = int(rng.integers(5, 40))
            duration = float(rng.uniform(0.1, 4.0))
            fwd_bytes = int(rng.integers(200, 1500))
            bwd_bytes = int(rng.integers(2000, 45000))
            proto = "TCP"

        elif profile == "dns":
            fwd_pkts = 1
            bwd_pkts = 1
            duration = float(rng.uniform(0.005, 0.15))
            fwd_bytes = int(rng.integers(50, 120))
            bwd_bytes = int(rng.integers(70, 350))
            proto = "UDP"

        elif profile == "api":
            fwd_pkts = int(rng.integers(2, 8))
            bwd_pkts = int(rng.integers(2, 8))
            duration = float(rng.uniform(0.02, 0.8))
            fwd_bytes = int(rng.integers(300, 3000))
            bwd_bytes = int(rng.integers(300, 4000))
            proto = "TCP"

        elif profile == "bulk":
            fwd_pkts = int(rng.integers(15, 60))  # Client ACKs
            bwd_pkts = int(rng.integers(30, 120)) # Server data chunks
            duration = float(rng.uniform(1.0, 15.0))
            fwd_bytes = int(fwd_pkts * rng.integers(40, 70))
            bwd_bytes = int(rng.integers(30000, 180000))
            proto = "TCP"

        else:  # icmp
            fwd_pkts = 1
            bwd_pkts = 1
            duration = float(rng.uniform(0.001, 0.05))
            fwd_bytes = int(rng.choice([64, 84]))
            bwd_bytes = int(rng.choice([64, 84]))
            proto = "ICMP"

        flows.append({
            "forward_packets": fwd_pkts,
            "backward_packets": bwd_pkts,
            "forward_bytes": fwd_bytes,
            "backward_bytes": bwd_bytes,
            "duration": duration,
            "protocol": proto,
        })

    return flows


def train_isolation_forest_model(
    num_samples: int = 2000,
    random_seed: int = 42,
    contamination: float = 0.03,
    n_estimators: int = 100,
    model_path: Path = DEFAULT_MODEL_PATH,
    metadata_path: Path = DEFAULT_METADATA_PATH,
) -> Tuple[IsolationForest, Dict[str, Any]]:
    """Train and persist the Isolation Forest model and baseline metadata."""
    # 1. Generate diverse benign training set
    benign_flows = generate_synthetic_benign_flows(num_samples=num_samples, seed=random_seed)

    # 2. Extract features using the exact production schema
    X_train = extract_batch_features(benign_flows)

    # 3. Fit Isolation Forest with fixed seed
    model = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        random_state=random_seed,
        max_samples="auto",
        n_jobs=-1,
    )
    model.fit(X_train)

    # 4. Calculate feature baseline statistics for explainable attribution
    means = np.mean(X_train, axis=0).tolist()
    stds = np.std(X_train, axis=0).tolist()

    metadata: Dict[str, Any] = {
        "model_name": "Isolation Forest Network Flow Anomaly Detector",
        "model_type": "IsolationForest",
        "library": "scikit-learn",
        "version": "0.1.0",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "random_seed": random_seed,
        "model_parameters": {
            "n_estimators": n_estimators,
            "contamination": contamination,
            "random_state": random_seed,
            "max_samples": "auto",
        },
        "training_data": {
            "source": "synthetic_baseline_v1",
            "sample_count": num_samples,
            "label": "benign_multi_protocol_synthetic",
            "profiles": ["http", "dns", "api", "bulk", "icmp"],
            "disclaimer": (
                "Trained on synthetic benign network traffic distributions for platform "
                "validation and statistical outlier detection. Does not claim real-world detection benchmarks."
            ),
        },
        "feature_schema": FEATURE_NAMES,
        "baseline_feature_stats": {
            "means": means,
            "stds": stds,
        },
        "scoring_notes": {
            "score_normalization": "normalized_score = clip(0.5 - decision_function(X), 0.0, 1.0)",
            "anomaly_threshold": 0.50,
            "interpretation": "Scores >= 0.50 indicate statistical outliers relative to baseline training distribution.",
        },
    }

    # 5. Persist model and metadata
    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, model_path)

    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    return model, metadata


if __name__ == "__main__":
    train_isolation_forest_model()
