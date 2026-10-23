"""Candidate Isolation Forest Model Wrapper for CIC-IDS2017 Experiment.

Trains and serializes candidate model artifacts strictly to isolated paths:
- data/models/candidate_isolation_forest_cic.joblib
- data/models/candidate_model_metadata_cic.json

Does NOT modify or overwrite NetShield's production model artifacts.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Tuple, Optional, List
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from experiments.cic_ids2017.features import FEATURE_NAMES, SCHEMA_VERSION

BASE_DIR = Path(__file__).resolve().parent.parent.parent
DEFAULT_CANDIDATE_MODEL_PATH = BASE_DIR / "data" / "models" / "candidate_isolation_forest_cic.joblib"
DEFAULT_CANDIDATE_METADATA_PATH = BASE_DIR / "data" / "models" / "candidate_model_metadata_cic.json"


class CandidateAnomalyDetector:
    """Manages training, persistence, and scoring for the candidate CIC model."""

    def __init__(
        self,
        model_path: Path = DEFAULT_CANDIDATE_MODEL_PATH,
        metadata_path: Path = DEFAULT_CANDIDATE_METADATA_PATH,
    ):
        self.model_path = Path(model_path)
        self.metadata_path = Path(metadata_path)
        self.model: Optional[IsolationForest] = None
        self.metadata: Dict[str, Any] = {}
        self.feature_means: Optional[np.ndarray] = None
        self.feature_stds: Optional[np.ndarray] = None
        self._load_if_exists()

    def _load_if_exists(self) -> bool:
        if self.model_path.exists():
            return self.load()
        return False

    @property
    def is_ready(self) -> bool:
        return self.model is not None

    def load(self) -> bool:
        """Load candidate model artifact and metadata."""
        try:
            self.model = joblib.load(self.model_path)
            if self.metadata_path.exists():
                with open(self.metadata_path, "r", encoding="utf-8") as f:
                    self.metadata = json.load(f)
                    stats = self.metadata.get("baseline_feature_stats", {})
                    if "means" in stats and "stds" in stats:
                        self.feature_means = np.array(stats["means"], dtype=np.float64)
                        self.feature_stds = np.array(stats["stds"], dtype=np.float64)
            return True
        except Exception:
            self.model = None
            return False

    def train(
        self,
        X_train: np.ndarray,
        random_seed: int = 42,
        contamination: float = 0.01,
        n_estimators: int = 100,
        extra_meta: Optional[Dict[str, Any]] = None,
    ) -> Tuple[IsolationForest, Dict[str, Any]]:
        """Fit Isolation Forest on pure benign training set and serialize to candidate paths."""
        self.model = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            random_state=random_seed,
            max_samples="auto",
            n_jobs=-1,
        )
        self.model.fit(X_train)

        means = np.mean(X_train, axis=0).tolist()
        stds = np.std(X_train, axis=0).tolist()
        self.feature_means = np.array(means, dtype=np.float64)
        self.feature_stds = np.array(stds, dtype=np.float64)

        metadata: Dict[str, Any] = {
            "model_name": "Candidate Isolation Forest (CIC-IDS2017 Benign Baseline)",
            "model_type": "IsolationForest",
            "library": "scikit-learn",
            "version": "0.2.0-candidate",
            "schema_version": SCHEMA_VERSION,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "random_seed": random_seed,
            "model_parameters": {
                "n_estimators": n_estimators,
                "contamination": contamination,
                "random_state": random_seed,
                "max_samples": "auto",
            },
            "training_summary": {
                "dataset_source": "CIC-IDS2017 Monday-WorkingHours.pcap_ISCX.csv (Verified Benign)",
                "sample_count": len(X_train),
                "features_count": len(FEATURE_NAMES),
                "disclaimer": (
                    "Trained strictly on verified Monday benign flows to establish nominal traffic baseline. "
                    "Completely isolated from production model artifacts."
                ),
            },
            "feature_schema": FEATURE_NAMES,
            "baseline_feature_stats": {
                "means": means,
                "stds": stds,
            },
            "scoring_convention": {
                "normalization": "normalized_score = clip(0.5 - decision_function(X), 0.0, 1.0)",
                "anomaly_threshold": 0.50,
                "interpretation": "Scores >= 0.50 indicate statistical outlier deviation relative to Monday benign baseline.",
            },
        }

        if extra_meta:
            metadata["dataset_audit_meta"] = extra_meta

        self.metadata = metadata

        # Save candidate model and metadata
        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.model, self.model_path)
        with open(self.metadata_path, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)

        return self.model, metadata

    def score_batch(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Compute anomaly scores and binary predictions for a batch of feature vectors.

        Returns:
            (normalized_scores, is_anomaly_preds)
        """
        assert self.model is not None, "Candidate model is not loaded or trained."
        raw_scores = self.model.decision_function(X)
        normalized_scores = np.clip(0.5 - raw_scores, 0.0, 1.0)
        is_anomaly_preds = (normalized_scores >= 0.50).astype(int)
        return normalized_scores, is_anomaly_preds

    def compute_attribution(self, feats: np.ndarray) -> Dict[str, Any]:
        """Identify top deviating features compared to Monday baseline."""
        if self.feature_means is None or self.feature_stds is None:
            return {}
        stds = np.where(self.feature_stds <= 1e-6, 1.0, self.feature_stds)
        z_scores = np.abs((feats - self.feature_means) / stds)
        top_indices = np.argsort(z_scores)[::-1][:3]
        deviations = {}
        for idx in top_indices:
            feat_name = FEATURE_NAMES[idx]
            z = float(z_scores[idx])
            if z > 1.5:
                deviations[feat_name] = {
                    "observed": round(float(feats[idx]), 2),
                    "baseline_mean": round(float(self.feature_means[idx]), 2),
                    "z_score": round(z, 2),
                }
        return {"top_deviations": deviations}
