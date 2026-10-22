"""Isolation Forest Anomaly Detection Model Wrapper.

Handles loading, inference, score normalization, and feature attribution for
network flow anomaly detection.
"""

import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from backend.app.config import settings
from backend.app.pipeline.ml.features import (
    FEATURE_NAMES,
    extract_flow_features,
    extract_batch_features,
)

logger = logging.getLogger(__name__)

DEFAULT_MODEL_FILE = settings.MODEL_DIR / "isolation_forest.joblib"
DEFAULT_METADATA_FILE = settings.MODEL_DIR / "model_metadata.json"


class AnomalyDetector:
    """Manages the lifecycle and inference of the Isolation Forest flow anomaly detector."""

    def __init__(
        self,
        model_path: Path = DEFAULT_MODEL_FILE,
        metadata_path: Path = DEFAULT_METADATA_FILE,
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
        """Load the persisted Isolation Forest model and its baseline metadata."""
        try:
            if not self.model_path.exists():
                logger.warning(f"Model artifact not found at {self.model_path}")
                self.model = None
                return False

            self.model = joblib.load(self.model_path)

            if self.metadata_path.exists():
                with open(self.metadata_path, "r", encoding="utf-8") as f:
                    self.metadata = json.load(f)
                    stats = self.metadata.get("baseline_feature_stats", {})
                    if "means" in stats and "stds" in stats:
                        self.feature_means = np.array(stats["means"], dtype=np.float64)
                        self.feature_stds = np.array(stats["stds"], dtype=np.float64)

            logger.info(f"Loaded Isolation Forest model from {self.model_path}")
            return True
        except Exception as exc:
            logger.error(f"Failed to load Isolation Forest model: {exc}")
            self.model = None
            return False

    def score_flow(self, flow: Any) -> Tuple[float, int, Dict[str, Any]]:
        """Compute an explainable anomaly score and attribution for a single flow.

        Returns:
            (normalized_score, is_anomaly, attribution_dict)
            - normalized_score: float in [0.0, 1.0] where >= 0.5 indicates an outlier.
            - is_anomaly: 1 if flagged as an anomaly by Isolation Forest, 0 otherwise.
            - attribution_dict: Top deviating features compared to baseline distribution.
        """
        if not self.is_ready:
            return 0.0, 0, {"status": "model_unavailable"}

        feats = extract_flow_features(flow)
        return self._score_single_vector(feats)

    def _score_single_vector(self, feats: np.ndarray) -> Tuple[float, int, Dict[str, Any]]:
        assert self.model is not None
        X = feats.reshape(1, -1)

        # Scikit-learn Isolation Forest:
        # decision_function: average anomaly score (lower means more abnormal, negative is outlier)
        # predict: -1 for outlier/anomaly, +1 for inlier
        raw_score = float(self.model.decision_function(X)[0])
        pred = int(self.model.predict(X)[0])
        is_anomaly = 1 if pred == -1 else 0

        # Normalization: map raw_score (typically in [-0.5, 0.25]) to [0.0, 1.0]
        # Inlier raw > 0.0 -> normalized < 0.50
        # Outlier raw < 0.0 -> normalized > 0.50
        normalized_score = round(float(np.clip(0.5 - raw_score, 0.0, 1.0)), 4)

        # Feature Attribution: compute z-scores against baseline distribution
        attribution = self._compute_attribution(feats)

        return normalized_score, is_anomaly, attribution

    def score_batch(self, flows: List[Any]) -> List[Tuple[float, int, Dict[str, Any]]]:
        """Score a list of flows in a single vectorized batch."""
        if not flows:
            return []

        if not self.is_ready:
            return [(0.0, 0, {"status": "model_unavailable"}) for _ in flows]

        X = extract_batch_features(flows)
        raw_scores = self.model.decision_function(X)
        preds = self.model.predict(X)

        results: List[Tuple[float, int, Dict[str, Any]]] = []
        for i in range(len(flows)):
            raw = float(raw_scores[i])
            pred = int(preds[i])
            is_anomaly = 1 if pred == -1 else 0
            normalized = round(float(np.clip(0.5 - raw, 0.0, 1.0)), 4)
            attribution = self._compute_attribution(X[i])
            results.append((normalized, is_anomaly, attribution))

        return results

    def _compute_attribution(self, feats: np.ndarray) -> Dict[str, Any]:
        """Identify features that deviate the most from baseline benign distribution."""
        if self.feature_means is None or self.feature_stds is None:
            return {}

        stds = np.where(self.feature_stds <= 1e-6, 1.0, self.feature_stds)
        z_scores = np.abs((feats - self.feature_means) / stds)

        # Pick top 3 feature outliers
        top_indices = np.argsort(z_scores)[::-1][:3]
        top_deviations: Dict[str, Any] = {}
        for idx in top_indices:
            feat_name = FEATURE_NAMES[idx]
            val = float(feats[idx])
            mean_val = float(self.feature_means[idx])
            z = float(z_scores[idx])
            if z > 1.5:  # Only report if noticeably deviating (> 1.5 std devs)
                top_deviations[feat_name] = {
                    "observed": round(val, 2),
                    "baseline_mean": round(mean_val, 2),
                    "z_score": round(z, 2),
                }

        return {"top_deviations": top_deviations}
