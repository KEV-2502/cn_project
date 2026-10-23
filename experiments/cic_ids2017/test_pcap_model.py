"""Regression tests for PCAP-derived model training, partitioning, and isolation."""

import hashlib
import json
from pathlib import Path
import numpy as np
import pytest

from experiments.cic_ids2017.train_pcap_model import (
    apply_log1p_transform,
    compute_normalized_scores,
    SKEWED_INDICES,
)
from backend.app.pipeline.flow_aggregator import AggregatedFlow
from backend.app.pipeline.ml.features import FEATURE_NAMES

BASE_DIR = Path(__file__).resolve().parent.parent.parent


def test_apply_log1p_transform_correctness():
    """Verify log1p transform applies strictly to specified skewed indices."""
    X = np.ones((2, 15), dtype=np.float64) * 10.0
    X_log = apply_log1p_transform(X)

    for i in range(15):
        if i in SKEWED_INDICES:
            assert np.isclose(X_log[0, i], np.log1p(10.0))
        else:
            assert X_log[0, i] == 10.0


def test_normalized_score_bounds_and_monotonicity():
    """Verify normalized score is clamped to [0.0, 1.0] and inverts raw score."""
    from sklearn.ensemble import IsolationForest

    # Dummy model
    X_train = np.random.RandomState(42).randn(50, 15)
    model = IsolationForest(n_estimators=10, random_state=42).fit(X_train)

    X_test = np.random.RandomState(43).randn(20, 15)
    scores = compute_normalized_scores(model, X_test)

    assert np.all(scores >= 0.0)
    assert np.all(scores <= 1.0)

    raw_scores = model.decision_function(X_test)
    # Higher raw score means more normal (inlier) -> lower normalized score
    for i in range(len(raw_scores) - 1):
        if raw_scores[i] < raw_scores[i + 1]:
            assert scores[i] >= scores[i + 1]


def test_production_artifacts_untouched():
    """Verify production artifacts have not been altered in any way."""
    prod_model = BASE_DIR / "data" / "models" / "isolation_forest.joblib"
    prod_meta = BASE_DIR / "data" / "models" / "model_metadata.json"

    assert prod_model.exists()
    assert prod_meta.exists()

    with open(prod_model, "rb") as f:
        model_sha = hashlib.sha256(f.read()).hexdigest()
    with open(prod_meta, "rb") as f:
        meta_sha = hashlib.sha256(f.read()).hexdigest()

    assert model_sha == "404dd5d8bc1cb714f14f7a49bddc6dc50a00a3edc29164e5767f2d69982d2da9"
    assert meta_sha == "2341207c4c0c785a3d0faaabe72f57c046f10081392301e855b6bb473a79110f"
