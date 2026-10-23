"""Unit tests for the CIC-IDS2017 Anomaly Detection Investigation."""

from pathlib import Path
import numpy as np
import pytest
from sklearn.ensemble import IsolationForest

from experiments.cic_ids2017.run_investigation import (
    apply_log1p_transform,
    evaluate_candidate,
    plot_recall_vs_fpr_curves,
    SKEWED_INDICES,
)


def test_apply_log1p_transform_preserves_shape_and_bounds():
    X = np.array([
        [10.0, 5.0, 1000.0, 5000.0, 2.5, 0.6, 0.4, 50.0, 25.0, 10000.0, 20000.0, 1.0, 0.0, 0.0, 150.0],
        [0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0],
    ])
    X_log = apply_log1p_transform(X)
    assert X_log.shape == X.shape
    # Check that skewed indices were transformed by log(1 + x)
    for idx in SKEWED_INDICES:
        assert np.isclose(X_log[0, idx], np.log1p(X[0, idx]))
    # Check that unskewed indices (ratios, protocol flags) remain unchanged
    assert X_log[0, 5] == X[0, 5]  # packet_ratio
    assert X_log[0, 6] == X[0, 6]  # byte_ratio
    assert X_log[0, 11] == X[0, 11]  # is_tcp
    assert X_log[0, 12] == X[0, 12]  # is_udp
    assert X_log[0, 13] == X[0, 13]  # is_icmp


def test_scoring_pipeline_offset_and_normalization_relationship():
    """Verify mathematical relationship between decision_function, score_samples, and offset_."""
    rng = np.random.default_rng(42)
    X_train = rng.normal(5.0, 1.0, size=(1000, 15))

    m_contam_01 = IsolationForest(n_estimators=50, contamination=0.01, random_state=42).fit(X_train)
    m_contam_auto = IsolationForest(n_estimators=50, contamination="auto", random_state=42).fit(X_train)

    # When contamination='auto', scikit-learn standard offset_ is -0.5
    assert np.isclose(m_contam_auto.offset_, -0.5)

    # When contamination=0.01, offset_ is strictly lower than -0.50 (1st percentile of training samples)
    assert m_contam_01.offset_ < -0.50

    # Test point
    X_test = rng.normal(5.0, 1.0, size=(10, 15))
    dec_func = m_contam_01.decision_function(X_test)
    score_samples = m_contam_01.score_samples(X_test)

    # Scikit-learn formula: decision_function = score_samples - offset_
    assert np.allclose(dec_func, score_samples - m_contam_01.offset_)

    # Normalization formula: normalized = 0.5 - dec_func
    # Outlier threshold normalized >= 0.50 <=> dec_func <= 0 <=> score_samples <= offset_
    norm_score = np.clip(0.5 - dec_func, 0.0, 1.0)
    outliers = (norm_score >= 0.50)
    assert np.array_equal(outliers, score_samples <= m_contam_01.offset_)


def test_evaluate_candidate_computation(tmp_path):
    rng = np.random.default_rng(42)
    X_train = rng.normal(0.0, 1.0, size=(100, 15))
    m = IsolationForest(n_estimators=20, contamination=0.05, random_state=42).fit(X_train)

    # 40 benign (20 monday, 20 drift) + 20 attack
    X_eval = np.vstack([
        rng.normal(0.0, 1.0, size=(20, 15)),
        rng.normal(0.1, 1.0, size=(20, 15)),
        rng.normal(10.0, 2.0, size=(20, 15)),
    ])
    y_eval = np.array([0] * 40 + [1] * 20, dtype=np.int32)
    class_labels = ["BENIGN_MONDAY"] * 20 + ["BENIGN_DRIFT"] * 20 + ["Heartbleed"] * 20

    res = evaluate_candidate(
        name="TestExp",
        model=m,
        X_eval=X_eval,
        y_eval=y_eval,
        class_labels=class_labels,
        threshold=0.50,
    )

    assert "metrics" in res
    assert "confusion_matrix" in res
    assert "per_class" in res
    assert res["metrics"]["recall"] > 0.0
    assert 0.0 <= res["metrics"]["fpr_monday"] <= 1.0
    assert 0.0 <= res["metrics"]["fpr_drift"] <= 1.0

    # Test plotting curves
    plot_path = tmp_path / "test_curve.png"
    plot_recall_vs_fpr_curves([res], y_eval, plot_path)
    assert plot_path.exists()
    assert plot_path.stat().st_size > 1000
