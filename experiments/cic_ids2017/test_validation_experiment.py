"""Regression tests for the Leakage-Free Train/Validation/Test Evaluation Experiment."""

from pathlib import Path
from typing import Dict, Any, List, Tuple
import numpy as np
import pytest

from experiments.cic_ids2017.partitioner import (
    ThreeWayDatasetPartitioner,
    FlowRecord,
    PartitionBundle,
)
from experiments.cic_ids2017.run_validation_experiment import (
    apply_log1p_transform,
    compute_anomaly_scores,
    calibrate_threshold_strict_fpr,
    calibrate_threshold_max_f1,
    evaluate_partition,
    SKEWED_INDICES,
)


class MockStreamer:
    """Mock streamer yielding deterministic synthetic records for fast unit testing."""

    def __init__(self):
        self.files = [
            "Monday-WorkingHours.pcap_ISCX.csv",
            "Tuesday-WorkingHours.pcap_ISCX.csv",
            "Wednesday-workingHours.pcap_ISCX.csv",
        ]

    def get_csv_filenames(self) -> List[str]:
        return self.files

    def stream_file(self, filename: str):
        if "Monday" in filename:
            # Yield 100 benign flows
            for i in range(100):
                row = {
                    "Total Fwd Packets": str(10 + i),
                    "Total Backward Packets": "5",
                    "Total Length of Fwd Packets": "1000",
                    "Total Length of Bwd Packets": "500",
                    "Flow Duration": "1000000",
                    "Protocol": "6",
                }
                yield row, "BENIGN"
        else:
            # Non-Monday: yield 40 benign flows + 20 FTP-Patator + 10 Heartbleed
            for i in range(40):
                row = {
                    "Total Fwd Packets": str(2 + i),
                    "Total Backward Packets": "2",
                    "Total Length of Fwd Packets": "200",
                    "Total Length of Bwd Packets": "200",
                    "Flow Duration": "500000",
                    "Protocol": "6",
                }
                yield row, "BENIGN"
            for i in range(20):
                row = {
                    "Total Fwd Packets": "1",
                    "Total Backward Packets": "0",
                    "Total Length of Fwd Packets": "0",
                    "Total Length of Bwd Packets": "0",
                    "Flow Duration": "100",
                    "Protocol": "6",
                }
                yield row, "FTP-Patator"
            for i in range(10):
                row = {
                    "Total Fwd Packets": "5000",
                    "Total Backward Packets": "5000",
                    "Total Length of Fwd Packets": "5000000",
                    "Total Length of Bwd Packets": "5000000",
                    "Flow Duration": "10000000",
                    "Protocol": "6",
                }
                yield row, "Heartbleed"


def test_three_way_partitioner_disjointness_and_purity():
    """Verify that Train, Val, and Test have zero overlap and Train is pure benign."""
    streamer = MockStreamer()
    partitioner = ThreeWayDatasetPartitioner(
        streamer=streamer,
        random_seed=42,
        train_samples=50,
        val_monday_samples=25,
        test_monday_samples=25,
        val_drift_samples=20,
        test_drift_samples=20,
    )

    train, val, test = partitioner.generate_partitions()

    # 1. Size checks
    assert len(train.X) == 50
    # Two non-Monday files yielded 20*2 = 40 FTP and 10*2 = 20 Heartbleed.
    # Val gets half: 20 FTP + 10 Heartbleed = 30 attacks + 25 Monday benign + 20 drift benign = 75.
    assert len(val.X) == 25 + 20 + 30
    assert len(test.X) == 25 + 20 + 30

    # 2. Strict benign-only training purity
    assert np.all(train.y == 0)
    assert all(lbl == "BENIGN_MONDAY" for lbl in train.class_labels)

    # 3. Mathematical record ID disjointness
    train_ids = set(train.record_ids)
    val_ids = set(val.record_ids)
    test_ids = set(test.record_ids)

    assert len(train_ids) == len(train.record_ids)  # No internal duplicates
    assert len(val_ids) == len(val.record_ids)
    assert len(test_ids) == len(test.record_ids)

    assert len(train_ids & val_ids) == 0, "Train and Val overlap!"
    assert len(train_ids & test_ids) == 0, "Train and Test overlap!"
    assert len(val_ids & test_ids) == 0, "Val and Test overlap!"

    # 4. Stratification of attack classes in Val and Test
    val_classes = set(val.class_labels)
    test_classes = set(test.class_labels)
    assert "FTP-Patator" in val_classes and "FTP-Patator" in test_classes
    assert "Heartbleed" in val_classes and "Heartbleed" in test_classes


def test_calibrate_threshold_strict_fpr():
    """Verify threshold calibration respects the FPR budget."""
    rng = np.random.default_rng(42)
    # 100 benign scores around 0.30, 100 attack scores around 0.60
    benign_scores = rng.normal(0.30, 0.05, 100)
    attack_scores = rng.normal(0.60, 0.05, 100)

    scores = np.concatenate([benign_scores, attack_scores])
    y_true = np.array([0] * 100 + [1] * 100, dtype=np.int32)

    thresh, meta = calibrate_threshold_strict_fpr(scores, y_true, max_fpr=0.05)

    assert meta["val_fpr"] <= 0.05
    assert meta["val_recall"] > 0.80

    # Test that evaluating at this threshold produces the same FPR
    preds = (scores >= thresh).astype(int)
    fp = np.sum((preds == 1) & (y_true == 0))
    actual_fpr = fp / 100
    assert np.isclose(actual_fpr, meta["val_fpr"])


def test_calibrate_threshold_max_f1():
    """Verify threshold calibration maximizes F1 score."""
    rng = np.random.default_rng(42)
    benign_scores = rng.normal(0.35, 0.05, 100)
    attack_scores = rng.normal(0.55, 0.05, 100)

    scores = np.concatenate([benign_scores, attack_scores])
    y_true = np.array([0] * 100 + [1] * 100, dtype=np.int32)

    thresh, meta = calibrate_threshold_max_f1(scores, y_true)
    assert 0.0 < thresh < 1.0
    assert meta["val_f1"] > 0.85


def test_evaluate_partition_metrics_consistency():
    """Verify confusion matrix, FPR, and metric calculations."""
    y_true = np.array([0, 0, 0, 0, 1, 1, 1, 1], dtype=np.int32)
    class_labels = [
        "BENIGN_MONDAY", "BENIGN_MONDAY",
        "BENIGN_DRIFT", "BENIGN_DRIFT",
        "DDoS", "DDoS", "PortScan", "PortScan"
    ]
    # Scores designed:
    # Benign: [0.1, 0.2, 0.3, 0.6] -> at tau=0.5: TN=3, FP=1 (1 drift FP)
    # Attack: [0.4, 0.7, 0.8, 0.9] -> at tau=0.5: FN=1, TP=3
    scores = np.array([0.1, 0.2, 0.3, 0.6, 0.4, 0.7, 0.8, 0.9])

    res = evaluate_partition(scores, y_true, class_labels, threshold=0.50)

    cm = res["confusion_matrix"]
    assert cm["tn"] == 3
    assert cm["fp"] == 1
    assert cm["fn"] == 1
    assert cm["tp"] == 3

    assert np.isclose(res["fpr_overall"], 0.25)
    assert np.isclose(res["fpr_monday"], 0.0)
    assert np.isclose(res["fpr_drift"], 0.5)

    assert np.isclose(res["precision"], 3 / 4)
    assert np.isclose(res["recall"], 3 / 4)
    assert np.isclose(res["f1_score"], 0.75)

    assert "DDoS" in res["per_class"]
    assert "PortScan" in res["per_class"]
    assert res["per_class"]["DDoS"]["samples"] == 2
    assert res["per_class"]["DDoS"]["flagged"] == 1
    assert res["per_class"]["PortScan"]["samples"] == 2
    assert res["per_class"]["PortScan"]["flagged"] == 2
