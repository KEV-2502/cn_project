"""Unit and Integration Tests for the Isolated CIC-IDS2017 ML Experiment."""

import io
import tempfile
import zipfile
from pathlib import Path
import numpy as np
import pytest

from experiments.cic_ids2017.data_loader import (
    clean_header,
    normalize_label,
    CICDatasetStreamer,
)
from experiments.cic_ids2017.features import (
    FEATURE_NAMES,
    extract_cic_features,
    extract_cic_batch,
    _safe_float,
)
from experiments.cic_ids2017.model import CandidateAnomalyDetector
from experiments.cic_ids2017.evaluate import run_evaluation


# --- 1. Data Loader & Preprocessing Tests ---

def test_clean_header_trims_whitespace_and_disambiguates_duplicates():
    raw = [" Flow ID", " Source IP ", " Fwd Header Length", " Fwd Header Length", " Label "]
    cleaned = clean_header(raw)
    assert cleaned == [
        "Flow ID",
        "Source IP",
        "Fwd Header Length",
        "Fwd Header Length_2",
        "Label",
    ]


def test_normalize_label_variants():
    assert normalize_label("BENIGN") == "BENIGN"
    assert normalize_label("  BENIGN  ") == "BENIGN"
    assert normalize_label("Web Attack \x96 Brute Force") == "Web Attack - Brute Force"
    assert normalize_label("Web Attack – XSS") == "Web Attack - XSS"
    assert normalize_label("Web Attack \x96 Sql Injection") == "Web Attack - SQL Injection"
    assert normalize_label("DDoS") == "DDoS"
    assert normalize_label("PortScan") == "PortScan"
    assert normalize_label("") is None
    assert normalize_label("   ") is None


def test_streamer_skips_empty_and_malformed_lines(tmp_path):
    # Construct a minimal in-memory zip
    zip_path = tmp_path / "test_capture.zip"
    with zipfile.ZipFile(zip_path, "w") as z:
        content = (
            "Flow ID, Flow Duration, Total Fwd Packets, Total Backward Packets, Total Length of Fwd Packets, Total Length of Bwd Packets, Protocol, Label\n"
            "flow1, 1000000, 5, 5, 500, 500, 6, BENIGN\n"
            ",,,,,,,\n"  # Empty comma line
            "\n"          # Blank line
            "short,row,only\n" # Malformed column count
            "flow2, 2000000, 2, 0, 100, 0, 17, PortScan\n"
        )
        z.writestr("test.csv", content.encode("latin-1"))

    streamer = CICDatasetStreamer(zip_path)
    records = list(streamer.stream_file("test.csv"))
    assert len(records) == 2
    row1, label1 = records[0]
    row2, label2 = records[1]
    assert label1 == "BENIGN"
    assert label2 == "PortScan"
    assert row1["Flow ID"] == "flow1"
    assert row2["Flow ID"] == "flow2"

    stats = streamer.file_audits["test.csv"]
    assert stats.empty_lines_dropped >= 2
    assert stats.malformed_rows_dropped >= 1


# --- 2. Feature Extraction & Semantics Tests ---

def test_feature_names_and_count():
    assert len(FEATURE_NAMES) == 15


def test_extract_cic_features_semantics():
    row = {
        "Total Fwd Packets": "10",
        "Total Backward Packets": "10",
        "Total Length of Fwd Packets": "1000",
        "Total Length of Bwd Packets": "2000",
        "Flow Duration": "2000000",  # 2,000,000 microseconds = 2.0 seconds
        "Protocol": "6",            # TCP
    }
    feats = extract_cic_features(row)
    assert isinstance(feats, np.ndarray)
    assert feats.shape == (15,)
    assert feats.dtype == np.float64

    # 0: fwd_pkts
    assert feats[0] == 10.0
    # 1: bwd_pkts
    assert feats[1] == 10.0
    # 2: fwd_bytes
    assert feats[2] == 1000.0
    # 3: bwd_bytes
    assert feats[3] == 2000.0
    # 4: duration in seconds
    assert feats[4] == 2.0
    # 5: packet_ratio (10 / 20)
    assert feats[5] == 0.5
    # 6: byte_ratio (1000 / 3000)
    assert abs(feats[6] - (1000.0 / 3000.0)) < 1e-6
    # 7: fwd_pkt_rate (10 / 2.0)
    assert feats[7] == 5.0
    # 8: bwd_pkt_rate (10 / 2.0)
    assert feats[8] == 5.0
    # 9: fwd_byte_rate (1000 / 2.0)
    assert feats[9] == 500.0
    # 10: bwd_byte_rate (2000 / 2.0)
    assert feats[10] == 1000.0
    # 11: is_tcp
    assert feats[11] == 1.0
    # 12: is_udp
    assert feats[12] == 0.0
    # 13: is_icmp
    assert feats[13] == 0.0
    # 14: avg_packet_size (3000 / 20)
    assert feats[14] == 150.0


def test_zero_and_negative_duration_handling():
    # Negative duration (clock skew / packet reordering)
    row_neg = {
        "Total Fwd Packets": "1",
        "Total Backward Packets": "0",
        "Total Length of Fwd Packets": "60",
        "Total Length of Bwd Packets": "0",
        "Flow Duration": "-15",  # negative
        "Protocol": "6",
    }
    feats_neg = extract_cic_features(row_neg)
    assert feats_neg[4] == 0.0  # Clamped to 0.0
    # Rates use epsilon duration floor 1e-3
    assert feats_neg[7] == 1000.0  # 1 / 1e-3
    assert np.all(np.isfinite(feats_neg))


def test_protocol_indicator_mapping():
    tcp_row = {"Protocol": "6"}
    udp_row = {"Protocol": "17"}
    icmp_row = {"Protocol": "1"}
    other_row = {"Protocol": "0"}

    assert extract_cic_features(tcp_row)[11] == 1.0
    assert extract_cic_features(tcp_row)[12] == 0.0
    assert extract_cic_features(udp_row)[12] == 1.0
    assert extract_cic_features(icmp_row)[13] == 1.0
    assert extract_cic_features(other_row)[11] == 0.0
    assert extract_cic_features(other_row)[12] == 0.0
    assert extract_cic_features(other_row)[13] == 0.0


# --- 3. Model Training & Isolation Tests ---

def test_candidate_detector_train_and_isolation(tmp_path):
    candidate_model_path = tmp_path / "candidate_model.joblib"
    candidate_meta_path = tmp_path / "candidate_meta.json"

    detector = CandidateAnomalyDetector(
        model_path=candidate_model_path,
        metadata_path=candidate_meta_path,
    )
    assert not detector.is_ready

    # Dummy benign training data
    rng = np.random.default_rng(42)
    X_train = rng.uniform(0.1, 10.0, size=(100, 15))

    model, meta = detector.train(
        X_train=X_train,
        random_seed=42,
        contamination=0.01,
        n_estimators=50,
    )

    assert candidate_model_path.exists()
    assert candidate_meta_path.exists()
    assert detector.is_ready

    # Score dummy batch
    scores, preds = detector.score_batch(X_train[:10])
    assert len(scores) == 10
    assert len(preds) == 10
    assert np.all((scores >= 0.0) & (scores <= 1.0))
    assert np.all(np.isin(preds, [0, 1]))


# --- 4. Evaluation Engine Tests ---

def test_run_evaluation_metrics_and_report_generation(tmp_path):
    detector = CandidateAnomalyDetector(
        model_path=tmp_path / "test_cand.joblib",
        metadata_path=tmp_path / "test_meta.json",
    )
    # Train detector on small normal distribution
    rng = np.random.default_rng(42)
    X_train = rng.normal(5.0, 1.0, size=(100, 15))
    detector.train(X_train=X_train, random_seed=42, n_estimators=20)

    # Eval set: 50 in-distribution benign + 50 extreme outlier attacks
    X_benign_mon = rng.normal(5.0, 1.0, size=(30, 15))
    X_benign_drift = rng.normal(5.2, 1.1, size=(20, 15))
    X_attack = rng.normal(50.0, 5.0, size=(50, 15))

    X_eval = np.vstack([X_benign_mon, X_benign_drift, X_attack])
    y_eval = np.array([0] * 50 + [1] * 50, dtype=np.int32)
    class_labels = ["BENIGN_MONDAY"] * 30 + ["BENIGN_DRIFT"] * 20 + ["PortScan"] * 50

    eval_meta = {
        "train_count": 100,
        "total_eval_samples": 100,
    }

    reports_dir = tmp_path / "reports"
    results = run_evaluation(
        detector=detector,
        X_eval=X_eval,
        y_eval=y_eval,
        class_labels=class_labels,
        eval_meta=eval_meta,
        reports_dir=reports_dir,
    )

    assert "overall_metrics" in results
    assert "confusion_matrix" in results
    assert "false_positive_analysis" in results
    assert "per_class_results" in results

    # Assert report files were created
    assert (reports_dir / "evaluation_report.json").exists()
    assert (reports_dir / "evaluation_report.md").exists()
