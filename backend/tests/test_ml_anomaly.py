"""Deterministic unit and integration tests for the ML Anomaly Detection pipeline."""

import json
import tempfile
from pathlib import Path
import numpy as np
import pytest
from scapy.all import Ether, IP, TCP, wrpcap

from backend.app.models.flow import NetworkFlow
from backend.app.pipeline.ml.features import (
    FEATURE_NAMES,
    extract_flow_features,
    extract_batch_features,
    _safe_float,
)
from backend.app.pipeline.ml.model import AnomalyDetector
from backend.app.pipeline.ml.trainer import (
    generate_synthetic_benign_flows,
    train_isolation_forest_model,
)


# --- 1. Feature Extraction Tests ---

def test_feature_names_order_and_count():
    assert len(FEATURE_NAMES) == 15
    expected_order = [
        "forward_packets",
        "backward_packets",
        "forward_bytes",
        "backward_bytes",
        "duration",
        "packet_ratio",
        "byte_ratio",
        "forward_packet_rate",
        "backward_packet_rate",
        "forward_byte_rate",
        "backward_byte_rate",
        "is_tcp",
        "is_udp",
        "is_icmp",
        "avg_packet_size",
    ]
    assert FEATURE_NAMES == expected_order


def test_extract_flow_features_correct_values():
    flow = {
        "forward_packets": 10,
        "backward_packets": 10,
        "forward_bytes": 1000,
        "backward_bytes": 2000,
        "duration": 2.0,
        "protocol": "TCP",
    }
    feats = extract_flow_features(flow)
    assert isinstance(feats, np.ndarray)
    assert feats.shape == (15,)
    assert feats.dtype == np.float64

    # Check specific indices
    assert feats[0] == 10.0   # forward_packets
    assert feats[1] == 10.0   # backward_packets
    assert feats[2] == 1000.0 # forward_bytes
    assert feats[3] == 2000.0 # backward_bytes
    assert feats[4] == 2.0    # duration
    assert feats[5] == 0.5    # packet_ratio (10 / 20)
    assert feats[6] == 1000.0 / 3000.0 # byte_ratio
    assert feats[7] == 5.0    # forward_packet_rate (10 / 2.0)
    assert feats[8] == 5.0    # backward_packet_rate (10 / 2.0)
    assert feats[9] == 500.0  # forward_byte_rate (1000 / 2.0)
    assert feats[10] == 1000.0 # backward_byte_rate (2000 / 2.0)
    assert feats[11] == 1.0   # is_tcp
    assert feats[12] == 0.0   # is_udp
    assert feats[13] == 0.0   # is_icmp
    assert feats[14] == 150.0 # avg_packet_size (3000 / 20)


def test_zero_duration_and_edge_cases():
    # Flow with 0.0 duration and missing reverse traffic (typical port scan probe)
    flow = {
        "forward_packets": 1,
        "backward_packets": 0,
        "forward_bytes": 60,
        "backward_bytes": 0,
        "duration": 0.0,
        "protocol": "TCP",
    }
    feats = extract_flow_features(flow)
    assert np.all(np.isfinite(feats)), "All features must be finite numbers"
    assert feats[4] == 0.0  # duration
    assert feats[5] == 1.0  # packet_ratio is 1.0
    assert feats[6] == 1.0  # byte_ratio is 1.0
    # Rates should use the epsilon duration floor (1e-3s)
    assert feats[7] == 1000.0  # 1 / 1e-3
    assert feats[8] == 0.0     # 0 / 1e-3


def test_safe_float_sanitization():
    assert _safe_float(float("nan"), 0.0) == 0.0
    assert _safe_float(float("inf"), 0.0) == 0.0
    assert _safe_float("invalid", 42.0) == 42.0
    assert _safe_float(123.45) == 123.45


def test_extract_batch_features_dimensions():
    flows = [
        {"forward_packets": 2, "backward_packets": 2, "forward_bytes": 100, "backward_bytes": 100, "duration": 1.0, "protocol": "UDP"},
        {"forward_packets": 1, "backward_packets": 1, "forward_bytes": 64, "backward_bytes": 64, "duration": 0.05, "protocol": "ICMP"},
    ]
    batch = extract_batch_features(flows)
    assert batch.shape == (2, 15)

    empty_batch = extract_batch_features([])
    assert empty_batch.shape == (0, 15)


# --- 2. Training Workflow & Serialization Tests ---

def test_model_training_and_serialization(tmp_path):
    model_path = tmp_path / "test_iso_forest.joblib"
    metadata_path = tmp_path / "test_metadata.json"

    model, meta = train_isolation_forest_model(
        num_samples=200,
        random_seed=42,
        model_path=model_path,
        metadata_path=metadata_path,
    )

    assert model_path.exists()
    assert metadata_path.exists()
    assert meta["random_seed"] == 42
    assert meta["training_data"]["sample_count"] == 200
    assert len(meta["feature_schema"]) == 15
    assert "baseline_feature_stats" in meta

    # Test loading using AnomalyDetector
    detector = AnomalyDetector(model_path=model_path, metadata_path=metadata_path)
    assert detector.is_ready is True
    assert detector.feature_means is not None
    assert detector.feature_stds is not None


# --- 3. Anomaly Scoring and Feature Attribution Tests ---

def test_anomaly_scoring_and_attribution():
    detector = AnomalyDetector()
    assert detector.is_ready is True

    # 1. Normal benign web browsing flow
    normal_flow = {
        "forward_packets": 6,
        "backward_packets": 12,
        "forward_bytes": 600,
        "backward_bytes": 14000,
        "duration": 1.5,
        "protocol": "TCP",
    }
    score, is_anomaly, attrib = detector.score_flow(normal_flow)
    assert 0.0 <= score <= 1.0
    assert is_anomaly == 0
    assert score < 0.50

    # 2. Extreme anomalous flow: huge volumetric burst in tiny duration
    anomalous_flow = {
        "forward_packets": 2000,
        "backward_packets": 0,
        "forward_bytes": 1500000,
        "backward_bytes": 0,
        "duration": 0.005,
        "protocol": "TCP",
    }
    a_score, a_is_anomaly, a_attrib = detector.score_flow(anomalous_flow)
    assert 0.0 <= a_score <= 1.0
    assert a_is_anomaly == 1
    assert a_score >= 0.50
    # Feature attribution should identify top outlier features
    assert "top_deviations" in a_attrib
    assert len(a_attrib["top_deviations"]) > 0


def test_graceful_handling_when_model_unavailable(tmp_path):
    missing_path = tmp_path / "non_existent.joblib"
    detector = AnomalyDetector(model_path=missing_path)
    assert detector.is_ready is False

    score, is_anomaly, attrib = detector.score_flow({"forward_packets": 1})
    assert score == 0.0
    assert is_anomaly == 0
    assert attrib == {"status": "model_unavailable"}

    batch_res = detector.score_batch([{"forward_packets": 1}])
    assert len(batch_res) == 1
    assert batch_res[0] == (0.0, 0, {"status": "model_unavailable"})


# --- 4. End-to-End Ingestion & API Persistence Tests ---

def test_pcap_upload_populates_real_anomaly_scores(client, db_session):
    """Verify that uploading a PCAP runs Isolation Forest and persists real scores."""
    pkts = [
        # Normal 3-way handshake + data
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src="192.168.1.100", dst="10.0.0.5") / TCP(sport=50000, dport=80, flags="S"),
        Ether(src="02:00:00:00:00:02", dst="02:00:00:00:00:01") / IP(src="10.0.0.5", dst="192.168.1.100") / TCP(sport=80, dport=50000, flags="SA"),
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src="192.168.1.100", dst="10.0.0.5") / TCP(sport=50000, dport=80, flags="A"),
    ]

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        wrpcap(f.name, pkts)
        f.seek(0)
        with open(f.name, "rb") as read_f:
            pcap_bytes = read_f.read()

    res = client.post(
        "/api/pcaps/upload",
        files={"file": ("ml_test.pcap", pcap_bytes, "application/octet-stream")},
    )
    assert res.status_code == 201
    pcap_id = res.json()["id"]

    # Verify flow record in database
    flow = db_session.query(NetworkFlow).filter(NetworkFlow.pcap_id == pcap_id).first()
    assert flow is not None
    # Anomaly score should be populated by the loaded model (> 0.0)
    assert flow.anomaly_score > 0.0
    assert flow.is_anomaly in (0, 1)
    assert isinstance(json.loads(flow.anomaly_features_json), dict)

    # Verify query via API
    api_res = client.get(f"/api/flows?pcap_id={pcap_id}")
    assert api_res.status_code == 200
    flow_item = api_res.json()["items"][0]
    assert flow_item["anomaly_score"] == flow.anomaly_score
    assert flow_item["is_anomaly"] == flow.is_anomaly


def test_flows_api_only_anomalies_filter(client, db_session):
    """Test filtering flows by only_anomalies in the API."""
    # Seed 2 flows: one normal, one anomalous
    flow_normal = NetworkFlow(
        pcap_id=999,
        flow_key="1.1.1.1:1-2.2.2.2:2-TCP",
        src_ip="1.1.1.1",
        dst_ip="2.2.2.2",
        src_port=1,
        dst_port=2,
        protocol="TCP",
        ip_version=4,
        start_time=100.0,
        end_time=101.0,
        duration=1.0,
        forward_packets=10,
        backward_packets=10,
        forward_bytes=500,
        backward_bytes=500,
        total_packets=20,
        total_bytes=1000,
        anomaly_score=0.25,
        is_anomaly=0,
    )
    flow_anomaly = NetworkFlow(
        pcap_id=999,
        flow_key="3.3.3.3:3-4.4.4.4:4-TCP",
        src_ip="3.3.3.3",
        dst_ip="4.4.4.4",
        src_port=3,
        dst_port=4,
        protocol="TCP",
        ip_version=4,
        start_time=100.0,
        end_time=100.01,
        duration=0.01,
        forward_packets=500,
        backward_packets=0,
        forward_bytes=50000,
        backward_bytes=0,
        total_packets=500,
        total_bytes=50000,
        anomaly_score=0.82,
        is_anomaly=1,
    )
    db_session.add_all([flow_normal, flow_anomaly])
    db_session.commit()

    # Query all flows
    all_res = client.get("/api/flows?pcap_id=999")
    assert all_res.status_code == 200
    assert all_res.json()["total"] == 2

    # Query only anomalies
    anom_res = client.get("/api/flows?pcap_id=999&only_anomalies=true")
    assert anom_res.status_code == 200
    assert anom_res.json()["total"] == 1
    assert anom_res.json()["items"][0]["src_ip"] == "3.3.3.3"
    assert anom_res.json()["items"][0]["is_anomaly"] == 1
