"""Regression tests for PCAP transfer adapter and feature transforms.

Ensures strict mathematical correctness of the semantic adapter, log1p transform,
and pipeline isolation.
"""

import hashlib
import json
from pathlib import Path
import numpy as np
import pytest

from experiments.cic_ids2017.evaluate_pcap_transfer import (
    adapt_pcap_flow_to_payload,
    apply_log1p_transform,
    SKEWED_INDICES,
)
from backend.app.pipeline.ml.features import FEATURE_NAMES, extract_flow_features

BASE_DIR = Path(__file__).resolve().parent.parent.parent


def test_adapt_pcap_flow_to_payload_tcp():
    """Verify that TCP payload adapter subtracts 40 bytes per packet."""
    raw_flow = {
        "duration": 2.5,
        "protocol": "TCP",
        "forward_packets": 10,
        "backward_packets": 5,
        "forward_bytes": 1000,  # 1000 - 10*40 = 600
        "backward_bytes": 500,  # 500 - 5*40 = 300
        "flow_packet_rate": 6.0,
        "flow_byte_rate": 600.0,
        "avg_packet_size": 100.0,
        "packet_length_variance": 50.0,
        "fwd_bwd_ratio": 2.0,
        "fwd_pkt_len_mean": 100.0,
        "bwd_pkt_len_mean": 100.0,
        "is_tcp": 1,
        "is_udp": 0,
        "is_icmp": 0,
    }

    adapted_feats = adapt_pcap_flow_to_payload(raw_flow)
    assert len(adapted_feats) == 15

    # Index 2 is forward_bytes, index 4 is backward_bytes
    idx_fwd = FEATURE_NAMES.index("forward_bytes")
    idx_bwd = FEATURE_NAMES.index("backward_bytes")

    assert adapted_feats[idx_fwd] == 600.0
    assert adapted_feats[idx_bwd] == 300.0


def test_adapt_pcap_flow_to_payload_udp_and_floor():
    """Verify UDP subtraction (28 bytes) and non-negative floor."""
    raw_flow = {
        "duration": 1.0,
        "protocol": "UDP",
        "forward_packets": 2,
        "backward_packets": 0,
        "forward_bytes": 40,  # 40 - 2*28 = -16 -> floored at 0
        "backward_bytes": 0,
        "flow_packet_rate": 2.0,
        "flow_byte_rate": 40.0,
        "avg_packet_size": 20.0,
        "packet_length_variance": 0.0,
        "fwd_bwd_ratio": 2.0,
        "fwd_pkt_len_mean": 20.0,
        "bwd_pkt_len_mean": 0.0,
        "is_tcp": 0,
        "is_udp": 1,
        "is_icmp": 0,
    }

    adapted_feats = adapt_pcap_flow_to_payload(raw_flow)
    idx_fwd = FEATURE_NAMES.index("forward_bytes")
    idx_bwd = FEATURE_NAMES.index("backward_bytes")

    assert adapted_feats[idx_fwd] == 0.0
    assert adapted_feats[idx_bwd] == 0.0


def test_apply_log1p_transform():
    """Verify log1p transform applied only to skewed indices."""
    X = np.array([
        [0.0, 10.0, 100.0, 5.0, 50.0, 0.5, 0.8, 10.0, 50.0, 20.0, 15.0, 1.0, 0.0, 0.0, 30.0]
    ])

    X_trans = apply_log1p_transform(X)

    for i in range(15):
        if i in SKEWED_INDICES:
            assert np.isclose(X_trans[0, i], np.log1p(X[0, i]))
        else:
            # Ratios and binary flags must be identical
            assert X_trans[0, i] == X[0, i]


def test_production_artifacts_unmodified():
    """Ensure production model artifacts and threat database were never touched."""
    prod_model = BASE_DIR / "data" / "models" / "isolation_forest.joblib"
    prod_meta = BASE_DIR / "data" / "models" / "model_metadata.json"

    assert prod_model.exists()
    assert prod_meta.exists()

    with open(prod_model, "rb") as f:
        model_sha = hashlib.sha256(f.read()).hexdigest()
    with open(prod_meta, "rb") as f:
        meta_sha = hashlib.sha256(f.read()).hexdigest()

    # Verified production SHA-256 hashes
    assert model_sha == "404dd5d8bc1cb714f14f7a49bddc6dc50a00a3edc29164e5767f2d69982d2da9"
    assert meta_sha == "2341207c4c0c785a3d0faaabe72f57c046f10081392301e855b6bb473a79110f"
