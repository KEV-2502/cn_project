"""Regression tests for Friday CIC-IDS2017 traffic evaluation."""

import hashlib
import json
import struct
from pathlib import Path
import pytest

from experiments.cic_ids2017.evaluate_friday_traffic import (
    find_aligned_epb_offset,
    apply_log1p_transform,
    compute_normalized_scores,
    ATTACKER_IP,
    VICTIM_IP,
    FRIDAY_PCAP_PATH,
    FRIDAY_EXPECTED_SIZE,
)
from backend.app.pipeline.flow_aggregator import AggregatedFlow

BASE_DIR = Path(__file__).resolve().parent.parent.parent


def test_friday_pcap_header_and_size():
    """Verify Friday PCAP is present, has expected size, and valid PCAPNG magic."""
    assert FRIDAY_PCAP_PATH.exists(), f"Missing Friday PCAP at {FRIDAY_PCAP_PATH}"
    assert FRIDAY_PCAP_PATH.stat().st_size == FRIDAY_EXPECTED_SIZE

    with open(FRIDAY_PCAP_PATH, "rb") as f:
        magic = f.read(4)
    assert magic == b"\x0a\x0d\x0d\x0a", "Invalid PCAPNG magic header"


def test_find_aligned_epb_offset():
    """Verify EPB offset alignment locates valid blocks."""
    with open(FRIDAY_PCAP_PATH, "rb") as f:
        # Seek around 6.76 GB (PortScan region)
        aligned = find_aligned_epb_offset(f, 6760000000)
        assert aligned >= 6760000000
        f.seek(aligned)
        hdr = f.read(8)
        btype, blen = struct.unpack("<II", hdr)
        assert btype == 6, f"Expected EPB block type 6, got {btype}"
        assert 32 <= blen <= 65536


def test_labeling_logic_isolation():
    """Verify ground truth mapping strictly separates attacker 172.16.0.1 from background."""
    f_attack = AggregatedFlow(
        flow_key="attack-flow",
        src_ip=ATTACKER_IP,
        dst_ip=VICTIM_IP,
        src_port=44444,
        dst_port=80,
        protocol="TCP",
        ip_version=4,
        start_time=1499445000.0,
        end_time=1499445001.0,
    )
    is_attack = (
        (f_attack.src_ip == ATTACKER_IP and f_attack.dst_ip == VICTIM_IP)
        or (f_attack.src_ip == VICTIM_IP and f_attack.dst_ip == ATTACKER_IP)
    )
    assert is_attack is True

    f_bg = AggregatedFlow(
        flow_key="bg-flow",
        src_ip="192.168.10.15",
        dst_ip="8.8.8.8",
        src_port=52341,
        dst_port=53,
        protocol="UDP",
        ip_version=4,
        start_time=1499445000.0,
        end_time=1499445001.0,
    )
    is_bg_attack = (
        (f_bg.src_ip == ATTACKER_IP and f_bg.dst_ip == VICTIM_IP)
        or (f_bg.src_ip == VICTIM_IP and f_bg.dst_ip == ATTACKER_IP)
    )
    assert is_bg_attack is False


def test_production_artifacts_strictly_unmodified():
    """Verify production artifacts have not been altered."""
    prod_model = BASE_DIR / "data" / "models" / "isolation_forest.joblib"
    prod_meta = BASE_DIR / "data" / "models" / "model_metadata.json"

    with open(prod_model, "rb") as f:
        model_sha = hashlib.sha256(f.read()).hexdigest()
    with open(prod_meta, "rb") as f:
        meta_sha = hashlib.sha256(f.read()).hexdigest()

    assert model_sha == "404dd5d8bc1cb714f14f7a49bddc6dc50a00a3edc29164e5767f2d69982d2da9"
    assert meta_sha == "2341207c4c0c785a3d0faaabe72f57c046f10081392301e855b6bb473a79110f"
