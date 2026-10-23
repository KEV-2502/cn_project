"""Tests for the Interactive Demo and Plotting Engine."""

from pathlib import Path
import numpy as np
import pytest

from experiments.cic_ids2017.demo_model import FlowInspector, CATEGORY_TO_FILE, ALL_ATTACK_CATEGORIES
from experiments.cic_ids2017.plot_results import (
    load_evaluation_metrics,
    plot_confusion_matrix,
    plot_score_distributions,
    plot_detection_rates,
    plot_composite_overview,
    REPORT_JSON_PATH,
)


def test_flow_inspector_initialization():
    zip_path = Path("data/datasets/GeneratedLabelledFlows.zip")
    inspector = FlowInspector(zip_path)
    assert inspector.detector.is_ready is True
    assert inspector.threshold == 0.50
    assert len(ALL_ATTACK_CATEGORIES) == 14


def test_flow_inspector_evaluation_verdicts():
    zip_path = Path("data/datasets/GeneratedLabelledFlows.zip")
    inspector = FlowInspector(zip_path)

    # 1. Normal benign flow mock
    normal_row = {
        "Flow ID": "test-benign-1",
        "Source IP": "192.168.1.10",
        "Destination IP": "8.8.8.8",
        "Source Port": "50000",
        "Destination Port": "53",
        "Protocol": "17",
        "Total Fwd Packets": "1",
        "Total Backward Packets": "1",
        "Total Length of Fwd Packets": "48",
        "Total Length of Bwd Packets": "48",
        "Flow Duration": "20000",
    }
    benign_eval = inspector.evaluate_flow(normal_row, label="BENIGN")
    assert benign_eval["verdict"] in ("TN", "FP")
    assert "metrics" in benign_eval
    assert benign_eval["metrics"]["forward_packets"] == 1
    assert benign_eval["metrics"]["backward_packets"] == 1
    assert benign_eval["metrics"]["forward_bytes"] == 48

    # 2. Extreme anomalous flow mock (Heartbleed-style volumetric exfiltration)
    extreme_row = {
        "Flow ID": "test-extreme-1",
        "Source IP": "172.16.0.1",
        "Destination IP": "192.168.10.51",
        "Source Port": "45000",
        "Destination Port": "444",
        "Protocol": "6",
        "Total Fwd Packets": "3000",
        "Total Backward Packets": "2500",
        "Total Length of Fwd Packets": "15000",
        "Total Length of Bwd Packets": "8000000",
        "Flow Duration": "120000000",
    }
    attack_eval = inspector.evaluate_flow(extreme_row, label="Heartbleed")
    assert attack_eval["verdict"] == "TP"
    assert attack_eval["score"] >= 0.50
    assert "top_deviations" in attack_eval.get("attribution", {}) or len(attack_eval.get("attribution", {})) > 0


def test_visual_plots_generation(tmp_path):
    # Verify that load_evaluation_metrics loads existing report
    data = load_evaluation_metrics(REPORT_JSON_PATH)
    assert "confusion_matrix" in data
    assert "overall_metrics" in data
    assert "per_class_results" in data

    # Test plotting functions into tmp_path
    cm_path = plot_confusion_matrix(data, tmp_path / "cm.png")
    dist_path = plot_score_distributions(data, tmp_path / "dist.png")
    det_path = plot_detection_rates(data, tmp_path / "det.png")
    comp_path = plot_composite_overview(data, tmp_path / "comp.png")

    assert cm_path.exists()
    assert dist_path.exists()
    assert det_path.exists()
    assert comp_path.exists()
    assert cm_path.stat().st_size > 1000
    assert comp_path.stat().st_size > 1000
