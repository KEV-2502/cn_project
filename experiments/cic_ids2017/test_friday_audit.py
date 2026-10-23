"""Regression tests for Friday evaluation audit."""

import hashlib
import json
from pathlib import Path
import pytest

BASE_DIR = Path(__file__).resolve().parent.parent.parent
REPORTS_DIR = BASE_DIR / "experiments" / "cic_ids2017" / "reports"
AUDIT_JSON_PATH = REPORTS_DIR / "friday_evaluation_audit.json"


def test_audit_json_report_exists_and_valid():
    """Verify audit JSON report exists and contains required sections."""
    assert AUDIT_JSON_PATH.exists(), f"Missing audit report at {AUDIT_JSON_PATH}"
    with open(AUDIT_JSON_PATH) as f:
        data = json.load(f)

    assert "audit_metadata" in data
    assert "ground_truth_tier_quantification" in data
    assert "rule_engine_reconciliation" in data
    assert "benign_overlap_investigation" in data
    assert "audited_detector_metrics" in data


def test_audit_mathematical_identities():
    """Verify that confusion matrix sums to total evaluated flows across all detectors."""
    with open(AUDIT_JSON_PATH) as f:
        data = json.load(f)

    total_flows = data["audit_metadata"]["total_flows_audited"]
    metrics = data["audited_detector_metrics"]

    for dname, dstats in metrics.items():
        cm = dstats["confusion_matrix"]
        tn, fp, fn, tp = cm["tn"], cm["fp"], cm["fn"], cm["tp"]
        assert tn + fp + fn + tp == total_flows, f"Detector {dname} sum mismatch: {tn+fp+fn+tp} != {total_flows}"
        assert abs((dstats["specificity"] + dstats["fpr"]) - 1.0) < 1e-4, f"Specificity + FPR != 1.0 in {dname}"
        assert abs((dstats["recall"] + dstats["fnr"]) - 1.0) < 1e-4, f"Recall + FNR != 1.0 in {dname}"


def test_rule_reconciliation_total_flows():
    """Verify unique flow count reconciled across 65 alerts."""
    with open(AUDIT_JSON_PATH) as f:
        data = json.load(f)

    r_rec = data["rule_engine_reconciliation"]
    assert r_rec["total_threat_alerts_generated"] == 65
    assert r_rec["total_unique_flows_flagged"] == 13532


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
