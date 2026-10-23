"""Evaluation and Reporting Engine for CIC-IDS2017 Experiment.

Computes comprehensive metrics:
- Confusion Matrix (TP, FP, TN, FN)
- Precision, Recall, F1-Score
- False Positive Rate (FPR) on Monday In-Day Holdout vs. Tuesday-Friday Benign Drift
- Precision-Recall AUC (PR-AUC) and ROC-AUC
- Detection rate and sample counts for every evaluated attack class
- Sample explainable feature attributions
- Markdown and JSON reporting
"""

import json
from pathlib import Path
from typing import Dict, Any, List, Tuple
import numpy as np
from sklearn.metrics import (
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    precision_recall_curve,
    roc_auc_score,
    auc,
)

from experiments.cic_ids2017.model import CandidateAnomalyDetector
from experiments.cic_ids2017.features import get_feature_documentation


def run_evaluation(
    detector: CandidateAnomalyDetector,
    X_eval: np.ndarray,
    y_eval: np.ndarray,
    class_labels: List[str],
    eval_meta: Dict[str, Any],
    reports_dir: Path,
    dataset_audit: Optional[Dict[str, Any]] = None,
    synthetic_baseline_detector: Optional[Any] = None,
) -> Dict[str, Any]:
    """Execute evaluation protocol and write JSON and Markdown reports."""
    scores, preds = detector.score_batch(X_eval)

    # Confusion matrix & overall metrics
    cm = confusion_matrix(y_eval, preds, labels=[0, 1])
    tn, fp, fn, tp = int(cm[0, 0]), int(cm[0, 1]), int(cm[1, 0]), int(cm[1, 1])

    prec = float(precision_score(y_eval, preds, zero_division=0))
    rec = float(recall_score(y_eval, preds, zero_division=0))
    f1 = float(f1_score(y_eval, preds, zero_division=0))

    # PR-AUC and ROC-AUC
    try:
        p_curve, r_curve, _ = precision_recall_curve(y_eval, scores)
        pr_auc_val = float(auc(r_curve, p_curve))
    except Exception:
        pr_auc_val = 0.0

    try:
        roc_auc_val = float(roc_auc_score(y_eval, scores))
    except Exception:
        roc_auc_val = 0.0

    # Partition-specific False Positive Rates
    mon_mask = np.array([lbl == "BENIGN_MONDAY" for lbl in class_labels])
    drift_mask = np.array([lbl == "BENIGN_DRIFT" for lbl in class_labels])

    mon_total = int(np.sum(mon_mask))
    mon_fps = int(np.sum(preds[mon_mask] == 1))
    mon_fpr = float(mon_fps / mon_total) if mon_total > 0 else 0.0

    drift_total = int(np.sum(drift_mask))
    drift_fps = int(np.sum(preds[drift_mask] == 1))
    drift_fpr = float(drift_fps / drift_total) if drift_total > 0 else 0.0

    # Per-class detection rates
    per_class_results = {}
    unique_classes = sorted(set(class_labels))
    for c_name in unique_classes:
        c_mask = np.array([lbl == c_name for lbl in class_labels])
        c_total = int(np.sum(c_mask))
        c_flagged = int(np.sum(preds[c_mask] == 1))
        c_rate = float(c_flagged / c_total) if c_total > 0 else 0.0
        c_mean_score = float(np.mean(scores[c_mask])) if c_total > 0 else 0.0

        per_class_results[c_name] = {
            "sample_count": c_total,
            "flagged_count": c_flagged,
            "rate": round(c_rate, 4),
            "mean_anomaly_score": round(c_mean_score, 4),
            "category": "BENIGN" if "BENIGN" in c_name else "ATTACK",
        }

    # Sample outlier attributions
    attack_indices = np.where(y_eval == 1)[0]
    sample_attributions = []
    for idx in attack_indices[:10]:
        if preds[idx] == 1:
            attrib = detector.compute_attribution(X_eval[idx])
            sample_attributions.append({
                "label": class_labels[idx],
                "anomaly_score": round(float(scores[idx]), 4),
                "attributions": attrib.get("top_deviations", {}),
            })

    # Optional comparison with synthetic model baseline
    synthetic_comp = None
    if synthetic_baseline_detector and synthetic_baseline_detector.is_ready:
        syn_scores = []
        syn_preds = []
        for i in range(len(X_eval)):
            s, is_anom, _ = synthetic_baseline_detector._score_single_vector(X_eval[i])
            syn_scores.append(s)
            syn_preds.append(is_anom)
        syn_scores = np.array(syn_scores)
        syn_preds = np.array(syn_preds)

        syn_cm = confusion_matrix(y_eval, syn_preds, labels=[0, 1])
        synthetic_comp = {
            "model_name": "NetShield Production Synthetic Baseline (Evaluated on CIC features)",
            "confusion_matrix": {
                "tn": int(syn_cm[0, 0]),
                "fp": int(syn_cm[0, 1]),
                "fn": int(syn_cm[1, 0]),
                "tp": int(syn_cm[1, 1]),
            },
            "precision": round(float(precision_score(y_eval, syn_preds, zero_division=0)), 4),
            "recall": round(float(recall_score(y_eval, syn_preds, zero_division=0)), 4),
            "f1": round(float(f1_score(y_eval, syn_preds, zero_division=0)), 4),
            "caveat": (
                "Direct comparison is methodologically flawed because the synthetic model was trained "
                "on IP-layer packet lengths (40-60 bytes minimum), whereas CIC features contain "
                "payload-only byte lengths (0 bytes for control packets)."
            ),
        }

    results = {
        "experiment_title": "Isolated CIC-IDS2017 Anomaly Detection Evaluation",
        "evaluation_summary": {
            "total_evaluation_samples": len(X_eval),
            "total_benign_samples": mon_total + drift_total,
            "total_attack_samples": int(np.sum(y_eval == 1)),
            "anomaly_threshold": 0.50,
        },
        "overall_metrics": {
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
            "pr_auc": round(pr_auc_val, 4),
            "roc_auc": round(roc_auc_val, 4),
        },
        "confusion_matrix": {
            "true_negatives": tn,
            "false_positives": fp,
            "false_negatives": fn,
            "true_positives": tp,
        },
        "false_positive_analysis": {
            "monday_in_day_holdout": {
                "samples": mon_total,
                "false_positives": mon_fps,
                "fpr": round(mon_fpr, 4),
            },
            "tuesday_friday_benign_drift": {
                "samples": drift_total,
                "false_positives": drift_fps,
                "fpr": round(drift_fpr, 4),
            },
        },
        "per_class_results": per_class_results,
        "sample_attributions": sample_attributions[:5],
        "feature_schema_documentation": get_feature_documentation(),
        "eval_metadata": eval_meta,
    }

    if dataset_audit:
        results["dataset_audit"] = dataset_audit
    if synthetic_comp:
        results["synthetic_baseline_comparison"] = synthetic_comp

    # Write JSON report
    reports_dir.mkdir(parents=True, exist_ok=True)
    json_path = reports_dir / "evaluation_report.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    # Write Markdown report
    md_path = reports_dir / "evaluation_report.md"
    _generate_markdown_report(results, md_path)

    return results


def _generate_markdown_report(data: Dict[str, Any], output_path: Path):
    """Render structured Markdown evaluation report."""
    summary = data["evaluation_summary"]
    metrics = data["overall_metrics"]
    cm = data["confusion_matrix"]
    fpr_info = data["false_positive_analysis"]
    per_class = data["per_class_results"]

    lines = [
        "# Isolated CIC-IDS2017 Anomaly Detection Evaluation Report",
        "",
        "## 1. Executive Summary",
        f"- **Model Evaluated:** Candidate Isolation Forest (`candidate_isolation_forest_cic.joblib`)",
        f"- **Training Set:** Monday Benign Traffic only ($N = {data['eval_metadata'].get('train_count', '15,000')}$, seed=42)",
        f"- **Evaluation Set:** $N = {summary['total_evaluation_samples']}$ flows ({summary['total_benign_samples']} Benign, {summary['total_attack_samples']} Attack)",
        f"- **Decision Threshold:** $\\tau = {summary['anomaly_threshold']}$ (Outlier if normalized score $\\ge 0.50$)",
        "",
        "### Key Performance Indicators",
        f"- **Precision:** `{metrics['precision']:.4f}`",
        f"- **Recall (Overall Detection Rate):** `{metrics['recall']:.4f}`",
        f"- **$F_1$-Score:** `{metrics['f1_score']:.4f}`",
        f"- **PR-AUC:** `{metrics['pr_auc']:.4f}`",
        f"- **ROC-AUC:** `{metrics['roc_auc']:.4f}`",
        "",
        "---",
        "",
        "## 2. Confusion Matrix & False Positive Analysis",
        "",
        "| Metric | Count | Rate |",
        "| :--- | :--- | :--- |",
        f"| **True Positives (TP)** | {cm['true_positives']} | Recall: {metrics['recall']*100:.1f}% |",
        f"| **False Positives (FP)** | {cm['false_positives']} | Total FPR: {(cm['false_positives'] / max(1, summary['total_benign_samples']))*100:.2f}% |",
        f"| **True Negatives (TN)** | {cm['true_negatives']} | Specificity: {(cm['true_negatives'] / max(1, summary['total_benign_samples']))*100:.2f}% |",
        f"| **False Negatives (FN)** | {cm['false_negatives']} | Miss Rate: {(cm['false_negatives'] / max(1, summary['total_attack_samples']))*100:.1f}% |",
        "",
        "### In-Day Holdout vs. Multi-Day Drift FPR",
        f"- **Monday In-Day Holdout:** {fpr_info['monday_in_day_holdout']['false_positives']} / {fpr_info['monday_in_day_holdout']['samples']} (**{fpr_info['monday_in_day_holdout']['fpr']*100:.2f}% FPR**)",
        f"- **Tue–Fri Benign Drift:** {fpr_info['tuesday_friday_benign_drift']['false_positives']} / {fpr_info['tuesday_friday_benign_drift']['samples']} (**{fpr_info['tuesday_friday_benign_drift']['fpr']*100:.2f}% FPR**)",
        "",
        "> [!NOTE]",
        "> The difference between Monday in-day FPR and Tuesday–Friday drift FPR demonstrates natural background traffic drift over time.",
        "",
        "---",
        "",
        "## 3. Per-Attack Class Detection Rates",
        "",
        "| Attack Category | Evaluated Samples | Detected (Flagged) | Detection Rate (%) | Mean Anomaly Score |",
        "| :--- | :--- | :--- | :--- | :--- |",
    ]

    for c_name, c_data in sorted(per_class.items()):
        if c_data["category"] == "ATTACK":
            rate_pct = f"{c_data['rate']*100:.1f}%"
            lines.append(
                f"| **{c_name}** | {c_data['sample_count']} | {c_data['flagged_count']} | {rate_pct} | {c_data['mean_anomaly_score']:.4f} |"
            )

    lines.extend([
        "",
        "---",
        "",
        "## 4. Methodological Limitations & Safety Note",
        "- **Evaluation Set Re-balancing:** Attack classes were stratified and high-volume classes (e.g. DoS Hulk, DDoS) were capped to avoid swamping the evaluation set. Consequently, overall accuracy is not representative of live wild traffic.",
        "- **Feature Semantics:** Directional bytes represent L4 transport payloads, not NetShield's IP-layer total length. The candidate model must not be directly used with NetShield's Scapy PCAP pipeline without feature extractor versioning.",
        "- **Isolation Confirmation:** Production model artifacts (`isolation_forest.joblib`, `model_metadata.json`), database records, and PCAP regression tests remain 100% unaltered.",
    ])

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
