#!/usr/bin/env python3
"""Main Entrypoint for the Isolated CIC-IDS2017 ML Evaluation Experiment.

Orchestrates streaming data auditing, day-separated sampling, candidate model fitting,
evaluation metrics calculation, and report generation.

Strict Isolation:
- Does NOT alter production models or database.
- Candidate artifacts saved exclusively to data/models/candidate_*.
- Reports saved to experiments/cic_ids2017/reports/.
"""

import sys
import time
import os
from pathlib import Path

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(BASE_DIR))

from experiments.cic_ids2017.data_loader import CICDatasetStreamer
from experiments.cic_ids2017.sampler import ExperimentSampler
from experiments.cic_ids2017.model import (
    CandidateAnomalyDetector,
    DEFAULT_CANDIDATE_MODEL_PATH,
    DEFAULT_CANDIDATE_METADATA_PATH,
)
from experiments.cic_ids2017.evaluate import run_evaluation
from backend.app.pipeline.ml.model import AnomalyDetector as ProductionDetector


def main():
    print("=" * 70)
    print("NetShield Isolated CIC-IDS2017 Anomaly Detection Experiment")
    print("=" * 70)
    start_time = time.time()

    zip_path = BASE_DIR / "data" / "datasets" / "GeneratedLabelledFlows.zip"
    if not zip_path.exists():
        print(f"ERROR: Dataset archive not found at: {zip_path}")
        sys.exit(1)

    reports_dir = BASE_DIR / "experiments" / "cic_ids2017" / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    # 1. Initialize Streamer & Sampler
    print("\n[Step 1/4] Initializing streaming dataset reader & day-separated sampler...")
    streamer = CICDatasetStreamer(zip_path)
    csv_files = streamer.get_csv_filenames()
    print(f"Found {len(csv_files)} CSV files in ZIP archive.")

    sampler = ExperimentSampler(
        streamer=streamer,
        random_seed=42,
        max_train_samples=15000,
        max_monday_eval_samples=5000,
        max_drift_eval_samples=5000,
    )

    # 2. Sample Monday Training and Holdout Sets
    print("\n[Step 2/4] Sampling Monday verified benign flows for training and holdout...")
    t0 = time.time()
    X_train, X_eval_mon, monday_meta = sampler.sample_monday_partitions()
    print(f"  Training samples (Monday Benign): {len(X_train)}")
    print(f"  In-Day Holdout samples (Monday Benign): {len(X_eval_mon)}")
    print(f"  Partitioning time: {time.time() - t0:.2f}s")

    # 3. Train Candidate Model (Fit strictly on Monday pure benign)
    print("\n[Step 3/4] Fitting Candidate Isolation Forest on Monday benign baseline...")
    t0 = time.time()
    candidate_detector = CandidateAnomalyDetector(
        model_path=DEFAULT_CANDIDATE_MODEL_PATH,
        metadata_path=DEFAULT_CANDIDATE_METADATA_PATH,
    )
    model, metadata = candidate_detector.train(
        X_train=X_train,
        random_seed=42,
        contamination=0.01,
        n_estimators=100,
        extra_meta=monday_meta,
    )
    print(f"  Model trained in {time.time() - t0:.2f}s")
    print(f"  Saved candidate artifact to: {DEFAULT_CANDIDATE_MODEL_PATH}")
    print(f"  Saved candidate metadata to: {DEFAULT_CANDIDATE_METADATA_PATH}")

    # 4. Stream Evaluation Set (Tuesday-Friday Drift + All Attack Categories)
    print("\n[Step 4/4] Streaming evaluation set (Tuesday-Friday Drift + Stratified Attacks)...")
    t0 = time.time()
    X_eval, y_eval, class_labels, eval_meta = sampler.sample_evaluation_set(X_eval_mon)
    eval_meta["train_count"] = len(X_train)
    print(f"  Total evaluation flows assembled: {len(X_eval)}")
    print(f"  Benign evaluation flows: {eval_meta['total_benign_samples']} ({eval_meta['monday_benign_holdout_samples']} Mon + {eval_meta['drift_benign_samples']} Tue-Fri)")
    print(f"  Attack evaluation flows: {eval_meta['total_attack_samples']}")
    print(f"  Sampling time: {time.time() - t0:.2f}s")

    # Audit summary
    audit_summary = {}
    print("\nData Quality & Dropped Rows Summary across Streamed Files:")
    for fname, fstats in streamer.file_audits.items():
        short_name = fname.split("/")[-1]
        audit_summary[short_name] = {
            "total_raw_lines": fstats.total_raw_lines,
            "valid_records": fstats.valid_records_yielded,
            "empty_dropped": fstats.empty_lines_dropped,
            "malformed_dropped": fstats.malformed_rows_dropped,
            "exact_duplicates": fstats.exact_duplicates_count,
            "negative_durations": fstats.negative_duration_count,
            "zero_durations": fstats.zero_duration_count,
            "nan_inf_rows": fstats.nan_inf_rows_count,
            "exclusion_reasons": fstats.exclusion_reasons,
        }
        print(f"  {short_name:<48} | Valid: {fstats.valid_records_yielded:>6} | Empty Dropped: {fstats.empty_lines_dropped:>6} | Dups: {fstats.exact_duplicates_count:>3}")

    # Load synthetic production model for comparison baseline if available
    prod_detector = ProductionDetector()

    # Run Evaluation and Generate Reports
    print("\nScoring evaluation set and calculating performance metrics...")
    results = run_evaluation(
        detector=candidate_detector,
        X_eval=X_eval,
        y_eval=y_eval,
        class_labels=class_labels,
        eval_meta=eval_meta,
        reports_dir=reports_dir,
        dataset_audit=audit_summary,
        synthetic_baseline_detector=prod_detector,
    )

    total_time = time.time() - start_time
    print("\n" + "=" * 70)
    print("EXPERIMENT EXECUTION COMPLETED")
    print("=" * 70)
    print(f"Total Execution Time: {total_time:.2f}s")
    print(f"Overall Metrics (Threshold = 0.50):")
    print(f"  Precision: {results['overall_metrics']['precision']:.4f}")
    print(f"  Recall:    {results['overall_metrics']['recall']:.4f}")
    print(f"  F1-Score:  {results['overall_metrics']['f1_score']:.4f}")
    print(f"  PR-AUC:    {results['overall_metrics']['pr_auc']:.4f}")
    print(f"  ROC-AUC:   {results['overall_metrics']['roc_auc']:.4f}")
    print(f"False Positive Rates:")
    print(f"  Monday Holdout FPR:  {results['false_positive_analysis']['monday_in_day_holdout']['fpr']*100:.2f}% ({results['false_positive_analysis']['monday_in_day_holdout']['false_positives']}/{results['false_positive_analysis']['monday_in_day_holdout']['samples']})")
    print(f"  Tue-Fri Drift FPR:   {results['false_positive_analysis']['tuesday_friday_benign_drift']['fpr']*100:.2f}% ({results['false_positive_analysis']['tuesday_friday_benign_drift']['false_positives']}/{results['false_positive_analysis']['tuesday_friday_benign_drift']['samples']})")
    print(f"\nPer-Attack Category Detection Rates:")
    for c_name, c_res in sorted(results["per_class_results"].items()):
        if c_res["category"] == "ATTACK":
            print(f"  {c_name:<30}: {c_res['flagged_count']:>5}/{c_res['sample_count']:>5} ({c_res['rate']*100:>5.1f}%) | Mean Score: {c_res['mean_anomaly_score']:.4f}")

    print(f"\nReports successfully generated:")
    print(f"  JSON:     {reports_dir / 'evaluation_report.json'}")
    print(f"  Markdown: {reports_dir / 'evaluation_report.md'}")
    print("=" * 70)


if __name__ == "__main__":
    main()
