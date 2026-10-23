"""Controlled ML Comparison for NetShield CIC-IDS2017 Threat Detection.

Compares small, justified candidate models using existing leakage-free train/val/test partitions:
- Partitioning: Chronological splits from Monday-WorkingHours.pcap with 60s quarantine gaps.
  Train: 2,078 benign flows
  Val:   2,886 benign flows (used strictly for threshold calibration targeting <= 5.0% FPR)
  Test:  1,827 benign flows (Monday untouched benign test)
- Held-out evaluation: Friday-WorkingHours.pcap (14,351 flows: 1,741 benign, 10,325 PortScan, 2,285 DDoS)

Candidates compared:
1. Candidate 1 (Baseline): Isolation Forest + Log1p (all 15 features, contamination=0.01)
2. Candidate 2: Isolation Forest + Log1p + RobustScaler (all 15 features)
3. Candidate 3: Isolation Forest + Log1p (Rate & Structure Subset: 11 features, omitting raw byte totals)
4. Candidate 4: One-Class SVM (RBF kernel, nu=0.01, fitted on Train with Scaler)
5. Candidate 5: EllipticEnvelope (Robust Covariance / Mahalanobis Distance, contamination=0.01)
"""

import sys
import time
import json
from pathlib import Path
import numpy as np
import joblib

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler, RobustScaler
from sklearn.svm import OneClassSVM
from sklearn.covariance import EllipticEnvelope
from sklearn.metrics import (
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    precision_recall_curve,
    auc,
)

PROJECT_ROOT = Path("/home/kev/Projects/CN Project")
sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.pipeline.ml.features import extract_batch_features, FEATURE_NAMES
from experiments.cic_ids2017.evaluate_friday_traffic import (
    apply_log1p_transform,
    compute_normalized_scores,
)

# Load cached data
mon_parts = joblib.load(PROJECT_ROOT / "experiments/cic_ids2017/artifacts/pcap_model/monday_partitions.joblib")
batch_morning, batch_portscan, batch_ddos = joblib.load(PROJECT_ROOT / "experiments/cic_ids2017/artifacts/friday_flows.joblib")

# Monday partitions
train_flows = mon_parts.train_flows
val_flows = mon_parts.val_flows
test_flows = mon_parts.test_flows

X_mon_train_raw = extract_batch_features(train_flows)
X_mon_val_raw = extract_batch_features(val_flows)
X_mon_test_raw = extract_batch_features(test_flows)

X_mon_train_log = apply_log1p_transform(X_mon_train_raw)
X_mon_val_log = apply_log1p_transform(X_mon_val_raw)
X_mon_test_log = apply_log1p_transform(X_mon_test_raw)

# Friday flows
friday_all_flows = batch_morning.flows + batch_portscan.flows + batch_ddos.flows
total_friday = len(friday_all_flows)

ATTACKER_IP = "172.16.0.1"
VICTIM_IP = "192.168.10.50"
y_friday = []
labels_friday = []
for i, f in enumerate(friday_all_flows):
    is_atk = (f.src_ip == ATTACKER_IP and f.dst_ip == VICTIM_IP) or (f.src_ip == VICTIM_IP and f.dst_ip == ATTACKER_IP)
    if i < len(batch_morning.flows):
        labels_friday.append("BENIGN")
        y_friday.append(0)
    elif is_atk:
        labels_friday.append("PortScan" if i < len(batch_morning.flows) + len(batch_portscan.flows) else "DDoS")
        y_friday.append(1)
    else:
        labels_friday.append("BENIGN")
        y_friday.append(0)

y_friday_arr = np.array(y_friday)
labels_friday_arr = np.array(labels_friday)
morning_mask = np.array([i < len(batch_morning.flows) for i in range(total_friday)])

X_friday_raw = extract_batch_features(friday_all_flows)
X_friday_log = apply_log1p_transform(X_friday_raw)

# Candidate 3 Feature Subset: Exclude raw byte volume [2: forward_bytes, 3: backward_bytes]
# keep rates, ratios, packet counts, duration, protocol indicators, avg packet size
SUBSET_INDICES = [0, 1, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]
X_mon_train_subset = X_mon_train_log[:, SUBSET_INDICES]
X_mon_val_subset = X_mon_val_log[:, SUBSET_INDICES]
X_mon_test_subset = X_mon_test_log[:, SUBSET_INDICES]
X_friday_subset = X_friday_log[:, SUBSET_INDICES]

# Fit Scalers strictly on train
scaler_all = RobustScaler().fit(X_mon_train_log)
X_mon_train_scaled = scaler_all.transform(X_mon_train_log)
X_mon_val_scaled = scaler_all.transform(X_mon_val_log)
X_mon_test_scaled = scaler_all.transform(X_mon_test_log)
X_friday_scaled = scaler_all.transform(X_friday_log)

print("Training candidate models...")

# Model 1: Baseline Isolation Forest (Log1p)
m1_if_base = IsolationForest(n_estimators=100, contamination=0.01, random_state=42, max_samples="auto", n_jobs=-1)
m1_if_base.fit(X_mon_train_log)

# Model 2: Isolation Forest (Log1p + RobustScaler)
m2_if_scaled = IsolationForest(n_estimators=100, contamination=0.01, random_state=42, max_samples="auto", n_jobs=-1)
m2_if_scaled.fit(X_mon_train_scaled)

# Model 3: Isolation Forest (Log1p + Feature Subset)
m3_if_subset = IsolationForest(n_estimators=100, contamination=0.01, random_state=42, max_samples="auto", n_jobs=-1)
m3_if_subset.fit(X_mon_train_subset)

# Model 4: One-Class SVM (RBF kernel, nu=0.01) on RobustScaled features
m4_ocsvm = OneClassSVM(kernel="rbf", nu=0.01, gamma="scale")
m4_ocsvm.fit(X_mon_train_scaled)

# Model 5: EllipticEnvelope (Robust Covariance) on Scaled Subset
# Use subset of features to ensure full-rank covariance
EE_INDICES = [0, 1, 4, 5, 6, 7, 8, 14]
scaler_ee = RobustScaler().fit(X_mon_train_log[:, EE_INDICES])
m5_ee = EllipticEnvelope(contamination=0.01, random_state=42, support_fraction=0.85)
m5_ee.fit(scaler_ee.transform(X_mon_train_log[:, EE_INDICES]))

models = [
    ("M1: IsoForest (Log1p All 15)", m1_if_base, X_mon_val_log, X_mon_test_log, X_friday_log, "iforest"),
    ("M2: IsoForest (Log1p+Scaler)", m2_if_scaled, X_mon_val_scaled, X_mon_test_scaled, X_friday_scaled, "iforest"),
    ("M3: IsoForest (Log1p Subset 13)", m3_if_subset, X_mon_val_subset, X_mon_test_subset, X_friday_subset, "iforest"),
    ("M4: OneClassSVM (RBF nu=0.01)", m4_ocsvm, X_mon_val_scaled, X_mon_test_scaled, X_friday_scaled, "svm"),
    ("M5: EllipticEnv (Robust Cov)", m5_ee, scaler_ee.transform(X_mon_val_log[:, EE_INDICES]), scaler_ee.transform(X_mon_test_log[:, EE_INDICES]), scaler_ee.transform(X_friday_log[:, EE_INDICES]), "ee"),
]

def get_scores(model, X, m_type):
    if m_type == "iforest":
        raw = model.decision_function(X)
        return np.clip(0.5 - raw, 0.0, 1.0)
    elif m_type == "svm":
        # SVM decision_function: positive is inlier, negative is outlier
        raw = model.decision_function(X)
        # Normalize: higher is more anomalous
        # Sigmoid of -raw
        return 1.0 / (1.0 + np.exp(raw))
    elif m_type == "ee":
        # Mahalanobis distance
        dists = model.mahalanobis(X)
        # Normalized score
        return 1.0 - np.exp(-dists / 20.0)

results = []

target_val_fprs = [0.05, 0.02, 0.01]  # 5%, 2%, 1% validation FPR targets

for name, model, X_val, X_test, X_fri, m_type in models:
    # Validation scores (benign only)
    val_scores = get_scores(model, X_val, m_type)
    test_scores = get_scores(model, X_test, m_type)

    t0_inf = time.time()
    fri_scores = get_scores(model, X_fri, m_type)
    inf_time_ms = (time.time() - t0_inf) * 1000.0

    # ROC / PR AUC on Friday test set
    try:
        roc_auc = roc_auc_score(y_friday_arr, fri_scores)
    except Exception:
        roc_auc = 0.0
    try:
        p_c, r_c, _ = precision_recall_curve(y_friday_arr, fri_scores)
        pr_auc = auc(r_c, p_c)
    except Exception:
        pr_auc = 0.0

    # Calibrate thresholds on validation data ONLY
    for target_fpr in target_val_fprs:
        # Threshold is the (1 - target_fpr) quantile of validation scores
        thresh = float(np.quantile(val_scores, 1.0 - target_fpr))
        actual_val_fpr = float(np.mean(val_scores >= thresh))
        test_fpr = float(np.mean(test_scores >= thresh))

        fri_preds = (fri_scores >= thresh).astype(int)
        cm = confusion_matrix(y_friday_arr, fri_preds)
        tn, fp, fn, tp = int(cm[0, 0]), int(cm[0, 1]), int(cm[1, 0]), int(cm[1, 1])

        prec = precision_score(y_friday_arr, fri_preds, zero_division=0)
        rec = recall_score(y_friday_arr, fri_preds, zero_division=0)
        f1 = f1_score(y_friday_arr, fri_preds, zero_division=0)
        fri_fpr = fp / (tn + fp) if (tn + fp) > 0 else 0.0
        fri_spec = tn / (tn + fp) if (tn + fp) > 0 else 0.0

        # Sub-class attack recalls
        ps_mask = (labels_friday_arr == "PortScan")
        ddos_mask = (labels_friday_arr == "DDoS")
        ps_rec = float(np.mean(fri_preds[ps_mask])) if np.sum(ps_mask) > 0 else 0.0
        ddos_rec = float(np.mean(fri_preds[ddos_mask])) if np.sum(ddos_mask) > 0 else 0.0

        # Confirmed Morning Benign FPR
        morning_fpr = float(np.mean(fri_preds[morning_mask]))

        results.append({
            "model_name": name,
            "target_val_fpr": target_fpr,
            "calib_thresh": thresh,
            "actual_val_fpr": actual_val_fpr,
            "mon_test_fpr": test_fpr,
            "friday_fpr": fri_fpr,
            "friday_spec": fri_spec,
            "morning_fpr": morning_fpr,
            "ps_rec": ps_rec,
            "ddos_rec": ddos_rec,
            "overall_rec": rec,
            "prec": prec,
            "f1": f1,
            "pr_auc": pr_auc,
            "roc_auc": roc_auc,
            "cm": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
            "inf_time_ms": inf_time_ms,
        })

print("\n" + "=" * 135)
print(f"Phase 2 ML Candidates Comparison (Thresholds Calibrated on Validation Data ONLY)")
print("=" * 135)
print(f"{'Model & Config':<30} | {'Val FPR':<7} | {'Thresh':<7} | {'Val%':<5} | {'Test%':<5} | {'Fri FPR':<7} | {'Morn FPR':<8} | {'PS Rec':<6} | {'DDoS Rec':<8} | {'All Rec':<7} | {'Prec':<6} | {'F1':<6} | {'PR-AUC':<6}")
print("-" * 135)
for r in results:
    print(f"{r['model_name']:<30} | {r['target_val_fpr']*100:>5.1f}% | {r['calib_thresh']:<7.4f} | {r['actual_val_fpr']*100:>4.1f}% | {r['mon_test_fpr']*100:>4.1f}% | {r['friday_fpr']*100:>5.2f}% | {r['morning_fpr']*100:>6.2f}% | {r['ps_rec']*100:>5.2f}% | {r['ddos_rec']*100:>6.2f}% | {r['overall_rec']*100:>5.2f}% | {r['prec']:<6.4f} | {r['f1']:<6.4f} | {r['pr_auc']:<6.4f}")
print("=" * 135)

# Save comparison results
with open(PROJECT_ROOT / "experiments/cic_ids2017/reports/ml_candidate_comparison.json", "w") as f:
    json.dump(results, f, indent=2)
print("\nWrote ml_candidate_comparison.json")
