"""Bounded-Memory Streaming Sampler for CIC-IDS2017 Experiment.

Implements day-separated, leakage-resistant sampling:
1. Training: up to 15,000 pure benign flows from Monday-WorkingHours.
2. Evaluation:
   - 5,000 held-out benign Monday flows (disjoint from training).
   - 5,000 benign flows sampled across Tuesday-Friday for background drift.
   - 100% of eligible rare attacks (Heartbleed, SQL Injection, Infiltration, XSS, Brute Force, Bot).
   - Stratified bounded sample of high-volume attacks (capped to keep evaluation fast & balanced).
"""

import random
from typing import Dict, List, Tuple, Any, Optional
import numpy as np

from experiments.cic_ids2017.data_loader import CICDatasetStreamer
from experiments.cic_ids2017.features import extract_cic_features, FEATURE_NAMES

RARE_ATTACK_CLASSES = {
    "Heartbleed",
    "Web Attack - SQL Injection",
    "Infiltration",
    "Web Attack - XSS",
    "Web Attack - Brute Force",
    "Bot",
}

COMMON_ATTACK_CAPS = {
    "FTP-Patator": 1000,
    "SSH-Patator": 1000,
    "DoS GoldenEye": 1000,
    "DoS slowloris": 1000,
    "DoS Slowhttptest": 1000,
    "DoS Hulk": 1500,
    "DDoS": 1500,
    "PortScan": 1500,
}


class ExperimentSampler:
    """Orchestrates streaming sampling for training and evaluation partitions."""

    def __init__(
        self,
        streamer: CICDatasetStreamer,
        random_seed: int = 42,
        max_train_samples: int = 15000,
        max_monday_eval_samples: int = 5000,
        max_drift_eval_samples: int = 5000,
    ):
        self.streamer = streamer
        self.seed = random_seed
        self.max_train_samples = max_train_samples
        self.max_monday_eval_samples = max_monday_eval_samples
        self.max_drift_eval_samples = max_drift_eval_samples
        self.rng = random.Random(self.seed)

    def sample_monday_partitions(
        self,
    ) -> Tuple[np.ndarray, np.ndarray, Dict[str, Any]]:
        """Stream Monday traffic and partition into disjoint training and in-day holdout sets."""
        csv_files = self.streamer.get_csv_filenames()
        monday_file = next((f for f in csv_files if "Monday" in f), None)
        if not monday_file:
            raise FileNotFoundError("Monday CSV not found in dataset archive.")

        total_needed = self.max_train_samples + self.max_monday_eval_samples

        # Reservoir sample total_needed items from Monday benign flows
        reservoir = []
        count = 0

        for row_dict, label in self.streamer.stream_file(monday_file):
            if label != "BENIGN":
                continue
            count += 1
            if len(reservoir) < total_needed:
                feats = extract_cic_features(row_dict)
                reservoir.append(feats)
            else:
                j = self.rng.randint(0, count - 1)
                if j < total_needed:
                    feats = extract_cic_features(row_dict)
                    reservoir[j] = feats

        # Shuffle reservoir deterministically
        self.rng.shuffle(reservoir)

        train_feats = reservoir[: self.max_train_samples]
        eval_feats = reservoir[self.max_train_samples : self.max_train_samples + self.max_monday_eval_samples]

        X_train = np.array(train_feats, dtype=np.float64)
        X_eval_mon = np.array(eval_feats, dtype=np.float64)

        meta = {
            "monday_file": monday_file,
            "monday_total_benign_seen": count,
            "train_count": len(X_train),
            "eval_monday_holdout_count": len(X_eval_mon),
            "disjoint_verification": "Partitioned from single shuffled reservoir; guaranteed zero overlap.",
        }

        return X_train, X_eval_mon, meta

    def sample_evaluation_set(
        self,
        X_eval_monday: np.ndarray,
    ) -> Tuple[np.ndarray, np.ndarray, List[str], Dict[str, Any]]:
        """Collect the complete evaluation set: Monday holdout + Tue-Fri drift + Attacks.

        Returns:
            (X_eval, y_eval, attack_labels, eval_metadata)
            - y_eval: 0 for benign, 1 for attack.
            - attack_labels: string label for each row in X_eval.
        """
        csv_files = self.streamer.get_csv_filenames()
        non_monday_files = [f for f in csv_files if "Monday" not in f]

        drift_reservoir = []
        drift_count = 0

        attack_samples_by_class: Dict[str, List[np.ndarray]] = {}
        attack_counts_seen: Dict[str, int] = {}

        for filename in non_monday_files:
            for row_dict, label in self.streamer.stream_file(filename):
                feats = extract_cic_features(row_dict)

                if label == "BENIGN":
                    drift_count += 1
                    if len(drift_reservoir) < self.max_drift_eval_samples:
                        drift_reservoir.append(feats)
                    else:
                        j = self.rng.randint(0, drift_count - 1)
                        if j < self.max_drift_eval_samples:
                            drift_reservoir[j] = feats
                else:
                    # Attack flow
                    attack_counts_seen[label] = attack_counts_seen.get(label, 0) + 1
                    if label not in attack_samples_by_class:
                        attack_samples_by_class[label] = []

                    cap = COMMON_ATTACK_CAPS.get(label, None)
                    if cap is None:
                        # Rare attack: retain 100% of flows
                        attack_samples_by_class[label].append(feats)
                    else:
                        # Common attack: reservoir sample up to cap
                        current_list = attack_samples_by_class[label]
                        if len(current_list) < cap:
                            current_list.append(feats)
                        else:
                            seen_k = attack_counts_seen[label]
                            j = self.rng.randint(0, seen_k - 1)
                            if j < cap:
                                current_list[j] = feats

        # Assemble evaluation arrays
        all_feats = []
        all_binary_labels = []
        all_class_labels = []

        # 1. Monday Benign Holdout
        for feats in X_eval_monday:
            all_feats.append(feats)
            all_binary_labels.append(0)
            all_class_labels.append("BENIGN_MONDAY")

        # 2. Tuesday-Friday Benign Drift
        for feats in drift_reservoir:
            all_feats.append(feats)
            all_binary_labels.append(0)
            all_class_labels.append("BENIGN_DRIFT")

        # 3. Attacks
        for label, feats_list in attack_samples_by_class.items():
            for feats in feats_list:
                all_feats.append(feats)
                all_binary_labels.append(1)
                all_class_labels.append(label)

        X_eval = np.array(all_feats, dtype=np.float64)
        y_eval = np.array(all_binary_labels, dtype=np.int32)

        actual_class_counts = {}
        for lbl in all_class_labels:
            actual_class_counts[lbl] = actual_class_counts.get(lbl, 0) + 1

        eval_meta = {
            "total_eval_samples": len(X_eval),
            "total_benign_samples": len(X_eval_monday) + len(drift_reservoir),
            "monday_benign_holdout_samples": len(X_eval_monday),
            "drift_benign_samples": len(drift_reservoir),
            "total_attack_samples": int(np.sum(y_eval == 1)),
            "per_class_sample_counts": actual_class_counts,
            "attack_counts_seen_in_stream": attack_counts_seen,
        }

        return X_eval, y_eval, all_class_labels, eval_meta
