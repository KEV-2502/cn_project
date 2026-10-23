"""Leakage-Free 3-Way Dataset Partitioner for CIC-IDS2017 Experiments.

Creates strictly disjoint Train, Validation, and Test partitions:
1. Train: Benign-only flows from Monday-WorkingHours (unsupervised baseline).
2. Validation: Disjoint Monday benign holdout + Tuesday-Friday benign drift + 50% stratified attack flows.
   Used exclusively for tuning/calibrating operating thresholds.
3. Test: Disjoint Monday benign holdout + Tuesday-Friday benign drift + remaining 50% stratified attack flows.
   Untouched during training and threshold selection; evaluated exactly once.

Guarantees:
- Zero record overlap between Train, Validation, and Test (verified by record IDs).
- Complete isolation of attack flows from the training set.
- Proportional representation of all attack categories in both Validation and Test sets.
"""

import random
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple, Any, Optional, Set
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


@dataclass
class FlowRecord:
    record_id: str
    features: np.ndarray
    binary_label: int  # 0 = Benign, 1 = Attack
    class_label: str   # BENIGN_MONDAY, BENIGN_DRIFT, or specific attack class name


@dataclass
class PartitionBundle:
    X: np.ndarray
    y: np.ndarray
    class_labels: List[str]
    record_ids: List[str]
    metadata: Dict[str, Any]


class ThreeWayDatasetPartitioner:
    """Streams CIC-IDS2017 archive and builds verified disjoint Train, Val, Test partitions."""

    def __init__(
        self,
        streamer: CICDatasetStreamer,
        random_seed: int = 42,
        train_samples: int = 15000,
        val_monday_samples: int = 5000,
        test_monday_samples: int = 5000,
        val_drift_samples: int = 2500,
        test_drift_samples: int = 2500,
    ):
        self.streamer = streamer
        self.seed = random_seed
        self.train_samples = train_samples
        self.val_monday_samples = val_monday_samples
        self.test_monday_samples = test_monday_samples
        self.val_drift_samples = val_drift_samples
        self.test_drift_samples = test_drift_samples
        self.rng = random.Random(self.seed)

    def generate_partitions(
        self,
    ) -> Tuple[PartitionBundle, PartitionBundle, PartitionBundle]:
        """Stream dataset and partition into disjoint Train, Validation, and Test sets."""
        csv_files = self.streamer.get_csv_filenames()
        monday_file = next((f for f in csv_files if "Monday" in f), None)
        if not monday_file:
            raise FileNotFoundError("Monday CSV not found in dataset archive.")

        non_monday_files = [f for f in csv_files if "Monday" not in f]

        # ---------------------------------------------------------
        # Phase 1: Stream Monday Benign traffic
        # ---------------------------------------------------------
        total_monday_needed = (
            self.train_samples + self.val_monday_samples + self.test_monday_samples
        )
        monday_reservoir: List[FlowRecord] = []
        monday_count = 0

        row_idx = 0
        for row_dict, label in self.streamer.stream_file(monday_file):
            row_idx += 1
            if label != "BENIGN":
                continue
            monday_count += 1
            rec_id = f"{monday_file}#row_{row_idx}"
            feats = extract_cic_features(row_dict)
            rec = FlowRecord(
                record_id=rec_id,
                features=feats,
                binary_label=0,
                class_label="BENIGN_MONDAY",
            )

            if len(monday_reservoir) < total_monday_needed:
                monday_reservoir.append(rec)
            else:
                j = self.rng.randint(0, monday_count - 1)
                if j < total_monday_needed:
                    monday_reservoir[j] = rec

        # Deterministically shuffle Monday reservoir
        self.rng.shuffle(monday_reservoir)

        train_records = monday_reservoir[: self.train_samples]
        val_monday_records = monday_reservoir[
            self.train_samples : self.train_samples + self.val_monday_samples
        ]
        test_monday_records = monday_reservoir[
            self.train_samples + self.val_monday_samples : total_monday_needed
        ]

        # ---------------------------------------------------------
        # Phase 2: Stream Tuesday-Friday Drift Benign & Attack traffic
        # ---------------------------------------------------------
        total_drift_needed = self.val_drift_samples + self.test_drift_samples
        drift_reservoir: List[FlowRecord] = []
        drift_count = 0

        attack_samples_by_class: Dict[str, List[FlowRecord]] = {}
        attack_counts_seen: Dict[str, int] = {}

        for filename in non_monday_files:
            file_row_idx = 0
            for row_dict, label in self.streamer.stream_file(filename):
                file_row_idx += 1
                rec_id = f"{filename}#row_{file_row_idx}"
                feats = extract_cic_features(row_dict)

                if label == "BENIGN":
                    drift_count += 1
                    rec = FlowRecord(
                        record_id=rec_id,
                        features=feats,
                        binary_label=0,
                        class_label="BENIGN_DRIFT",
                    )
                    if len(drift_reservoir) < total_drift_needed:
                        drift_reservoir.append(rec)
                    else:
                        j = self.rng.randint(0, drift_count - 1)
                        if j < total_drift_needed:
                            drift_reservoir[j] = rec
                else:
                    # Attack flow
                    attack_counts_seen[label] = attack_counts_seen.get(label, 0) + 1
                    if label not in attack_samples_by_class:
                        attack_samples_by_class[label] = []

                    rec = FlowRecord(
                        record_id=rec_id,
                        features=feats,
                        binary_label=1,
                        class_label=label,
                    )
                    cap = COMMON_ATTACK_CAPS.get(label, None)
                    current_list = attack_samples_by_class[label]
                    if cap is None:
                        # Rare attack: retain all
                        current_list.append(rec)
                    else:
                        if len(current_list) < cap:
                            current_list.append(rec)
                        else:
                            seen_k = attack_counts_seen[label]
                            j = self.rng.randint(0, seen_k - 1)
                            if j < cap:
                                current_list[j] = rec

        # Deterministically shuffle Drift Benign reservoir
        self.rng.shuffle(drift_reservoir)
        val_drift_records = drift_reservoir[: self.val_drift_samples]
        test_drift_records = drift_reservoir[self.val_drift_samples : total_drift_needed]

        # ---------------------------------------------------------
        # Phase 3: Stratified 50/50 Split for Attacks
        # ---------------------------------------------------------
        val_attack_records: List[FlowRecord] = []
        test_attack_records: List[FlowRecord] = []

        for attack_name in sorted(attack_samples_by_class.keys()):
            items = attack_samples_by_class[attack_name]
            self.rng.shuffle(items)
            split_idx = len(items) // 2
            val_items = items[:split_idx]
            test_items = items[split_idx:]
            val_attack_records.extend(val_items)
            test_attack_records.extend(test_items)

        # ---------------------------------------------------------
        # Assemble Validation and Test records
        # ---------------------------------------------------------
        val_all_records = val_monday_records + val_drift_records + val_attack_records
        test_all_records = test_monday_records + test_drift_records + test_attack_records

        # Deterministically shuffle final sets so classes are intermixed
        self.rng.shuffle(val_all_records)
        self.rng.shuffle(test_all_records)

        # Build bundles
        train_bundle = self._build_bundle(
            train_records,
            name="train",
            extra_meta={
                "benign_source": "Monday-WorkingHours pure benign",
                "total_monday_benign_seen": monday_count,
            },
        )

        val_bundle = self._build_bundle(
            val_all_records,
            name="validation",
            extra_meta={
                "monday_benign_count": len(val_monday_records),
                "drift_benign_count": len(val_drift_records),
                "attack_count": len(val_attack_records),
                "total_drift_benign_seen": drift_count,
            },
        )

        test_bundle = self._build_bundle(
            test_all_records,
            name="test",
            extra_meta={
                "monday_benign_count": len(test_monday_records),
                "drift_benign_count": len(test_drift_records),
                "attack_count": len(test_attack_records),
            },
        )

        # Verify strict disjointness
        self._verify_disjointness(train_bundle, val_bundle, test_bundle)

        return train_bundle, val_bundle, test_bundle

    def _build_bundle(
        self, records: List[FlowRecord], name: str, extra_meta: Dict[str, Any]
    ) -> PartitionBundle:
        X = np.array([r.features for r in records], dtype=np.float64)
        y = np.array([r.binary_label for r in records], dtype=np.int32)
        class_labels = [r.class_label for r in records]
        record_ids = [r.record_id for r in records]

        class_counts = {}
        for lbl in class_labels:
            class_counts[lbl] = class_counts.get(lbl, 0) + 1

        meta = {
            "partition_name": name,
            "total_samples": len(records),
            "benign_samples": int(np.sum(y == 0)),
            "attack_samples": int(np.sum(y == 1)),
            "class_distribution": class_counts,
            **extra_meta,
        }

        return PartitionBundle(
            X=X,
            y=y,
            class_labels=class_labels,
            record_ids=record_ids,
            metadata=meta,
        )

    @staticmethod
    def _verify_disjointness(
        train: PartitionBundle, val: PartitionBundle, test: PartitionBundle
    ):
        """Assert mathematically zero record ID overlap between all pairs."""
        train_ids = set(train.record_ids)
        val_ids = set(val.record_ids)
        test_ids = set(test.record_ids)

        train_val_overlap = train_ids & val_ids
        train_test_overlap = train_ids & test_ids
        val_test_overlap = val_ids & test_ids

        if train_val_overlap:
            raise AssertionError(
                f"Data leakage detected: {len(train_val_overlap)} records in Train & Val!"
            )
        if train_test_overlap:
            raise AssertionError(
                f"Data leakage detected: {len(train_test_overlap)} records in Train & Test!"
            )
        if val_test_overlap:
            raise AssertionError(
                f"Data leakage detected: {len(val_test_overlap)} records in Val & Test!"
            )
