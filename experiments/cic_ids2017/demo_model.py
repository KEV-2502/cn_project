#!/usr/bin/env python3
"""Interactive CLI Demo for Inspecting the CIC-IDS2017 Candidate Isolation Forest.

Loads the saved candidate model (data/models/candidate_isolation_forest_cic.joblib)
and allows interactive inspection of individual real labelled flows directly from the
dataset archive (data/datasets/GeneratedLabelledFlows.zip).

Strict Safety:
- Read-only on dataset and production models.
- Uses exact scoring convention and feature extraction from the experiment.
- Compatible with Fish, Bash, and automated non-interactive runs.
"""

import argparse
import random
import sys
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(BASE_DIR))

from experiments.cic_ids2017.data_loader import CICDatasetStreamer
from experiments.cic_ids2017.features import (
    extract_cic_features,
    FEATURE_NAMES,
    SCHEMA_VERSION,
)
from experiments.cic_ids2017.model import (
    CandidateAnomalyDetector,
    DEFAULT_CANDIDATE_MODEL_PATH,
    DEFAULT_CANDIDATE_METADATA_PATH,
)
from experiments.cic_ids2017.plot_results import generate_all_plots, FIGURES_DIR

# Mapping attack categories directly to their primary CSV files inside the ZIP
CATEGORY_TO_FILE: Dict[str, str] = {
    "PortScan": "TrafficLabelling /Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "DDoS": "TrafficLabelling /Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    "Heartbleed": "TrafficLabelling /Wednesday-workingHours.pcap_ISCX.csv",
    "Infiltration": "TrafficLabelling /Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "Bot": "TrafficLabelling /Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "DoS Hulk": "TrafficLabelling /Wednesday-workingHours.pcap_ISCX.csv",
    "DoS GoldenEye": "TrafficLabelling /Wednesday-workingHours.pcap_ISCX.csv",
    "DoS slowloris": "TrafficLabelling /Wednesday-workingHours.pcap_ISCX.csv",
    "DoS Slowhttptest": "TrafficLabelling /Wednesday-workingHours.pcap_ISCX.csv",
    "FTP-Patator": "TrafficLabelling /Tuesday-WorkingHours.pcap_ISCX.csv",
    "SSH-Patator": "TrafficLabelling /Tuesday-WorkingHours.pcap_ISCX.csv",
    "Web Attack - Brute Force": "TrafficLabelling /Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Web Attack - XSS": "TrafficLabelling /Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Web Attack - SQL Injection": "TrafficLabelling /Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "BENIGN_MONDAY": "TrafficLabelling /Monday-WorkingHours.pcap_ISCX.csv",
    "BENIGN_TUESDAY": "TrafficLabelling /Tuesday-WorkingHours.pcap_ISCX.csv",
    "BENIGN_FRIDAY": "TrafficLabelling /Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
}

ALL_ATTACK_CATEGORIES = [
    "PortScan",
    "DDoS",
    "Heartbleed",
    "Infiltration",
    "Bot",
    "DoS Hulk",
    "DoS GoldenEye",
    "DoS slowloris",
    "DoS Slowhttptest",
    "FTP-Patator",
    "SSH-Patator",
    "Web Attack - Brute Force",
    "Web Attack - XSS",
    "Web Attack - SQL Injection",
]


class FlowInspector:
    """Handles flow sampling and scoring using the candidate model."""

    def __init__(
        self,
        zip_path: Path,
        model_path: Path = DEFAULT_CANDIDATE_MODEL_PATH,
        metadata_path: Path = DEFAULT_CANDIDATE_METADATA_PATH,
    ):
        self.streamer = CICDatasetStreamer(zip_path)
        self.detector = CandidateAnomalyDetector(model_path, metadata_path)
        if not self.detector.is_ready:
            raise RuntimeError(
                f"Candidate model artifact could not be loaded from {model_path}. "
                "Ensure run_experiment.py has been executed."
            )
        self.threshold = float(self.detector.metadata.get("scoring_convention", {}).get("anomaly_threshold", 0.50))

    def sample_flows_by_filter(
        self,
        target_labels: List[str],
        target_files: Optional[List[str]] = None,
        count: int = 5,
        seed: Optional[int] = None,
    ) -> List[Tuple[Dict[str, Any], str]]:
        """Sample up to `count` flows matching target labels using reservoir sampling."""
        rng = random.Random(seed)
        if target_files is None:
            # Map labels to files
            target_files = []
            for lbl in target_labels:
                f = CATEGORY_TO_FILE.get(lbl)
                if f and f not in target_files:
                    target_files.append(f)
            if not target_files:
                target_files = self.streamer.get_csv_filenames()

        reservoir: List[Tuple[Dict[str, Any], str]] = []
        seen = 0

        for fname in target_files:
            for row_dict, label in self.streamer.stream_file(fname):
                if label in target_labels:
                    seen += 1
                    if len(reservoir) < count:
                        reservoir.append((row_dict, label))
                    else:
                        j = rng.randint(0, seen - 1)
                        if j < count:
                            reservoir[j] = (row_dict, label)
            if len(reservoir) >= count and seen > count * 5:
                # Early stop once sufficient randomized mixing has occurred
                break

        rng.shuffle(reservoir)
        return reservoir

    def evaluate_flow(
        self, row_dict: Dict[str, Any], label: str
    ) -> Dict[str, Any]:
        """Extract features, score vector, and evaluate prediction correctness."""
        feats = extract_cic_features(row_dict)
        scores, preds = self.detector.score_batch(feats.reshape(1, -1))
        score = float(scores[0])
        pred = int(preds[0])

        is_actual_attack = 1 if label != "BENIGN" else 0
        is_pred_attack = 1 if pred == 1 else 0

        if is_actual_attack == 1 and is_pred_attack == 1:
            verdict = "TP"
            verdict_desc = "True Positive (Malicious flow correctly flagged)"
        elif is_actual_attack == 0 and is_pred_attack == 0:
            verdict = "TN"
            verdict_desc = "True Negative (Benign flow correctly cleared)"
        elif is_actual_attack == 0 and is_pred_attack == 1:
            verdict = "FP"
            verdict_desc = "False Positive (Benign flow incorrectly flagged)"
        else:
            verdict = "FN"
            verdict_desc = "False Negative (Attack flow missed by model)"

        attribution = self.detector.compute_attribution(feats)

        # Parse key readable features
        fwd_pkts = int(feats[0])
        bwd_pkts = int(feats[1])
        fwd_bytes = int(feats[2])
        bwd_bytes = int(feats[3])
        dur_s = float(feats[4])
        fwd_pkt_rate = float(feats[7])
        bwd_pkt_rate = float(feats[8])
        fwd_byte_rate = float(feats[9])
        bwd_byte_rate = float(feats[10])
        is_tcp = bool(feats[11] == 1.0)
        is_udp = bool(feats[12] == 1.0)
        proto_str = "TCP" if is_tcp else ("UDP" if is_udp else f"Protocol-{row_dict.get('Protocol', '?')}")
        avg_pkt_size = float(feats[14])

        return {
            "flow_id": row_dict.get("Flow ID", "N/A"),
            "src_ip": row_dict.get("Source IP", "?"),
            "src_port": row_dict.get("Source Port", "?"),
            "dst_ip": row_dict.get("Destination IP", "?"),
            "dst_port": row_dict.get("Destination Port", "?"),
            "protocol": proto_str,
            "label": label,
            "score": round(score, 4),
            "threshold": self.threshold,
            "prediction": "ANOMALY" if is_pred_attack == 1 else "NORMAL",
            "verdict": verdict,
            "verdict_desc": verdict_desc,
            "metrics": {
                "forward_packets": fwd_pkts,
                "backward_packets": bwd_pkts,
                "total_packets": fwd_pkts + bwd_pkts,
                "forward_bytes": fwd_bytes,
                "backward_bytes": bwd_bytes,
                "total_payload_bytes": fwd_bytes + bwd_bytes,
                "duration_s": round(dur_s, 6),
                "duration_formatted": f"{dur_s*1000:.2f} ms" if dur_s < 1.0 else f"{dur_s:.3f} s",
                "forward_packet_rate": round(fwd_pkt_rate, 2),
                "backward_packet_rate": round(bwd_pkt_rate, 2),
                "forward_byte_rate": round(fwd_byte_rate, 2),
                "backward_byte_rate": round(bwd_byte_rate, 2),
                "avg_packet_size": round(avg_pkt_size, 2),
            },
            "attribution": attribution.get("top_deviations", {}),
        }


def print_flow_report(idx: int, evaluated: Dict[str, Any]):
    """Format and print an individual flow analysis card."""
    print("━" * 78)
    print(f" Flow #{idx}: {evaluated['flow_id']}")
    print("━" * 78)
    print(f" Endpoints    : {evaluated['src_ip']}:{evaluated['src_port']} ➔ {evaluated['dst_ip']}:{evaluated['dst_port']} ({evaluated['protocol']})")
    print(f" Ground Truth : \033[1m{evaluated['label']}\033[0m")

    # Score coloring and threshold display
    score = evaluated['score']
    thresh = evaluated['threshold']
    verdict = evaluated['verdict']

    if verdict in ("TP", "TN"):
        verdict_color = "\033[32m"  # Green
    elif verdict == "FP":
        verdict_color = "\033[33m"  # Yellow
    else:
        verdict_color = "\033[31m"  # Red (FN)
    reset = "\033[0m"

    print(f" Anomaly Score: \033[1m{score:.4f}\033[0m  (Decision Threshold τ = {thresh:.2f})")
    print(f" Model Verdict: {verdict_color}[{verdict}] {evaluated['verdict_desc']}{reset}")

    # Readable metrics breakdown
    m = evaluated["metrics"]
    print(" ┌─ Extracted Feature Snapshot (Schema: v2_cicids2017_payload_features) ──")
    print(f" │  Packets     : Fwd = {m['forward_packets']:<6} | Bwd = {m['backward_packets']:<6} | Total = {m['total_packets']}")
    print(f" │  Payload     : Fwd = {m['forward_bytes']:<6} B | Bwd = {m['backward_bytes']:<6} B | Total = {m['total_payload_bytes']} bytes")
    print(f" │  Duration    : {m['duration_formatted']} ({m['duration_s']:.6f} s)")
    print(f" │  Packet Rate : Fwd = {m['forward_packet_rate']:<10.1f} pkts/s | Bwd = {m['backward_packet_rate']:<10.1f} pkts/s")
    print(f" │  Byte Rate   : Fwd = {m['forward_byte_rate']:<10.1f} B/s    | Bwd = {m['backward_byte_rate']:<10.1f} B/s")
    print(f" │  Avg Payload : {m['avg_packet_size']} bytes/packet")

    # Feature attributions
    attribs = evaluated.get("attribution", {})
    if attribs:
        print(" ├─ Top Deviating Outlier Features vs Monday Benign Baseline ─────────")
        for feat, d in attribs.items():
            print(f" │  • {feat:<20}: Observed={d['observed']} vs Mean={d['baseline_mean']} (z-score: +{d['z_score']})")
    print(" └────────────────────────────────────────────────────────────────────\n")


def display_batch_summary(evaluated_flows: List[Dict[str, Any]]):
    """Display tabular summary for the sampled batch."""
    total = len(evaluated_flows)
    tp = sum(1 for f in evaluated_flows if f["verdict"] == "TP")
    tn = sum(1 for f in evaluated_flows if f["verdict"] == "TN")
    fp = sum(1 for f in evaluated_flows if f["verdict"] == "FP")
    fn = sum(1 for f in evaluated_flows if f["verdict"] == "FN")

    accuracy = (tp + tn) / max(1, total) * 100
    print("═" * 78)
    print(f" BATCH INSPECTION SUMMARY (Total Flows: {total})")
    print("═" * 78)
    print(f"  True Positives  [TP] : {tp:>4}  (Malicious correctly flagged)")
    print(f"  True Negatives  [TN] : {tn:>4}  (Benign correctly cleared)")
    print(f"  False Positives [FP] : {fp:>4}  (Benign incorrectly flagged)")
    print(f"  False Negatives [FN] : {fn:>4}  (Malicious missed by model)")
    print(f"  Batch Agreement Rate : {accuracy:.1f}%\n")


def interactive_menu(inspector: FlowInspector):
    """Run interactive terminal menu loop."""
    while True:
        print("\n" + "=" * 70)
        print(" CIC-IDS2017 Candidate Isolation Forest — Interactive Model Demo")
        print("=" * 70)
        print(" [1] View a random sample of BENIGN flows")
        print(" [2] View a random sample of ATTACK flows (mixed categories)")
        print(" [3] Select a particular ATTACK CATEGORY (e.g. Heartbleed, PortScan, DDoS)")
        print(" [4] Show a MIXED sample of Benign & Attack flows")
        print(" [5] Generate / View visual evaluation charts (Confusion Matrix & Distributions)")
        print(" [0] Exit safely")
        print("=" * 70)

        choice = input("Enter your choice [0-5]: ").strip()

        if choice == "0":
            print("Exiting demo. Production models and datasets remain untouched.")
            break

        elif choice == "1":
            count = _prompt_sample_count()
            print(f"\nSampling {count} benign flows...")
            flows = inspector.sample_flows_by_filter(target_labels=["BENIGN"], count=count)
            evaluated = [inspector.evaluate_flow(r, l) for r, l in flows]
            for i, ev in enumerate(evaluated, 1):
                print_flow_report(i, ev)
            display_batch_summary(evaluated)

        elif choice == "2":
            count = _prompt_sample_count()
            print(f"\nSampling {count} attack flows across categories...")
            flows = inspector.sample_flows_by_filter(target_labels=ALL_ATTACK_CATEGORIES, count=count)
            evaluated = [inspector.evaluate_flow(r, l) for r, l in flows]
            for i, ev in enumerate(evaluated, 1):
                print_flow_report(i, ev)
            display_batch_summary(evaluated)

        elif choice == "3":
            print("\nSelect an Attack Category:")
            for idx, cat in enumerate(ALL_ATTACK_CATEGORIES, 1):
                print(f"  [{idx:2d}] {cat}")
            sub_choice = input(f"Select category [1-{len(ALL_ATTACK_CATEGORIES)}]: ").strip()
            try:
                cat_idx = int(sub_choice) - 1
                if 0 <= cat_idx < len(ALL_ATTACK_CATEGORIES):
                    chosen_cat = ALL_ATTACK_CATEGORIES[cat_idx]
                    count = _prompt_sample_count(default=5)
                    print(f"\nSampling {count} flows for attack '{chosen_cat}'...")
                    flows = inspector.sample_flows_by_filter(target_labels=[chosen_cat], count=count)
                    evaluated = [inspector.evaluate_flow(r, l) for r, l in flows]
                    for i, ev in enumerate(evaluated, 1):
                        print_flow_report(i, ev)
                    display_batch_summary(evaluated)
                else:
                    print("Invalid selection.")
            except ValueError:
                print("Invalid input.")

        elif choice == "4":
            count = _prompt_sample_count(default=6)
            half = max(1, count // 2)
            print(f"\nSampling mixed batch: {half} benign + {half} attack flows...")
            benign_sample = inspector.sample_flows_by_filter(target_labels=["BENIGN"], count=half)
            attack_sample = inspector.sample_flows_by_filter(target_labels=ALL_ATTACK_CATEGORIES, count=half)
            mixed = benign_sample + attack_sample
            random.shuffle(mixed)
            evaluated = [inspector.evaluate_flow(r, l) for r, l in mixed]
            for i, ev in enumerate(evaluated, 1):
                print_flow_report(i, ev)
            display_batch_summary(evaluated)

        elif choice == "5":
            print("\nGenerating visual evaluation charts...")
            generated = generate_all_plots()
            print("Successfully rendered visual evaluation charts to:")
            for name, path in generated.items():
                print(f"  • {name:<20}: {path}")
            print("\nTo view them in your desktop environment or image viewer:")
            print(f"  xdg-open {FIGURES_DIR / 'cic_ids2017_evaluation_overview.png'}")

        else:
            print("Invalid option. Please choose a valid menu item.")


def _prompt_sample_count(default: int = 5) -> int:
    cnt_str = input(f"How many flows to inspect? [default: {default}]: ").strip()
    if not cnt_str:
        return default
    try:
        val = int(cnt_str)
        return max(1, min(val, 50))
    except ValueError:
        return default


def main():
    parser = argparse.ArgumentParser(
        description="Interactive Inspection Demo for CIC-IDS2017 Candidate Isolation Forest"
    )
    parser.add_argument(
        "--mode",
        choices=["interactive", "benign", "attack", "category", "mixed", "plots"],
        default="interactive",
        help="Execution mode (default: interactive)",
    )
    parser.add_argument(
        "--category",
        type=str,
        default="Heartbleed",
        help="Attack category to inspect when --mode is 'category'",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=5,
        help="Number of flows to inspect (default: 5)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="Optional random seed for reproducible sampling",
    )
    args = parser.parse_args()

    zip_path = BASE_DIR / "data" / "datasets" / "GeneratedLabelledFlows.zip"
    if not zip_path.exists():
        print(f"ERROR: Dataset archive not found at: {zip_path}")
        sys.exit(1)

    if args.mode == "plots":
        print("Generating visual evaluation plots...")
        generated = generate_all_plots()
        for name, path in generated.items():
            print(f"  {name:<20}: {path}")
        return

    inspector = FlowInspector(zip_path)

    if args.mode == "interactive":
        interactive_menu(inspector)
    else:
        # Non-interactive CLI mode for testing or scripted execution
        if args.mode == "benign":
            flows = inspector.sample_flows_by_filter(["BENIGN"], count=args.count, seed=args.seed)
        elif args.mode == "attack":
            flows = inspector.sample_flows_by_filter(ALL_ATTACK_CATEGORIES, count=args.count, seed=args.seed)
        elif args.mode == "category":
            flows = inspector.sample_flows_by_filter([args.category], count=args.count, seed=args.seed)
        elif args.mode == "mixed":
            half = max(1, args.count // 2)
            b = inspector.sample_flows_by_filter(["BENIGN"], count=half, seed=args.seed)
            a = inspector.sample_flows_by_filter(ALL_ATTACK_CATEGORIES, count=half, seed=args.seed)
            flows = b + a
            random.shuffle(flows)
        else:
            flows = []

        evaluated = [inspector.evaluate_flow(r, l) for r, l in flows]
        for i, ev in enumerate(evaluated, 1):
            print_flow_report(i, ev)
        display_batch_summary(evaluated)


if __name__ == "__main__":
    main()
