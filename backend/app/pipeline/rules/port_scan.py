"""Port Scanning Detection Rule.

Detects both vertical port scanning (one source probing many distinct destination ports
on a target host) and horizontal host scanning (one source probing many distinct destination hosts).
"""

from typing import List, Dict, Set
from collections import defaultdict
from backend.app.models.flow import NetworkFlow
from backend.app.models.dns import DnsQueryRecord
from backend.app.pipeline.rules.base import BaseRule, DetectionResult
from backend.app.config import settings


class PortScanRule(BaseRule):
    """Detects vertical port scans and horizontal host sweeps within configurable time windows."""

    def __init__(
        self,
        vertical_port_threshold: int = settings.PORT_SCAN_UNIQUE_PORTS,
        horizontal_host_threshold: int = settings.PORT_SCAN_HORIZONTAL_HOSTS,
        window_seconds: float = settings.PORT_SCAN_WINDOW_SECONDS,
    ):
        self.vertical_port_threshold = vertical_port_threshold
        self.horizontal_host_threshold = horizontal_host_threshold
        self.window_seconds = window_seconds

    def evaluate(
        self,
        pcap_id: int,
        flows: List[NetworkFlow],
        dns_records: List[DnsQueryRecord],
    ) -> List[DetectionResult]:
        results: List[DetectionResult] = []
        if not flows:
            return results

        # Group flows by source IP
        src_flows: Dict[str, List[NetworkFlow]] = defaultdict(list)
        for f in flows:
            src_flows[f.src_ip].append(f)

        for src_ip, f_list in src_flows.items():
            f_list.sort(key=lambda x: x.start_time)

            # --- 1. Vertical Port Scan Evaluation (per target host) ---
            target_flows: Dict[str, List[NetworkFlow]] = defaultdict(list)
            for f in f_list:
                target_flows[f.dst_ip].append(f)

            for dst_ip, t_flows in target_flows.items():
                # Form temporal clusters where consecutive flows are within window_seconds
                clusters: List[List[NetworkFlow]] = []
                cur: List[NetworkFlow] = []
                for f in t_flows:
                    if not cur:
                        cur.append(f)
                    elif f.start_time - cur[-1].start_time <= self.window_seconds:
                        cur.append(f)
                    else:
                        clusters.append(cur)
                        cur = [f]
                if cur:
                    clusters.append(cur)

                for cluster in clusters:
                    unique_ports = {f.dst_port for f in cluster if f.dst_port > 0}
                    if len(unique_ports) >= self.vertical_port_threshold:
                        excess = len(unique_ports) - self.vertical_port_threshold
                        intensity_bonus = min(25.0, (excess // 5) * 5.0)
                        risk_score = min(95.0, 70.0 + intensity_bonus)

                        earliest_time = cluster[0].start_time
                        flow_ids = [f.id for f in cluster if f.id is not None]

                        evidence = {
                            "scan_type": "vertical",
                            "src_ip": src_ip,
                            "target_ip": dst_ip,
                            "unique_ports_observed": len(unique_ports),
                            "threshold": self.vertical_port_threshold,
                            "time_window_seconds": self.window_seconds,
                            "sample_probed_ports": sorted(list(unique_ports))[:25],
                        }

                        explanation = (
                            f"Source host {src_ip} probed {len(unique_ports)} unique destination ports "
                            f"on target {dst_ip} within a {self.window_seconds}s time window "
                            f"(threshold: {self.vertical_port_threshold}). Base severity: HIGH (70). "
                            f"Observed intensity modifier: +{intensity_bonus}. Total risk score: {risk_score}/100."
                        )

                        results.append(
                            DetectionResult(
                                rule_id="RULE_PORT_SCAN_VERTICAL",
                                rule_name="Vertical Port Scan Detected",
                                severity="HIGH",
                                risk_score=risk_score,
                                timestamp=earliest_time,
                                description=f"Source {src_ip} scanned {len(unique_ports)} ports on {dst_ip}",
                                explanation=explanation,
                                evidence=evidence,
                                src_ip=src_ip,
                                dst_ip=dst_ip,
                                protocol=cluster[0].protocol,
                                flow_ids=flow_ids,
                            )
                        )

            # --- 2. Horizontal Host Scan Evaluation (across distinct hosts) ---
            clusters = []
            cur = []
            for f in f_list:
                if not cur:
                    cur.append(f)
                elif f.start_time - cur[-1].start_time <= self.window_seconds:
                    cur.append(f)
                else:
                    clusters.append(cur)
                    cur = [f]
            if cur:
                clusters.append(cur)

            for cluster in clusters:
                unique_hosts = {f.dst_ip for f in cluster}
                if len(unique_hosts) >= self.horizontal_host_threshold:
                    excess = len(unique_hosts) - self.horizontal_host_threshold
                    intensity_bonus = min(25.0, (excess // 5) * 5.0)
                    risk_score = min(95.0, 70.0 + intensity_bonus)

                    earliest_time = cluster[0].start_time
                    flow_ids = [f.id for f in cluster if f.id is not None]

                    evidence = {
                        "scan_type": "horizontal",
                        "src_ip": src_ip,
                        "unique_targets_observed": len(unique_hosts),
                        "threshold": self.horizontal_host_threshold,
                        "time_window_seconds": self.window_seconds,
                        "sample_probed_hosts": sorted(list(unique_hosts))[:25],
                    }

                    explanation = (
                        f"Source host {src_ip} probed {len(unique_hosts)} distinct destination hosts "
                        f"within a {self.window_seconds}s time window "
                        f"(threshold: {self.horizontal_host_threshold}). Base severity: HIGH (70). "
                        f"Observed intensity modifier: +{intensity_bonus}. Total risk score: {risk_score}/100."
                    )

                    results.append(
                        DetectionResult(
                            rule_id="RULE_PORT_SCAN_HORIZONTAL",
                            rule_name="Horizontal Network Sweep Detected",
                            severity="HIGH",
                            risk_score=risk_score,
                            timestamp=earliest_time,
                            description=f"Source {src_ip} swept {len(unique_hosts)} destination hosts",
                            explanation=explanation,
                            evidence=evidence,
                            src_ip=src_ip,
                            dst_ip=None,
                            protocol=cluster[0].protocol,
                            flow_ids=flow_ids,
                        )
                    )

        return results
