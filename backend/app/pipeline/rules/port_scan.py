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

    @staticmethod
    def is_scan_probe(flow: NetworkFlow) -> bool:
        """Determines if a flow represents a scanning probe rather than an established session.

        A flow is classified as a probe if:
        1. It received no backward response (unanswered SYN, UDP, or ICMP probe).
        2. TCP connection was rejected (RESET) with minimal backward data.
        3. TCP connection remained incomplete (SYN_SENT, INCOMPLETE).
        4. Embryonic TCP connection without application data exchange
           (total_packets <= 3, forward_bytes <= 120, backward_bytes <= 80).
        """
        bwd_pkts = flow.backward_packets or 0
        bwd_bytes = flow.backward_bytes or 0
        fwd_bytes = flow.forward_bytes or 0
        tot_pkts = flow.total_packets or (flow.forward_packets or 0) + bwd_pkts
        tcp_state = flow.tcp_state or "N/A"

        # Unanswered / unreplied flow
        if bwd_pkts == 0 or bwd_bytes == 0:
            return True

        if flow.protocol == "TCP":
            # Incomplete or rejected handshakes
            if tcp_state in ("SYN_SENT", "INCOMPLETE"):
                return True
            if tcp_state == "RESET" and (bwd_bytes <= 60 or bwd_pkts <= 1):
                return True
            # Embryonic handshake without application data payload
            if tot_pkts <= 3 and fwd_bytes <= 120 and bwd_bytes <= 80:
                return True
        elif flow.protocol in ("UDP", "ICMP", "DNS"):
            if bwd_pkts == 0 or bwd_bytes == 0:
                return True

        return False

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
            # Filter for scan probe flows and evaluate across a bounded sliding window
            probe_flows_only = [f for f in f_list if self.is_scan_probe(f)]
            if len(probe_flows_only) >= self.horizontal_host_threshold:
                probe_flows_only.sort(key=lambda x: x.start_time)
                i = 0
                n = len(probe_flows_only)
                while i < n:
                    window_end = probe_flows_only[i].start_time + self.window_seconds
                    j = i
                    while j < n and probe_flows_only[j].start_time <= window_end:
                        j += 1

                    window_probes = probe_flows_only[i:j]
                    unique_probe_hosts = {f.dst_ip for f in window_probes}

                    if len(unique_probe_hosts) >= self.horizontal_host_threshold:
                        excess = len(unique_probe_hosts) - self.horizontal_host_threshold
                        intensity_bonus = min(25.0, (excess // 5) * 5.0)
                        risk_score = min(95.0, 70.0 + intensity_bonus)

                        earliest_time = window_probes[0].start_time
                        flow_ids = [f.id for f in window_probes if f.id is not None]

                        evidence = {
                            "scan_type": "horizontal",
                            "src_ip": src_ip,
                            "unique_targets_observed": len(unique_probe_hosts),
                            "probe_flows_observed": len(window_probes),
                            "threshold": self.horizontal_host_threshold,
                            "time_window_seconds": self.window_seconds,
                            "sample_probed_hosts": sorted(list(unique_probe_hosts))[:25],
                        }

                        explanation = (
                            f"Source host {src_ip} probed {len(unique_probe_hosts)} distinct destination hosts "
                            f"with scan probes within a {self.window_seconds}s time window "
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
                                description=f"Source {src_ip} swept {len(unique_probe_hosts)} destination hosts",
                                explanation=explanation,
                                evidence=evidence,
                                src_ip=src_ip,
                                dst_ip=None,
                                protocol=window_probes[0].protocol,
                                flow_ids=flow_ids,
                            )
                        )
                        # Advance past this alerted burst to prevent duplicate alerts
                        i = j
                    else:
                        i += 1

        return results
