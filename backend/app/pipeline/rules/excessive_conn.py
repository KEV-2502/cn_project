"""Excessive Connection Attempts Detection Rule.

Detects unusually high connection rates directed at a target host or service
within a sliding time window.
"""

from typing import List, Dict, Set
from collections import defaultdict
from backend.app.models.flow import NetworkFlow
from backend.app.models.dns import DnsQueryRecord
from backend.app.pipeline.rules.base import BaseRule, DetectionResult
from backend.app.config import settings


class ExcessiveConnectionRule(BaseRule):
    """Detects connection bursts targeting a specific service or host."""

    def __init__(
        self,
        rate_threshold: int = settings.EXCESSIVE_CONN_RATE,
        window_seconds: float = settings.EXCESSIVE_CONN_WINDOW_SECONDS,
    ):
        self.rate_threshold = rate_threshold
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

        # Filter for connection-oriented (TCP) flows
        tcp_flows = [f for f in flows if f.protocol == "TCP"]
        if not tcp_flows:
            return results

        # Group flows by (src_ip, dst_ip, dst_port)
        target_groups: Dict[tuple, List[NetworkFlow]] = defaultdict(list)
        for f in tcp_flows:
            target_groups[(f.src_ip, f.dst_ip, f.dst_port)].append(f)

        for (src_ip, dst_ip, dst_port), t_flows in target_groups.items():
            if len(t_flows) < self.rate_threshold:
                continue

            t_flows.sort(key=lambda x: x.start_time)
            i = 0
            n = len(t_flows)
            while i < n:
                window_end = t_flows[i].start_time + self.window_seconds
                j = i
                while j < n and t_flows[j].start_time <= window_end:
                    j += 1

                count = j - i
                if count >= self.rate_threshold:
                    cluster = t_flows[i:j]
                    excess = count - self.rate_threshold
                    intensity_bonus = min(25.0, (excess // 10) * 5.0)
                    risk_score = min(90.0, 55.0 + intensity_bonus)

                    flow_ids = [f.id for f in cluster if f.id is not None]
                    tcp_states = sorted(list({f.tcp_state for f in cluster}))

                    evidence = {
                        "src_ip": src_ip,
                        "target_ip": dst_ip,
                        "target_port": dst_port,
                        "attempt_count": count,
                        "threshold": self.rate_threshold,
                        "time_window_seconds": self.window_seconds,
                        "tcp_states_observed": tcp_states,
                    }

                    explanation = (
                        f"Observed {count} connection attempts from {src_ip} to target {dst_ip}:{dst_port} "
                        f"within {self.window_seconds}s (threshold: {self.rate_threshold}). "
                        f"High connection frequency suggests automated polling, service stress, or connection exhaustion. "
                        f"Packet metadata does not indicate whether application authentication succeeded or failed. "
                        f"Base severity: MEDIUM (55). Intensity modifier: +{intensity_bonus}. Total risk: {risk_score}/100."
                    )

                    results.append(
                        DetectionResult(
                            rule_id="RULE_EXCESSIVE_CONN_RATE",
                            rule_name="Excessive Connection Attempts Detected",
                            severity="MEDIUM" if risk_score < 75.0 else "HIGH",
                            risk_score=risk_score,
                            timestamp=cluster[0].start_time,
                            description=f"Source {src_ip} opened {count} connection attempts to {dst_ip}:{dst_port}",
                            explanation=explanation,
                            evidence=evidence,
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            src_port=None,
                            dst_port=dst_port,
                            protocol="TCP",
                            flow_ids=flow_ids,
                        )
                    )
                    # Advance past this alerted window to prevent duplicate alert spam
                    i = j
                else:
                    i += 1

        return results
