"""Suspicious DNS Behaviour Detection Rule.

Detects high-volume DNS bursts, abnormally long query names (potential DNS tunneling / exfiltration),
and high unique subdomain/domain query diversity (domain generation / enumeration).
"""

from typing import List, Dict, Set
from collections import defaultdict
from backend.app.models.flow import NetworkFlow
from backend.app.models.dns import DnsQueryRecord
from backend.app.pipeline.rules.base import BaseRule, DetectionResult
from backend.app.config import settings


class DnsThreatRule(BaseRule):
    """Evaluates DNS query records for anomalies and suspicious indicators."""

    def __init__(
        self,
        burst_threshold: int = settings.DNS_BURST_QUERY_COUNT,
        burst_window_seconds: float = settings.DNS_BURST_WINDOW_SECONDS,
        long_name_length: int = settings.DNS_LONG_NAME_LENGTH,
        unique_domains_threshold: int = settings.DNS_UNIQUE_DOMAINS_THRESHOLD,
    ):
        self.burst_threshold = burst_threshold
        self.burst_window_seconds = burst_window_seconds
        self.long_name_length = long_name_length
        self.unique_domains_threshold = unique_domains_threshold

    def evaluate(
        self,
        pcap_id: int,
        flows: List[NetworkFlow],
        dns_records: List[DnsQueryRecord],
    ) -> List[DetectionResult]:
        results: List[DetectionResult] = []
        if not dns_records:
            return results

        # Group queries by source IP
        src_queries: Dict[str, List[DnsQueryRecord]] = defaultdict(list)
        for r in dns_records:
            if not r.is_response and r.query_name:
                src_queries[r.src_ip].append(r)

        for src_ip, q_list in src_queries.items():
            q_list.sort(key=lambda x: x.timestamp)

            # --- Indicator 1: Abnormally Long Query Names (DNS Tunneling) ---
            long_queries = [q for q in q_list if q.query_length >= self.long_name_length]
            if long_queries:
                longest = max(long_queries, key=lambda x: x.query_length)
                excess = longest.query_length - self.long_name_length
                intensity_bonus = min(25.0, (excess // 10) * 5.0)
                risk_score = min(95.0, 70.0 + intensity_bonus)

                evidence = {
                    "src_ip": src_ip,
                    "target_dns_server": longest.dst_ip,
                    "longest_query_name": longest.query_name,
                    "longest_query_length": longest.query_length,
                    "threshold_length": self.long_name_length,
                    "total_long_queries_observed": len(long_queries),
                    "sample_long_queries": [q.query_name for q in long_queries[:5]],
                }

                explanation = (
                    f"Observed DNS query '{longest.query_name[:35]}...' of length {longest.query_length} "
                    f"from {src_ip} exceeding maximum expected name length threshold {self.long_name_length}. "
                    f"Abnormally long DNS names frequently indicate base32/hex-encoded data tunneling or C2 communications. "
                    f"Base severity: HIGH (70). Length intensity modifier: +{intensity_bonus}. Risk score: {risk_score}/100."
                )

                results.append(
                    DetectionResult(
                        rule_id="RULE_DNS_TUNNELING_LONG_NAME",
                        rule_name="Potential DNS Tunneling / Exfiltration Detected",
                        severity="HIGH",
                        risk_score=risk_score,
                        timestamp=longest.timestamp,
                        description=f"Source {src_ip} queried abnormally long domain ({longest.query_length} chars)",
                        explanation=explanation,
                        evidence=evidence,
                        src_ip=src_ip,
                        dst_ip=longest.dst_ip,
                        src_port=None,
                        dst_port=53,
                        protocol="DNS",
                    )
                )

            # --- Indicator 2: High DNS Query Volume (DNS Burst) ---
            clusters: List[List[DnsQueryRecord]] = []
            cur: List[DnsQueryRecord] = []
            for q in q_list:
                if not cur:
                    cur.append(q)
                elif q.timestamp - cur[-1].timestamp <= self.burst_window_seconds:
                    cur.append(q)
                else:
                    clusters.append(cur)
                    cur = [q]
            if cur:
                clusters.append(cur)

            for cluster in clusters:
                count = len(cluster)
                if count >= self.burst_threshold:
                    excess = count - self.burst_threshold
                    intensity_bonus = min(30.0, (excess // 10) * 5.0)
                    risk_score = min(85.0, 50.0 + intensity_bonus)

                    evidence = {
                        "src_ip": src_ip,
                        "query_count": count,
                        "threshold": self.burst_threshold,
                        "time_window_seconds": self.burst_window_seconds,
                    }

                    explanation = (
                        f"Source {src_ip} generated {count} DNS queries within {self.burst_window_seconds}s "
                        f"(threshold: {self.burst_threshold}). Rapid query bursts may indicate fast-flux lookups, "
                        f"resolver flooding, or heavy network scanning. Base severity: MEDIUM (50). "
                        f"Volume modifier: +{intensity_bonus}. Total risk score: {risk_score}/100."
                    )

                    results.append(
                        DetectionResult(
                            rule_id="RULE_DNS_HIGH_VOLUME",
                            rule_name="Excessive DNS Query Volume Detected",
                            severity="MEDIUM",
                            risk_score=risk_score,
                            timestamp=cluster[0].timestamp,
                            description=f"Source {src_ip} sent {count} DNS queries in {self.burst_window_seconds}s",
                            explanation=explanation,
                            evidence=evidence,
                            src_ip=src_ip,
                            dst_ip=cluster[0].dst_ip,
                            protocol="DNS",
                        )
                    )

            # --- Indicator 3: High Subdomain / Unique Domain Diversity ---
            unique_domains = {q.query_name for q in q_list}
            if len(unique_domains) >= self.unique_domains_threshold:
                excess = len(unique_domains) - self.unique_domains_threshold
                intensity_bonus = min(25.0, (excess // 5) * 5.0)
                risk_score = min(85.0, 60.0 + intensity_bonus)

                evidence = {
                    "src_ip": src_ip,
                    "unique_domains_count": len(unique_domains),
                    "threshold": self.unique_domains_threshold,
                    "sample_queries": sorted(list(unique_domains))[:15],
                }

                explanation = (
                    f"Source {src_ip} queried {len(unique_domains)} unique domain names (threshold: {self.unique_domains_threshold}). "
                    f"High query diversity with low reuse is characteristic of Domain Generation Algorithms (DGA) or subdomain enumeration. "
                    f"Base severity: MEDIUM (60). Diversity modifier: +{intensity_bonus}. Total risk score: {risk_score}/100."
                )

                results.append(
                    DetectionResult(
                        rule_id="RULE_DNS_HIGH_DIVERSITY",
                        rule_name="Suspicious DNS Domain Generation / Diversity Detected",
                        severity="MEDIUM" if risk_score < 75.0 else "HIGH",
                        risk_score=risk_score,
                        timestamp=q_list[0].timestamp,
                        description=f"Source {src_ip} queried {len(unique_domains)} unique domain names",
                        explanation=explanation,
                        evidence=evidence,
                        src_ip=src_ip,
                        protocol="DNS",
                    )
                )

        return results
