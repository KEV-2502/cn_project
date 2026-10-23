"""CIC-IDS2017 Feature Extraction and Semantic Normalization.

Extracts fixed 15-feature vectors from CIC-IDS2017 flow dictionaries.
Explicitly accounts for semantic divergences from NetShield's production schema:
1. Duration is converted from microseconds (CIC) to seconds (NetShield).
2. Rate features use a 1ms duration floor (1e-3 s) to prevent division by zero on instantaneous flows.
3. Ratios are derived from raw forward/backward counts and bytes (NOT from CIC's truncated Down/Up Ratio).
4. Directional byte counts in CICFlowMeter represent L4 transport payload bytes, unlike NetShield's
   production schema which sums IP-layer packet lengths (RFC 7011 IPFIX octet counts).
   This is explicitly recorded in metadata schema version 'v2_cicids2017_payload_features'.
"""

import math
from typing import Dict, Any, List
import numpy as np

# Feature schema names matching the 15 positions
FEATURE_NAMES: List[str] = [
    "forward_packets",
    "backward_packets",
    "forward_bytes",
    "backward_bytes",
    "duration",
    "packet_ratio",
    "byte_ratio",
    "forward_packet_rate",
    "backward_packet_rate",
    "forward_byte_rate",
    "backward_byte_rate",
    "is_tcp",
    "is_udp",
    "is_icmp",
    "avg_packet_size",
]

SCHEMA_VERSION: str = "v2_cicids2017_payload_features"
EPSILON_DURATION: float = 1e-3  # 1 millisecond floor to prevent zero-division


def _safe_float(val: Any, default: float = 0.0) -> float:
    """Safely convert value to finite float; return default if NaN, infinite, or invalid."""
    if val is None:
        return default
    try:
        f = float(val)
        return f if math.isfinite(f) else default
    except (TypeError, ValueError):
        return default


def extract_cic_features(row: Dict[str, Any]) -> np.ndarray:
    """Extract a 15-feature vector from a parsed CIC-IDS2017 CSV row dictionary.

    Returns:
        np.ndarray of shape (15,) with dtype float64.
    """
    # 1 & 2: Packet counts
    fwd_pkts = _safe_float(row.get("Total Fwd Packets", 0.0))
    bwd_pkts = _safe_float(row.get("Total Backward Packets", 0.0))
    fwd_pkts = max(0.0, fwd_pkts)
    bwd_pkts = max(0.0, bwd_pkts)

    # 3 & 4: Directional Byte totals (Note: CIC measures L4 payload bytes)
    fwd_bytes = _safe_float(row.get("Total Length of Fwd Packets", 0.0))
    bwd_bytes = _safe_float(row.get("Total Length of Bwd Packets", 0.0))
    fwd_bytes = max(0.0, fwd_bytes)
    bwd_bytes = max(0.0, bwd_bytes)

    # 5: Flow Duration (Convert microseconds to seconds, clamp negative to 0.0)
    raw_duration_us = _safe_float(row.get("Flow Duration", 0.0))
    duration_s = max(0.0, raw_duration_us / 1_000_000.0)

    # Total counts for ratios and averages
    total_pkts = max(1.0, fwd_pkts + bwd_pkts)
    total_bytes = max(0.0, fwd_bytes + bwd_bytes)

    # 6: Packet ratio (forward packets / total packets, bounded [0.0, 1.0])
    packet_ratio = min(1.0, max(0.0, fwd_pkts / total_pkts))

    # 7: Byte ratio (forward bytes / total bytes, bounded [0.0, 1.0])
    byte_ratio = min(1.0, max(0.0, fwd_bytes / max(1.0, total_bytes)))

    # 8 - 11: Directional packet and byte rates with safe duration floor
    effective_duration = max(duration_s, EPSILON_DURATION)
    fwd_pkt_rate = fwd_pkts / effective_duration
    bwd_pkt_rate = bwd_pkts / effective_duration
    fwd_byte_rate = fwd_bytes / effective_duration
    bwd_byte_rate = bwd_bytes / effective_duration

    # 12 - 14: Protocol indicators (Protocol in CIC is IANA number: 6=TCP, 17=UDP, 1=ICMP)
    try:
        proto_num = int(float(row.get("Protocol", 0)))
    except (ValueError, TypeError):
        proto_num = 0

    is_tcp = 1.0 if proto_num == 6 else 0.0
    is_udp = 1.0 if proto_num == 17 else 0.0
    is_icmp = 1.0 if proto_num == 1 else 0.0

    # 15: Average packet size (mean payload bytes per packet)
    avg_packet_size = total_bytes / total_pkts

    features = [
        fwd_pkts,
        bwd_pkts,
        fwd_bytes,
        bwd_bytes,
        duration_s,
        packet_ratio,
        byte_ratio,
        fwd_pkt_rate,
        bwd_pkt_rate,
        fwd_byte_rate,
        bwd_byte_rate,
        is_tcp,
        is_udp,
        is_icmp,
        avg_packet_size,
    ]

    sanitized = [_safe_float(x) for x in features]
    return np.array(sanitized, dtype=np.float64)


def extract_cic_batch(rows: List[Dict[str, Any]]) -> np.ndarray:
    """Extract a 2D matrix of shape (N, 15) from a list of row dicts."""
    if not rows:
        return np.empty((0, len(FEATURE_NAMES)), dtype=np.float64)
    return np.vstack([extract_cic_features(r) for r in rows])


def get_feature_documentation() -> List[Dict[str, Any]]:
    """Return explicit documentation of all 15 features and their semantic mapping."""
    return [
        {
            "index": 0,
            "feature": "forward_packets",
            "source_column": "Total Fwd Packets",
            "units": "packets",
            "directionality": "Forward (initiator -> responder)",
            "transformation": "max(0, float(col))",
            "semantic_compatibility": "Exact match with NetShield definition.",
        },
        {
            "index": 1,
            "feature": "backward_packets",
            "source_column": "Total Backward Packets",
            "units": "packets",
            "directionality": "Backward (responder -> initiator)",
            "transformation": "max(0, float(col))",
            "semantic_compatibility": "Exact match with NetShield definition.",
        },
        {
            "index": 2,
            "feature": "forward_bytes",
            "source_column": "Total Length of Fwd Packets",
            "units": "bytes",
            "directionality": "Forward",
            "transformation": "max(0, float(col))",
            "semantic_compatibility": (
                "SEMANTIC DIVERGENCE: CICFlowMeter measures L4 transport payload bytes "
                "(pure TCP control packets have 0 bytes). NetShield measures IP-layer total length "
                "(pure control packets have 40-60 bytes). Not directly interchangeable."
            ),
        },
        {
            "index": 3,
            "feature": "backward_bytes",
            "source_column": "Total Length of Bwd Packets",
            "units": "bytes",
            "directionality": "Backward",
            "transformation": "max(0, float(col))",
            "semantic_compatibility": "SEMANTIC DIVERGENCE: Same L4 payload vs IP-layer discrepancy.",
        },
        {
            "index": 4,
            "feature": "duration",
            "source_column": "Flow Duration",
            "units": "seconds",
            "directionality": "Bidirectional",
            "transformation": "max(0.0, float(col) / 1,000,000.0)",
            "semantic_compatibility": (
                "Valid with scale conversion. CIC is in microseconds; converted to seconds. "
                "Negative durations clamped to 0.0."
            ),
        },
        {
            "index": 5,
            "feature": "packet_ratio",
            "source_column": "Derived from Total Fwd Packets and Total Backward Packets",
            "units": "ratio [0.0, 1.0]",
            "directionality": "Forward / Total",
            "transformation": "fwd_pkts / max(1.0, fwd_pkts + bwd_pkts)",
            "semantic_compatibility": (
                "Valid mathematical derivation. CIC's Down/Up Ratio is an integer-truncated "
                "backward/forward ratio and was not used."
            ),
        },
        {
            "index": 6,
            "feature": "byte_ratio",
            "source_column": "Derived from Total Length of Fwd and Bwd Packets",
            "units": "ratio [0.0, 1.0]",
            "directionality": "Forward / Total",
            "transformation": "fwd_bytes / max(1.0, fwd_bytes + bwd_bytes)",
            "semantic_compatibility": "Valid derivation on payload bytes (inherits payload semantics).",
        },
        {
            "index": 7,
            "feature": "forward_packet_rate",
            "source_column": "Total Fwd Packets / max(duration_s, 1e-3)",
            "units": "packets/second",
            "directionality": "Forward",
            "transformation": "fwd_pkts / max(duration_s, 0.001)",
            "semantic_compatibility": (
                "Harmonized with NetShield rate formula. Avoids CIC Fwd Packets/s non-finite values."
            ),
        },
        {
            "index": 8,
            "feature": "backward_packet_rate",
            "source_column": "Total Backward Packets / max(duration_s, 1e-3)",
            "units": "packets/second",
            "directionality": "Backward",
            "transformation": "bwd_pkts / max(duration_s, 0.001)",
            "semantic_compatibility": "Harmonized with NetShield rate formula.",
        },
        {
            "index": 9,
            "feature": "forward_byte_rate",
            "source_column": "Total Length of Fwd Packets / max(duration_s, 1e-3)",
            "units": "bytes/second",
            "directionality": "Forward",
            "transformation": "fwd_bytes / max(duration_s, 0.001)",
            "semantic_compatibility": "Synthesized directional rate (unavailable in raw CIC CSV).",
        },
        {
            "index": 10,
            "feature": "backward_byte_rate",
            "source_column": "Total Length of Bwd Packets / max(duration_s, 1e-3)",
            "units": "bytes/second",
            "directionality": "Backward",
            "transformation": "bwd_bytes / max(duration_s, 0.001)",
            "semantic_compatibility": "Synthesized directional rate (unavailable in raw CIC CSV).",
        },
        {
            "index": 11,
            "feature": "is_tcp",
            "source_column": "Protocol",
            "units": "binary {0.0, 1.0}",
            "directionality": "N/A",
            "transformation": "1.0 if Protocol == 6 else 0.0",
            "semantic_compatibility": "Exact match for IANA TCP protocol number.",
        },
        {
            "index": 12,
            "feature": "is_udp",
            "source_column": "Protocol",
            "units": "binary {0.0, 1.0}",
            "directionality": "N/A",
            "transformation": "1.0 if Protocol == 17 else 0.0",
            "semantic_compatibility": "Exact match for IANA UDP protocol number.",
        },
        {
            "index": 13,
            "feature": "is_icmp",
            "source_column": "Protocol",
            "units": "binary {0.0, 1.0}",
            "directionality": "N/A",
            "transformation": "1.0 if Protocol == 1 else 0.0",
            "semantic_compatibility": "Valid mapping, but 0 instances of ICMP exist in CIC-IDS2017.",
        },
        {
            "index": 14,
            "feature": "avg_packet_size",
            "source_column": "(fwd_bytes + bwd_bytes) / max(1.0, fwd_pkts + bwd_pkts)",
            "units": "bytes/packet",
            "directionality": "Bidirectional",
            "transformation": "(fwd_bytes + bwd_bytes) / total_pkts",
            "semantic_compatibility": (
                "Calculated reliably from totals; raw CIC 'Average Packet Size' exhibits "
                "accumulator bugs on asymmetric flows and was not used."
            ),
        },
    ]
