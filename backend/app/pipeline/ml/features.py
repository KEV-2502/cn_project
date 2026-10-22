"""Network Flow Feature Extraction Pipeline.

Extracts fixed-order numerical feature vectors from bidirectional network flows
for machine-learning anomaly detection.

Feature Semantics:
------------------
1. forward_packets: Number of packets transmitted from initiator to responder.
2. backward_packets: Number of packets transmitted from responder to initiator.
3. forward_bytes: Total IP-layer bytes from initiator to responder.
4. backward_bytes: Total IP-layer bytes from responder to initiator.
5. duration: Total flow duration in seconds.
6. packet_ratio: Ratio of forward packets to total packets [0.0, 1.0].
7. byte_ratio: Ratio of forward bytes to total bytes [0.0, 1.0].
8. forward_packet_rate: Forward packets per second (packets/s).
9. backward_packet_rate: Backward packets per second (packets/s).
10. forward_byte_rate: Forward bytes per second (bytes/s).
11. backward_byte_rate: Backward bytes per second (bytes/s).
12. is_tcp: Binary indicator (1 if protocol is TCP, 0 otherwise).
13. is_udp: Binary indicator (1 if protocol is UDP, 0 otherwise).
14. is_icmp: Binary indicator (1 if protocol is ICMP, 0 otherwise).
15. avg_packet_size: Average byte size per packet across the entire flow.

Zero-Duration and Edge Cases:
------------------------------
For sub-millisecond or zero-duration flows, rates are computed using a small epsilon
(1e-3 seconds) to prevent division by zero while preserving relative rate ordering.
Missing, NaN, or non-finite values are sanitized to 0.0.
"""

from typing import List, Dict, Any, Union
import math
import numpy as np

# Fixed feature schema shared strictly between training and inference
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

EPSILON_DURATION: float = 1e-3  # 1 ms floor to prevent zero-division


def _safe_float(val: Any, default: float = 0.0) -> float:
    """Convert value to finite float; return default if NaN, infinite, or invalid."""
    try:
        f = float(val)
        return f if math.isfinite(f) else default
    except (TypeError, ValueError):
        return default


def extract_flow_features(flow: Any) -> np.ndarray:
    """Extract a 1D numpy array of numerical features from a flow object or dict.

    Accepts SQLAlchemy NetworkFlow models, AggregatedFlow instances, or dicts.
    Returns a numpy array of shape (15,) with dtype float64.
    """
    if isinstance(flow, dict):
        fwd_pkts = _safe_float(flow.get("forward_packets", 0))
        bwd_pkts = _safe_float(flow.get("backward_packets", 0))
        fwd_bytes = _safe_float(flow.get("forward_bytes", 0))
        bwd_bytes = _safe_float(flow.get("backward_bytes", 0))
        duration = max(0.0, _safe_float(flow.get("duration", 0.0)))
        proto = str(flow.get("protocol", "")).upper()
    else:
        fwd_pkts = _safe_float(getattr(flow, "forward_packets", 0))
        bwd_pkts = _safe_float(getattr(flow, "backward_packets", 0))
        fwd_bytes = _safe_float(getattr(flow, "forward_bytes", 0))
        bwd_bytes = _safe_float(getattr(flow, "backward_bytes", 0))
        duration = max(0.0, _safe_float(getattr(flow, "duration", 0.0)))
        proto = str(getattr(flow, "protocol", "")).upper()

    total_pkts = max(1.0, fwd_pkts + bwd_pkts)
    total_bytes = max(0.0, fwd_bytes + bwd_bytes)

    # Ratios (bounded in [0.0, 1.0])
    packet_ratio = min(1.0, max(0.0, fwd_pkts / total_pkts))
    byte_ratio = min(1.0, max(0.0, fwd_bytes / max(1.0, total_bytes)))

    # Rates with duration floor
    effective_duration = max(duration, EPSILON_DURATION)
    fwd_pkt_rate = fwd_pkts / effective_duration
    bwd_pkt_rate = bwd_pkts / effective_duration
    fwd_byte_rate = fwd_bytes / effective_duration
    bwd_byte_rate = bwd_bytes / effective_duration

    # Protocol flags
    is_tcp = 1.0 if proto == "TCP" else 0.0
    is_udp = 1.0 if proto in ("UDP", "DNS") else 0.0
    is_icmp = 1.0 if proto == "ICMP" else 0.0

    # Average packet size
    avg_packet_size = total_bytes / total_pkts

    features = [
        fwd_pkts,
        bwd_pkts,
        fwd_bytes,
        bwd_bytes,
        duration,
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

    # Sanitize any unexpected non-finite floats
    sanitized = [_safe_float(x) for x in features]
    return np.array(sanitized, dtype=np.float64)


def extract_batch_features(flows: List[Any]) -> np.ndarray:
    """Extract a 2D numpy matrix of features of shape (N, 15) from a list of flows."""
    if not flows:
        return np.empty((0, len(FEATURE_NAMES)), dtype=np.float64)
    return np.vstack([extract_flow_features(f) for f in flows])
