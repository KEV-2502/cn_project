"""Bidirectional Network Flow Aggregation Engine.

Aggregates individual packets into bidirectional network flows using a canonical
5-tuple key. Tracks directional packet/byte statistics, TCP connection states,
flow duration, and applies idle timeouts and TCP termination semantics.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
from backend.app.pipeline.parser import ParsedPacket


def get_canonical_flow_key(src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: str) -> str:
    """Generate a direction-independent canonical flow key.

    Normalizes endpoint order so packets travelling in opposite directions
    map to the exact same canonical key.
    """
    ep1 = (src_ip, src_port)
    ep2 = (dst_ip, dst_port)
    if ep1 > ep2:
        ep1, ep2 = ep2, ep1
    return f"{ep1[0]}:{ep1[1]}-{ep2[0]}:{ep2[1]}-{protocol}"


@dataclass
class AggregatedFlow:
    flow_key: str
    src_ip: str          # Initiator endpoint IP
    dst_ip: str          # Responder endpoint IP
    src_port: int        # Initiator port
    dst_port: int        # Responder port
    protocol: str        # TCP, UDP, ICMP, DNS
    ip_version: int      # 4 or 6

    start_time: float    # First seen epoch timestamp
    end_time: float      # Last seen epoch timestamp
    duration: float = 0.0

    forward_packets: int = 0
    backward_packets: int = 0
    forward_bytes: int = 0
    backward_bytes: int = 0
    total_packets: int = 0
    total_bytes: int = 0

    tcp_flags_forward_set: Set[str] = field(default_factory=set)
    tcp_flags_backward_set: Set[str] = field(default_factory=set)
    tcp_state: str = "N/A"

    # Tracking flags seen in each direction for connection state
    _fwd_has_syn: bool = False
    _rev_has_syn: bool = False
    _fwd_has_ack: bool = False
    _rev_has_ack: bool = False
    _fwd_has_fin: bool = False
    _rev_has_fin: bool = False
    _has_rst: bool = False

    @property
    def tcp_flags_forward(self) -> str:
        return "".join(sorted(self.tcp_flags_forward_set))

    @property
    def tcp_flags_backward(self) -> str:
        return "".join(sorted(self.tcp_flags_backward_set))

    def update_with_packet(self, pkt: ParsedPacket) -> None:
        """Update flow metrics with a newly observed packet."""
        # Timestamps
        if pkt.timestamp < self.start_time:
            self.start_time = pkt.timestamp
        if pkt.timestamp > self.end_time:
            self.end_time = pkt.timestamp
        self.duration = max(0.0, self.end_time - self.start_time)

        is_forward = (pkt.src_ip == self.src_ip and pkt.src_port == self.src_port)

        if is_forward:
            self.forward_packets += 1
            self.forward_bytes += pkt.ip_len
            if pkt.tcp_flags:
                for char in pkt.tcp_flags:
                    self.tcp_flags_forward_set.add(char)
        else:
            self.backward_packets += 1
            self.backward_bytes += pkt.ip_len
            if pkt.tcp_flags:
                for char in pkt.tcp_flags:
                    self.tcp_flags_backward_set.add(char)

        self.total_packets = self.forward_packets + self.backward_packets
        self.total_bytes = self.forward_bytes + self.backward_bytes

        # Update TCP connection state
        if self.protocol == "TCP":
            self._update_tcp_state(pkt, is_forward)
        else:
            self.tcp_state = "N/A"

    def _update_tcp_state(self, pkt: ParsedPacket, is_forward: bool) -> None:
        flags = pkt.tcp_flags
        if not flags:
            return

        if "R" in flags:
            self._has_rst = True
            self.tcp_state = "RESET"
            return

        if is_forward:
            if "S" in flags:
                self._fwd_has_syn = True
            if "A" in flags:
                self._fwd_has_ack = True
            if "F" in flags:
                self._fwd_has_fin = True
        else:
            if "S" in flags:
                self._rev_has_syn = True
            if "A" in flags:
                self._rev_has_ack = True
            if "F" in flags:
                self._rev_has_fin = True

        # State evaluation
        if self._has_rst:
            self.tcp_state = "RESET"
        elif self._fwd_has_fin and self._rev_has_fin:
            self.tcp_state = "CLOSED"
        elif self._fwd_has_fin or self._rev_has_fin:
            self.tcp_state = "CLOSING"
        elif self._fwd_has_syn and self._rev_has_syn and (self._fwd_has_ack or self._rev_has_ack):
            self.tcp_state = "ESTABLISHED"
        elif self._fwd_has_syn and self._rev_has_syn:
            self.tcp_state = "SYN_ACK_RECEIVED"
        elif self._fwd_has_syn and not self._rev_has_syn:
            self.tcp_state = "SYN_SENT"
        elif self._fwd_has_ack or self._rev_has_ack:
            # Established communication observed mid-stream
            self.tcp_state = "ESTABLISHED"


class FlowAggregator:
    """Manages active bidirectional network flows, session expiration, and state tracking."""

    def __init__(self, timeout_seconds: float = 60.0):
        self.timeout_seconds = timeout_seconds
        self.active_flows: Dict[str, AggregatedFlow] = {}
        self.completed_flows: List[AggregatedFlow] = []

    def add_packet(self, pkt: ParsedPacket) -> None:
        """Process a packet and update or create its corresponding bidirectional flow."""
        flow_key = get_canonical_flow_key(
            pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port, pkt.protocol
        )

        existing_flow = self.active_flows.get(flow_key)

        if existing_flow:
            # Check for idle timeout expiration
            time_gap = pkt.timestamp - existing_flow.end_time
            if time_gap > self.timeout_seconds:
                # Flow has timed out; finalize current session and start a new one
                self.completed_flows.append(existing_flow)
                existing_flow = None

            # Check for TCP connection restart after termination
            elif existing_flow.protocol == "TCP":
                if existing_flow.tcp_state in ("CLOSED", "RESET") and "S" in pkt.tcp_flags:
                    # New connection handshake on same 5-tuple
                    self.completed_flows.append(existing_flow)
                    existing_flow = None

        if existing_flow is None:
            # Initialize a new bidirectional flow
            new_flow = AggregatedFlow(
                flow_key=flow_key,
                src_ip=pkt.src_ip,
                dst_ip=pkt.dst_ip,
                src_port=pkt.src_port,
                dst_port=pkt.dst_port,
                protocol=pkt.protocol,
                ip_version=pkt.ip_version,
                start_time=pkt.timestamp,
                end_time=pkt.timestamp,
                duration=0.0,
            )
            new_flow.update_with_packet(pkt)
            self.active_flows[flow_key] = new_flow
        else:
            existing_flow.update_with_packet(pkt)

    def finalize_all(self) -> List[AggregatedFlow]:
        """Retire all active flows and return the full list of aggregated flows."""
        for flow in self.active_flows.values():
            self.completed_flows.append(flow)
        self.active_flows.clear()
        return self.completed_flows
