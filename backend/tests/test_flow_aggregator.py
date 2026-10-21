"""Unit tests for the Bidirectional Flow Aggregation engine."""

from backend.app.pipeline.parser import ParsedPacket
from backend.app.pipeline.flow_aggregator import FlowAggregator, get_canonical_flow_key


def make_test_packet(
    src_ip="192.168.1.10",
    dst_ip="10.0.0.1",
    src_port=50000,
    dst_port=80,
    protocol="TCP",
    ip_version=4,
    timestamp=1000.0,
    ip_len=60,
    tcp_flags="S",
):
    return ParsedPacket(
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        ip_version=ip_version,
        frame_len=ip_len + 14,
        ip_len=ip_len,
        payload_len=0,
        tcp_flags=tcp_flags,
    )


def test_canonical_flow_key_direction_independence():
    key_fwd = get_canonical_flow_key("192.168.1.10", "10.0.0.1", 50000, 80, "TCP")
    key_rev = get_canonical_flow_key("10.0.0.1", "192.168.1.10", 80, 50000, "TCP")
    assert key_fwd == key_rev


def test_bidirectional_flow_merging_and_directional_counts():
    aggregator = FlowAggregator(timeout_seconds=60.0)

    # 1. Initiator packet (forward)
    pkt1 = make_test_packet(src_ip="192.168.1.10", dst_ip="10.0.0.1", src_port=50000, dst_port=80, timestamp=100.0, ip_len=60, tcp_flags="S")
    aggregator.add_packet(pkt1)

    # 2. Responder packet (backward)
    pkt2 = make_test_packet(src_ip="10.0.0.1", dst_ip="192.168.1.10", src_port=80, dst_port=50000, timestamp=100.1, ip_len=60, tcp_flags="SA")
    aggregator.add_packet(pkt2)

    # 3. Initiator packet (forward)
    pkt3 = make_test_packet(src_ip="192.168.1.10", dst_ip="10.0.0.1", src_port=50000, dst_port=80, timestamp=100.2, ip_len=100, tcp_flags="A")
    aggregator.add_packet(pkt3)

    flows = aggregator.finalize_all()
    assert len(flows) == 1

    flow = flows[0]
    assert flow.src_ip == "192.168.1.10"
    assert flow.dst_ip == "10.0.0.1"
    assert flow.src_port == 50000
    assert flow.dst_port == 80
    assert flow.protocol == "TCP"

    # Directional counts
    assert flow.forward_packets == 2
    assert flow.backward_packets == 1
    assert flow.total_packets == 3

    # Directional byte counts
    assert flow.forward_bytes == 160  # 60 + 100
    assert flow.backward_bytes == 60
    assert flow.total_bytes == 220

    # Timestamps & duration
    assert flow.start_time == 100.0
    assert flow.end_time == 100.2
    assert round(flow.duration, 2) == 0.20

    # Flags & TCP state
    assert flow.tcp_flags_forward == "AS"
    assert flow.tcp_flags_backward == "AS"
    assert flow.tcp_state == "ESTABLISHED"


def test_tcp_flags_and_connection_termination():
    aggregator = FlowAggregator(timeout_seconds=60.0)

    # Handshake
    aggregator.add_packet(make_test_packet(timestamp=10.0, tcp_flags="S"))
    aggregator.add_packet(make_test_packet(src_ip="10.0.0.1", dst_ip="192.168.1.10", src_port=80, dst_port=50000, timestamp=10.1, tcp_flags="SA"))
    aggregator.add_packet(make_test_packet(timestamp=10.2, tcp_flags="A"))
    assert aggregator.active_flows[get_canonical_flow_key("192.168.1.10", "10.0.0.1", 50000, 80, "TCP")].tcp_state == "ESTABLISHED"

    # Termination: FIN from client
    aggregator.add_packet(make_test_packet(timestamp=12.0, tcp_flags="FA"))
    flow = aggregator.active_flows[get_canonical_flow_key("192.168.1.10", "10.0.0.1", 50000, 80, "TCP")]
    assert flow.tcp_state == "CLOSING"

    # FIN from server
    aggregator.add_packet(make_test_packet(src_ip="10.0.0.1", dst_ip="192.168.1.10", src_port=80, dst_port=50000, timestamp=12.1, tcp_flags="FA"))
    assert flow.tcp_state == "CLOSED"

    # If server or client sends RST:
    aggregator.add_packet(make_test_packet(timestamp=12.2, tcp_flags="R"))
    assert flow.tcp_state == "RESET"


def test_flow_expiration_after_idle_timeout():
    aggregator = FlowAggregator(timeout_seconds=10.0)

    # First session
    aggregator.add_packet(make_test_packet(timestamp=100.0, tcp_flags="A"))
    aggregator.add_packet(make_test_packet(timestamp=102.0, tcp_flags="A"))

    # Packet arriving after 15 seconds (> 10.0s timeout)
    aggregator.add_packet(make_test_packet(timestamp=117.1, tcp_flags="A"))

    flows = aggregator.finalize_all()
    # Must separate into 2 distinct flows
    assert len(flows) == 2

    flow1 = flows[0]
    flow2 = flows[1]

    assert flow1.start_time == 100.0
    assert flow1.end_time == 102.0
    assert flow1.total_packets == 2

    assert flow2.start_time == 117.1
    assert flow2.end_time == 117.1
    assert flow2.total_packets == 1


def test_tcp_connection_reconnection_after_termination():
    aggregator = FlowAggregator(timeout_seconds=60.0)

    # Initial session ending with RST
    aggregator.add_packet(make_test_packet(timestamp=10.0, tcp_flags="S"))
    aggregator.add_packet(make_test_packet(timestamp=10.5, tcp_flags="R"))

    # New connection initiated on the exact same 5-tuple
    aggregator.add_packet(make_test_packet(timestamp=11.0, tcp_flags="S"))

    flows = aggregator.finalize_all()
    # Must separate into 2 flows
    assert len(flows) == 2
    assert flows[0].tcp_state == "RESET"
    assert flows[1].tcp_state == "SYN_SENT"


def test_udp_and_icmp_flows():
    aggregator = FlowAggregator(timeout_seconds=60.0)

    # UDP Flow
    aggregator.add_packet(make_test_packet(protocol="UDP", src_port=1234, dst_port=53, timestamp=1.0, tcp_flags=""))
    aggregator.add_packet(make_test_packet(protocol="UDP", src_ip="10.0.0.1", dst_ip="192.168.1.10", src_port=53, dst_port=1234, timestamp=1.1, tcp_flags=""))

    # ICMP Flow
    aggregator.add_packet(make_test_packet(protocol="ICMP", src_port=0, dst_port=0, timestamp=2.0, tcp_flags=""))

    flows = aggregator.finalize_all()
    assert len(flows) == 2

    udp_flow = [f for f in flows if f.protocol == "UDP"][0]
    icmp_flow = [f for f in flows if f.protocol == "ICMP"][0]

    assert udp_flow.forward_packets == 1
    assert udp_flow.backward_packets == 1
    assert udp_flow.tcp_state == "N/A"

    assert icmp_flow.src_port == 0
    assert icmp_flow.dst_port == 0
    assert icmp_flow.tcp_state == "N/A"


def test_synthetic_bidirectional_tcp_conversation():
    """Verify that a full 9-packet synthetic TCP session merges into a single bidirectional flow."""
    from data.generate_bidirectional_test_pcap import generate_bidirectional_packets
    from backend.app.pipeline.parser import parse_packet

    packets = generate_bidirectional_packets(
        client_ip="192.168.1.100",
        server_ip="10.0.0.5",
        client_port=54321,
        server_port=80,
        base_time=1766100000.0,
    )

    aggregator = FlowAggregator(timeout_seconds=60.0)
    for pkt in packets:
        parsed = parse_packet(pkt)
        assert parsed is not None
        aggregator.add_packet(parsed)

    flows = aggregator.finalize_all()

    # 1. All packets grouped into exactly one bidirectional flow
    assert len(flows) == 1
    flow = flows[0]

    # Endpoints & 5-tuple canonical key
    assert flow.src_ip == "192.168.1.100"
    assert flow.dst_ip == "10.0.0.5"
    assert flow.src_port == 54321
    assert flow.dst_port == 80
    assert flow.protocol == "TCP"
    assert flow.flow_key == "10.0.0.5:80-192.168.1.100:54321-TCP"

    # 2. Forward and reverse packet counts
    assert flow.forward_packets == 6
    assert flow.backward_packets == 3
    assert flow.total_packets == 9

    # 3. Directional byte counts matching documented semantics (IP layer length)
    # Forward: 40 (SYN) + 40 (ACK) + 93 (REQ) + 40 (ACK) + 40 (FIN-ACK) + 40 (ACK) = 293
    # Backward: 40 (SYN-ACK) + 118 (RESP) + 40 (FIN-ACK) = 198
    assert flow.forward_bytes == 293
    assert flow.backward_bytes == 198
    assert flow.total_bytes == 491

    # 4. TCP flags and connection-state indicators
    assert flow.tcp_flags_forward == "AFPS"
    assert flow.tcp_flags_backward == "AFPS"
    assert flow.tcp_state == "CLOSED"

    # 5. Flow duration calculation
    assert flow.start_time == 1766100000.0
    assert flow.end_time == 1766100000.8
    assert round(flow.duration, 4) == 0.8

