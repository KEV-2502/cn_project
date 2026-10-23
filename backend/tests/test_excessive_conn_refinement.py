"""Regression tests for the refined ExcessiveConnectionRule.

Verifies:
1. Bounded sliding window correctly detects genuine high-rate bursts within window_seconds.
2. Traffic spread across extended intervals (e.g. 45 flows over 20s) does NOT chain or false-alarm.
3. UDP flows (such as DNS query datagrams) are NOT treated as connection attempts.
4. TCP connection floods targeting ANY port (including port 53) ARE detected (no port whitelisting).
5. Strict boundary rate thresholding (39 vs 40 attempts).
"""

import pytest
from backend.app.models.flow import NetworkFlow
from backend.app.pipeline.rules.excessive_conn import ExcessiveConnectionRule


def make_conn_flow(
    id: int,
    src_ip: str = "192.168.1.100",
    dst_ip: str = "10.0.0.1",
    src_port: int = 40000,
    dst_port: int = 80,
    protocol: str = "TCP",
    start_time: float = 100.0,
    duration: float = 0.05,
    forward_packets: int = 2,
    backward_packets: int = 1,
    forward_bytes: int = 120,
    backward_bytes: int = 60,
    tcp_state: str = "ESTABLISHED",
) -> NetworkFlow:
    """Helper to construct NetworkFlow objects for testing."""
    return NetworkFlow(
        id=id,
        pcap_id=1,
        flow_key=f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}",
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        ip_version=4,
        start_time=start_time,
        end_time=start_time + duration,
        duration=duration,
        forward_packets=forward_packets,
        backward_packets=backward_packets,
        forward_bytes=forward_bytes,
        backward_bytes=backward_bytes,
        total_packets=forward_packets + backward_packets,
        total_bytes=forward_bytes + backward_bytes,
        tcp_flags_forward="S",
        tcp_flags_backward="SA",
        tcp_state=tcp_state,
        anomaly_score=0.0,
        is_anomaly=0,
    )


def test_sliding_window_burst_detected():
    """45 TCP connections within 3 seconds must trigger an alert."""
    rule = ExcessiveConnectionRule(rate_threshold=40, window_seconds=5.0)

    flows = [
        make_conn_flow(
            id=i,
            src_ip="172.16.0.1",
            dst_ip="192.168.10.50",
            src_port=30000 + i,
            dst_port=80,
            start_time=10.0 + (i * 0.06),
        )
        for i in range(45)
    ]

    results = rule.evaluate(pcap_id=1, flows=flows, dns_records=[])
    assert len(results) == 1
    alert = results[0]
    assert alert.rule_id == "RULE_EXCESSIVE_CONN_RATE"
    assert alert.src_ip == "172.16.0.1"
    assert alert.dst_ip == "192.168.10.50"
    assert alert.dst_port == 80
    assert alert.evidence["attempt_count"] == 45
    assert len(alert.flow_ids) == 45


def test_spread_traffic_no_chaining_false_alert():
    """45 TCP connections spread evenly over 20 seconds (gaps of ~0.45s) must NOT chain into a false alert."""
    rule = ExcessiveConnectionRule(rate_threshold=40, window_seconds=5.0)

    # In any 5-second window, at most ~12 flows occur
    flows = [
        make_conn_flow(
            id=i,
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=30000 + i,
            dst_port=443,
            start_time=10.0 + (i * 0.45),
        )
        for i in range(45)
    ]

    results = rule.evaluate(pcap_id=1, flows=flows, dns_records=[])
    assert len(results) == 0, f"Expected 0 alerts for spread traffic, got {len(results)}"


def test_udp_flows_not_treated_as_connections():
    """High-rate UDP traffic (such as DNS queries) must NOT trigger excessive connection alerts."""
    rule = ExcessiveConnectionRule(rate_threshold=40, window_seconds=5.0)

    # 60 UDP queries to port 53 in 2 seconds
    flows = [
        make_conn_flow(
            id=i,
            src_ip="192.168.1.17",
            dst_ip="192.168.1.3",
            src_port=50000 + i,
            dst_port=53,
            protocol="UDP",
            start_time=10.0 + (i * 0.03),
            tcp_state="N/A",
        )
        for i in range(60)
    ]

    results = rule.evaluate(pcap_id=1, flows=flows, dns_records=[])
    assert len(results) == 0, "UDP datagrams should not trigger connection attempt alerts"


def test_tcp_flood_on_port_53_detected():
    """TCP connection flood on port 53 MUST be detected (verifies port 53 is NOT whitelisted)."""
    rule = ExcessiveConnectionRule(rate_threshold=40, window_seconds=5.0)

    # 45 TCP connections to port 53 in 2 seconds
    flows = [
        make_conn_flow(
            id=i,
            src_ip="10.0.0.99",
            dst_ip="192.168.1.1",
            src_port=40000 + i,
            dst_port=53,
            protocol="TCP",
            start_time=10.0 + (i * 0.04),
        )
        for i in range(45)
    ]

    results = rule.evaluate(pcap_id=1, flows=flows, dns_records=[])
    assert len(results) == 1
    assert results[0].dst_port == 53
    assert results[0].evidence["attempt_count"] == 45


def test_boundary_rate_threshold():
    """Boundary test: 39 connection attempts (below threshold 40) vs 40 attempts."""
    rule = ExcessiveConnectionRule(rate_threshold=40, window_seconds=5.0)

    # 39 attempts in 3 seconds -> 0 alerts
    flows_39 = [
        make_conn_flow(id=i, src_port=30000 + i, start_time=1.0 + i * 0.07)
        for i in range(39)
    ]
    assert len(rule.evaluate(pcap_id=1, flows=flows_39, dns_records=[])) == 0

    # 40 attempts in 3 seconds -> 1 alert
    flows_40 = [
        make_conn_flow(id=i, src_port=30000 + i, start_time=1.0 + i * 0.07)
        for i in range(40)
    ]
    results_40 = rule.evaluate(pcap_id=1, flows=flows_40, dns_records=[])
    assert len(results_40) == 1
    assert results_40[0].evidence["attempt_count"] == 40
