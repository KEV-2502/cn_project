"""Regression and validation tests for the refined PortScanRule horizontal sweep detection.

Verifies:
1. Normal client HTTPS browsing across multiple distinct endpoints does NOT trigger false alerts.
2. Benign DNS activity across multiple destinations does NOT trigger false alerts.
3. Genuine horizontal SYN, RST, and embryonic connect scans across distinct hosts ARE detected.
4. Genuine vertical scans across many destination ports remain fully detected.
5. Excessive connection rate / DDoS detection remains fully intact.
6. Boundary timing and threshold conditions are strictly respected.
7. Alert flow_ids isolate probe flows and do NOT pollute benign background flows.
8. Ports 443 and 53 are NOT whitelisted: probing either port without response triggers alerts.
"""

import pytest
from backend.app.models.flow import NetworkFlow
from backend.app.pipeline.rules.port_scan import PortScanRule
from backend.app.pipeline.rules.excessive_conn import ExcessiveConnectionRule
from backend.app.pipeline.rules.engine import RuleEngine


def make_test_flow(
    id: int,
    src_ip: str = "192.168.1.50",
    dst_ip: str = "10.0.0.1",
    src_port: int = 40000,
    dst_port: int = 80,
    protocol: str = "TCP",
    start_time: float = 100.0,
    duration: float = 0.1,
    forward_packets: int = 1,
    backward_packets: int = 0,
    forward_bytes: int = 60,
    backward_bytes: int = 0,
    tcp_state: str = "SYN_SENT",
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
        tcp_flags_forward="S" if tcp_state == "SYN_SENT" else "",
        tcp_flags_backward="",
        tcp_state=tcp_state,
        anomaly_score=0.0,
        is_anomaly=0,
    )


# --- 1. Client Browsing & Benign Traffic ---

def test_normal_client_https_browsing_no_alert():
    """Client opening 15 parallel HTTPS connections to distinct CDN/web IPs must not trigger an alert."""
    rule = PortScanRule(horizontal_host_threshold=10, window_seconds=10.0)

    # 15 distinct destination IPs contacted within 4 seconds
    flows = [
        make_test_flow(
            id=i,
            src_ip="192.168.1.100",
            dst_ip=f"104.16.{i}.1",
            src_port=50000 + i,
            dst_port=443,
            protocol="TCP",
            start_time=10.0 + (i * 0.25),
            duration=1.5,
            forward_packets=8,
            backward_packets=10,
            forward_bytes=1200,
            backward_bytes=8500,
            tcp_state="ESTABLISHED",
        )
        for i in range(15)
    ]

    results = rule.evaluate(pcap_id=1, flows=flows, dns_records=[])
    horizontal_alerts = [r for r in results if r.rule_id == "RULE_PORT_SCAN_HORIZONTAL"]
    assert len(horizontal_alerts) == 0, f"Expected 0 horizontal alerts, got {len(horizontal_alerts)}"


def test_benign_dns_activity_no_alert():
    """Client querying multiple DNS servers with responses must not trigger an alert."""
    rule = PortScanRule(horizontal_host_threshold=10, window_seconds=10.0)

    # 12 distinct DNS queries/servers with valid replies within 3 seconds
    flows = [
        make_test_flow(
            id=i,
            src_ip="192.168.1.100",
            dst_ip=f"192.168.1.{10 + i}",
            src_port=52000 + i,
            dst_port=53,
            protocol="UDP",
            start_time=5.0 + (i * 0.2),
            duration=0.05,
            forward_packets=1,
            backward_packets=1,
            forward_bytes=65,
            backward_bytes=140,
            tcp_state="N/A",
        )
        for i in range(12)
    ]

    results = rule.evaluate(pcap_id=1, flows=flows, dns_records=[])
    horizontal_alerts = [r for r in results if r.rule_id == "RULE_PORT_SCAN_HORIZONTAL"]
    assert len(horizontal_alerts) == 0


# --- 2. Genuine Horizontal Port Scans ---

def test_genuine_horizontal_syn_scan_detected():
    """Attacker probing 15 distinct IPs with unanswered TCP SYN probes must be detected."""
    rule = PortScanRule(horizontal_host_threshold=10, window_seconds=10.0)

    flows = [
        make_test_flow(
            id=i,
            src_ip="10.0.0.66",
            dst_ip=f"192.168.1.{i + 1}",
            src_port=44000,
            dst_port=80,
            protocol="TCP",
            start_time=20.0 + (i * 0.3),
            duration=0.05,
            forward_packets=1,
            backward_packets=0,
            forward_bytes=60,
            backward_bytes=0,
            tcp_state="SYN_SENT",
        )
        for i in range(15)
    ]

    results = rule.evaluate(pcap_id=1, flows=flows, dns_records=[])
    horizontal_alerts = [r for r in results if r.rule_id == "RULE_PORT_SCAN_HORIZONTAL"]
    assert len(horizontal_alerts) == 1

    alert = horizontal_alerts[0]
    assert alert.src_ip == "10.0.0.66"
    assert alert.dst_ip is None
    assert alert.severity == "HIGH"
    assert alert.risk_score >= 70.0
    assert alert.evidence["unique_targets_observed"] == 15
    assert alert.evidence["threshold"] == 10
    assert len(alert.flow_ids) == 15


def test_genuine_horizontal_rst_scan_detected():
    """Attacker probing 12 distinct IPs where destinations actively reject with TCP RST must be detected."""
    rule = PortScanRule(horizontal_host_threshold=10, window_seconds=10.0)

    flows = [
        make_test_flow(
            id=i,
            src_ip="10.0.0.66",
            dst_ip=f"192.168.1.{i + 1}",
            src_port=44000,
            dst_port=22,
            protocol="TCP",
            start_time=20.0 + (i * 0.3),
            duration=0.05,
            forward_packets=1,
            backward_packets=1,
            forward_bytes=60,
            backward_bytes=40,
            tcp_state="RESET",
        )
        for i in range(12)
    ]

    results = rule.evaluate(pcap_id=1, flows=flows, dns_records=[])
    horizontal_alerts = [r for r in results if r.rule_id == "RULE_PORT_SCAN_HORIZONTAL"]
    assert len(horizontal_alerts) == 1
    assert horizontal_alerts[0].evidence["unique_targets_observed"] == 12


def test_genuine_horizontal_embryonic_connect_scan_detected():
    """Attacker probing 14 distinct IPs with embryonic TCP connections (no application data) must be detected."""
    rule = PortScanRule(horizontal_host_threshold=10, window_seconds=10.0)

    flows = [
        make_test_flow(
            id=i,
            src_ip="10.0.0.66",
            dst_ip=f"192.168.1.{i + 1}",
            src_port=44000,
            dst_port=80,
            protocol="TCP",
            start_time=20.0 + (i * 0.3),
            duration=0.08,
            forward_packets=2,
            backward_packets=1,
            forward_bytes=104,
            backward_bytes=52,
            tcp_state="ESTABLISHED",
        )
        for i in range(14)
    ]

    results = rule.evaluate(pcap_id=1, flows=flows, dns_records=[])
    horizontal_alerts = [r for r in results if r.rule_id == "RULE_PORT_SCAN_HORIZONTAL"]
    assert len(horizontal_alerts) == 1
    assert horizontal_alerts[0].evidence["unique_targets_observed"] == 14


# --- 3. No Port Whitelisting Verification ---

def test_no_port_whitelisting_scan_on_443_detected():
    """Probing port 443 across 12 distinct IPs with unanswered SYN packets must still be detected."""
    rule = PortScanRule(horizontal_host_threshold=10, window_seconds=10.0)

    flows = [
        make_test_flow(
            id=i,
            src_ip="172.16.1.5",
            dst_ip=f"10.0.1.{i + 1}",
            src_port=45000,
            dst_port=443,
            protocol="TCP",
            start_time=30.0 + (i * 0.2),
            forward_packets=1,
            backward_packets=0,
            forward_bytes=60,
            backward_bytes=0,
            tcp_state="SYN_SENT",
        )
        for i in range(12)
    ]

    results = rule.evaluate(pcap_id=1, flows=flows, dns_records=[])
    horizontal_alerts = [r for r in results if r.rule_id == "RULE_PORT_SCAN_HORIZONTAL"]
    assert len(horizontal_alerts) == 1
    assert horizontal_alerts[0].evidence["unique_targets_observed"] == 12


def test_no_port_whitelisting_scan_on_53_detected():
    """Probing UDP port 53 across 12 distinct IPs without response must still be detected."""
    rule = PortScanRule(horizontal_host_threshold=10, window_seconds=10.0)

    flows = [
        make_test_flow(
            id=i,
            src_ip="172.16.1.5",
            dst_ip=f"10.0.1.{i + 1}",
            src_port=45000,
            dst_port=53,
            protocol="UDP",
            start_time=30.0 + (i * 0.2),
            forward_packets=1,
            backward_packets=0,
            forward_bytes=48,
            backward_bytes=0,
            tcp_state="N/A",
        )
        for i in range(12)
    ]

    results = rule.evaluate(pcap_id=1, flows=flows, dns_records=[])
    horizontal_alerts = [r for r in results if r.rule_id == "RULE_PORT_SCAN_HORIZONTAL"]
    assert len(horizontal_alerts) == 1
    assert horizontal_alerts[0].evidence["unique_targets_observed"] == 12


# --- 4. Regression & Boundary Checks ---

def test_genuine_vertical_scan_unaffected():
    """Probing 18 ports on a single host must trigger vertical scan and NOT horizontal scan."""
    rule = PortScanRule(vertical_port_threshold=15, horizontal_host_threshold=10, window_seconds=10.0)

    flows = [
        make_test_flow(
            id=i,
            src_ip="192.168.1.50",
            dst_ip="10.0.0.1",
            src_port=40000 + i,
            dst_port=1000 + i,
            protocol="TCP",
            start_time=10.0 + (i * 0.2),
            forward_packets=1,
            backward_packets=0,
            forward_bytes=60,
            backward_bytes=0,
            tcp_state="SYN_SENT",
        )
        for i in range(18)
    ]

    results = rule.evaluate(pcap_id=1, flows=flows, dns_records=[])
    vertical = [r for r in results if r.rule_id == "RULE_PORT_SCAN_VERTICAL"]
    horizontal = [r for r in results if r.rule_id == "RULE_PORT_SCAN_HORIZONTAL"]

    assert len(vertical) == 1
    assert vertical[0].evidence["unique_ports_observed"] == 18
    assert len(horizontal) == 0


def test_ddos_excessive_connection_rate_unaffected():
    """High connection rate directed at a single target service triggers DDoS rule without regression."""
    engine = RuleEngine([
        PortScanRule(horizontal_host_threshold=10, window_seconds=10.0),
        ExcessiveConnectionRule(rate_threshold=40, window_seconds=5.0),
    ])

    # 45 connections to same destination IP and port
    flows = [
        make_test_flow(
            id=i,
            src_ip="192.168.1.99",
            dst_ip="10.0.0.1",
            src_port=30000 + i,
            dst_port=80,
            protocol="TCP",
            start_time=50.0 + (i * 0.05),
            duration=0.1,
            forward_packets=3,
            backward_packets=2,
            forward_bytes=180,
            backward_bytes=120,
            tcp_state="ESTABLISHED",
        )
        for i in range(45)
    ]

    results = engine.evaluate_all(pcap_id=1, flows=flows, dns_records=[])
    excessive = [r for r in results if r.rule_id == "RULE_EXCESSIVE_CONN_RATE"]
    horizontal = [r for r in results if r.rule_id == "RULE_PORT_SCAN_HORIZONTAL"]

    assert len(excessive) == 1
    assert len(horizontal) == 0


def test_boundary_threshold_behavior():
    """Boundary test: 9 probe targets (below threshold 10) vs exactly 10 probe targets."""
    rule = PortScanRule(horizontal_host_threshold=10, window_seconds=10.0)

    # 9 targets -> 0 alerts
    flows_9 = [
        make_test_flow(id=i, src_ip="10.0.0.1", dst_ip=f"192.168.1.{i + 1}", start_time=1.0 + i * 0.3)
        for i in range(9)
    ]
    assert len(rule.evaluate(pcap_id=1, flows=flows_9, dns_records=[])) == 0

    # 10 targets -> 1 alert
    flows_10 = [
        make_test_flow(id=i, src_ip="10.0.0.1", dst_ip=f"192.168.1.{i + 1}", start_time=1.0 + i * 0.3)
        for i in range(10)
    ]
    results_10 = rule.evaluate(pcap_id=1, flows=flows_10, dns_records=[])
    assert len(results_10) == 1
    assert results_10[0].evidence["unique_targets_observed"] == 10


def test_boundary_timing_behavior():
    """Boundary test: 15 probes spread over 30s (exceeding window) vs 15 probes within 9s."""
    rule = PortScanRule(horizontal_host_threshold=10, window_seconds=10.0)

    # 15 probes spread over 30 seconds (1 probe every 2.0s -> at most 5 per 10s window)
    flows_spread = [
        make_test_flow(id=i, src_ip="10.0.0.1", dst_ip=f"192.168.1.{i + 1}", start_time=1.0 + i * 2.0)
        for i in range(15)
    ]
    assert len(rule.evaluate(pcap_id=1, flows=flows_spread, dns_records=[])) == 0

    # 15 probes within 7 seconds (1 probe every 0.5s)
    flows_burst = [
        make_test_flow(id=i, src_ip="10.0.0.1", dst_ip=f"192.168.1.{i + 1}", start_time=1.0 + i * 0.5)
        for i in range(15)
    ]
    results_burst = rule.evaluate(pcap_id=1, flows=flows_burst, dns_records=[])
    assert len(results_burst) == 1


def test_mixed_traffic_preserves_flow_ids():
    """In mixed traffic (5 established sessions + 12 scan probes), alert flow_ids must only contain probes."""
    rule = PortScanRule(horizontal_host_threshold=10, window_seconds=10.0)

    # 5 established sessions (IDs 1-5)
    established = [
        make_test_flow(
            id=i + 1,
            src_ip="192.168.1.50",
            dst_ip=f"10.0.0.{i + 1}",
            dst_port=443,
            start_time=10.0 + i * 0.2,
            forward_packets=10,
            backward_packets=12,
            forward_bytes=1500,
            backward_bytes=6000,
            tcp_state="ESTABLISHED",
        )
        for i in range(5)
    ]

    # 12 scan probes (IDs 101-112)
    probes = [
        make_test_flow(
            id=100 + i + 1,
            src_ip="192.168.1.50",
            dst_ip=f"172.16.0.{i + 1}",
            dst_port=80,
            start_time=10.5 + i * 0.2,
            forward_packets=1,
            backward_packets=0,
            forward_bytes=60,
            backward_bytes=0,
            tcp_state="SYN_SENT",
        )
        for i in range(12)
    ]

    all_flows = established + probes
    results = rule.evaluate(pcap_id=1, flows=all_flows, dns_records=[])
    assert len(results) == 1

    alert = results[0]
    # Check that flow_ids contains only probe IDs (101-112), NOT established IDs (1-5)
    for f_id in range(1, 6):
        assert f_id not in alert.flow_ids, f"Established flow {f_id} was incorrectly included in alert.flow_ids"
    for f_id in range(101, 113):
        assert f_id in alert.flow_ids, f"Probe flow {f_id} was missing from alert.flow_ids"
