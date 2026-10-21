"""Deterministic unit and integration tests for the rule-based threat detection engine."""

import json
from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, wrpcap
import tempfile

from backend.app.models.flow import NetworkFlow
from backend.app.models.dns import DnsQueryRecord
from backend.app.models.alert import ThreatAlert
from backend.app.pipeline.rules.port_scan import PortScanRule
from backend.app.pipeline.rules.excessive_conn import ExcessiveConnectionRule
from backend.app.pipeline.rules.dns_threats import DnsThreatRule
from backend.app.pipeline.rules.engine import RuleEngine


def make_dummy_flow(
    id=1,
    pcap_id=1,
    src_ip="192.168.1.100",
    dst_ip="10.0.0.1",
    src_port=50000,
    dst_port=80,
    protocol="TCP",
    start_time=100.0,
    tcp_state="SYN_SENT",
):
    return NetworkFlow(
        id=id,
        pcap_id=pcap_id,
        flow_key=f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}",
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        ip_version=4,
        start_time=start_time,
        end_time=start_time + 0.1,
        duration=0.1,
        forward_packets=1,
        backward_packets=0,
        forward_bytes=60,
        backward_bytes=0,
        total_packets=1,
        total_bytes=60,
        tcp_flags_forward="S",
        tcp_flags_backward="",
        tcp_state=tcp_state,
        anomaly_score=0.0,
        is_anomaly=0,
    )


# --- 1. Port Scan Tests ---

def test_vertical_port_scan_detected():
    rule = PortScanRule(vertical_port_threshold=15, window_seconds=10.0)

    # 18 unique ports probed from 192.168.1.50 to 10.0.0.1 within 5 seconds
    flows = [
        make_dummy_flow(id=i, src_ip="192.168.1.50", dst_ip="10.0.0.1", src_port=40000 + i, dst_port=1000 + i, start_time=10.0 + (i * 0.2))
        for i in range(18)
    ]

    results = rule.evaluate(pcap_id=1, flows=flows, dns_records=[])
    assert len(results) == 1

    alert = results[0]
    assert alert.rule_id == "RULE_PORT_SCAN_VERTICAL"
    assert alert.severity == "HIGH"
    assert alert.src_ip == "192.168.1.50"
    assert alert.dst_ip == "10.0.0.1"
    assert alert.evidence["unique_ports_observed"] == 18
    assert alert.evidence["threshold"] == 15
    assert alert.risk_score >= 70.0
    assert len(alert.flow_ids) == 18


def test_horizontal_host_sweep_detected():
    rule = PortScanRule(horizontal_host_threshold=10, window_seconds=10.0)

    # 12 unique destination hosts probed by 192.168.1.50 on port 80
    flows = [
        make_dummy_flow(id=i, src_ip="192.168.1.50", dst_ip=f"10.0.0.{i + 1}", src_port=40000, dst_port=80, start_time=20.0 + (i * 0.3))
        for i in range(12)
    ]

    results = rule.evaluate(pcap_id=1, flows=flows, dns_records=[])
    assert len(results) == 1

    alert = results[0]
    assert alert.rule_id == "RULE_PORT_SCAN_HORIZONTAL"
    assert alert.severity == "HIGH"
    assert alert.src_ip == "192.168.1.50"
    assert alert.evidence["unique_targets_observed"] == 12
    assert alert.evidence["threshold"] == 10
    assert alert.risk_score >= 70.0


def test_port_scan_below_threshold_produces_no_alerts():
    rule = PortScanRule(vertical_port_threshold=15, horizontal_host_threshold=10, window_seconds=10.0)

    # 5 unique ports (well below threshold of 15)
    flows = [
        make_dummy_flow(id=i, src_ip="192.168.1.50", dst_ip="10.0.0.1", dst_port=80 + i, start_time=1.0 + i)
        for i in range(5)
    ]

    results = rule.evaluate(pcap_id=1, flows=flows, dns_records=[])
    assert len(results) == 0


def test_port_scan_multiple_independent_sources():
    rule = PortScanRule(vertical_port_threshold=15, window_seconds=10.0)

    # Source A probes 16 ports
    flows_a = [
        make_dummy_flow(id=i, src_ip="192.168.1.10", dst_ip="10.0.0.1", dst_port=100 + i, start_time=1.0 + (i * 0.1))
        for i in range(16)
    ]
    # Source B probes 17 ports
    flows_b = [
        make_dummy_flow(id=100 + i, src_ip="192.168.1.20", dst_ip="10.0.0.2", dst_port=200 + i, start_time=1.0 + (i * 0.1))
        for i in range(17)
    ]

    results = rule.evaluate(pcap_id=1, flows=flows_a + flows_b, dns_records=[])
    assert len(results) == 2
    sources = {r.src_ip for r in results}
    assert sources == {"192.168.1.10", "192.168.1.20"}


# --- 2. Excessive Connection Rate Tests ---

def test_excessive_connection_rate_detected():
    rule = ExcessiveConnectionRule(rate_threshold=40, window_seconds=5.0)

    # 45 connections from 192.168.1.99 to 10.0.0.1:443 in 3 seconds
    flows = [
        make_dummy_flow(id=i, src_ip="192.168.1.99", dst_ip="10.0.0.1", src_port=30000 + i, dst_port=443, start_time=50.0 + (i * 0.05))
        for i in range(45)
    ]

    results = rule.evaluate(pcap_id=1, flows=flows, dns_records=[])
    assert len(results) == 1

    alert = results[0]
    assert alert.rule_id == "RULE_EXCESSIVE_CONN_RATE"
    assert alert.src_ip == "192.168.1.99"
    assert alert.dst_ip == "10.0.0.1"
    assert alert.dst_port == 443
    assert alert.evidence["attempt_count"] >= 40
    assert alert.evidence["threshold"] == 40
    assert "authentication" in alert.explanation.lower()


def test_connection_rate_below_threshold():
    rule = ExcessiveConnectionRule(rate_threshold=40, window_seconds=5.0)

    # 20 connections in 5 seconds (below threshold 40)
    flows = [
        make_dummy_flow(id=i, src_ip="192.168.1.99", dst_ip="10.0.0.1", src_port=30000 + i, dst_port=443, start_time=50.0 + (i * 0.2))
        for i in range(20)
    ]

    results = rule.evaluate(pcap_id=1, flows=flows, dns_records=[])
    assert len(results) == 0


# --- 3. DNS Threats Tests ---

def test_dns_tunneling_long_name_detected():
    rule = DnsThreatRule(long_name_length=50)

    long_domain = "a" * 55 + ".exfiltration.attacker.com"  # 80 characters
    dns_records = [
        DnsQueryRecord(
            id=1,
            pcap_id=1,
            timestamp=100.0,
            src_ip="192.168.1.75",
            dst_ip="8.8.8.8",
            query_name=long_domain,
            query_length=len(long_domain),
            is_response=0,
        )
    ]

    results = rule.evaluate(pcap_id=1, flows=[], dns_records=dns_records)
    assert len(results) == 1

    alert = results[0]
    assert alert.rule_id == "RULE_DNS_TUNNELING_LONG_NAME"
    assert alert.severity == "HIGH"
    assert alert.evidence["longest_query_length"] == len(long_domain)
    assert alert.evidence["threshold_length"] == 50
    assert alert.risk_score >= 70.0


def test_dns_high_volume_burst_detected():
    rule = DnsThreatRule(burst_threshold=25, burst_window_seconds=5.0)

    # 28 queries within 3 seconds
    dns_records = [
        DnsQueryRecord(
            id=i,
            pcap_id=1,
            timestamp=10.0 + (i * 0.1),
            src_ip="192.168.1.80",
            dst_ip="8.8.8.8",
            query_name=f"sub{i}.example.com",
            query_length=len(f"sub{i}.example.com"),
            is_response=0,
        )
        for i in range(28)
    ]

    results = rule.evaluate(pcap_id=1, flows=[], dns_records=dns_records)
    high_vol = [r for r in results if r.rule_id == "RULE_DNS_HIGH_VOLUME"]
    assert len(high_vol) == 1
    assert high_vol[0].evidence["threshold"] == 25
    assert high_vol[0].evidence["query_count"] >= 25


def test_missing_dns_metadata_handles_cleanly():
    rule = DnsThreatRule()
    # Empty DNS records
    results = rule.evaluate(pcap_id=1, flows=[], dns_records=[])
    assert len(results) == 0


# --- 4. Integration & API Tests ---

def test_pcap_upload_triggers_rules_and_persists_alerts(client, db_session):
    """Generate a PCAP with a vertical port scan and long DNS query, upload, and assert alerts."""
    pkts = []
    # 16 TCP SYN packets to unique ports (vertical scan)
    for port in range(1000, 1016):
        pkts.append(Ether() / IP(src="192.168.1.222", dst="10.0.0.5") / TCP(sport=50000, dport=port, flags="S"))

    # Long DNS query
    tunnel_name = "b" * 52 + ".tunnel.net"
    pkts.append(Ether() / IP(src="192.168.1.222", dst="8.8.8.8") / UDP(sport=53000, dport=53) / DNS(rd=1, qd=DNSQR(qname=tunnel_name)))

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        wrpcap(f.name, pkts)
        f.seek(0)
        with open(f.name, "rb") as read_f:
            pcap_bytes = read_f.read()

    # Upload PCAP
    res = client.post(
        "/api/pcaps/upload",
        files={"file": ("threat_capture.pcap", pcap_bytes, "application/octet-stream")},
    )
    assert res.status_code == 201
    pcap_data = res.json()
    assert pcap_data["status"] == "COMPLETED"
    assert pcap_data["alert_count"] >= 2

    pcap_id = pcap_data["id"]

    # Verify alerts retrieved through API
    alerts_res = client.get(f"/api/alerts?pcap_id={pcap_id}")
    assert alerts_res.status_code == 200
    alert_items = alerts_res.json()["items"]
    assert len(alert_items) >= 2

    rule_ids = {a["rule_id"] for a in alert_items}
    assert "RULE_PORT_SCAN_VERTICAL" in rule_ids
    assert "RULE_DNS_TUNNELING_LONG_NAME" in rule_ids

    # Check alert evidence is valid JSON
    scan_alert = [a for a in alert_items if a["rule_id"] == "RULE_PORT_SCAN_VERTICAL"][0]
    evidence = json.loads(scan_alert["evidence_json"])
    assert evidence["unique_ports_observed"] == 16
    assert scan_alert["risk_score"] >= 70.0


def test_re_running_detection_endpoint_is_deterministic_and_idempotent(client, db_session):
    """Test POST /api/pcaps/{id}/detect re-runs rules without duplicating alerts."""
    pkts = []
    for port in range(2000, 2016):
        pkts.append(Ether() / IP(src="192.168.1.111", dst="10.0.0.9") / TCP(sport=50000, dport=port, flags="S"))

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        wrpcap(f.name, pkts)
        f.seek(0)
        with open(f.name, "rb") as read_f:
            pcap_bytes = read_f.read()

    upload_res = client.post(
        "/api/pcaps/upload",
        files={"file": ("re_detect.pcap", pcap_bytes, "application/octet-stream")},
    )
    pcap_id = upload_res.json()["id"]

    initial_alerts_count = db_session.query(ThreatAlert).filter(ThreatAlert.pcap_id == pcap_id).count()
    assert initial_alerts_count == 1

    # Call detect endpoint again
    re_detect_res = client.post(f"/api/pcaps/{pcap_id}/detect")
    assert re_detect_res.status_code == 200
    assert len(re_detect_res.json()) == 1

    # Verify database still has exactly 1 alert (no duplicates)
    final_alerts_count = db_session.query(ThreatAlert).filter(ThreatAlert.pcap_id == pcap_id).count()
    assert final_alerts_count == 1
