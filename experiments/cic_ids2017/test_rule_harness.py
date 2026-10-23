"""Unit tests for the Multi-Flow Rule Evaluation Harness."""

from pathlib import Path
import tempfile
import numpy as np
import pytest
from scapy.all import Ether, IP, TCP, wrpcap

from backend.app.models.flow import NetworkFlow
from backend.app.pipeline.rules.port_scan import PortScanRule
from backend.app.pipeline.rules.excessive_conn import ExcessiveConnectionRule
from backend.app.pipeline.rules.engine import RuleEngine
from experiments.cic_ids2017.rule_evaluation_harness import (
    check_pcap_availability,
    parse_cic_timestamp,
    cic_row_to_network_flow,
    synthesize_monotonic_timestamps,
    MultiFlowRuleEvaluator,
    KNOWN_ATTACKERS,
)


def test_check_pcap_availability_nonexistent(tmp_path):
    check = check_pcap_availability(tmp_path / "does_not_exist.pcap")
    assert not check.exists
    assert not check.is_complete
    assert not check.has_valid_header


def test_check_pcap_availability_aria2_in_progress(tmp_path):
    pcap = tmp_path / "downloading.pcap"
    pcap.write_bytes(b"partial content" * 100)
    aria2_file = tmp_path / "downloading.pcap.aria2"
    aria2_file.write_bytes(b"aria2_control_data")

    check = check_pcap_availability(pcap)
    assert check.exists
    assert not check.is_complete
    assert "aria2" in check.status_reason.lower()


def test_check_pcap_availability_valid_pcap(tmp_path):
    pcap = tmp_path / "valid.pcap"
    pkts = [Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=1000, dport=80)]
    wrpcap(str(pcap), pkts)

    check = check_pcap_availability(pcap)
    assert check.exists
    assert check.is_complete
    assert check.has_valid_header
    assert "valid" in check.status_reason.lower()


def test_check_pcap_availability_partial_monday(tmp_path):
    pcap = tmp_path / "Monday-WorkingHours.pcap"
    pkts = [Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=1000, dport=80)]
    wrpcap(str(pcap), pkts)

    check = check_pcap_availability(pcap)
    assert check.exists
    assert not check.is_complete
    assert check.has_valid_header
    assert "partial" in check.status_reason.lower()


def test_parse_cic_timestamp():
    ts1 = parse_cic_timestamp("7/7/2017 1:05")
    assert ts1 > 0.0

    ts2 = parse_cic_timestamp("07/07/2017 01:05:30")
    assert ts2 > 0.0

    ts3 = parse_cic_timestamp("4/7/2017 8:55")
    assert ts3 > 0.0


def test_synthesize_monotonic_timestamps_preserves_ordering():
    raw_rows = [
        (i, {
            "Source IP": "10.0.0.1",
            "Destination IP": "10.0.0.2",
            "Source Port": "50000",
            "Destination Port": "80",
            "Protocol": "6",
            "Flow Duration": "1000",
            "Timestamp": "7/7/2017 1:05",
            "Label": "BENIGN",
        })
        for i in range(100)
    ]

    flows_and_labels = synthesize_monotonic_timestamps(raw_rows)
    assert len(flows_and_labels) == 100

    timestamps = [f[0].start_time for f in flows_and_labels]
    # Assert timestamps are strictly non-decreasing (monotonic)
    for i in range(len(timestamps) - 1):
        assert timestamps[i] <= timestamps[i + 1]

    # Assert timestamps span across the 60s minute window
    span = timestamps[-1] - timestamps[0]
    assert 55.0 <= span < 60.0


def test_cic_row_to_network_flow():
    row = {
        "Source IP": "172.16.0.1",
        "Destination IP": "192.168.10.50",
        "Source Port": "45000",
        "Destination Port": "80",
        "Protocol": "6",
        "Flow Duration": "2000000",
        "Total Fwd Packets": "5",
        "Total Backward Packets": "3",
        "Total Length of Fwd Packets": "500",
        "Total Length of Bwd Packets": "300",
        "Timestamp": "7/7/2017 1:05",
        "Label": "PortScan",
    }
    flow, label = cic_row_to_network_flow(1, row)
    assert flow.src_ip == "172.16.0.1"
    assert flow.dst_ip == "192.168.10.50"
    assert flow.protocol == "TCP"
    assert flow.duration == 2.0
    assert flow.total_packets == 8
    assert label == "PortScan"


def test_evaluator_requires_genuine_attack_flows_for_supported_detection():
    """Verify that an alert is NOT marked supported if the flow cluster contains only benign flows, even if from attacker IP."""
    rule_engine = RuleEngine([
        PortScanRule(vertical_port_threshold=5, window_seconds=10.0),
    ])
    evaluator = MultiFlowRuleEvaluator(rule_engine=rule_engine)

    # Attacker IP (172.16.0.1) sending flows labelled BENIGN
    flows_benign_from_attacker = [
        NetworkFlow(
            id=i,
            pcap_id=1,
            flow_key=f"172.16.0.1:40000-192.168.10.50:{80 + i}-TCP",
            src_ip="172.16.0.1",
            dst_ip="192.168.10.50",
            src_port=40000,
            dst_port=80 + i,
            protocol="TCP",
            ip_version=4,
            start_time=100.0 + (i * 0.1),
            end_time=100.1 + (i * 0.1),
            duration=0.1,
            forward_packets=1,
            backward_packets=0,
            forward_bytes=60,
            backward_bytes=0,
            total_packets=1,
            total_bytes=60,
        )
        for i in range(6)
    ]
    labels = ["BENIGN"] * 6

    res = evaluator.evaluate_flow_sequence(flows_benign_from_attacker, labels)
    assert res["total_alerts_generated"] == 1
    # Must NOT be marked SUPPORTED_DETECTION because ground truth flows were BENIGN
    assert res["supported_detections"] == 0
    assert res["false_positives"] == 1
    assert res["assessments"][0].category == "FALSE_POSITIVE"


def test_evaluator_reports_missed_attacks():
    """Verify evaluator reports missed attack classes when attack flows exist but trigger no alerts."""
    rule_engine = RuleEngine([
        ExcessiveConnectionRule(rate_threshold=40, window_seconds=5.0),
    ])
    evaluator = MultiFlowRuleEvaluator(rule_engine=rule_engine)

    # 10 low-rate brute-force flows (well below threshold 40)
    flows = [
        NetworkFlow(
            id=i,
            pcap_id=1,
            flow_key=f"172.16.0.1:40000-192.168.10.50:21-TCP",
            src_ip="172.16.0.1",
            dst_ip="192.168.10.50",
            src_port=40000 + i,
            dst_port=21,
            protocol="TCP",
            ip_version=4,
            start_time=100.0 + (i * 1.0),
            end_time=100.1 + (i * 1.0),
            duration=0.1,
            forward_packets=2,
            backward_packets=2,
            forward_bytes=100,
            backward_bytes=100,
            total_packets=4,
            total_bytes=200,
        )
        for i in range(10)
    ]
    labels = ["FTP-Patator"] * 10

    res = evaluator.evaluate_flow_sequence(flows, labels)
    assert res["total_alerts_generated"] == 0
    assert res["supported_detections"] == 0
    assert "FTP-Patator" in res["missed_attack_classes"]
    assert res["total_attack_flows"] == 10
    assert res["detected_attack_flows_count"] == 0


def test_evaluator_statelessness_between_scenarios():
    """Verify that evaluating scenario A then scenario B produces identical results to scenario B alone."""
    rule_engine = RuleEngine([
        PortScanRule(vertical_port_threshold=5, window_seconds=10.0),
    ])
    evaluator = MultiFlowRuleEvaluator(rule_engine=rule_engine)

    flows_a = [
        NetworkFlow(
            id=i,
            pcap_id=1,
            flow_key=f"192.168.1.1:40000-10.0.0.1:{80 + i}-TCP",
            src_ip="192.168.1.1",
            dst_ip="10.0.0.1",
            src_port=40000,
            dst_port=80 + i,
            protocol="TCP",
            ip_version=4,
            start_time=100.0 + (i * 0.1),
            end_time=100.1 + (i * 0.1),
            duration=0.1,
        )
        for i in range(6)
    ]
    labels_a = ["PortScan"] * 6

    flows_b = [
        NetworkFlow(
            id=100 + i,
            pcap_id=1,
            flow_key=f"192.168.1.2:40000-10.0.0.2:{80 + i}-TCP",
            src_ip="192.168.1.2",
            dst_ip="10.0.0.2",
            src_port=40000,
            dst_port=80 + i,
            protocol="TCP",
            ip_version=4,
            start_time=200.0 + (i * 0.1),
            end_time=200.1 + (i * 0.1),
            duration=0.1,
        )
        for i in range(6)
    ]
    labels_b = ["PortScan"] * 6

    # Run A then B
    evaluator.evaluate_flow_sequence(flows_a, labels_a)
    res_b_sequential = evaluator.evaluate_flow_sequence(flows_b, labels_b)

    # Run B alone with fresh evaluator with the same custom threshold
    fresh_rule_engine = RuleEngine([
        PortScanRule(vertical_port_threshold=5, window_seconds=10.0),
    ])
    fresh_evaluator = MultiFlowRuleEvaluator(rule_engine=fresh_rule_engine)
    res_b_alone = fresh_evaluator.evaluate_flow_sequence(flows_b, labels_b)

    assert res_b_sequential["total_alerts_generated"] == res_b_alone["total_alerts_generated"]
    assert res_b_sequential["supported_detections"] == res_b_alone["supported_detections"]
    assert res_b_sequential["assessments"][0].alert.risk_score == res_b_alone["assessments"][0].alert.risk_score
