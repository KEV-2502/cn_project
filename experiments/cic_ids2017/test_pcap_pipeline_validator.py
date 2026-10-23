"""Unit and regression tests for the Real-PCAP Pipeline Validator."""

from pathlib import Path
import tempfile
import pytest
from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, wrpcap

from experiments.cic_ids2017.pcap_pipeline_validator import (
    verify_capture_integrity,
    run_bounded_pcap_pipeline_test,
)


def test_verify_capture_integrity_missing_file(tmp_path):
    report = verify_capture_integrity(tmp_path / "non_existent.pcap", verify_sha256=False)
    assert not report.file_exists
    assert report.size_bytes == 0
    assert not report.is_pcapng


def test_run_bounded_pipeline_on_synthetic_pcap(tmp_path):
    """Test the complete bounded validator on a synthetic capture."""
    pcap_file = tmp_path / "synthetic_test.pcap"
    db_file = tmp_path / "isolated_test.db"

    pkts = []
    # 20 TCP packets across two flows
    for i in range(10):
        pkts.append(Ether() / IP(src="192.168.1.10", dst="10.0.0.1") / TCP(sport=50000, dport=80, flags="S"))
    for i in range(10):
        pkts.append(Ether() / IP(src="192.168.1.20", dst="10.0.0.2") / TCP(sport=50001, dport=443, flags="S"))
    # 5 DNS queries
    for i in range(5):
        pkts.append(Ether() / IP(src="192.168.1.10", dst="8.8.8.8") / UDP(sport=53000 + i, dport=53) / DNS(rd=1, qd=DNSQR(qname=f"test{i}.example.com")))

    wrpcap(str(pcap_file), pkts)

    res = run_bounded_pcap_pipeline_test(
        pcap_path=pcap_file,
        max_packets=50,
        isolated_db_path=db_file,
    )

    assert res["parser_metrics"]["raw_packets_read"] == 25
    assert res["parser_metrics"]["parser_errors"] == 0
    assert res["parser_metrics"]["dns_queries_extracted"] == 5
    assert res["flow_aggregation_metrics"]["aggregated_flows_count"] >= 2
    assert res["database_consistency"]["all_counts_match"] is True
    assert db_file.exists()
