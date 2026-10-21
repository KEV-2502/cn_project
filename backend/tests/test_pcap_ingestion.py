"""Integration tests for PCAP upload, ingestion pipeline, and database persistence."""

import io
import tempfile
from scapy.all import Ether, IP, TCP, UDP, ICMP, DNS, DNSQR, wrpcap
from backend.app.models.pcap import PcapFile, PcapStatus
from backend.app.models.flow import NetworkFlow


def create_sample_pcap_bytes():
    """Generate a valid PCAP byte buffer containing diverse test traffic."""
    pkts = [
        # TCP Flow 1: 3-way handshake + data
        Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=50001, dport=80, flags="S"),
        Ether() / IP(src="10.0.0.1", dst="192.168.1.100") / TCP(sport=80, dport=50001, flags="SA"),
        Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=50001, dport=80, flags="A"),
        # UDP DNS Flow
        Ether() / IP(src="192.168.1.100", dst="8.8.8.8") / UDP(sport=53000, dport=53) / DNS(rd=1, qd=DNSQR(qname="test.local")),
        # ICMP Ping
        Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / ICMP(type=8, code=0),
    ]

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        wrpcap(f.name, pkts)
        f.seek(0)
        with open(f.name, "rb") as read_f:
            data = read_f.read()
    return data


def test_valid_pcap_upload_and_persistence(client, db_session):
    pcap_data = create_sample_pcap_bytes()
    response = client.post(
        "/api/pcaps/upload",
        files={"file": ("sample_traffic.pcap", pcap_data, "application/octet-stream")},
    )

    assert response.status_code == 201
    data = response.json()
    assert data["filename"] == "sample_traffic.pcap"
    assert data["status"] == "COMPLETED"
    assert data["packet_count"] == 5
    assert data["flow_count"] == 3  # TCP, DNS, ICMP
    assert len(data["sha256_hash"]) == 64

    # Verify NetworkFlow records in database
    pcap_id = data["id"]
    db_flows = db_session.query(NetworkFlow).filter(NetworkFlow.pcap_id == pcap_id).all()
    assert len(db_flows) == 3

    # Check TCP flow bidirectional merging
    tcp_flow = [f for f in db_flows if f.protocol == "TCP"][0]
    assert tcp_flow.src_ip == "192.168.1.100"
    assert tcp_flow.dst_ip == "10.0.0.1"
    assert tcp_flow.src_port == 50001
    assert tcp_flow.dst_port == 80
    assert tcp_flow.forward_packets == 2
    assert tcp_flow.backward_packets == 1
    assert tcp_flow.total_packets == 3
    assert tcp_flow.tcp_state == "ESTABLISHED"

    # Verify query via API
    flow_res = client.get(f"/api/flows?pcap_id={pcap_id}")
    assert flow_res.status_code == 200
    assert flow_res.json()["total"] == 3


def test_duplicate_upload_handling(client, db_session):
    pcap_data = create_sample_pcap_bytes()

    # First upload
    res1 = client.post(
        "/api/pcaps/upload",
        files={"file": ("capture1.pcap", pcap_data, "application/octet-stream")},
    )
    assert res1.status_code == 201
    first_id = res1.json()["id"]

    # Duplicate upload of same capture without reprocess
    res2 = client.post(
        "/api/pcaps/upload",
        files={"file": ("capture1_copy.pcap", pcap_data, "application/octet-stream")},
    )
    assert res2.status_code == 200  # Returns existing record
    assert res2.json()["id"] == first_id

    # Verify no duplicate flows created
    flows_count = db_session.query(NetworkFlow).filter(NetworkFlow.pcap_id == first_id).count()
    assert flows_count == 3


def test_repeat_processing_with_reprocess_flag(client, db_session):
    pcap_data = create_sample_pcap_bytes()

    # Initial upload
    res1 = client.post(
        "/api/pcaps/upload",
        files={"file": ("reprocess_test.pcap", pcap_data, "application/octet-stream")},
    )
    pcap_id = res1.json()["id"]

    # Re-upload with reprocess=true
    res2 = client.post(
        "/api/pcaps/upload?reprocess=true",
        files={"file": ("reprocess_test.pcap", pcap_data, "application/octet-stream")},
    )
    assert res2.status_code == 200
    assert res2.json()["id"] == pcap_id
    assert res2.json()["status"] == "COMPLETED"

    # Confirm flows count is still exactly 3 (cleaned old, created fresh)
    flows_count = db_session.query(NetworkFlow).filter(NetworkFlow.pcap_id == pcap_id).count()
    assert flows_count == 3


def test_empty_pcap_rejected(client):
    empty_bytes = b""
    response = client.post(
        "/api/pcaps/upload",
        files={"file": ("empty.pcap", empty_bytes, "application/octet-stream")},
    )
    assert response.status_code == 400
    assert "empty" in response.json()["detail"].lower()


def test_malformed_pcap_rejected(client):
    garbage_bytes = b"NOT_A_VALID_PCAP_OR_PCAPNG_DATA"
    response = client.post(
        "/api/pcaps/upload",
        files={"file": ("corrupt.pcap", garbage_bytes, "application/octet-stream")},
    )
    assert response.status_code == 400
    assert "invalid" in response.json()["detail"].lower()


def test_unsupported_extension_rejected(client):
    response = client.post(
        "/api/pcaps/upload",
        files={"file": ("payload.exe", b"MZ\x90\x00", "application/octet-stream")},
    )
    assert response.status_code == 400
    assert "unsupported file extension" in response.json()["detail"].lower()


def test_large_capture_streaming_processing(client, db_session):
    """Test streaming ingestion with 120 packets spanning multiple flows."""
    pkts = []
    # 4 distinct TCP conversations with 30 packets each
    for flow_idx in range(4):
        sport = 40000 + flow_idx
        for p in range(15):
            # Forward
            pkts.append(Ether() / IP(src="192.168.1.50", dst=f"10.0.0.{flow_idx + 1}") / TCP(sport=sport, dport=443, flags="A"))
            # Backward
            pkts.append(Ether() / IP(src=f"10.0.0.{flow_idx + 1}", dst="192.168.1.50") / TCP(sport=443, dport=sport, flags="A"))

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        wrpcap(f.name, pkts)
        f.seek(0)
        with open(f.name, "rb") as read_f:
            large_data = read_f.read()

    response = client.post(
        "/api/pcaps/upload",
        files={"file": ("bulk_stream.pcap", large_data, "application/octet-stream")},
    )
    assert response.status_code == 201
    data = response.json()
    assert data["packet_count"] == 120
    assert data["flow_count"] == 4
    assert data["status"] == "COMPLETED"
