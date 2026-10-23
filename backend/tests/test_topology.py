import pytest
from backend.app.models.pcap import PcapFile, PcapStatus
from backend.app.models.flow import NetworkFlow
from backend.app.models.alert import ThreatAlert, AlertSeverity, IncidentStatus


@pytest.fixture
def populated_db(db_session):
    """Seed test database with known PCAPs, flows, and alerts."""
    # PCAP 1
    pcap1 = PcapFile(
        id=1,
        filename="scan_capture.pcap",
        file_path="/tmp/scan_capture.pcap",
        file_size_bytes=1024,
        sha256_hash="a" * 64,
        status=PcapStatus.COMPLETED.value,
        packet_count=20,
        flow_count=4,
        alert_count=1,
        duration_seconds=5.0,
    )
    # PCAP 2
    pcap2 = PcapFile(
        id=2,
        filename="benign_capture.pcap",
        file_path="/tmp/benign_capture.pcap",
        file_size_bytes=2048,
        sha256_hash="b" * 64,
        status=PcapStatus.COMPLETED.value,
        packet_count=10,
        flow_count=2,
        alert_count=0,
        duration_seconds=2.0,
    )
    db_session.add_all([pcap1, pcap2])
    db_session.commit()

    # Flows for PCAP 1:
    # 10.0.0.1 -> 10.0.0.2 (TCP port 80)
    f1 = NetworkFlow(
        pcap_id=1,
        flow_key="10.0.0.1-10.0.0.2-50000-80-TCP",
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=50000,
        dst_port=80,
        protocol="TCP",
        ip_version=4,
        start_time=100.0,
        end_time=101.0,
        duration=1.0,
        forward_packets=5,
        backward_packets=4,
        forward_bytes=500,
        backward_bytes=1200,
        total_packets=9,
        total_bytes=1700,
        tcp_state="ESTABLISHED",
        anomaly_score=0.1,
        is_anomaly=0,
    )
    # 10.0.0.1 -> 10.0.0.2 (TCP port 443)
    f2 = NetworkFlow(
        pcap_id=1,
        flow_key="10.0.0.1-10.0.0.2-50001-443-TCP",
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=50001,
        dst_port=443,
        protocol="TCP",
        ip_version=4,
        start_time=101.0,
        end_time=102.0,
        duration=1.0,
        forward_packets=3,
        backward_packets=3,
        forward_bytes=300,
        backward_bytes=600,
        total_packets=6,
        total_bytes=900,
        tcp_state="ESTABLISHED",
        anomaly_score=0.2,
        is_anomaly=0,
    )
    # 10.0.0.1 -> 8.8.8.8 (DNS port 53)
    f3 = NetworkFlow(
        pcap_id=1,
        flow_key="10.0.0.1-8.8.8.8-53000-53-DNS",
        src_ip="10.0.0.1",
        dst_ip="8.8.8.8",
        src_port=53000,
        dst_port=53,
        protocol="DNS",
        ip_version=4,
        start_time=100.5,
        end_time=100.6,
        duration=0.1,
        forward_packets=1,
        backward_packets=1,
        forward_bytes=60,
        backward_bytes=120,
        total_packets=2,
        total_bytes=180,
        tcp_state="N/A",
        anomaly_score=0.05,
        is_anomaly=0,
    )
    # 192.168.1.100 -> 10.0.0.2 (UDP port 123)
    f4 = NetworkFlow(
        pcap_id=1,
        flow_key="192.168.1.100-10.0.0.2-123-123-UDP",
        src_ip="192.168.1.100",
        dst_ip="10.0.0.2",
        src_port=123,
        dst_port=123,
        protocol="UDP",
        ip_version=4,
        start_time=102.0,
        end_time=102.1,
        duration=0.1,
        forward_packets=1,
        backward_packets=1,
        forward_bytes=48,
        backward_bytes=48,
        total_packets=2,
        total_bytes=96,
        tcp_state="N/A",
        anomaly_score=0.01,
        is_anomaly=0,
    )
    # Flow for PCAP 2: 172.16.0.5 -> 172.16.0.1
    f5 = NetworkFlow(
        pcap_id=2,
        flow_key="172.16.0.5-172.16.0.1-8080-80-TCP",
        src_ip="172.16.0.5",
        dst_ip="172.16.0.1",
        src_port=8080,
        dst_port=80,
        protocol="TCP",
        ip_version=4,
        start_time=200.0,
        end_time=201.0,
        duration=1.0,
        forward_packets=2,
        backward_packets=2,
        forward_bytes=100,
        backward_bytes=100,
        total_packets=4,
        total_bytes=200,
        tcp_state="ESTABLISHED",
        anomaly_score=0.0,
        is_anomaly=0,
    )
    db_session.add_all([f1, f2, f3, f4, f5])
    db_session.commit()

    # Alert on PCAP 1 (High severity vertical scan on 10.0.0.2)
    alert1 = ThreatAlert(
        pcap_id=1,
        rule_id="RULE_PORT_SCAN_VERTICAL",
        rule_name="Vertical Port Scan Detected",
        detection_type="RULE",
        severity=AlertSeverity.HIGH.value,
        risk_score=75.0,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=50000,
        dst_port=80,
        protocol="TCP",
        timestamp=100.0,
        description="Source 10.0.0.1 scanned ports on 10.0.0.2",
        explanation="High severity port scan",
        evidence_json='{"ports": [80, 443]}',
        flow_ids_json="[1, 2]",
        status=IncidentStatus.OPEN.value,
    )
    db_session.add(alert1)
    db_session.commit()


def test_topology_all_pcaps(client, populated_db):
    """Test retrieving global topology without PCAP filter."""
    res = client.get("/api/topology")
    assert res.status_code == 200
    data = res.json()
    assert "nodes" in data
    assert "edges" in data
    assert "summary" in data

    summary = data["summary"]
    assert summary["total_nodes"] == 6  # 10.0.0.1, 10.0.0.2, 8.8.8.8, 192.168.1.100, 172.16.0.5, 172.16.0.1
    assert summary["total_edges"] == 4
    assert summary["total_flows"] == 5
    assert summary["alerted_nodes_count"] == 2  # 10.0.0.1 and 10.0.0.2
    assert summary["alerted_edges_count"] == 1  # 10.0.0.1 -> 10.0.0.2


def test_topology_filter_by_pcap(client, populated_db):
    """Test filtering topology by pcap_id."""
    res = client.get("/api/topology?pcap_id=1")
    assert res.status_code == 200
    data = res.json()
    summary = data["summary"]

    assert summary["pcap_id"] == 1
    assert summary["pcap_name"] == "scan_capture.pcap"
    assert summary["total_nodes"] == 4  # 10.0.0.1, 10.0.0.2, 8.8.8.8, 192.168.1.100
    assert summary["total_edges"] == 3
    assert summary["total_flows"] == 4

    # Check node metrics for 10.0.0.1
    node_1 = next(n for n in data["nodes"] if n["ip"] == "10.0.0.1")
    assert node_1["role"] == "client"
    assert node_1["alert_count"] == 1
    assert node_1["max_severity"] == "HIGH"
    assert set(node_1["peers"]) == {"10.0.0.2", "8.8.8.8"}
    assert set(node_1["protocols"]) == {"TCP", "DNS"}

    # Check edge metrics between 10.0.0.1 and 10.0.0.2
    edge_1_2 = next(e for e in data["edges"] if e["source"] == "10.0.0.1" and e["target"] == "10.0.0.2")
    assert edge_1_2["flow_count"] == 2
    assert edge_1_2["total_packets"] == 15
    assert edge_1_2["total_bytes"] == 2600
    assert edge_1_2["has_alerts"] is True
    assert edge_1_2["max_severity"] == "HIGH"
    assert set(edge_1_2["ports"]) == {80, 443}


def test_topology_pcap_not_found(client, populated_db):
    """Test 404 response when pcap_id does not exist."""
    res = client.get("/api/topology?pcap_id=9999")
    assert res.status_code == 404


def test_topology_filter_protocol(client, populated_db):
    """Test filtering topology by protocol."""
    res = client.get("/api/topology?pcap_id=1&protocol=DNS")
    assert res.status_code == 200
    data = res.json()

    assert data["summary"]["total_nodes"] == 2  # 10.0.0.1 and 8.8.8.8
    assert data["summary"]["total_edges"] == 1
    assert data["edges"][0]["source"] == "10.0.0.1"
    assert data["edges"][0]["target"] == "8.8.8.8"
    assert data["edges"][0]["protocols"] == ["DNS"]


def test_topology_filter_min_flows(client, populated_db):
    """Test min_flows filter."""
    # Only 10.0.0.1 -> 10.0.0.2 has 2 flows, others have 1
    res = client.get("/api/topology?pcap_id=1&min_flows=2")
    assert res.status_code == 200
    data = res.json()

    assert data["summary"]["total_edges"] == 1
    assert data["edges"][0]["source"] == "10.0.0.1"
    assert data["edges"][0]["target"] == "10.0.0.2"


def test_topology_filter_only_alerts(client, populated_db):
    """Test only_alerts filter."""
    res = client.get("/api/topology?pcap_id=1&only_alerts=true")
    assert res.status_code == 200
    data = res.json()

    # Only 10.0.0.1 and 10.0.0.2 have alerts
    ips = {n["ip"] for n in data["nodes"]}
    assert ips == {"10.0.0.1", "10.0.0.2"}
    assert len(data["edges"]) == 1
    assert data["edges"][0]["has_alerts"] is True


def test_topology_limit_nodes(client, populated_db):
    """Test limiting node count for large topologies."""
    res = client.get("/api/topology?limit_nodes=5")
    assert res.status_code == 200
    data = res.json()
    assert len(data["nodes"]) <= 5
    assert data["summary"]["is_truncated"] is True
    assert data["summary"]["total_unfiltered_nodes"] == 6
