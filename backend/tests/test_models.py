import datetime
from backend.app.models.pcap import PcapFile, PcapStatus
from backend.app.models.flow import NetworkFlow
from backend.app.models.alert import ThreatAlert, AlertSeverity, IncidentStatus


def test_create_pcap_record(db_session):
    pcap = PcapFile(
        filename="test_capture.pcap",
        file_path="/tmp/test_capture.pcap",
        file_size_bytes=1024,
        sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        status=PcapStatus.COMPLETED.value,
        packet_count=50,
        flow_count=5,
        alert_count=1,
        duration_seconds=12.5,
    )
    db_session.add(pcap)
    db_session.commit()
    db_session.refresh(pcap)

    assert pcap.id is not None
    assert pcap.packet_count == 50
    assert pcap.status == PcapStatus.COMPLETED.value


def test_create_flow_and_alert(db_session, client):
    pcap = PcapFile(
        filename="scan.pcap",
        file_path="/tmp/scan.pcap",
        file_size_bytes=2048,
        sha256_hash="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        status=PcapStatus.COMPLETED.value,
    )
    db_session.add(pcap)
    db_session.commit()

    flow = NetworkFlow(
        pcap_id=pcap.id,
        flow_key="192.168.1.10:44321-10.0.0.1:80-TCP",
        src_ip="192.168.1.10",
        dst_ip="10.0.0.1",
        src_port=44321,
        dst_port=80,
        protocol="TCP",
        ip_version=4,
        start_time=1000.0,
        end_time=1005.0,
        duration=5.0,
        forward_packets=10,
        backward_packets=8,
        forward_bytes=1200,
        backward_bytes=4500,
        total_packets=18,
        total_bytes=5700,
        tcp_state="ESTABLISHED",
        anomaly_score=0.15,
        is_anomaly=0,
    )
    db_session.add(flow)

    alert = ThreatAlert(
        pcap_id=pcap.id,
        rule_id="RULE_PORT_SCAN",
        rule_name="Horizontal Port Scanning Detected",
        detection_type="RULE",
        severity=AlertSeverity.HIGH.value,
        risk_score=75.0,
        src_ip="192.168.1.10",
        dst_ip="10.0.0.1",
        timestamp=1002.5,
        description="Source 192.168.1.10 probed 25 unique ports",
        explanation="High frequency port probing indicates active reconnaissance",
        evidence_json='{"unique_ports": 25, "threshold": 15}',
        flow_ids_json='[1]',
        status=IncidentStatus.OPEN.value,
    )
    db_session.add(alert)
    db_session.commit()

    # Query via API client
    res_pcaps = client.get("/api/pcaps")
    assert res_pcaps.status_code == 200
    assert len(res_pcaps.json()) == 1

    res_flows = client.get("/api/flows")
    assert res_flows.status_code == 200
    flows_data = res_flows.json()
    assert flows_data["total"] == 1
    assert flows_data["items"][0]["src_ip"] == "192.168.1.10"

    res_alerts = client.get("/api/alerts")
    assert res_alerts.status_code == 200
    alerts_data = res_alerts.json()
    assert alerts_data["total"] == 1
    assert alerts_data["items"][0]["severity"] == "HIGH"

    # Test status update
    alert_id = alerts_data["items"][0]["id"]
    patch_res = client.patch(f"/api/alerts/{alert_id}/status", json={"status": "INVESTIGATING", "resolution_notes": "SOC team reviewing"})
    assert patch_res.status_code == 200
    assert patch_res.json()["status"] == "INVESTIGATING"

    # Test stats overview
    res_stats = client.get("/api/stats/overview")
    assert res_stats.status_code == 200
    stats_data = res_stats.json()
    assert stats_data["total_pcaps"] == 1
    assert stats_data["total_flows"] == 1
    assert stats_data["total_alerts"] == 1
    assert stats_data["high_alerts"] == 1
