"""Regression tests for PCAP re-analysis API and safe persistence."""

import tempfile
from pathlib import Path
from scapy.all import Ether, IP, TCP, UDP, ICMP, DNS, DNSQR, wrpcap
import pytest

from backend.app.models.pcap import PcapFile, PcapStatus
from backend.app.models.flow import NetworkFlow
from backend.app.models.alert import ThreatAlert, IncidentStatus
from backend.app.models.dns import DnsQueryRecord


def create_sample_pcap_bytes():
    """Generate a valid PCAP byte buffer containing diverse test traffic."""
    pkts = [
        # TCP Flow 1: 3-way handshake + data
        Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=50001, dport=80, flags="S"),
        Ether() / IP(src="10.0.0.1", dst="192.168.1.100") / TCP(sport=80, dport=50001, flags="SA"),
        Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=50001, dport=80, flags="A"),
        # UDP DNS Flow
        Ether() / IP(src="192.168.1.100", dst="8.8.8.8") / UDP(sport=53000, dport=53) / DNS(rd=1, qd=DNSQR(qname="test.local")),
    ]
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        wrpcap(f.name, pkts)
        f.seek(0)
        with open(f.name, "rb") as read_f:
            data = read_f.read()
    return data


def test_reanalyze_existing_capture_successfully(client, db_session):
    """Verify that re-analyzing an existing capture succeeds and returns explicit summary."""
    pcap_data = create_sample_pcap_bytes()
    upload_res = client.post(
        "/api/pcaps/upload",
        files={"file": ("reanalyze_sample.pcap", pcap_data, "application/octet-stream")},
    )
    assert upload_res.status_code == 201
    pcap_id = upload_res.json()["id"]

    # Call re-analysis endpoint
    reanalyze_res = client.post(f"/api/pcaps/{pcap_id}/reanalyze")
    assert reanalyze_res.status_code == 200
    res_data = reanalyze_res.json()

    assert res_data["id"] == pcap_id
    assert res_data["filename"] == "reanalyze_sample.pcap"
    assert res_data["status"] == "COMPLETED"
    assert res_data["packet_count"] == 4
    assert res_data["flow_count"] == 2
    assert "anomaly_count" in res_data
    assert "successfully re-analyzed" in res_data["message"]


def test_reanalysis_updates_old_flows_with_ml_results(client, db_session):
    """Simulate an old pre-ML capture with 0.0 anomaly scores and verify reanalysis updates them."""
    pcap_data = create_sample_pcap_bytes()
    upload_res = client.post(
        "/api/pcaps/upload",
        files={"file": ("old_ml_sample.pcap", pcap_data, "application/octet-stream")},
    )
    pcap_id = upload_res.json()["id"]

    # Artificially reset anomaly scores to 0.0 and is_anomaly to 0 to simulate pre-ML database state
    flows = db_session.query(NetworkFlow).filter(NetworkFlow.pcap_id == pcap_id).all()
    for f in flows:
        f.anomaly_score = 0.0
        f.is_anomaly = 0
        f.anomaly_features_json = "{}"
    db_session.commit()

    # Confirm flows are reset in DB
    flows_before = db_session.query(NetworkFlow).filter(NetworkFlow.pcap_id == pcap_id).all()
    assert all(f.anomaly_score == 0.0 for f in flows_before)

    # Re-analyze
    res = client.post(f"/api/pcaps/{pcap_id}/reanalyze")
    assert res.status_code == 200

    # Query flows after reanalysis
    flows_after = db_session.query(NetworkFlow).filter(NetworkFlow.pcap_id == pcap_id).all()
    assert len(flows_after) == 2
    # Machine learning model must have calculated genuine anomaly scores
    assert all(f.anomaly_score > 0.0 for f in flows_after)


def test_repeated_reanalysis_does_not_duplicate_flows_or_alerts(client, db_session):
    """Verify that analyzing the same capture multiple times is strictly idempotent."""
    pcap_data = create_sample_pcap_bytes()
    upload_res = client.post(
        "/api/pcaps/upload",
        files={"file": ("idempotence_sample.pcap", pcap_data, "application/octet-stream")},
    )
    pcap_id = upload_res.json()["id"]

    initial_flow_count = db_session.query(NetworkFlow).filter(NetworkFlow.pcap_id == pcap_id).count()
    initial_alert_count = db_session.query(ThreatAlert).filter(ThreatAlert.pcap_id == pcap_id).count()
    initial_dns_count = db_session.query(DnsQueryRecord).filter(DnsQueryRecord.pcap_id == pcap_id).count()

    # Re-analyze 3 consecutive times
    for _ in range(3):
        res = client.post(f"/api/pcaps/{pcap_id}/reanalyze")
        assert res.status_code == 200

    flow_count_after = db_session.query(NetworkFlow).filter(NetworkFlow.pcap_id == pcap_id).count()
    alert_count_after = db_session.query(ThreatAlert).filter(ThreatAlert.pcap_id == pcap_id).count()
    dns_count_after = db_session.query(DnsQueryRecord).filter(DnsQueryRecord.pcap_id == pcap_id).count()

    assert flow_count_after == initial_flow_count
    assert alert_count_after == initial_alert_count
    assert dns_count_after == initial_dns_count


def test_capture_id_and_original_file_remain_unchanged(client, db_session):
    """Verify that re-analyzing preserves the PcapFile id, sha256_hash, and disk file."""
    pcap_data = create_sample_pcap_bytes()
    upload_res = client.post(
        "/api/pcaps/upload",
        files={"file": ("identity_sample.pcap", pcap_data, "application/octet-stream")},
    )
    original_meta = upload_res.json()
    pcap_id = original_meta["id"]

    res = client.post(f"/api/pcaps/{pcap_id}/reanalyze")
    assert res.status_code == 200

    pcap_record = db_session.query(PcapFile).filter(PcapFile.id == pcap_id).first()
    assert pcap_record is not None
    assert pcap_record.id == pcap_id
    assert pcap_record.sha256_hash == original_meta["sha256_hash"]
    assert pcap_record.file_path == original_meta["file_path"]
    assert Path(pcap_record.file_path).exists()


def test_reanalysis_affects_only_selected_capture(client, db_session):
    """Verify that re-analyzing capture A does not alter capture B's flows or alerts."""
    pcap_data_1 = create_sample_pcap_bytes()
    upload_1 = client.post(
        "/api/pcaps/upload",
        files={"file": ("capture_a.pcap", pcap_data_1, "application/octet-stream")},
    )
    pcap_1_id = upload_1.json()["id"]

    # Upload capture 2
    pkts_2 = [Ether() / IP(src="10.1.1.1", dst="10.2.2.2") / ICMP(type=8, code=0)]
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        wrpcap(f.name, pkts_2)
        f.seek(0)
        with open(f.name, "rb") as read_f:
            pcap_data_2 = read_f.read()

    upload_2 = client.post(
        "/api/pcaps/upload",
        files={"file": ("capture_b.pcap", pcap_data_2, "application/octet-stream")},
    )
    pcap_2_id = upload_2.json()["id"]

    # Get initial flows of capture 2
    c2_flow_ids = [f.id for f in db_session.query(NetworkFlow).filter(NetworkFlow.pcap_id == pcap_2_id).all()]

    # Re-analyze capture 1
    res = client.post(f"/api/pcaps/{pcap_1_id}/reanalyze")
    assert res.status_code == 200

    # Ensure capture 2 flows are unchanged
    c2_flows_after = db_session.query(NetworkFlow).filter(NetworkFlow.pcap_id == pcap_2_id).all()
    assert [f.id for f in c2_flows_after] == c2_flow_ids


def test_reanalyze_missing_or_unreadable_pcap(client, db_session):
    """Verify that a non-existent capture ID returns 404, and missing file on disk returns 404."""
    # 1. Non-existent ID
    res_404 = client.post("/api/pcaps/99999/reanalyze")
    assert res_404.status_code == 404
    assert "not found" in res_404.json()["detail"]

    # 2. Existing record whose file on disk is deleted
    pcap_data = create_sample_pcap_bytes()
    upload_res = client.post(
        "/api/pcaps/upload",
        files={"file": ("deleted_file.pcap", pcap_data, "application/octet-stream")},
    )
    pcap_id = upload_res.json()["id"]
    pcap_record = db_session.query(PcapFile).filter(PcapFile.id == pcap_id).first()

    # Delete the physical file on disk
    file_on_disk = Path(pcap_record.file_path)
    if file_on_disk.exists():
        file_on_disk.unlink()

    res_missing = client.post(f"/api/pcaps/{pcap_id}/reanalyze")
    assert res_missing.status_code == 404
    assert "missing on disk" in res_missing.json()["detail"]


def test_triage_state_preserved_across_reanalysis(client, db_session):
    """Verify that incident investigation notes and RESOLVED status are preserved upon re-analysis."""
    from pathlib import Path
    pcap_path = Path("data/test_port_scan.pcap")
    assert pcap_path.exists()

    with open(pcap_path, "rb") as f:
        file_bytes = f.read()

    upload_res = client.post(
        "/api/pcaps/upload",
        files={"file": ("test_port_scan.pcap", file_bytes, "application/octet-stream")},
    )
    pcap_id = upload_res.json()["id"]

    # Mark the generated alert as RESOLVED with custom resolution notes
    alerts = db_session.query(ThreatAlert).filter(ThreatAlert.pcap_id == pcap_id).all()
    assert len(alerts) >= 1
    target_alert = alerts[0]
    target_alert.status = IncidentStatus.RESOLVED.value
    target_alert.resolution_notes = "Verified as simulated pentest by SecOps team."
    db_session.commit()

    # Trigger re-analysis
    reanalyze_res = client.post(f"/api/pcaps/{pcap_id}/reanalyze")
    assert reanalyze_res.status_code == 200

    # Verify that the alert is re-generated and retains the RESOLVED status and notes
    refreshed_alerts = db_session.query(ThreatAlert).filter(ThreatAlert.pcap_id == pcap_id).all()
    assert len(refreshed_alerts) >= 1
    match = [a for a in refreshed_alerts if a.rule_id == target_alert.rule_id][0]
    assert match.status == IncidentStatus.RESOLVED.value
    assert match.resolution_notes == "Verified as simulated pentest by SecOps team."


def test_deduplication_without_reprocess_remains_intact(client, db_session):
    """Verify that re-uploading the same PCAP without reprocess=True returns existing record."""
    pcap_data = create_sample_pcap_bytes()
    upload1 = client.post(
        "/api/pcaps/upload",
        files={"file": ("dedup_test.pcap", pcap_data, "application/octet-stream")},
    )
    assert upload1.status_code == 201
    pcap1 = upload1.json()

    # Upload identical bytes again
    upload2 = client.post(
        "/api/pcaps/upload",
        files={"file": ("dedup_test.pcap", pcap_data, "application/octet-stream")},
    )
    assert upload2.status_code == 200
    pcap2 = upload2.json()
    assert pcap2["id"] == pcap1["id"]
    assert pcap2["sha256_hash"] == pcap1["sha256_hash"]
