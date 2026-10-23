"""Threat Detection Rule Orchestrator Engine.

Coordinates rule evaluation, deduplicates alert findings, and persists
ThreatAlert records to the database.
"""

import json
from typing import List, Optional
from sqlalchemy.orm import Session

from backend.app.models.pcap import PcapFile
from backend.app.models.flow import NetworkFlow
from backend.app.models.alert import ThreatAlert, IncidentStatus
from backend.app.models.dns import DnsQueryRecord
from backend.app.pipeline.rules.base import BaseRule, DetectionResult
from backend.app.pipeline.rules.port_scan import PortScanRule
from backend.app.pipeline.rules.excessive_conn import ExcessiveConnectionRule
from backend.app.pipeline.rules.dns_threats import DnsThreatRule


class RuleEngine:
    """Manages rule registration, execution against traffic data, and alert generation."""

    def __init__(self, rules: Optional[List[BaseRule]] = None):
        if rules is None:
            self.rules: List[BaseRule] = [
                PortScanRule(),
                ExcessiveConnectionRule(),
                DnsThreatRule(),
            ]
        else:
            self.rules = rules

    def evaluate_all(
        self,
        pcap_id: int,
        flows: List[NetworkFlow],
        dns_records: List[DnsQueryRecord],
    ) -> List[DetectionResult]:
        """Execute all configured rules and aggregate detection results."""
        results: List[DetectionResult] = []
        for rule in self.rules:
            findings = rule.evaluate(pcap_id, flows, dns_records)
            results.extend(findings)
        return results

    def run_and_persist(
        self,
        pcap_id: int,
        db: Session,
    ) -> List[ThreatAlert]:
        """Execute detection for a capture, replace prior alerts idempotently, and persist.

        Preserves existing incident triage state (status and resolution notes)
        for alerts matching the same (rule_id, src_ip, dst_ip) tuple.
        """
        flows = db.query(NetworkFlow).filter(NetworkFlow.pcap_id == pcap_id).all()
        dns_records = db.query(DnsQueryRecord).filter(DnsQueryRecord.pcap_id == pcap_id).all()

        detection_results = self.evaluate_all(pcap_id, flows, dns_records)

        # Retrieve existing alerts to preserve triage state (status, resolution_notes)
        existing_alerts = db.query(ThreatAlert).filter(ThreatAlert.pcap_id == pcap_id).all()
        triage_map = {
            (a.rule_id, a.src_ip or "", a.dst_ip or ""): (a.status, a.resolution_notes)
            for a in existing_alerts
        }

        # Remove previous alerts for this capture to ensure deterministic idempotence
        db.query(ThreatAlert).filter(ThreatAlert.pcap_id == pcap_id).delete()

        alert_models: List[ThreatAlert] = []
        for res in detection_results:
            key = (res.rule_id, res.src_ip or "", res.dst_ip or "")
            saved_status, saved_notes = triage_map.get(key, (IncidentStatus.OPEN.value, None))

            alert = ThreatAlert(
                pcap_id=pcap_id,
                rule_id=res.rule_id,
                rule_name=res.rule_name,
                detection_type=res.detection_type,
                severity=res.severity,
                risk_score=res.risk_score,
                src_ip=res.src_ip,
                dst_ip=res.dst_ip,
                src_port=res.src_port,
                dst_port=res.dst_port,
                protocol=res.protocol,
                timestamp=res.timestamp,
                description=res.description,
                explanation=res.explanation,
                evidence_json=json.dumps(res.evidence),
                flow_ids_json=json.dumps(res.flow_ids),
                status=saved_status,
                resolution_notes=saved_notes,
            )
            alert_models.append(alert)

        if alert_models:
            db.add_all(alert_models)

        # Update PcapFile alert count
        pcap_record = db.query(PcapFile).filter(PcapFile.id == pcap_id).first()
        if pcap_record:
            pcap_record.alert_count = len(alert_models)

        db.commit()

        for a in alert_models:
            db.refresh(a)

        return alert_models
