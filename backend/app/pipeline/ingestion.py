"""PCAP Ingestion & Processing Pipeline.

Streams packets from disk, decodes metadata, generates bidirectional flows,
and persists results to the database.
"""

import time
import json
import logging
from typing import Optional
from pathlib import Path
from sqlalchemy.orm import Session

from backend.app.models.pcap import PcapFile, PcapStatus, utc_now
from backend.app.models.flow import NetworkFlow
from backend.app.models.dns import DnsQueryRecord
from backend.app.pipeline.parser import get_pcap_reader, parse_packet
from backend.app.pipeline.flow_aggregator import FlowAggregator
from backend.app.pipeline.rules.engine import RuleEngine
from backend.app.pipeline.ml.model import AnomalyDetector
from backend.app.config import settings

logger = logging.getLogger(__name__)


def process_pcap_ingestion(
    pcap_id: int,
    db: Session,
    timeout_seconds: Optional[float] = None,
    clear_existing: bool = False,
) -> PcapFile:
    """Ingest a PCAP capture file incrementally, aggregate flows, and persist to the database.

    Updates the PcapFile status from QUEUED -> PROCESSING -> COMPLETED (or FAILED).
    If clear_existing is True, previous derived records (NetworkFlow, DnsQueryRecord)
    belonging to this pcap_id are purged before newly parsed objects are committed.
    """
    if timeout_seconds is None:
        timeout_seconds = settings.FLOW_TIMEOUT_SECONDS

    pcap_record = db.query(PcapFile).filter(PcapFile.id == pcap_id).first()
    if not pcap_record:
        raise ValueError(f"PcapFile with ID {pcap_id} not found.")

    pcap_record.status = PcapStatus.PROCESSING.value
    db.commit()
    db.refresh(pcap_record)

    file_path = Path(pcap_record.file_path)
    if not file_path.exists():
        pcap_record.status = PcapStatus.FAILED.value
        pcap_record.error_message = f"Capture file not found on disk: {file_path}"
        db.commit()
        raise FileNotFoundError(pcap_record.error_message)

    flow_aggregator = FlowAggregator(timeout_seconds=timeout_seconds)
    packet_count = 0
    min_time: Optional[float] = None
    max_time: Optional[float] = None
    dns_query_models: list[DnsQueryRecord] = []

    try:
        reader = get_pcap_reader(str(file_path))
        
        for raw_pkt in reader:
            parsed = parse_packet(raw_pkt)
            if not parsed:
                continue

            packet_count += 1
            if min_time is None or parsed.timestamp < min_time:
                min_time = parsed.timestamp
            if max_time is None or parsed.timestamp > max_time:
                max_time = parsed.timestamp

            flow_aggregator.add_packet(parsed)

            # Preserve DNS query metadata for security analysis
            if parsed.dns_query_name:
                dns_rec = DnsQueryRecord(
                    pcap_id=pcap_id,
                    timestamp=parsed.timestamp,
                    src_ip=parsed.src_ip,
                    dst_ip=parsed.dst_ip,
                    query_name=parsed.dns_query_name,
                    query_length=len(parsed.dns_query_name),
                    is_response=1 if parsed.dns_is_response else 0,
                )
                dns_query_models.append(dns_rec)

        # Close reader if applicable
        if hasattr(reader, "close"):
            try:
                reader.close()
            except Exception:
                pass

        # Finalize all flows
        aggregated_flows = flow_aggregator.finalize_all()

        # Batch insert NetworkFlow records
        flow_models = []
        for af in aggregated_flows:
            flow_model = NetworkFlow(
                pcap_id=pcap_id,
                flow_key=af.flow_key,
                src_ip=af.src_ip,
                dst_ip=af.dst_ip,
                src_port=af.src_port,
                dst_port=af.dst_port,
                protocol=af.protocol,
                ip_version=af.ip_version,
                start_time=af.start_time,
                end_time=af.end_time,
                duration=round(af.duration, 4),
                forward_packets=af.forward_packets,
                backward_packets=af.backward_packets,
                forward_bytes=af.forward_bytes,
                backward_bytes=af.backward_bytes,
                total_packets=af.total_packets,
                total_bytes=af.total_bytes,
                tcp_flags_forward=af.tcp_flags_forward,
                tcp_flags_backward=af.tcp_flags_backward,
                tcp_state=af.tcp_state,
                anomaly_score=0.0,
                is_anomaly=0,
                anomaly_features_json="{}",
            )
            flow_models.append(flow_model)

        # Apply Isolation Forest anomaly scoring if model is available
        try:
            detector = AnomalyDetector()
            if detector.is_ready and flow_models:
                scores = detector.score_batch(aggregated_flows)
                for idx, (score, is_anomaly, attrib) in enumerate(scores):
                    flow_models[idx].anomaly_score = score
                    flow_models[idx].is_anomaly = is_anomaly
                    flow_models[idx].anomaly_features_json = json.dumps(attrib)
            elif not detector.is_ready:
                logger.warning("Anomaly detector model artifact not found. Flows persisted with default score 0.0.")
        except Exception as ml_err:
            logger.error(f"Error during ML anomaly scoring: {ml_err}. Continuing with default scores.")

        # If reprocessing, safely purge old flows & DNS queries before inserting fresh ones
        if clear_existing:
            db.query(DnsQueryRecord).filter(DnsQueryRecord.pcap_id == pcap_id).delete()
            db.query(NetworkFlow).filter(NetworkFlow.pcap_id == pcap_id).delete()

        if flow_models:
            db.bulk_save_objects(flow_models)

        if dns_query_models:
            db.bulk_save_objects(dns_query_models)

        db.commit()

        # Run Rule-Based Threat Detection Engine
        rule_engine = RuleEngine()
        alerts = rule_engine.run_and_persist(pcap_id, db)

        # Calculate duration
        duration = 0.0
        if min_time is not None and max_time is not None:
            duration = max(0.0, max_time - min_time)

        pcap_record.packet_count = packet_count
        pcap_record.flow_count = len(aggregated_flows)
        pcap_record.alert_count = len(alerts)
        pcap_record.duration_seconds = round(duration, 2)
        pcap_record.status = PcapStatus.COMPLETED.value
        pcap_record.error_message = None
        pcap_record.processed_at = utc_now()
        db.commit()
        db.refresh(pcap_record)

        return pcap_record

    except Exception as exc:
        db.rollback()
        pcap_record.status = PcapStatus.FAILED.value
        pcap_record.error_message = str(exc)
        db.commit()
        raise exc
