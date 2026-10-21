from typing import List, Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import func
from backend.app.database import get_db
from backend.app.models.pcap import PcapFile
from backend.app.models.flow import NetworkFlow
from backend.app.models.alert import ThreatAlert, AlertSeverity, IncidentStatus
from backend.app.schemas.stats import (
    OverviewStats,
    ProtocolDistribution,
    TopHost,
    TimeSeriesPoint,
    AnalyticsSummary,
)
import datetime

router = APIRouter(prefix="/stats", tags=["Security Analytics"])

@router.get("/overview", response_model=OverviewStats)
def get_overview_stats(pcap_id: Optional[int] = Query(None), db: Session = Depends(get_db)):
    pcap_q = db.query(PcapFile)
    flow_q = db.query(NetworkFlow)
    alert_q = db.query(ThreatAlert)

    if pcap_id is not None:
        pcap_q = pcap_q.filter(PcapFile.id == pcap_id)
        flow_q = flow_q.filter(NetworkFlow.pcap_id == pcap_id)
        alert_q = alert_q.filter(ThreatAlert.pcap_id == pcap_id)

    total_pcaps = pcap_q.count()
    
    flow_totals = flow_q.with_entities(
        func.count(NetworkFlow.id),
        func.coalesce(func.sum(NetworkFlow.total_packets), 0),
        func.coalesce(func.sum(NetworkFlow.total_bytes), 0)
    ).first()

    total_flows = flow_totals[0] if flow_totals else 0
    total_packets = flow_totals[1] if flow_totals else 0
    total_bytes = flow_totals[2] if flow_totals else 0

    total_alerts = alert_q.count()
    critical_alerts = alert_q.filter(ThreatAlert.severity == AlertSeverity.CRITICAL.value).count()
    high_alerts = alert_q.filter(ThreatAlert.severity == AlertSeverity.HIGH.value).count()
    medium_alerts = alert_q.filter(ThreatAlert.severity == AlertSeverity.MEDIUM.value).count()
    low_alerts = alert_q.filter(ThreatAlert.severity == AlertSeverity.LOW.value).count()
    active_incidents = alert_q.filter(ThreatAlert.status.in_([IncidentStatus.OPEN.value, IncidentStatus.INVESTIGATING.value])).count()

    avg_score_res = alert_q.with_entities(func.avg(ThreatAlert.risk_score)).scalar()
    avg_risk_score = round(float(avg_score_res), 1) if avg_score_res else 0.0

    return OverviewStats(
        total_pcaps=total_pcaps,
        total_packets=int(total_packets),
        total_flows=int(total_flows),
        total_bytes=int(total_bytes),
        total_alerts=total_alerts,
        critical_alerts=critical_alerts,
        high_alerts=high_alerts,
        medium_alerts=medium_alerts,
        low_alerts=low_alerts,
        active_incidents=active_incidents,
        avg_risk_score=avg_risk_score,
    )

@router.get("/analytics", response_model=AnalyticsSummary)
def get_analytics(pcap_id: Optional[int] = Query(None), db: Session = Depends(get_db)):
    overview = get_overview_stats(pcap_id=pcap_id, db=db)
    flow_q = db.query(NetworkFlow)
    alert_q = db.query(ThreatAlert)

    if pcap_id is not None:
        flow_q = flow_q.filter(NetworkFlow.pcap_id == pcap_id)
        alert_q = alert_q.filter(ThreatAlert.pcap_id == pcap_id)

    # Protocol breakdown
    proto_records = flow_q.with_entities(
        NetworkFlow.protocol,
        func.count(NetworkFlow.id),
        func.coalesce(func.sum(NetworkFlow.total_packets), 0),
        func.coalesce(func.sum(NetworkFlow.total_bytes), 0)
    ).group_by(NetworkFlow.protocol).all()

    total_flow_count = overview.total_flows if overview.total_flows > 0 else 1
    protocol_distribution = [
        ProtocolDistribution(
            protocol=proto,
            flow_count=cnt,
            packet_count=int(pkts),
            byte_count=int(bts),
            percentage=round((cnt / total_flow_count) * 100, 1),
        )
        for proto, cnt, pkts, bts in proto_records
    ]

    # Top sources
    top_src_records = flow_q.with_entities(
        NetworkFlow.src_ip,
        func.coalesce(func.sum(NetworkFlow.total_packets), 0),
        func.coalesce(func.sum(NetworkFlow.total_bytes), 0),
        func.count(NetworkFlow.id)
    ).group_by(NetworkFlow.src_ip).order_by(func.sum(NetworkFlow.total_bytes).desc()).limit(5).all()

    top_sources = [
        TopHost(ip=ip, packets=int(pkts), bytes=int(bts), flow_count=cnt)
        for ip, pkts, bts, cnt in top_src_records
    ]

    # Top destinations
    top_dst_records = flow_q.with_entities(
        NetworkFlow.dst_ip,
        func.coalesce(func.sum(NetworkFlow.total_packets), 0),
        func.coalesce(func.sum(NetworkFlow.total_bytes), 0),
        func.count(NetworkFlow.id)
    ).group_by(NetworkFlow.dst_ip).order_by(func.sum(NetworkFlow.total_bytes).desc()).limit(5).all()

    top_destinations = [
        TopHost(ip=ip, packets=int(pkts), bytes=int(bts), flow_count=cnt)
        for ip, pkts, bts, cnt in top_dst_records
    ]

    # Timeline buckets (10 intervals or based on flows)
    flows = flow_q.order_by(NetworkFlow.start_time.asc()).all()
    timeline: List[TimeSeriesPoint] = []
    if flows:
        min_time = flows[0].start_time
        max_time = flows[-1].end_time
        time_span = max(max_time - min_time, 1.0)
        bucket_count = min(12, len(flows))
        bucket_size = max(time_span / bucket_count, 1.0)

        for b in range(bucket_count):
            b_start = min_time + b * bucket_size
            b_end = b_start + bucket_size
            b_flows = [f for f in flows if (b_start <= f.start_time < b_end) or (b_start <= f.end_time < b_end)]
            pkts = sum(f.total_packets for f in b_flows)
            bts = sum(f.total_bytes for f in b_flows)
            
            # Count alerts occurring in this bucket
            alerts_in_b = alert_q.filter(ThreatAlert.timestamp >= b_start, ThreatAlert.timestamp < b_end).count()
            
            dt_str = datetime.datetime.fromtimestamp(b_start).strftime("%H:%M:%S")
            timeline.append(TimeSeriesPoint(
                timestamp=b_start,
                formatted_time=dt_str,
                packet_count=pkts,
                byte_count=bts,
                alert_count=alerts_in_b
            ))

    return AnalyticsSummary(
        overview=overview,
        protocol_distribution=protocol_distribution,
        top_sources=top_sources,
        top_destinations=top_destinations,
        timeline=timeline,
    )
