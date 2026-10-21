from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, Text, Index
from backend.app.database import Base
import enum

def utc_now():
    return datetime.now(timezone.utc)

class IncidentStatus(str, enum.Enum):
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"

class AlertSeverity(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class ThreatAlert(Base):
    __tablename__ = "threat_alerts"

    id = Column(Integer, primary_key=True, index=True)
    pcap_id = Column(Integer, ForeignKey("pcap_files.id", ondelete="CASCADE"), nullable=False, index=True)
    
    rule_id = Column(String(64), nullable=False, index=True)      # e.g., "RULE_PORT_SCAN", "RULE_DNS_TUNNEL"
    rule_name = Column(String(128), nullable=False)               # Human-readable rule name
    detection_type = Column(String(32), default="RULE", nullable=False) # "RULE" or "ANOMALY" or "HYBRID"
    
    severity = Column(String(16), default=AlertSeverity.MEDIUM.value, nullable=False, index=True)
    risk_score = Column(Float, default=50.0, nullable=False)       # 0 - 100 explainable score
    
    src_ip = Column(String(64), nullable=True, index=True)
    dst_ip = Column(String(64), nullable=True, index=True)
    src_port = Column(Integer, nullable=True)
    dst_port = Column(Integer, nullable=True)
    protocol = Column(String(16), nullable=True)

    timestamp = Column(Float, nullable=False)                     # Packet/alert timestamp
    description = Column(Text, nullable=False)
    explanation = Column(Text, nullable=False)                    # Explainable risk factor breakdown
    evidence_json = Column(Text, default="{}", nullable=False)    # Observed metrics/thresholds
    flow_ids_json = Column(Text, default="[]", nullable=False)    # Associated flow IDs

    # Incident Management State
    status = Column(String(32), default=IncidentStatus.OPEN.value, nullable=False, index=True)
    resolution_notes = Column(Text, nullable=True)

    created_at = Column(DateTime, default=utc_now, nullable=False)

    __table_args__ = (
        Index("idx_alert_pcap_rule", "pcap_id", "rule_id"),
    )
