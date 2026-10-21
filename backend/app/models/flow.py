from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, Index
from backend.app.database import Base

def utc_now():
    return datetime.now(timezone.utc)

class NetworkFlow(Base):
    __tablename__ = "network_flows"

    id = Column(Integer, primary_key=True, index=True)
    pcap_id = Column(Integer, ForeignKey("pcap_files.id", ondelete="CASCADE"), nullable=False, index=True)
    
    # Flow 5-tuple canonical key
    flow_key = Column(String(255), nullable=False, index=True)
    
    src_ip = Column(String(64), nullable=False, index=True)
    dst_ip = Column(String(64), nullable=False, index=True)
    src_port = Column(Integer, nullable=False)
    dst_port = Column(Integer, nullable=False)
    protocol = Column(String(16), nullable=False, index=True)  # TCP, UDP, ICMP, DNS
    ip_version = Column(Integer, default=4, nullable=False)    # 4 or 6

    # Timestamps & duration
    start_time = Column(Float, nullable=False)  # Epoch seconds
    end_time = Column(Float, nullable=False)
    duration = Column(Float, nullable=False, default=0.0)

    # Directional traffic statistics
    forward_packets = Column(Integer, default=0, nullable=False)
    backward_packets = Column(Integer, default=0, nullable=False)
    forward_bytes = Column(Integer, default=0, nullable=False)
    backward_bytes = Column(Integer, default=0, nullable=False)
    total_packets = Column(Integer, default=0, nullable=False)
    total_bytes = Column(Integer, default=0, nullable=False)

    # TCP state and flags observed
    tcp_flags_forward = Column(String(32), default="", nullable=False)
    tcp_flags_backward = Column(String(32), default="", nullable=False)
    tcp_state = Column(String(32), default="N/A", nullable=False)  # ESTABLISHED, RESET, INCOMPLETE, etc.

    # AI Anomaly Detection Scores
    anomaly_score = Column(Float, default=0.0, nullable=False)      # continuous score from Isolation Forest
    is_anomaly = Column(Integer, default=0, nullable=False)         # 1 if flagged anomalous, 0 otherwise
    anomaly_features_json = Column(String(1024), default="{}", nullable=False) # Top feature contributions

    created_at = Column(DateTime, default=utc_now, nullable=False)

    __table_args__ = (
        Index("idx_flow_endpoints", "src_ip", "dst_ip", "dst_port", "protocol"),
    )
