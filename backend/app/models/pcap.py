from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Float, DateTime, Text
from backend.app.database import Base
import enum

def utc_now():
    return datetime.now(timezone.utc)

class PcapStatus(str, enum.Enum):
    QUEUED = "QUEUED"
    PROCESSING = "PROCESSING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"

class PcapFile(Base):
    __tablename__ = "pcap_files"

    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String(255), nullable=False)
    file_path = Column(String(1024), nullable=False)
    file_size_bytes = Column(Integer, nullable=False, default=0)
    sha256_hash = Column(String(64), nullable=False, index=True)
    status = Column(String(32), default=PcapStatus.QUEUED.value, nullable=False)
    
    packet_count = Column(Integer, default=0, nullable=False)
    flow_count = Column(Integer, default=0, nullable=False)
    alert_count = Column(Integer, default=0, nullable=False)
    duration_seconds = Column(Float, default=0.0, nullable=False)
    
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    processed_at = Column(DateTime, nullable=True)
