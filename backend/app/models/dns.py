from sqlalchemy import Column, Integer, String, Float, ForeignKey, Index
from backend.app.database import Base


class DnsQueryRecord(Base):
    __tablename__ = "dns_query_records"

    id = Column(Integer, primary_key=True, index=True)
    pcap_id = Column(Integer, ForeignKey("pcap_files.id", ondelete="CASCADE"), nullable=False, index=True)
    timestamp = Column(Float, nullable=False, index=True)
    src_ip = Column(String(64), nullable=False, index=True)
    dst_ip = Column(String(64), nullable=False)
    query_name = Column(String(255), nullable=False)
    query_length = Column(Integer, nullable=False)
    is_response = Column(Integer, default=0, nullable=False)

    __table_args__ = (
        Index("idx_dns_pcap_src", "pcap_id", "src_ip"),
    )
