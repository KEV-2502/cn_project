from datetime import datetime
from typing import Optional, Any, Dict, List
from pydantic import BaseModel, ConfigDict

class AlertStatusUpdate(BaseModel):
    status: str
    resolution_notes: Optional[str] = None

class AlertResponse(BaseModel):
    id: int
    pcap_id: int
    rule_id: str
    rule_name: str
    detection_type: str
    severity: str
    risk_score: float
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    timestamp: float
    description: str
    explanation: str
    evidence_json: str
    flow_ids_json: str
    status: str
    resolution_notes: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

class AlertFilterParams(BaseModel):
    pcap_id: Optional[int] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    rule_id: Optional[str] = None
