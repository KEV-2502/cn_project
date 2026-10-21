from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict

class FlowResponse(BaseModel):
    id: int
    pcap_id: int
    flow_key: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    ip_version: int
    start_time: float
    end_time: float
    duration: float
    forward_packets: int
    backward_packets: int
    forward_bytes: int
    backward_bytes: int
    total_packets: int
    total_bytes: int
    tcp_flags_forward: str
    tcp_flags_backward: str
    tcp_state: str
    anomaly_score: float
    is_anomaly: int
    anomaly_features_json: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

class FlowFilterParams(BaseModel):
    pcap_id: Optional[int] = None
    protocol: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    port: Optional[int] = None
    only_anomalies: Optional[bool] = False
