from typing import List, Dict, Any, Optional
from pydantic import BaseModel

class OverviewStats(BaseModel):
    total_pcaps: int
    total_packets: int
    total_flows: int
    total_bytes: int
    total_alerts: int
    critical_alerts: int
    high_alerts: int
    medium_alerts: int
    low_alerts: int
    active_incidents: int
    avg_risk_score: float

class ProtocolDistribution(BaseModel):
    protocol: str
    flow_count: int
    packet_count: int
    byte_count: int
    percentage: float

class TopHost(BaseModel):
    ip: str
    packets: int
    bytes: int
    flow_count: int

class TimeSeriesPoint(BaseModel):
    timestamp: float
    formatted_time: str
    packet_count: int
    byte_count: int
    alert_count: int

class AnalyticsSummary(BaseModel):
    overview: OverviewStats
    protocol_distribution: List[ProtocolDistribution]
    top_sources: List[TopHost]
    top_destinations: List[TopHost]
    timeline: List[TimeSeriesPoint]
