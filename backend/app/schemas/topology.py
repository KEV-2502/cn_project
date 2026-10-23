from typing import List, Optional
from pydantic import BaseModel


class TopologyAlertSummary(BaseModel):
    id: int
    rule_id: str
    rule_name: str
    severity: str
    risk_score: float
    description: str
    timestamp: float


class TopologyNode(BaseModel):
    id: str  # IP address
    ip: str
    total_flows: int
    total_packets: int
    total_bytes: int
    sent_packets: int
    received_packets: int
    sent_bytes: int
    received_bytes: int
    protocols: List[str]
    peer_count: int
    peers: List[str]
    alert_count: int
    max_severity: Optional[str] = None
    alerts: List[TopologyAlertSummary]
    role: str  # "client" | "server" | "mixed"


class TopologyEdge(BaseModel):
    id: str  # e.g., "192.168.1.50->10.0.0.10"
    source: str
    target: str
    flow_count: int
    total_packets: int
    total_bytes: int
    forward_packets: int
    backward_packets: int
    forward_bytes: int
    backward_bytes: int
    protocols: List[str]
    ports: List[int]
    tcp_states: List[str]
    has_alerts: bool
    alert_count: int
    max_severity: Optional[str] = None
    alerts: List[TopologyAlertSummary]


class TopologySummary(BaseModel):
    total_nodes: int
    total_edges: int
    total_flows: int
    total_packets: int
    total_bytes: int
    alerted_nodes_count: int
    alerted_edges_count: int
    is_truncated: bool = False
    total_unfiltered_nodes: int
    pcap_id: Optional[int] = None
    pcap_name: Optional[str] = None


class TopologyResponse(BaseModel):
    nodes: List[TopologyNode]
    edges: List[TopologyEdge]
    summary: TopologySummary
