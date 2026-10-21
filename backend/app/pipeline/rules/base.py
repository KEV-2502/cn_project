"""Base detection rule interface and result schema."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from backend.app.models.flow import NetworkFlow
from backend.app.models.dns import DnsQueryRecord


@dataclass
class DetectionResult:
    rule_id: str
    rule_name: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    risk_score: float  # 0.0 to 100.0
    timestamp: float
    description: str
    explanation: str
    evidence: Dict[str, Any]
    detection_type: str = "RULE"
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    flow_ids: List[int] = field(default_factory=list)


class BaseRule(ABC):
    """Abstract base class for all network detection rules."""

    @abstractmethod
    def evaluate(
        self,
        pcap_id: int,
        flows: List[NetworkFlow],
        dns_records: List[DnsQueryRecord],
    ) -> List[DetectionResult]:
        """Evaluate traffic data and return any triggered detection alerts."""
        pass
