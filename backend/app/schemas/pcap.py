from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict

class PcapBase(BaseModel):
    filename: str

class PcapCreate(PcapBase):
    pass

class PcapResponse(PcapBase):
    id: int
    file_path: str
    file_size_bytes: int
    sha256_hash: str
    status: str
    packet_count: int
    flow_count: int
    alert_count: int
    duration_seconds: float
    error_message: Optional[str] = None
    created_at: datetime
    processed_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)
