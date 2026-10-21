import os
from pathlib import Path
from pydantic import BaseModel

BASE_DIR = Path(__file__).resolve().parent.parent.parent
DATA_DIR = BASE_DIR / "data"
UPLOAD_DIR = DATA_DIR / "uploads"
MODEL_DIR = DATA_DIR / "models"

UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
MODEL_DIR.mkdir(parents=True, exist_ok=True)

class Settings(BaseModel):
    PROJECT_NAME: str = "Intelligent Network Threat Detection & Security Analytics"
    VERSION: str = "0.1.0"
    API_V1_PREFIX: str = "/api"
    
    # Storage
    DATABASE_URL: str = os.getenv("DATABASE_URL", f"sqlite:///{DATA_DIR / 'threat_detection.db'}")
    UPLOAD_DIR: Path = UPLOAD_DIR
    MODEL_DIR: Path = MODEL_DIR
    MAX_UPLOAD_SIZE_BYTES: int = 100 * 1024 * 1024  # 100 MB max for local MVP
    
    # Flow processing
    FLOW_TIMEOUT_SECONDS: float = 60.0  # Inactive timeout for bidirectional flows
    
    # Rule Detection Thresholds (Configurable)
    PORT_SCAN_UNIQUE_PORTS: int = 15     # unique ports from same src in window
    PORT_SCAN_WINDOW_SECONDS: float = 10.0
    
    EXCESSIVE_CONN_RATE: int = 40        # connections to same dst within window
    EXCESSIVE_CONN_WINDOW_SECONDS: float = 5.0
    
    DNS_BURST_QUERY_COUNT: int = 25      # queries from src in window
    DNS_BURST_WINDOW_SECONDS: float = 5.0
    DNS_LONG_NAME_LENGTH: int = 50       # suspicious domain length (exfiltration/tunneling)
    DNS_SUBDOMAIN_ENTROPY_THRESHOLD: float = 3.5  # entropy or high subdomain count

settings = Settings()
