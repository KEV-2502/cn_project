from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from backend.app.database import get_db
from backend.app.models.flow import NetworkFlow
from backend.app.schemas.flow import FlowResponse
from backend.app.schemas.common import PaginatedResponse

router = APIRouter(prefix="/flows", tags=["Network Flows"])

@router.get("", response_model=PaginatedResponse[FlowResponse])
def list_flows(
    pcap_id: Optional[int] = Query(None),
    protocol: Optional[str] = Query(None),
    src_ip: Optional[str] = Query(None),
    dst_ip: Optional[str] = Query(None),
    port: Optional[int] = Query(None),
    only_anomalies: bool = Query(False),
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    db: Session = Depends(get_db)
):
    query = db.query(NetworkFlow)
    
    if pcap_id is not None:
        query = query.filter(NetworkFlow.pcap_id == pcap_id)
    if protocol:
        query = query.filter(NetworkFlow.protocol == protocol.upper())
    if src_ip:
        query = query.filter(NetworkFlow.src_ip.like(f"%{src_ip}%"))
    if dst_ip:
        query = query.filter(NetworkFlow.dst_ip.like(f"%{dst_ip}%"))
    if port is not None:
        query = query.filter((NetworkFlow.src_port == port) | (NetworkFlow.dst_port == port))
    if only_anomalies:
        query = query.filter(NetworkFlow.is_anomaly == 1)

    total = query.count()
    offset = (page - 1) * page_size
    items = query.order_by(NetworkFlow.start_time.desc()).offset(offset).limit(page_size).all()
    pages = (total + page_size - 1) // page_size if total > 0 else 1

    return PaginatedResponse[FlowResponse](
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        pages=pages
    )

@router.get("/{flow_id}", response_model=FlowResponse)
def get_flow(flow_id: int, db: Session = Depends(get_db)):
    flow = db.query(NetworkFlow).filter(NetworkFlow.id == flow_id).first()
    if not flow:
        raise HTTPException(status_code=404, detail=f"Flow with ID {flow_id} not found")
    return flow
