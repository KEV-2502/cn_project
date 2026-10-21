from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from backend.app.database import get_db
from backend.app.models.alert import ThreatAlert, IncidentStatus
from backend.app.schemas.alert import AlertResponse, AlertStatusUpdate
from backend.app.schemas.common import PaginatedResponse

router = APIRouter(prefix="/alerts", tags=["Threat Alerts"])

@router.get("", response_model=PaginatedResponse[AlertResponse])
def list_alerts(
    pcap_id: Optional[int] = Query(None),
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    rule_id: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    db: Session = Depends(get_db)
):
    query = db.query(ThreatAlert)

    if pcap_id is not None:
        query = query.filter(ThreatAlert.pcap_id == pcap_id)
    if severity:
        query = query.filter(ThreatAlert.severity == severity.upper())
    if status:
        query = query.filter(ThreatAlert.status == status.upper())
    if rule_id:
        query = query.filter(ThreatAlert.rule_id == rule_id)

    total = query.count()
    offset = (page - 1) * page_size
    items = query.order_by(ThreatAlert.risk_score.desc(), ThreatAlert.timestamp.desc()).offset(offset).limit(page_size).all()
    pages = (total + page_size - 1) // page_size if total > 0 else 1

    return PaginatedResponse[AlertResponse](
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        pages=pages
    )

@router.get("/{alert_id}", response_model=AlertResponse)
def get_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(ThreatAlert).filter(ThreatAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert with ID {alert_id} not found")
    return alert

@router.patch("/{alert_id}/status", response_model=AlertResponse)
def update_alert_status(alert_id: int, payload: AlertStatusUpdate, db: Session = Depends(get_db)):
    alert = db.query(ThreatAlert).filter(ThreatAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert with ID {alert_id} not found")
    
    valid_statuses = [s.value for s in IncidentStatus]
    status_upper = payload.status.upper()
    if status_upper not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid status '{payload.status}'. Valid: {valid_statuses}")

    alert.status = status_upper
    if payload.resolution_notes is not None:
        alert.resolution_notes = payload.resolution_notes

    db.commit()
    db.refresh(alert)
    return alert
