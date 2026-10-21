import hashlib
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Query, BackgroundTasks
from sqlalchemy.orm import Session
from backend.app.database import get_db
from backend.app.models.pcap import PcapFile, PcapStatus
from backend.app.models.flow import NetworkFlow
from backend.app.models.alert import ThreatAlert
from backend.app.schemas.pcap import PcapResponse
from backend.app.config import settings

router = APIRouter(prefix="/pcaps", tags=["PCAPs"])

@router.get("", response_model=List[PcapResponse])
def list_pcaps(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db)
):
    pcaps = db.query(PcapFile).order_by(PcapFile.created_at.desc()).offset(skip).limit(limit).all()
    return pcaps

@router.get("/{pcap_id}", response_model=PcapResponse)
def get_pcap(pcap_id: int, db: Session = Depends(get_db)):
    pcap = db.query(PcapFile).filter(PcapFile.id == pcap_id).first()
    if not pcap:
        raise HTTPException(status_code=404, detail=f"PCAP with ID {pcap_id} not found")
    return pcap

@router.delete("/{pcap_id}")
def delete_pcap(pcap_id: int, db: Session = Depends(get_db)):
    pcap = db.query(PcapFile).filter(PcapFile.id == pcap_id).first()
    if not pcap:
        raise HTTPException(status_code=404, detail=f"PCAP with ID {pcap_id} not found")
    
    # Delete associated flows and alerts
    db.query(ThreatAlert).filter(ThreatAlert.pcap_id == pcap_id).delete()
    db.query(NetworkFlow).filter(NetworkFlow.pcap_id == pcap_id).delete()
    db.delete(pcap)
    db.commit()

    return {"message": f"PCAP {pcap_id} and associated flows/alerts successfully deleted"}
