import hashlib
import os
import uuid
from pathlib import Path
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Query, Response, status
from sqlalchemy.orm import Session
from scapy.utils import Scapy_Exception

from backend.app.database import get_db
from backend.app.models.pcap import PcapFile, PcapStatus
from backend.app.models.flow import NetworkFlow
from backend.app.models.alert import ThreatAlert
from backend.app.models.dns import DnsQueryRecord
from backend.app.schemas.pcap import PcapResponse, PcapReanalyzeResponse
from backend.app.schemas.alert import AlertResponse
from backend.app.config import settings
from backend.app.pipeline.parser import get_pcap_reader
from backend.app.pipeline.ingestion import process_pcap_ingestion
from backend.app.pipeline.rules.engine import RuleEngine
from backend.app.pipeline.ml.model import AnomalyDetector

router = APIRouter(prefix="/pcaps", tags=["PCAPs"])

ALLOWED_EXTENSIONS = {".pcap", ".pcapng", ".cap"}


@router.get("", response_model=List[PcapResponse])
def list_pcaps(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db),
):
    pcaps = db.query(PcapFile).order_by(PcapFile.created_at.desc()).offset(skip).limit(limit).all()
    return pcaps


@router.get("/{pcap_id}", response_model=PcapResponse)
def get_pcap(pcap_id: int, db: Session = Depends(get_db)):
    pcap = db.query(PcapFile).filter(PcapFile.id == pcap_id).first()
    if not pcap:
        raise HTTPException(status_code=404, detail=f"PCAP with ID {pcap_id} not found")
    return pcap


@router.post("/upload", response_model=PcapResponse)
def upload_pcap(
    response: Response,
    file: UploadFile = File(...),
    reprocess: bool = Query(False, description="Force re-processing if capture already exists"),
    db: Session = Depends(get_db),
):
    """Upload and ingest a PCAP/PCAPNG capture file.

    Validates extension and file size limit, calculates SHA-256 hash,
    handles duplicates deliberately, extracts bidirectional flows, and persists
    metadata to the database.
    """
    # 1. Validate file extension
    filename = file.filename or "unknown.pcap"
    ext = Path(filename).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported file extension '{ext}'. Allowed extensions are: {', '.join(sorted(ALLOWED_EXTENSIONS))}",
        )

    # 2. Stream file to disk while calculating SHA-256 and enforcing size limit
    hasher = hashlib.sha256()
    total_bytes = 0
    safe_name = f"{uuid.uuid4().hex}_{Path(filename).name}"
    # Keep safe chars only
    safe_name = "".join(c for c in safe_name if c.isalnum() or c in "._-")
    temp_target = settings.UPLOAD_DIR / safe_name

    try:
        with open(temp_target, "wb") as out_f:
            while chunk := file.file.read(1024 * 64):  # 64 KB chunks
                total_bytes += len(chunk)
                if total_bytes > settings.MAX_UPLOAD_SIZE_BYTES:
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail=f"Uploaded file exceeds maximum allowed size of {settings.MAX_UPLOAD_SIZE_BYTES // (1024 * 1024)} MB",
                    )
                hasher.update(chunk)
                out_f.write(chunk)

        if total_bytes == 0:
            if temp_target.exists():
                temp_target.unlink()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Uploaded file is empty (0 bytes). Please upload a valid packet capture.",
            )

        sha256_hash = hasher.hexdigest()

        # 3. Handle duplicate capture deliberately
        existing_pcap = db.query(PcapFile).filter(PcapFile.sha256_hash == sha256_hash).first()
        if existing_pcap:
            response.status_code = status.HTTP_200_OK
            if not reprocess:
                # Capture already indexed; delete duplicate uploaded temp file and return existing record
                if temp_target.exists() and temp_target != Path(existing_pcap.file_path):
                    try:
                        temp_target.unlink()
                    except Exception:
                        pass
                return existing_pcap
            else:
                # Reprocess requested: clean previous flows & alerts for this capture
                db.query(ThreatAlert).filter(ThreatAlert.pcap_id == existing_pcap.id).delete()
                db.query(NetworkFlow).filter(NetworkFlow.pcap_id == existing_pcap.id).delete()
                db.commit()
                pcap_record = existing_pcap
                pcap_record.filename = filename
                pcap_record.file_path = str(temp_target)
                pcap_record.file_size_bytes = total_bytes
                pcap_record.status = PcapStatus.QUEUED.value
                db.commit()
        else:
            response.status_code = status.HTTP_201_CREATED
            # Create new PcapFile record
            pcap_record = PcapFile(
                filename=filename,
                file_path=str(temp_target),
                file_size_bytes=total_bytes,
                sha256_hash=sha256_hash,
                status=PcapStatus.QUEUED.value,
                packet_count=0,
                flow_count=0,
                alert_count=0,
                duration_seconds=0.0,
            )
            db.add(pcap_record)
            db.commit()
            db.refresh(pcap_record)

        # 4. Validate that the capture can actually be parsed by Scapy
        try:
            reader = get_pcap_reader(str(temp_target))
            # Test reading the first packet to confirm header validity
            try:
                next(iter(reader), None)
            finally:
                if hasattr(reader, "close"):
                    try:
                        reader.close()
                    except Exception:
                        pass
        except (Scapy_Exception, Exception) as parse_err:
            pcap_record.status = PcapStatus.FAILED.value
            pcap_record.error_message = f"Invalid or corrupted PCAP capture: {str(parse_err)}"
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid packet capture file: {str(parse_err)}",
            )

        # 5. Ingest packets and generate bidirectional flows
        process_pcap_ingestion(pcap_record.id, db)
        db.refresh(pcap_record)
        return pcap_record

    except HTTPException:
        raise
    except Exception as e:
        if temp_target.exists():
            try:
                temp_target.unlink()
            except Exception:
                pass
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred while processing the capture: {str(e)}",
        )


@router.post("/{pcap_id}/reanalyze", response_model=PcapReanalyzeResponse)
def reanalyze_pcap(pcap_id: int, db: Session = Depends(get_db)):
    """Re-analyze an existing capture file with the complete detection pipeline.

    1. Loads the original capture metadata from SQLite.
    2. Validates that the capture file exists on disk and is readable.
    3. Runs packet parsing, flow aggregation, ML anomaly scoring, and rule threat detection.
    4. Safely refreshes derived flows, DNS records, and alerts without multiplying records or altering capture identity.
    5. Returns an explicit summary including packet, flow, alert, and anomaly counts.
    """
    pcap = db.query(PcapFile).filter(PcapFile.id == pcap_id).first()
    if not pcap:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"PCAP capture with ID {pcap_id} not found",
        )

    file_path = Path(pcap.file_path)
    if not file_path.exists() or not file_path.is_file():
        pcap.status = PcapStatus.FAILED.value
        pcap.error_message = f"Original capture file not found on disk: {file_path}"
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Original capture file '{file_path.name}' is missing on disk",
        )

    # Validate that the file is readable
    try:
        reader = get_pcap_reader(str(file_path))
        try:
            next(iter(reader), None)
        finally:
            if hasattr(reader, "close"):
                try:
                    reader.close()
                except Exception:
                    pass
    except Exception as read_err:
        pcap.status = PcapStatus.FAILED.value
        pcap.error_message = f"Capture file cannot be parsed or read: {str(read_err)}"
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Original capture file cannot be read: {str(read_err)}",
        )

    # Process ingestion with clear_existing=True to atomically replace previous derived results
    try:
        updated_pcap = process_pcap_ingestion(pcap_id, db, clear_existing=True)
    except Exception as proc_err:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Re-analysis failed during ingestion pipeline: {str(proc_err)}",
        )

    # Count anomalous flows
    anomaly_count = (
        db.query(NetworkFlow)
        .filter(NetworkFlow.pcap_id == pcap_id, NetworkFlow.is_anomaly == 1)
        .count()
    )

    return PcapReanalyzeResponse(
        id=updated_pcap.id,
        filename=updated_pcap.filename,
        status=updated_pcap.status,
        packet_count=updated_pcap.packet_count,
        flow_count=updated_pcap.flow_count,
        alert_count=updated_pcap.alert_count,
        anomaly_count=anomaly_count,
        duration_seconds=updated_pcap.duration_seconds,
        processed_at=updated_pcap.processed_at,
        message=f"Capture '{updated_pcap.filename}' successfully re-analyzed. Generated {updated_pcap.flow_count} flows ({anomaly_count} anomalous) and {updated_pcap.alert_count} alerts.",
    )


@router.post("/{pcap_id}/detect", response_model=List[AlertResponse])
def run_threat_detection(pcap_id: int, db: Session = Depends(get_db)):
    """Re-run threat detection and ML anomaly scoring on an existing capture deterministically."""
    pcap = db.query(PcapFile).filter(PcapFile.id == pcap_id).first()
    if not pcap:
        raise HTTPException(status_code=404, detail=f"PCAP with ID {pcap_id} not found")

    # Re-score flows if ML model is ready
    detector = AnomalyDetector()
    if detector.is_ready:
        flows = db.query(NetworkFlow).filter(NetworkFlow.pcap_id == pcap_id).all()
        if flows:
            import json
            scores = detector.score_batch(flows)
            for idx, (score, is_anomaly, attrib) in enumerate(scores):
                flows[idx].anomaly_score = score
                flows[idx].is_anomaly = is_anomaly
                flows[idx].anomaly_features_json = json.dumps(attrib)
            db.commit()

    rule_engine = RuleEngine()
    alerts = rule_engine.run_and_persist(pcap_id, db)
    return alerts


@router.delete("/{pcap_id}")
def delete_pcap(pcap_id: int, db: Session = Depends(get_db)):
    pcap = db.query(PcapFile).filter(PcapFile.id == pcap_id).first()
    if not pcap:
        raise HTTPException(status_code=404, detail=f"PCAP with ID {pcap_id} not found")

    # Remove file from disk if it exists
    try:
        p = Path(pcap.file_path)
        if p.exists():
            p.unlink()
    except Exception:
        pass

    # Delete associated flows, DNS records, and alerts
    db.query(ThreatAlert).filter(ThreatAlert.pcap_id == pcap_id).delete()
    db.query(DnsQueryRecord).filter(DnsQueryRecord.pcap_id == pcap_id).delete()
    db.query(NetworkFlow).filter(NetworkFlow.pcap_id == pcap_id).delete()
    db.delete(pcap)
    db.commit()

    return {"message": f"PCAP {pcap_id} and associated flows/alerts successfully deleted"}
