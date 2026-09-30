"""
FastAPI Backend Application - Home-Care Device Fleet Monitoring
Operational device support only — this system does not provide medical advice or clinical recommendations.
"""

from contextlib import asynccontextmanager
from datetime import datetime
from typing import List, Optional
import uuid
from fastapi import FastAPI, Depends, HTTPException, Query, status, Body
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from app.config import MEDICAL_DISCLAIMER
from app.database import get_db, init_db
from app.models import Device, Advisory, MaintenanceApproval, Telemetry, UpdateSchedule, Remediation
from app.schemas import (
    TelemetryIngestRequest,
    TelemetryResponse,
    MaintenanceApprovalRequest,
    MaintenanceApprovalResponse,
    FleetInventoryResponse,
    DeviceInventoryItem,
    ScheduleBatchRequest,
    ScheduleResponse,
    CapacityStatusResponse,
    RemediationRequest,
    RemediationResponse,
    AdvisoryResponse,
)
from app.risk_engine import evaluate_device_risk
from app.scheduler import schedule_updates, get_capacity_status
from app.remediation import execute_remediation
from app.telemetry import (
    ingest_telemetry_record,
    simulate_network_flapping,
    simulate_missing_telemetry,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="Home-Care Device Fleet Monitoring API",
    description=(
        "Operational device fleet monitoring and firmware lifecycle management. "
        f"\n\n**CRITICAL DISCLAIMER:** {MEDICAL_DISCLAIMER}"
    ),
    version="1.0.0",
    lifespan=lifespan,
)

# Enable CORS for Streamlit and other frontend clients
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health", tags=["System"])
def health_check():
    """Health check endpoint indicating service operational status."""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "disclaimer": MEDICAL_DISCLAIMER,
    }


@app.post("/ingest", response_model=TelemetryResponse, tags=["Telemetry"])
def ingest_telemetry(payload: TelemetryIngestRequest, db: Session = Depends(get_db)):
    """
    Ingest real-time device telemetry.
    Updates the device configuration inventory, computes drift and recalculates risk.
    """
    try:
        record = ingest_telemetry_record(db, payload)
        return record
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@app.get("/inventory", response_model=FleetInventoryResponse, tags=["Inventory"])
def get_inventory(
    model: Optional[str] = Query(None, description="Filter by device model"),
    risk_category: Optional[str] = Query(None, description="Filter by risk category (LOW, MEDIUM, HIGH, CRITICAL)"),
    fallback_only: Optional[bool] = Query(False, description="Filter for fallback devices only"),
    db: Session = Depends(get_db),
):
    """
    Return full fleet inventory with contextual risk calculations, approval statuses, and fallback flags.
    """
    query = db.query(Device)
    if model:
        query = query.filter(Device.device_model == model)
    if fallback_only:
        query = query.filter(Device.fallback_status != "NONE")

    devices = query.all()
    advisories = db.query(Advisory).filter(Advisory.active.is_(True)).all()
    approvals_map = {a.device_id: a for a in db.query(MaintenanceApproval).all()}

    inventory_items: List[DeviceInventoryItem] = []

    for dev in devices:
        appr = approvals_map.get(dev.device_id)
        latest_tel = (
            db.query(Telemetry)
            .filter(Telemetry.device_id == dev.device_id)
            .order_by(Telemetry.timestamp.desc())
            .first()
        )

        risk_breakdown = evaluate_device_risk(dev, advisories, appr, latest_tel)

        if risk_category and risk_breakdown.risk_category != risk_category.upper():
            continue

        it_appr = appr.it_approved if appr else False
        clin_appr = appr.clinical_ops_approved if appr else False

        if appr:
            if it_appr and clin_appr:
                approval_status_str = "APPROVED"
            elif it_appr != clin_appr:
                approval_status_str = "CONFLICTING"
            else:
                approval_status_str = "PENDING"
        else:
            approval_status_str = "NOT_CONFIGURED"

        item = DeviceInventoryItem(
            device_id=dev.device_id,
            patient_reference=dev.patient_reference,
            device_model=dev.device_model,
            serial_number=dev.serial_number,
            firmware_version=dev.firmware_version,
            software_version=dev.software_version,
            latest_supported_firmware=dev.latest_supported_firmware,
            latest_supported_software=dev.latest_supported_software,
            firmware_status=dev.firmware_status,
            software_status=dev.software_status,
            network_location=dev.network_location,
            network_type=dev.network_type,
            telemetry_last_seen=dev.telemetry_last_seen or datetime.utcnow(),
            telemetry_status=dev.telemetry_status,
            version_drift_state=dev.version_drift_state,
            current_risk_score=risk_breakdown.final_risk_score,
            risk_status=risk_breakdown.risk_category,
            fallback_status=dev.fallback_status,
            it_approved=it_appr,
            clinical_ops_approved=clin_appr,
            approval_status=approval_status_str,
            cve_id=risk_breakdown.cve_id,
            cvss_base_score=risk_breakdown.cvss_base_score,
            version_lag=risk_breakdown.versions_behind,
            risk_breakdown=risk_breakdown,
        )
        inventory_items.append(item)

    return FleetInventoryResponse(
        total_devices=len(inventory_items),
        devices=inventory_items,
        disclaimer=MEDICAL_DISCLAIMER,
    )


@app.post("/approvals", response_model=MaintenanceApprovalResponse, tags=["Approvals"])
def update_maintenance_approval(payload: MaintenanceApprovalRequest, db: Session = Depends(get_db)):
    """
    Update IT and Clinical maintenance approval status for a device.
    Detects conflicting approvals and applies safe fallback automatically.
    """
    device = db.query(Device).filter(Device.device_id == payload.device_id).first()
    if not device:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Device {payload.device_id} not found")

    approval = db.query(MaintenanceApproval).filter(MaintenanceApproval.device_id == payload.device_id).first()
    if not approval:
        approval = MaintenanceApproval(
            approval_id=f"APP-{uuid.uuid4().hex[:8].upper()}",
            device_id=payload.device_id,
            it_approved=payload.it_approved,
            clinical_ops_approved=payload.clinical_ops_approved,
            approved_by=payload.approved_by or "Operator",
            approved_at=datetime.utcnow(),
            notes=payload.notes,
        )
        db.add(approval)
    else:
        approval.it_approved = payload.it_approved
        approval.clinical_ops_approved = payload.clinical_ops_approved
        approval.approved_by = payload.approved_by or approval.approved_by
        approval.approved_at = datetime.utcnow()
        approval.notes = payload.notes or approval.notes

    is_conflicting = (payload.it_approved != payload.clinical_ops_approved)
    if is_conflicting:
        device.fallback_status = "UNTRUSTED_FALLBACK"
    elif device.fallback_status == "UNTRUSTED_FALLBACK" and payload.it_approved and payload.clinical_ops_approved:
        # Check if any other fallback trigger remains
        advisories = db.query(Advisory).filter(Advisory.active.is_(True)).all()
        risk_eval = evaluate_device_risk(device, advisories, approval, None)
        if not risk_eval.fallback_triggered:
            device.fallback_status = "NONE"

    db.commit()
    db.refresh(approval)

    return MaintenanceApprovalResponse(
        approval_id=approval.approval_id,
        device_id=approval.device_id,
        it_approved=approval.it_approved,
        clinical_ops_approved=approval.clinical_ops_approved,
        approved_by=approval.approved_by,
        approved_at=approval.approved_at,
        notes=approval.notes,
        is_conflicting=is_conflicting,
    )


@app.post("/schedule", response_model=ScheduleResponse, tags=["Scheduler"])
def schedule_updates_endpoint(payload: ScheduleBatchRequest = Body(default=None), db: Session = Depends(get_db)):
    """
    Schedule update batches enforcing the strict <=50 devices/hour capacity guardrail.
    """
    device_ids = payload.device_ids if payload else None
    force_resched = payload.force_reschedule if payload else False
    response = schedule_updates(
        db=db,
        device_ids=device_ids,
        force_reschedule=force_resched or False,
    )
    return response


@app.get("/capacity", response_model=CapacityStatusResponse, tags=["Scheduler"])
def get_capacity_endpoint(db: Session = Depends(get_db)):
    """
    Query hourly update slot utilization and remaining capacity.
    """
    return get_capacity_status(db)


@app.post("/remediate/{device_id}", response_model=RemediationResponse, tags=["Remediation"])
def remediate_device_endpoint(
    device_id: str,
    payload: Optional[RemediationRequest] = Body(default=None),
    db: Session = Depends(get_db),
):
    """
    Execute simulated OTA firmware remediation with complete safety and fallback validation.
    """
    override = payload.override_fallback if payload else False
    result = execute_remediation(db, device_id, override_fallback=override)
    return result


@app.post("/telemetry/mock", response_model=TelemetryResponse, tags=["Telemetry Simulation"])
def mock_telemetry_post(payload: TelemetryIngestRequest, db: Session = Depends(get_db)):
    """Inject mock telemetry into the operational pipeline."""
    return ingest_telemetry_record(db, payload)


@app.get("/telemetry/{device_id}", response_model=List[TelemetryResponse], tags=["Telemetry Simulation"])
def get_device_telemetry(device_id: str, limit: int = 10, db: Session = Depends(get_db)):
    """Retrieve historical telemetry entries for a specific device."""
    records = (
        db.query(Telemetry)
        .filter(Telemetry.device_id == device_id)
        .order_by(Telemetry.timestamp.desc())
        .limit(limit)
        .all()
    )
    return records


@app.post("/telemetry/simulate-flapping/{device_id}", tags=["Telemetry Simulation"])
def trigger_network_flapping(device_id: str, db: Session = Depends(get_db)):
    """Simulate rapid connection drops and high packet loss for failure mode testing."""
    try:
        dev = simulate_network_flapping(db, device_id)
        return {
            "message": f"Device {device_id} network set to FLAPPING. Fallback status: {dev.fallback_status}",
            "device_id": dev.device_id,
            "telemetry_status": dev.telemetry_status,
            "fallback_status": dev.fallback_status,
        }
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@app.post("/telemetry/simulate-missing/{device_id}", tags=["Telemetry Simulation"])
def trigger_missing_telemetry(device_id: str, stale_hours: float = 72.0, db: Session = Depends(get_db)):
    """Simulate missing telemetry exceeding 48 hours."""
    try:
        dev = simulate_missing_telemetry(db, device_id, stale_hours=stale_hours)
        return {
            "message": f"Device {device_id} telemetry marked missing ({stale_hours}h stale). Fallback status: {dev.fallback_status}",
            "device_id": dev.device_id,
            "telemetry_status": dev.telemetry_status,
            "fallback_status": dev.fallback_status,
            "telemetry_last_seen": dev.telemetry_last_seen.isoformat(),
        }
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@app.get("/advisories", response_model=List[AdvisoryResponse], tags=["Advisories"])
def list_advisories(db: Session = Depends(get_db)):
    """List all active security advisories and CVEs."""
    return db.query(Advisory).filter(Advisory.active.is_(True)).all()
