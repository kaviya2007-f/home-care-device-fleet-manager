"""
Telemetry Ingestion & Simulation Subsystem
Operational device support only — this system does not provide medical advice or clinical recommendations.
"""

from datetime import datetime, timedelta
from typing import Optional, List
import uuid
from sqlalchemy.orm import Session
from app.models import Device, Advisory, MaintenanceApproval, Telemetry
from app.schemas import TelemetryIngestRequest
from app.risk_engine import evaluate_device_risk


def ingest_telemetry_record(db: Session, data: TelemetryIngestRequest) -> Telemetry:
    """Ingest a single device telemetry record and update device state."""
    device = db.query(Device).filter(Device.device_id == data.device_id).first()

    now = datetime.utcnow()
    telemetry_entry = Telemetry(
        telemetry_id=f"TEL-{uuid.uuid4().hex[:8].upper()}",
        device_id=data.device_id,
        timestamp=now,
        firmware_version=data.firmware_version,
        software_version=data.software_version,
        network_location=data.network_location or "Patient Residence",
        network_type=data.network_type or "Home Wi-Fi NAT",
        connectivity_status=data.connectivity_status or "ONLINE",
        packet_loss=data.packet_loss or 0.0,
        telemetry_source=data.telemetry_source or "agent_daemon",
    )
    db.add(telemetry_entry)

    if device:
        device.firmware_version = data.firmware_version
        device.software_version = data.software_version
        device.network_location = data.network_location or device.network_location
        device.network_type = data.network_type or device.network_type
        device.telemetry_last_seen = now
        device.telemetry_status = data.connectivity_status or "ONLINE"

        # Check drift
        if (
            device.firmware_version != device.latest_supported_firmware
            or device.software_version != device.latest_supported_software
        ):
            device.version_drift_state = "DRIFTED"
        else:
            device.version_drift_state = "IN_SYNC"

        # Re-evaluate risk
        advisories = db.query(Advisory).filter(Advisory.active.is_(True)).all()
        approval = db.query(MaintenanceApproval).filter(MaintenanceApproval.device_id == device.device_id).first()
        risk_eval = evaluate_device_risk(device, advisories, approval, telemetry_entry)

        device.current_risk_score = risk_eval.final_risk_score
        device.risk_status = risk_eval.risk_category
        if risk_eval.fallback_triggered:
            device.fallback_status = "UNTRUSTED_FALLBACK"
        elif device.fallback_status == "UNTRUSTED_FALLBACK":
            device.fallback_status = "NONE"

    db.commit()
    db.refresh(telemetry_entry)
    return telemetry_entry


def simulate_network_flapping(db: Session, device_id: str) -> Device:
    """Simulate severe network flapping / connection instability."""
    device = db.query(Device).filter(Device.device_id == device_id).first()
    if not device:
        raise ValueError(f"Device {device_id} not found")

    now = datetime.utcnow()
    device.telemetry_status = "FLAPPING"
    device.fallback_status = "UNTRUSTED_FALLBACK"
    device.telemetry_last_seen = now

    # Add flapping telemetry entry
    flapping_telemetry = Telemetry(
        telemetry_id=f"TEL-{uuid.uuid4().hex[:8].upper()}",
        device_id=device_id,
        timestamp=now,
        firmware_version=device.firmware_version,
        software_version=device.software_version,
        network_location=device.network_location,
        network_type=device.network_type,
        connectivity_status="FLAPPING",
        packet_loss=38.5,
        telemetry_source="flapping_simulator",
    )
    db.add(flapping_telemetry)

    # Recompute risk
    advisories = db.query(Advisory).filter(Advisory.active.is_(True)).all()
    approval = db.query(MaintenanceApproval).filter(MaintenanceApproval.device_id == device_id).first()
    risk_eval = evaluate_device_risk(device, advisories, approval, flapping_telemetry)
    device.current_risk_score = risk_eval.final_risk_score
    device.risk_status = risk_eval.risk_category

    db.commit()
    db.refresh(device)
    return device


def simulate_missing_telemetry(db: Session, device_id: str, stale_hours: float = 72.0) -> Device:
    """Simulate missing / stale telemetry > 48 hours."""
    device = db.query(Device).filter(Device.device_id == device_id).first()
    if not device:
        raise ValueError(f"Device {device_id} not found")

    stale_time = datetime.utcnow() - timedelta(hours=stale_hours)
    device.telemetry_last_seen = stale_time
    device.telemetry_status = "MISSING"
    device.version_drift_state = "UNKNOWN"
    device.fallback_status = "UNTRUSTED_FALLBACK"

    # Recompute risk
    advisories = db.query(Advisory).filter(Advisory.active.is_(True)).all()
    approval = db.query(MaintenanceApproval).filter(MaintenanceApproval.device_id == device_id).first()
    risk_eval = evaluate_device_risk(device, advisories, approval, None, current_time=datetime.utcnow())
    device.current_risk_score = risk_eval.final_risk_score
    device.risk_status = risk_eval.risk_category

    db.commit()
    db.refresh(device)
    return device
