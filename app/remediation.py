"""
Remediation Execution Engine
Operational device support only — this system does not provide medical advice or clinical recommendations.

WORKFLOW:
1. Find device
2. Calculate current risk
3. Check telemetry freshness (>48h -> UNTRUSTED_FALLBACK)
4. Check approvals (conflicting -> UNTRUSTED_FALLBACK / BLOCKED_APPROVAL)
5. Check network stability (flapping -> UNTRUSTED_FALLBACK / NETWORK_FAILURE)
6. Check fallback state (stop automatic remediation, require manual field dispatch)
7. Determine target version
8. Simulate/execute remediation
9. Update device version
10. Recalculate risk
11. Record remediation result
12. Return clear operational status
"""

from datetime import datetime
from typing import Optional
import uuid
from sqlalchemy.orm import Session
from app.models import Device, Advisory, MaintenanceApproval, Telemetry, Remediation, UpdateSchedule
from app.risk_engine import evaluate_device_risk
from app.schemas import RemediationResponse


def execute_remediation(
    db: Session,
    device_id: str,
    override_fallback: bool = False,
) -> RemediationResponse:
    """Execute simulated OTA remediation workflow with safe fallback checks."""
    device = db.query(Device).filter(Device.device_id == device_id).first()
    if not device:
        return RemediationResponse(
            device_id=device_id,
            status="DEVICE_NOT_FOUND",
            previous_version="UNKNOWN",
            target_version="UNKNOWN",
            fallback_triggered=True,
            error_message=f"Device {device_id} does not exist in inventory.",
            new_risk_score=0.0,
            new_risk_status="UNKNOWN",
            operational_message="Failed: Device ID not found.",
        )

    # Gather context
    advisories = db.query(Advisory).filter(Advisory.active.is_(True)).all()
    approval = db.query(MaintenanceApproval).filter(MaintenanceApproval.device_id == device_id).first()
    latest_telemetry = (
        db.query(Telemetry)
        .filter(Telemetry.device_id == device_id)
        .order_by(Telemetry.timestamp.desc())
        .first()
    )

    # 1. Calculate risk and check fallback triggers
    risk_eval = evaluate_device_risk(device, advisories, approval, latest_telemetry)

    # Fallback Condition 1: Missing Telemetry / Stale
    if (
        "Missing/stale telemetry" in " ".join(risk_eval.fallback_reasons)
        or device.telemetry_status == "MISSING"
        or device.version_drift_state == "UNKNOWN"
    ):
        device.fallback_status = "UNTRUSTED_FALLBACK"
        db.commit()
        record_remediation_log(
            db, device_id, device.firmware_version, device.latest_supported_firmware,
            "UNTRUSTED_FALLBACK", fallback_triggered=True,
            error_message="Fallback triggered: Telemetry is missing or stale >48 hours. Automatic OTA remediation blocked."
        )
        return RemediationResponse(
            device_id=device_id,
            status="UNTRUSTED_FALLBACK",
            previous_version=device.firmware_version,
            target_version=device.latest_supported_firmware,
            fallback_triggered=True,
            error_message="Telemetry missing or stale (>48 hours). Device is in UNTRUSTED_FALLBACK mode. Manual field dispatch required.",
            new_risk_score=risk_eval.final_risk_score,
            new_risk_status=risk_eval.risk_category,
            operational_message="Blocked: Safe Fallback active due to missing telemetry. Dispatch field technician.",
        )

    # Fallback Condition 2: Conflicting Approvals
    if approval and approval.it_approved != approval.clinical_ops_approved:
        device.fallback_status = "UNTRUSTED_FALLBACK"
        db.commit()
        record_remediation_log(
            db, device_id, device.firmware_version, device.latest_supported_firmware,
            "BLOCKED_APPROVAL", fallback_triggered=True,
            error_message=f"Conflict: IT_Approved={approval.it_approved}, Clinical_Ops_Approved={approval.clinical_ops_approved}."
        )
        return RemediationResponse(
            device_id=device_id,
            status="BLOCKED_APPROVAL",
            previous_version=device.firmware_version,
            target_version=device.latest_supported_firmware,
            fallback_triggered=True,
            error_message="Conflicting maintenance approvals detected. Automatic remediation blocked until resolved.",
            new_risk_score=risk_eval.final_risk_score,
            new_risk_status=risk_eval.risk_category,
            operational_message="Blocked: Conflicting maintenance approvals (IT vs Clinical Ops).",
        )

    # Check unapproved status
    if not approval or not (approval.it_approved and approval.clinical_ops_approved):
        return RemediationResponse(
            device_id=device_id,
            status="BLOCKED_APPROVAL",
            previous_version=device.firmware_version,
            target_version=device.latest_supported_firmware,
            fallback_triggered=False,
            error_message="Device requires both IT and Clinical Operations approvals prior to remediation.",
            new_risk_score=risk_eval.final_risk_score,
            new_risk_status=risk_eval.risk_category,
            operational_message="Blocked: Awaiting dual maintenance approvals.",
        )

    # Fallback Condition 3: Network Flapping
    if (
        device.telemetry_status == "FLAPPING"
        or (latest_telemetry and latest_telemetry.connectivity_status == "FLAPPING")
        or (latest_telemetry and (latest_telemetry.packet_loss or 0.0) > 15.0)
    ):
        device.fallback_status = "UNTRUSTED_FALLBACK"
        db.commit()
        record_remediation_log(
            db, device_id, device.firmware_version, device.latest_supported_firmware,
            "NETWORK_FAILURE", fallback_triggered=True,
            error_message="Network flapping or severe packet loss detected. OTA aborted to prevent bricking device."
        )
        return RemediationResponse(
            device_id=device_id,
            status="NETWORK_FAILURE",
            previous_version=device.firmware_version,
            target_version=device.latest_supported_firmware,
            fallback_triggered=True,
            error_message="Network instability/flapping detected. Automatic OTA aborted to avoid firmware corruption.",
            new_risk_score=risk_eval.final_risk_score,
            new_risk_status=risk_eval.risk_category,
            operational_message="Blocked: Network unstable (Flapping/Packet Loss). Manual field dispatch required.",
        )

    # If all dynamic checks pass, reset fallback_status if it was previously set
    if not risk_eval.fallback_triggered and device.fallback_status == "UNTRUSTED_FALLBACK":
        device.fallback_status = "NONE"

    # Fallback status check on device
    if device.fallback_status == "UNTRUSTED_FALLBACK" and not override_fallback:
        return RemediationResponse(
            device_id=device_id,
            status="UNTRUSTED_FALLBACK",
            previous_version=device.firmware_version,
            target_version=device.latest_supported_firmware,
            fallback_triggered=True,
            error_message="Device marked in UNTRUSTED_FALLBACK mode. Automatic remediation disallowed.",
            new_risk_score=risk_eval.final_risk_score,
            new_risk_status=risk_eval.risk_category,
            operational_message="Blocked: Device in safe fallback. Operator inspection required.",
        )

    # Check if already current
    if (
        device.firmware_version == device.latest_supported_firmware
        and device.software_version == device.latest_supported_software
        and not risk_eval.is_vulnerable
    ):
        return RemediationResponse(
            device_id=device_id,
            status="SAFE_TO_REMEDIATE",
            previous_version=device.firmware_version,
            target_version=device.latest_supported_firmware,
            fallback_triggered=False,
            new_risk_score=risk_eval.final_risk_score,
            new_risk_status=risk_eval.risk_category,
            operational_message="Device is already running the latest supported firmware and software.",
        )

    # Check unsupported device status
    if device.firmware_status == "UNSUPPORTED" or device.software_status == "UNSUPPORTED":
        record_remediation_log(
            db, device_id, device.firmware_version, device.latest_supported_firmware,
            "UNSUPPORTED_VERSION", fallback_triggered=False,
            error_message="Device hardware revision cannot receive OTA firmware beyond current tier. Hardware refresh needed."
        )
        return RemediationResponse(
            device_id=device_id,
            status="UNSUPPORTED_VERSION",
            previous_version=device.firmware_version,
            target_version=device.latest_supported_firmware,
            fallback_triggered=False,
            error_message="Hardware revision has reached End-Of-Life and cannot be updated OTA.",
            new_risk_score=risk_eval.final_risk_score,
            new_risk_status=risk_eval.risk_category,
            operational_message="Blocked: Hardware is unsupported for OTA updates. Physical replacement required.",
        )

    # Perform Simulated Remediation Execution
    prev_firmware = device.firmware_version
    target_firmware = device.latest_supported_firmware
    target_software = device.latest_supported_software

    # Update device records
    device.firmware_version = target_firmware
    device.software_version = target_software
    device.firmware_status = "CURRENT"
    device.software_status = "CURRENT"
    device.version_drift_state = "IN_SYNC"
    device.fallback_status = "NONE"
    device.updated_at = datetime.utcnow()

    # Re-evaluate risk post-remediation
    new_risk_eval = evaluate_device_risk(device, advisories, approval, latest_telemetry)
    device.current_risk_score = new_risk_eval.final_risk_score
    device.risk_status = new_risk_eval.risk_category

    # Mark schedule item as COMPLETED if it was scheduled
    active_sched = (
        db.query(UpdateSchedule)
        .filter(UpdateSchedule.device_id == device_id, UpdateSchedule.status.in_(["SCHEDULED", "QUEUED"]))
        .first()
    )
    if active_sched:
        active_sched.status = "COMPLETED"

    # Record remediation audit entry
    remediation_entry = record_remediation_log(
        db, device_id, prev_firmware, target_firmware,
        status="REMEDIATED", fallback_triggered=False,
        completed_at=datetime.utcnow()
    )

    db.commit()

    return RemediationResponse(
        remediation_id=remediation_entry.remediation_id,
        device_id=device_id,
        status="REMEDIATED",
        previous_version=prev_firmware,
        target_version=target_firmware,
        fallback_triggered=False,
        error_message=None,
        new_risk_score=new_risk_eval.final_risk_score,
        new_risk_status=new_risk_eval.risk_category,
        operational_message=f"Success: Device successfully remediated from {prev_firmware} to {target_firmware}. Risk score reduced to {new_risk_eval.final_risk_score}.",
    )


def record_remediation_log(
    db: Session,
    device_id: str,
    previous_version: str,
    target_version: str,
    status: str,
    fallback_triggered: bool = False,
    error_message: Optional[str] = None,
    completed_at: Optional[datetime] = None,
) -> Remediation:
    """Record remediation attempt into database audit table."""
    remediation = Remediation(
        remediation_id=f"REM-{uuid.uuid4().hex[:8].upper()}",
        device_id=device_id,
        previous_version=previous_version,
        target_version=target_version,
        scheduled_slot="ADHOC",
        status=status,
        started_at=datetime.utcnow(),
        completed_at=completed_at,
        fallback_triggered=fallback_triggered,
        error_message=error_message,
    )
    db.add(remediation)
    db.commit()
    db.refresh(remediation)
    return remediation
