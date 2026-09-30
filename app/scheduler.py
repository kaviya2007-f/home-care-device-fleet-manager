"""
Capacity-Aware Firmware Update Scheduler
Operational device support only — this system does not provide medical advice or clinical recommendations.

CAPACITY GUARDRAILS:
====================
- Maximum OTA Updates = 50 devices per hourly slot.
- Scheduler assigns slots sequentially without exceeding 50 devices in any slot.
- Devices in UNTRUSTED_FALLBACK are strictly blocked from automated OTA scheduling.
- Devices with pending or conflicting approvals are blocked from automated scheduling.
- Sorting priority: Risk Score (descending) -> Vulnerability Status -> Version Lag.
"""

from datetime import datetime
from typing import List, Dict, Tuple, Optional
import uuid
from sqlalchemy.orm import Session
from app.config import MAX_HOURLY_UPDATES
from app.models import Device, Advisory, MaintenanceApproval, Telemetry, UpdateSchedule
from app.risk_engine import evaluate_device_risk
from app.schemas import ScheduledItem, ScheduleResponse, CapacityStatusResponse


def get_hourly_utilization(db: Session) -> Dict[int, int]:
    """Get the count of scheduled updates per hour slot."""
    active_schedules = (
        db.query(UpdateSchedule)
        .filter(UpdateSchedule.status.in_(["SCHEDULED", "QUEUED"]))
        .all()
    )
    utilization: Dict[int, int] = {}
    for s in active_schedules:
        utilization[s.scheduled_hour] = utilization.get(s.scheduled_hour, 0) + 1
    return utilization


def get_capacity_status(db: Session) -> CapacityStatusResponse:
    """Return current capacity status across all scheduled hours."""
    schedules = db.query(UpdateSchedule).filter(UpdateSchedule.status.in_(["SCHEDULED", "QUEUED"])).all()

    hours_data: Dict[str, dict] = {}
    for h in range(1, 6):  # show hours 1 through 5 by default
        hours_data[str(h)] = {"used": 0, "remaining": MAX_HOURLY_UPDATES, "devices": []}

    total_queued = 0
    for s in schedules:
        h_str = str(s.scheduled_hour)
        if h_str not in hours_data:
            hours_data[h_str] = {"used": 0, "remaining": MAX_HOURLY_UPDATES, "devices": []}
        hours_data[h_str]["used"] += 1
        hours_data[h_str]["remaining"] = max(0, MAX_HOURLY_UPDATES - hours_data[h_str]["used"])
        hours_data[h_str]["devices"].append(
            {
                "schedule_id": s.schedule_id,
                "device_id": s.device_id,
                "priority": s.priority,
                "risk_score": s.risk_score,
                "status": s.status,
            }
        )
        if s.scheduled_hour > 1:
            total_queued += 1

    return CapacityStatusResponse(
        max_hourly_capacity=MAX_HOURLY_UPDATES,
        hours=hours_data,
        total_queued=total_queued,
    )


def schedule_updates(
    db: Session,
    device_ids: Optional[List[str]] = None,
    force_reschedule: bool = False,
) -> ScheduleResponse:
    """
    Schedule eligible devices respecting the 50 updates/hour limit.
    """
    if force_reschedule:
        # Clear existing active schedules
        db.query(UpdateSchedule).delete()
        db.commit()

    advisories = db.query(Advisory).filter(Advisory.active.is_(True)).all()
    approvals = {a.device_id: a for a in db.query(MaintenanceApproval).all()}
    
    # Query latest telemetry per device
    all_devices_query = db.query(Device)
    if device_ids:
        all_devices_query = all_devices_query.filter(Device.device_id.in_(device_ids))
    all_devices = all_devices_query.all()

    # Find devices already scheduled
    already_scheduled_ids = {
        s.device_id
        for s in db.query(UpdateSchedule)
        .filter(UpdateSchedule.status.in_(["SCHEDULED", "QUEUED"]))
        .all()
    }

    # Evaluate each device for eligibility
    eligible_candidates = []
    blocked_count = 0

    for device in all_devices:
        if device.device_id in already_scheduled_ids and not force_reschedule:
            continue

        approval = approvals.get(device.device_id)
        latest_telemetry = (
            db.query(Telemetry)
            .filter(Telemetry.device_id == device.device_id)
            .order_by(Telemetry.timestamp.desc())
            .first()
        )

        risk_eval = evaluate_device_risk(device, advisories, approval, latest_telemetry)

        # Eligibility Rules:
        # 1. Device must not be in UNTRUSTED_FALLBACK
        if risk_eval.fallback_triggered:
            blocked_count += 1
            continue

        # 2. Both IT and Clinical Ops must be approved for automatic scheduling
        if not approval or not (approval.it_approved and approval.clinical_ops_approved):
            blocked_count += 1
            continue

        # 3. Device must actually have an update available (outdated or vulnerable)
        is_current = (
            device.firmware_version == device.latest_supported_firmware
            and device.software_version == device.latest_supported_software
            and not risk_eval.is_vulnerable
        )
        if is_current:
            continue

        eligible_candidates.append({
            "device": device,
            "risk_eval": risk_eval,
            "priority_weight": (risk_eval.final_risk_score * 10.0) + (5.0 if risk_eval.is_vulnerable else 0.0) + risk_eval.versions_behind,
        })

    # Sort eligible devices by priority descending (highest risk first)
    eligible_candidates.sort(key=lambda x: x["priority_weight"], reverse=True)

    # Get current slot utilization
    utilization = get_hourly_utilization(db)

    scheduled_results = []
    hourly_distribution: Dict[str, int] = {}
    current_hour_slot = 1

    for idx, candidate in enumerate(eligible_candidates, start=1):
        dev = candidate["device"]
        risk_info = candidate["risk_eval"]

        # Find the next available hour slot with remaining capacity (< MAX_HOURLY_UPDATES)
        while utilization.get(current_hour_slot, 0) >= MAX_HOURLY_UPDATES:
            current_hour_slot += 1

        slot = current_hour_slot
        utilization[slot] = utilization.get(slot, 0) + 1
        status_label = "SCHEDULED" if slot == 1 else "QUEUED"

        schedule_entry = UpdateSchedule(
            schedule_id=f"SCHED-{uuid.uuid4().hex[:8].upper()}",
            device_id=dev.device_id,
            scheduled_hour=slot,
            priority=idx,
            risk_score=risk_info.final_risk_score,
            status=status_label,
            created_at=datetime.utcnow(),
        )
        db.add(schedule_entry)

        scheduled_results.append(
            ScheduledItem(
                schedule_id=schedule_entry.schedule_id,
                device_id=dev.device_id,
                device_model=dev.device_model,
                scheduled_hour=slot,
                priority=idx,
                risk_score=risk_info.final_risk_score,
                status=status_label,
            )
        )

        h_key = f"Hour {slot}"
        hourly_distribution[h_key] = hourly_distribution.get(h_key, 0) + 1

    db.commit()

    total_scheduled = sum(1 for item in scheduled_results if item.scheduled_hour == 1)
    total_queued = sum(1 for item in scheduled_results if item.scheduled_hour > 1)

    return ScheduleResponse(
        message=f"Scheduled {len(scheduled_results)} updates with {MAX_HOURLY_UPDATES} max per hour limit.",
        total_requested=len(all_devices),
        total_scheduled=total_scheduled,
        total_queued=total_queued,
        total_blocked=blocked_count,
        schedules=scheduled_results,
        hourly_distribution=hourly_distribution,
    )
