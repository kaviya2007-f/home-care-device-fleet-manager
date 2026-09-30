import pytest
from datetime import datetime, timedelta
from app.database import SessionLocal, init_db
from app.models import Device, Advisory, MaintenanceApproval, Telemetry, UpdateSchedule, Remediation
from app.risk_engine import evaluate_device_risk
from app.scheduler import schedule_updates
from app.remediation import execute_remediation
from app.telemetry import ingest_telemetry_record
from app.schemas import TelemetryIngestRequest


def test_complete_end_to_end_lifecycle():
    init_db()
    db = SessionLocal()

    # Clear test artifacts
    db.query(UpdateSchedule).delete()
    db.query(Remediation).delete()
    db.query(Telemetry).delete()
    db.query(MaintenanceApproval).delete()
    db.query(Device).delete()
    db.query(Advisory).delete()
    db.commit()

    # Step 1: Create Advisory
    adv = Advisory(
        advisory_id="ADV-E2E-001",
        cve_id="CVE-2026-1001",
        device_model="OxiPulse-v2",
        affected_version="v2.1.0",
        fixed_version="v2.4.0",
        cvss_base_score=8.5,
        severity="HIGH",
        description="E2E test vulnerability",
        active=True,
    )
    db.add(adv)

    # Step 2: Create Vulnerable Device on Cellular Direct
    dev = Device(
        device_id="DEV-E2E-100",
        patient_reference="PAT-ANON-E2E",
        device_model="OxiPulse-v2",
        serial_number="SN-E2E-100",
        firmware_version="v2.1.0",
        software_version="v1.0.0",
        latest_supported_firmware="v2.4.0",
        latest_supported_software="v3.1.0",
        firmware_status="VULNERABLE",
        software_status="OUTDATED",
        network_location="Patient Residence",
        network_type="Cellular Direct",
        telemetry_last_seen=datetime.utcnow(),
        telemetry_status="ONLINE",
        version_drift_state="DRIFTED",
    )
    db.add(dev)

    # Step 3: Pending Approvals
    appr = MaintenanceApproval(
        approval_id="APP-E2E-100",
        device_id=dev.device_id,
        it_approved=False,
        clinical_ops_approved=False,
    )
    db.add(appr)
    db.commit()

    # Step 4: Verify Initial High Risk & Blocked Remediation
    risk_breakdown = evaluate_device_risk(dev, [adv], appr, None)
    # Expected: min(10.0, (8.5 * 1.2) + version_penalty) = 10.0 (CRITICAL)
    assert risk_breakdown.final_risk_score == 10.0
    assert risk_breakdown.risk_category == "CRITICAL"

    # Attempting remediation before dual approvals must be blocked
    rem_attempt_1 = execute_remediation(db, dev.device_id)
    assert rem_attempt_1.status == "BLOCKED_APPROVAL"

    # Step 5: Test Conflicting Approvals Safe Fallback
    appr.it_approved = True
    appr.clinical_ops_approved = False
    db.commit()

    rem_attempt_2 = execute_remediation(db, dev.device_id)
    assert rem_attempt_2.status == "BLOCKED_APPROVAL"
    assert rem_attempt_2.fallback_triggered is True

    # Step 6: Grant Dual Approvals (resolving conflict)
    appr.it_approved = True
    appr.clinical_ops_approved = True
    dev.fallback_status = "NONE"
    db.commit()

    # Step 7: Schedule Batch & Verify Inclusion
    sched_res = schedule_updates(db, device_ids=[dev.device_id])
    assert sched_res.total_scheduled >= 1

    # Step 8: Execute Successful Remediation
    rem_success = execute_remediation(db, dev.device_id)
    assert rem_success.status == "REMEDIATED"
    assert rem_success.previous_version == "v2.1.0"
    assert rem_success.target_version == "v2.4.0"

    # Verify device is updated in DB
    db.refresh(dev)
    assert dev.firmware_version == "v2.4.0"
    assert dev.firmware_status == "CURRENT"
    assert dev.version_drift_state == "IN_SYNC"
    assert dev.current_risk_score == 0.0

    # Step 9: Ingest New Telemetry Confirming In-Sync State
    tel_req = TelemetryIngestRequest(
        device_id=dev.device_id,
        firmware_version="v2.4.0",
        software_version="v3.1.0",
        network_location="Patient Residence",
        network_type="Cellular Direct",
        connectivity_status="ONLINE",
        packet_loss=0.1,
    )
    tel_entry = ingest_telemetry_record(db, tel_req)
    assert tel_entry.firmware_version == "v2.4.0"

    # Verify audit trail
    rem_logs = db.query(Remediation).filter(Remediation.device_id == dev.device_id).all()
    assert len(rem_logs) >= 1
    assert any(log.status == "REMEDIATED" for log in rem_logs)

    db.close()
