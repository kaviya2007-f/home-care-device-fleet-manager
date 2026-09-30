import pytest
from datetime import datetime, timedelta
from app.models import Device, Advisory, MaintenanceApproval, Telemetry
from app.risk_engine import evaluate_device_risk


def test_fallback_missing_telemetry_over_48h():
    now = datetime.utcnow()
    stale_time = now - timedelta(hours=50)

    dev = Device(
        device_id="DEV-FALLBACK-001",
        patient_reference="PAT-FB-001",
        device_model="OxiPulse-v2",
        serial_number="SN-FB-001",
        firmware_version="v2.4.0",
        software_version="v3.1.0",
        latest_supported_firmware="v2.4.0",
        latest_supported_software="v3.1.0",
        firmware_status="CURRENT",
        software_status="CURRENT",
        network_type="Home Wi-Fi NAT",
        telemetry_last_seen=stale_time,
        telemetry_status="OFFLINE",
        version_drift_state="IN_SYNC",
    )

    risk_eval = evaluate_device_risk(dev, [], None, None, current_time=now)
    assert risk_eval.fallback_triggered is True
    assert any("Missing/stale telemetry" in r for r in risk_eval.fallback_reasons)


def test_fallback_unknown_version_drift():
    now = datetime.utcnow()
    dev = Device(
        device_id="DEV-FALLBACK-002",
        patient_reference="PAT-FB-002",
        device_model="OxiPulse-v2",
        serial_number="SN-FB-002",
        firmware_version="v2.4.0",
        software_version="v3.1.0",
        latest_supported_firmware="v2.4.0",
        latest_supported_software="v3.1.0",
        firmware_status="CURRENT",
        software_status="CURRENT",
        network_type="Home Wi-Fi NAT",
        telemetry_last_seen=now,
        telemetry_status="MISSING",
        version_drift_state="UNKNOWN",
    )

    risk_eval = evaluate_device_risk(dev, [], None, None, current_time=now)
    assert risk_eval.fallback_triggered is True
    assert any("UNKNOWN" in r for r in risk_eval.fallback_reasons)


def test_fallback_conflicting_maintenance_approvals():
    now = datetime.utcnow()
    dev = Device(
        device_id="DEV-FALLBACK-003",
        patient_reference="PAT-FB-003",
        device_model="HomeGateway-3",
        serial_number="SN-FB-003",
        firmware_version="v1.8.2",
        software_version="v2.0.0",
        latest_supported_firmware="v1.8.2",
        latest_supported_software="v2.0.0",
        firmware_status="CURRENT",
        software_status="CURRENT",
        network_type="Home Wi-Fi NAT",
        telemetry_last_seen=now,
        telemetry_status="ONLINE",
        version_drift_state="IN_SYNC",
    )

    # IT approved = True, Clinical Ops approved = False
    appr = MaintenanceApproval(
        approval_id="APP-CONF-01",
        device_id="DEV-FALLBACK-003",
        it_approved=True,
        clinical_ops_approved=False,
    )

    risk_eval = evaluate_device_risk(dev, [], appr, None, current_time=now)
    assert risk_eval.fallback_triggered is True
    assert any("Conflicting approvals" in r for r in risk_eval.fallback_reasons)


def test_fallback_network_flapping_and_packet_loss():
    now = datetime.utcnow()
    dev = Device(
        device_id="DEV-FALLBACK-004",
        patient_reference="PAT-FB-004",
        device_model="HomeGateway-3",
        serial_number="SN-FB-004",
        firmware_version="v1.8.2",
        software_version="v2.0.0",
        latest_supported_firmware="v1.8.2",
        latest_supported_software="v2.0.0",
        firmware_status="CURRENT",
        software_status="CURRENT",
        network_type="Cellular Direct",
        telemetry_last_seen=now,
        telemetry_status="FLAPPING",
        version_drift_state="IN_SYNC",
    )

    tel = Telemetry(
        telemetry_id="TEL-004",
        device_id="DEV-FALLBACK-004",
        timestamp=now,
        firmware_version="v1.8.2",
        software_version="v2.0.0",
        connectivity_status="FLAPPING",
        packet_loss=45.0,
    )

    risk_eval = evaluate_device_risk(dev, [], None, tel, current_time=now)
    assert risk_eval.fallback_triggered is True
    assert any("flapping" in r.lower() or "packet loss" in r.lower() for r in risk_eval.fallback_reasons)
