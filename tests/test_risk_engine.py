import pytest
from datetime import datetime, timedelta
from app.models import Device, Advisory, MaintenanceApproval, Telemetry
from app.risk_engine import (
    evaluate_device_risk,
    calculate_version_lag,
    calculate_version_lag_penalty,
    get_network_multiplier,
    classify_risk,
)


def test_version_lag_calculation():
    # Identical versions -> 0 lag
    assert calculate_version_lag("v2.4.0", "v2.4.0") == 0
    # Minor step -> 1 lag
    assert calculate_version_lag("v2.3.0", "v2.4.0") >= 1
    # Major step -> at least 3 lag
    assert calculate_version_lag("v1.0.0", "v2.0.0") >= 3


def test_version_lag_penalty():
    # 0 lag -> 0 penalty
    assert calculate_version_lag_penalty(0) == 0.0
    # 1 lag -> 0.5 penalty
    assert calculate_version_lag_penalty(1) == 0.5
    # 2 lag -> 1.0 penalty
    assert calculate_version_lag_penalty(2) == 1.0
    # 10 lag -> capped at max 2.0 penalty
    assert calculate_version_lag_penalty(10) == 2.0


def test_network_multipliers():
    assert get_network_multiplier("Cellular Direct") == 1.2
    assert get_network_multiplier("Home Wi-Fi NAT") == 1.0
    assert get_network_multiplier("Hospital Subnet") == 0.8
    assert get_network_multiplier("Unknown Network") == 1.0


def test_risk_classification():
    assert classify_risk(0.0) == "LOW"
    assert classify_risk(3.0) == "LOW"
    assert classify_risk(3.5) == "MEDIUM"
    assert classify_risk(6.0) == "MEDIUM"
    assert classify_risk(7.5) == "HIGH"
    assert classify_risk(8.0) == "HIGH"
    assert classify_risk(8.5) == "CRITICAL"
    assert classify_risk(10.0) == "CRITICAL"


def test_formal_risk_formula_calculation():
    # Device with CVSS 7.5, Cellular Direct (1.2), 2 versions behind (lag penalty = 1.0)
    # Expected: min(10.0, (7.5 * 1.2) + 1.0) = min(10.0, 9.0 + 1.0) = 10.0
    dev = Device(
        device_id="DEV-TEST-001",
        patient_reference="PAT-001",
        device_model="CardioGuard-X",
        serial_number="SN-001",
        firmware_version="v4.0.0",
        software_version="v5.0.1",
        latest_supported_firmware="v4.2.0",
        latest_supported_software="v5.0.1",
        firmware_status="VULNERABLE",
        software_status="CURRENT",
        network_type="Cellular Direct",
        telemetry_last_seen=datetime.utcnow(),
        telemetry_status="ONLINE",
        version_drift_state="DRIFTED",
    )
    adv = Advisory(
        advisory_id="ADV-TEST",
        cve_id="CVE-2026-9999",
        device_model="CardioGuard-X",
        affected_version="v4.0.0",
        fixed_version="v4.2.0",
        cvss_base_score=7.5,
        severity="HIGH",
        description="Test CVE",
        active=True,
    )
    appr = MaintenanceApproval(
        approval_id="APP-001",
        device_id="DEV-TEST-001",
        it_approved=True,
        clinical_ops_approved=True,
    )

    risk_eval = evaluate_device_risk(dev, [adv], appr, None)
    assert risk_eval.cvss_base_score == 7.5
    assert risk_eval.network_multiplier == 1.2
    assert risk_eval.final_risk_score == 10.0
    assert risk_eval.risk_category == "CRITICAL"


def test_hospital_subnet_multiplier_reduction():
    # Same CVSS 7.5 on Hospital Subnet (0.8), version penalty 0
    # Expected: (7.5 * 0.8) + 0 = 6.0 (MEDIUM)
    dev = Device(
        device_id="DEV-TEST-002",
        patient_reference="PAT-002",
        device_model="CardioGuard-X",
        serial_number="SN-002",
        firmware_version="v4.0.0",
        software_version="v5.0.1",
        latest_supported_firmware="v4.0.0",
        latest_supported_software="v5.0.1",
        firmware_status="VULNERABLE",
        software_status="CURRENT",
        network_type="Hospital Subnet",
        telemetry_last_seen=datetime.utcnow(),
        telemetry_status="ONLINE",
        version_drift_state="IN_SYNC",
    )
    adv = Advisory(
        advisory_id="ADV-TEST",
        cve_id="CVE-2026-9999",
        device_model="CardioGuard-X",
        affected_version="v4.0.0",
        fixed_version="v4.2.0",
        cvss_base_score=7.5,
        severity="HIGH",
        description="Test CVE",
        active=True,
    )
    appr = MaintenanceApproval(
        approval_id="APP-002",
        device_id="DEV-TEST-002",
        it_approved=True,
        clinical_ops_approved=True,
    )

    risk_eval = evaluate_device_risk(dev, [adv], appr, None)
    assert risk_eval.final_risk_score == 6.0
    assert risk_eval.risk_category == "MEDIUM"
