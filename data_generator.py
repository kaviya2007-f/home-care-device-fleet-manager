"""
Synthetic Realistic Fleet Data Generator
Operational device support only — this system does not provide medical advice or clinical recommendations.

Generates 500+ realistic home-care monitoring devices with diverse firmware/software versions,
network locations, network multipliers, CVE advisories, approval combinations, and failure modes.
"""

from datetime import datetime, timedelta
import random
import uuid
from typing import List
from app.database import SessionLocal, init_db
from app.models import Device, Advisory, MaintenanceApproval, Telemetry, UpdateSchedule, Remediation
from app.risk_engine import evaluate_device_risk

# Models & their version definitions
MODELS_CATALOG = {
    "OxiPulse-v2": {
        "latest_firmware": "v2.4.0",
        "latest_software": "v3.1.0",
        "versions": ["v2.4.0", "v2.3.1", "v2.2.0", "v2.1.0", "v1.9.0", "v1.0.0"],
        "unsupported_threshold": "v2.0.0",
    },
    "CardioGuard-X": {
        "latest_firmware": "v4.2.0",
        "latest_software": "v5.0.1",
        "versions": ["v4.2.0", "v4.1.2", "v4.0.0", "v3.8.0", "v3.5.0", "v2.0.0"],
        "unsupported_threshold": "v3.6.0",
    },
    "HomeGateway-3": {
        "latest_firmware": "v1.8.2",
        "latest_software": "v2.0.0",
        "versions": ["v1.8.2", "v1.8.0", "v1.7.5", "v1.6.0", "v1.4.0", "v1.0.0"],
        "unsupported_threshold": "v1.5.0",
    },
    "RespiraCare-100": {
        "latest_firmware": "v3.0.0",
        "latest_software": "v3.2.0",
        "versions": ["v3.0.0", "v2.9.0", "v2.8.1", "v2.5.0", "v2.0.0"],
        "unsupported_threshold": "v2.6.0",
    },
}

ADVISORIES_DATA = [
    {
        "advisory_id": "ADV-2026-001",
        "cve_id": "CVE-2026-4401",
        "device_model": "OxiPulse-v2",
        "affected_version": "v2.2.0",
        "fixed_version": "v2.4.0",
        "cvss_base_score": 8.8,
        "severity": "HIGH",
        "description": "Unauthenticated buffer overflow in remote telemetry daemon allowing arbitrary command execution.",
    },
    {
        "advisory_id": "ADV-2026-002",
        "cve_id": "CVE-2026-4402",
        "device_model": "OxiPulse-v2",
        "affected_version": "v2.1.0",
        "fixed_version": "v2.4.0",
        "cvss_base_score": 9.2,
        "severity": "CRITICAL",
        "description": "Hardcoded debug certificate allows remote unauthorized TLS session hijacking.",
    },
    {
        "advisory_id": "ADV-2026-003",
        "cve_id": "CVE-2026-5510",
        "device_model": "CardioGuard-X",
        "affected_version": "v4.0.0",
        "fixed_version": "v4.2.0",
        "cvss_base_score": 7.5,
        "severity": "HIGH",
        "description": "Improper input validation in BLE beacon stack causing denial of service reboot loop.",
    },
    {
        "advisory_id": "ADV-2026-004",
        "cve_id": "CVE-2026-5511",
        "device_model": "CardioGuard-X",
        "affected_version": "v3.8.0",
        "fixed_version": "v4.2.0",
        "cvss_base_score": 8.5,
        "severity": "HIGH",
        "description": "Remote code execution in MQTT synchronization pipeline over unauthenticated socket.",
    },
    {
        "advisory_id": "ADV-2026-005",
        "cve_id": "CVE-2026-6601",
        "device_model": "HomeGateway-3",
        "affected_version": "v1.6.0",
        "fixed_version": "v1.8.2",
        "cvss_base_score": 9.8,
        "severity": "CRITICAL",
        "description": "Embedded web administration bypass permitting remote root shell over WAN interface.",
    },
    {
        "advisory_id": "ADV-2026-006",
        "cve_id": "CVE-2026-7701",
        "device_model": "RespiraCare-100",
        "affected_version": "v2.5.0",
        "fixed_version": "v3.0.0",
        "cvss_base_score": 6.8,
        "severity": "MEDIUM",
        "description": "Information disclosure in periodic diagnostic logging subsystem.",
    },
]

NETWORK_LOCATIONS = [
    "Patient Residence - North District",
    "Patient Residence - South District",
    "Patient Residence - Metro East",
    "Rural Clinic Satellite-A",
    "Outpatient Center B-4",
    "Assisted Living Unit C",
]

NETWORK_TYPES = ["Cellular Direct", "Home Wi-Fi NAT", "Hospital Subnet"]


def seed_database(num_devices: int = 520, clear_existing: bool = True):
    """Generate and insert synthetic fleet data into the database."""
    init_db()
    db = SessionLocal()
    random.seed(42)  # Deterministic generation for reproducible experiments

    if clear_existing:
        db.query(UpdateSchedule).delete()
        db.query(Remediation).delete()
        db.query(Telemetry).delete()
        db.query(MaintenanceApproval).delete()
        db.query(Device).delete()
        db.query(Advisory).delete()
        db.commit()

    # 1. Seed Advisories
    advisory_objects = []
    for adv in ADVISORIES_DATA:
        obj = Advisory(
            advisory_id=adv["advisory_id"],
            cve_id=adv["cve_id"],
            device_model=adv["device_model"],
            affected_version=adv["affected_version"],
            fixed_version=adv["fixed_version"],
            cvss_base_score=adv["cvss_base_score"],
            severity=adv["severity"],
            description=adv["description"],
            active=True,
            published_at=datetime.utcnow() - timedelta(days=random.randint(10, 180)),
        )
        db.add(obj)
        advisory_objects.append(obj)
    db.commit()

    # 2. Seed Devices and related records
    now = datetime.utcnow()
    created_devices = []

    for i in range(1, num_devices + 1):
        model_name = random.choice(list(MODELS_CATALOG.keys()))
        m_info = MODELS_CATALOG[model_name]
        dev_id = f"DEV-{model_name[:4].upper()}-{i:04d}"
        serial_no = f"SN-{model_name[:3].upper()}-{uuid.uuid4().hex[:6].upper()}"
        patient_ref = f"PAT-ANON-{random.randint(10000, 99999)}"

        # Version distribution:
        # 35% Current, 30% Outdated (1-2 versions behind), 20% Vulnerable specific version, 15% Unsupported legacy
        rand_profile = random.random()
        if rand_profile < 0.35:
            # Current
            fw_ver = m_info["latest_firmware"]
            sw_ver = m_info["latest_software"]
            fw_status = "CURRENT"
            sw_status = "CURRENT"
            drift_state = "IN_SYNC"
        elif rand_profile < 0.65:
            # Outdated
            available_versions = [v for v in m_info["versions"] if v != m_info["latest_firmware"]]
            fw_ver = available_versions[0] if available_versions else m_info["latest_firmware"]
            sw_ver = "v1.0.0"
            fw_status = "OUTDATED"
            sw_status = "OUTDATED"
            drift_state = "DRIFTED"
        elif rand_profile < 0.85:
            # Vulnerable
            adv_for_model = [a for a in ADVISORIES_DATA if a["device_model"] == model_name]
            if adv_for_model:
                chosen_adv = random.choice(adv_for_model)
                fw_ver = chosen_adv["affected_version"]
            else:
                fw_ver = m_info["versions"][-1]
            sw_ver = "v1.0.0"
            fw_status = "VULNERABLE"
            sw_status = "OUTDATED"
            drift_state = "CRITICAL_DRIFT"
        else:
            # Legacy / Unsupported
            fw_ver = m_info["versions"][-1]
            sw_ver = "v0.9.0"
            fw_status = "UNSUPPORTED"
            sw_status = "UNSUPPORTED"
            drift_state = "DRIFTED"

        net_type = random.choice(NETWORK_TYPES)
        net_location = random.choice(NETWORK_LOCATIONS)

        # Telemetry state distribution
        # 75% Online / Recent, 12% Stale (>48h), 8% Network Flapping, 5% Missing
        tel_profile = random.random()
        packet_loss = 0.0
        fallback_initial = "NONE"

        if tel_profile < 0.75:
            last_seen = now - timedelta(minutes=random.randint(2, 120))
            tel_status = "ONLINE"
            packet_loss = round(random.uniform(0.0, 3.5), 1)
        elif tel_profile < 0.87:
            # Stale / Missing > 48h
            stale_hours = random.randint(50, 240)
            last_seen = now - timedelta(hours=stale_hours)
            tel_status = "OFFLINE"
            fallback_initial = "UNTRUSTED_FALLBACK"
        elif tel_profile < 0.95:
            # Network Flapping
            last_seen = now - timedelta(minutes=random.randint(1, 10))
            tel_status = "FLAPPING"
            packet_loss = round(random.uniform(18.0, 65.0), 1)
            fallback_initial = "UNTRUSTED_FALLBACK"
        else:
            # Missing / Drift state UNKNOWN
            last_seen = now - timedelta(hours=random.randint(72, 300))
            tel_status = "MISSING"
            drift_state = "UNKNOWN"
            fallback_initial = "UNTRUSTED_FALLBACK"

        # Approvals distribution:
        # 60% Dual Approved (IT=True, Clinical=True)
        # 20% Conflicting (IT=True, Clinical=False or vice versa) -> Triggers Fallback
        # 20% Pending (IT=False, Clinical=False)
        appr_profile = random.random()
        if appr_profile < 0.60:
            it_appr = True
            clin_appr = True
            notes = "Standard operational maintenance approval granted."
        elif appr_profile < 0.80:
            # Conflicting approvals
            it_appr = random.choice([True, False])
            clin_appr = not it_appr
            fallback_initial = "UNTRUSTED_FALLBACK"
            notes = "Conflicting approvals: IT and Clinical Operations disagree on maintenance window."
        else:
            it_appr = False
            clin_appr = False
            notes = "Pending routine maintenance review."

        device = Device(
            device_id=dev_id,
            patient_reference=patient_ref,
            device_model=model_name,
            serial_number=serial_no,
            firmware_version=fw_ver,
            software_version=sw_ver,
            latest_supported_firmware=m_info["latest_firmware"],
            latest_supported_software=m_info["latest_software"],
            firmware_status=fw_status,
            software_status=sw_status,
            network_location=net_location,
            network_type=net_type,
            telemetry_last_seen=last_seen,
            telemetry_status=tel_status,
            version_drift_state=drift_state,
            current_risk_score=0.0,
            risk_status="LOW",
            fallback_status=fallback_initial,
            created_at=now - timedelta(days=random.randint(30, 365)),
            updated_at=last_seen,
        )
        db.add(device)
        created_devices.append(device)

        # Create Approval record
        approval = MaintenanceApproval(
            approval_id=f"APP-{uuid.uuid4().hex[:8].upper()}",
            device_id=dev_id,
            it_approved=it_appr,
            clinical_ops_approved=clin_appr,
            approved_by="Fleet_Admin" if (it_appr or clin_appr) else None,
            approved_at=now - timedelta(days=random.randint(1, 10)),
            notes=notes,
        )
        db.add(approval)

        # Create Telemetry history record
        telemetry_entry = Telemetry(
            telemetry_id=f"TEL-{uuid.uuid4().hex[:8].upper()}",
            device_id=dev_id,
            timestamp=last_seen,
            firmware_version=fw_ver,
            software_version=sw_ver,
            network_location=net_location,
            network_type=net_type,
            connectivity_status=tel_status,
            packet_loss=packet_loss,
            telemetry_source="agent_daemon",
        )
        db.add(telemetry_entry)

    db.commit()

    # Calculate initial risk scores for all generated devices
    advisories = db.query(Advisory).filter(Advisory.active.is_(True)).all()
    for dev in created_devices:
        appr = db.query(MaintenanceApproval).filter(MaintenanceApproval.device_id == dev.device_id).first()
        tel = db.query(Telemetry).filter(Telemetry.device_id == dev.device_id).first()
        risk_breakdown = evaluate_device_risk(dev, advisories, appr, tel, current_time=now)
        dev.current_risk_score = risk_breakdown.final_risk_score
        dev.risk_status = risk_breakdown.risk_category
        if risk_breakdown.fallback_triggered:
            dev.fallback_status = "UNTRUSTED_FALLBACK"

    db.commit()
    db.close()
    print(f" Successfully seeded {num_devices} devices with realistic operational attributes.")


if __name__ == "__main__":
    seed_database(num_devices=520)
