import pytest
from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.database import Base
from app.models import Device, Advisory, MaintenanceApproval, Telemetry, UpdateSchedule
from app.scheduler import schedule_updates, get_hourly_utilization
from app.config import MAX_HOURLY_UPDATES


@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


def create_mock_device(session, idx, fw="v1.0.0", target_fw="v2.0.0", it_appr=True, clin_appr=True, fallback="NONE", tel_status="ONLINE"):
    dev = Device(
        device_id=f"DEV-{idx:04d}",
        patient_reference=f"PAT-{idx:04d}",
        device_model="OxiPulse-v2",
        serial_number=f"SN-{idx:04d}",
        firmware_version=fw,
        software_version="v1.0.0",
        latest_supported_firmware=target_fw,
        latest_supported_software="v2.0.0",
        firmware_status="OUTDATED",
        software_status="OUTDATED",
        network_type="Home Wi-Fi NAT",
        telemetry_last_seen=datetime.utcnow(),
        telemetry_status=tel_status,
        version_drift_state="DRIFTED",
        fallback_status=fallback,
    )
    session.add(dev)
    appr = MaintenanceApproval(
        approval_id=f"APP-{idx:04d}",
        device_id=dev.device_id,
        it_approved=it_appr,
        clinical_ops_approved=clin_appr,
    )
    session.add(appr)
    session.commit()
    return dev


def test_schedule_10_devices(db_session):
    for i in range(1, 11):
        create_mock_device(db_session, i)

    res = schedule_updates(db_session)
    assert res.total_scheduled == 10
    assert res.total_queued == 0
    assert res.hourly_distribution.get("Hour 1") == 10


def test_schedule_50_devices_exact_limit(db_session):
    for i in range(1, 51):
        create_mock_device(db_session, i)

    res = schedule_updates(db_session)
    assert res.total_scheduled == 50
    assert res.total_queued == 0
    assert res.hourly_distribution.get("Hour 1") == 50


def test_schedule_51_devices_overflow_guardrail(db_session):
    # 51 devices must strictly yield 50 in Hour 1 and 1 in Hour 2
    for i in range(1, 52):
        create_mock_device(db_session, i)

    res = schedule_updates(db_session)
    assert res.total_scheduled == 50
    assert res.total_queued == 1
    assert res.hourly_distribution.get("Hour 1") == 50
    assert res.hourly_distribution.get("Hour 2") == 1


def test_schedule_125_devices_multiple_slots(db_session):
    # 125 devices -> Hour 1: 50, Hour 2: 50, Hour 3: 25. No slot > 50.
    for i in range(1, 126):
        create_mock_device(db_session, i)

    res = schedule_updates(db_session)
    assert res.total_scheduled == 50
    assert res.total_queued == 75
    assert res.hourly_distribution.get("Hour 1") == 50
    assert res.hourly_distribution.get("Hour 2") == 50
    assert res.hourly_distribution.get("Hour 3") == 25

    # Check database records
    schedules = db_session.query(UpdateSchedule).all()
    assert len(schedules) == 125
    hour_counts = {}
    for s in schedules:
        hour_counts[s.scheduled_hour] = hour_counts.get(s.scheduled_hour, 0) + 1

    assert all(count <= MAX_HOURLY_UPDATES for count in hour_counts.values())


def test_unapproved_and_fallback_devices_are_blocked(db_session):
    # 1 approved normal device
    create_mock_device(db_session, 1, it_appr=True, clin_appr=True)
    # 1 unapproved device
    create_mock_device(db_session, 2, it_appr=False, clin_appr=False)
    # 1 conflicting approval device
    create_mock_device(db_session, 3, it_appr=True, clin_appr=False)
    # 1 fallback device (flapping)
    create_mock_device(db_session, 4, it_appr=True, clin_appr=True, tel_status="FLAPPING", fallback="UNTRUSTED_FALLBACK")

    res = schedule_updates(db_session)
    assert res.total_scheduled == 1
    assert res.total_blocked >= 3
