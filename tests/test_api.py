import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.database import init_db
from data_generator import seed_database

client = TestClient(app)


@pytest.fixture(scope="module", autouse=True)
def setup_test_db():
    seed_database(num_devices=30, clear_existing=True)


def get_first_device_id():
    response = client.get("/inventory")
    assert response.status_code == 200
    data = response.json()
    assert len(data["devices"]) > 0
    return data["devices"][0]["device_id"]


def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "Operational device support only" in data["disclaimer"]


def test_inventory_endpoint():
    response = client.get("/inventory")
    assert response.status_code == 200
    data = response.json()
    assert data["total_devices"] >= 30
    assert len(data["devices"]) >= 30
    assert "disclaimer" in data


def test_advisories_endpoint():
    response = client.get("/advisories")
    assert response.status_code == 200
    data = response.json()
    assert len(data) >= 1
    assert "cve_id" in data[0]


def test_telemetry_ingest_endpoint():
    dev_id = get_first_device_id()
    payload = {
        "device_id": dev_id,
        "firmware_version": "v2.4.0",
        "software_version": "v3.1.0",
        "network_location": "Patient Residence",
        "network_type": "Home Wi-Fi NAT",
        "connectivity_status": "ONLINE",
        "packet_loss": 0.5,
    }
    response = client.post("/ingest", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["device_id"] == dev_id
    assert data["connectivity_status"] == "ONLINE"


def test_approvals_endpoint():
    dev_id = get_first_device_id()
    payload = {
        "device_id": dev_id,
        "it_approved": True,
        "clinical_ops_approved": True,
        "approved_by": "Test_Admin",
        "notes": "Approved for QA testing",
    }
    response = client.post("/approvals", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["it_approved"] is True
    assert data["clinical_ops_approved"] is True
    assert data["is_conflicting"] is False


def test_approvals_conflicting_endpoint():
    dev_id = get_first_device_id()
    payload = {
        "device_id": dev_id,
        "it_approved": True,
        "clinical_ops_approved": False,
        "approved_by": "Test_Admin",
        "notes": "Conflicting test approval",
    }
    response = client.post("/approvals", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["is_conflicting"] is True


def test_schedule_endpoint():
    response = client.post("/schedule", json={"force_reschedule": True})
    assert response.status_code == 200
    data = response.json()
    assert "total_scheduled" in data
    assert "hourly_distribution" in data


def test_capacity_endpoint():
    response = client.get("/capacity")
    assert response.status_code == 200
    data = response.json()
    assert data["max_hourly_capacity"] == 50
    assert "1" in data["hours"]


def test_remediate_endpoint():
    dev_id = get_first_device_id()
    # Approve device first
    client.post(
        "/approvals",
        json={"device_id": dev_id, "it_approved": True, "clinical_ops_approved": True},
    )
    response = client.post(f"/remediate/{dev_id}", json={"override_fallback": True})
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert "operational_message" in data


def test_telemetry_simulation_flapping():
    dev_id = get_first_device_id()
    response = client.post(f"/telemetry/simulate-flapping/{dev_id}")
    assert response.status_code == 200
    data = response.json()
    assert data["fallback_status"] == "UNTRUSTED_FALLBACK"


def test_telemetry_simulation_missing():
    dev_id = get_first_device_id()
    response = client.post(f"/telemetry/simulate-missing/{dev_id}?stale_hours=80.0")
    assert response.status_code == 200
    data = response.json()
    assert data["fallback_status"] == "UNTRUSTED_FALLBACK"
