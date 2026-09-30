-- =====================================================================
-- HOME-CARE DEVICE FLEET MONITORING DATABASE SCHEMA (DDL)
-- Operational device support only — does not provide medical advice.
-- =====================================================================

-- Table: devices
CREATE TABLE IF NOT EXISTS devices (
    device_id VARCHAR(64) PRIMARY KEY,
    patient_reference VARCHAR(64) NOT NULL,
    device_model VARCHAR(64) NOT NULL,
    serial_number VARCHAR(64) UNIQUE NOT NULL,
    firmware_version VARCHAR(32) NOT NULL,
    software_version VARCHAR(32) NOT NULL,
    latest_supported_firmware VARCHAR(32) NOT NULL,
    latest_supported_software VARCHAR(32) NOT NULL,
    firmware_status VARCHAR(32) DEFAULT 'CURRENT',
    software_status VARCHAR(32) DEFAULT 'CURRENT',
    network_location VARCHAR(64) DEFAULT 'Patient Residence',
    network_type VARCHAR(32) DEFAULT 'Home Wi-Fi NAT',
    telemetry_last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    telemetry_status VARCHAR(32) DEFAULT 'ONLINE',
    version_drift_state VARCHAR(32) DEFAULT 'IN_SYNC',
    current_risk_score FLOAT DEFAULT 0.0,
    risk_status VARCHAR(32) DEFAULT 'LOW',
    fallback_status VARCHAR(32) DEFAULT 'NONE',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS ix_devices_device_id ON devices(device_id);
CREATE INDEX IF NOT EXISTS ix_devices_patient_reference ON devices(patient_reference);
CREATE INDEX IF NOT EXISTS ix_devices_device_model ON devices(device_model);

-- Table: advisories
CREATE TABLE IF NOT EXISTS advisories (
    advisory_id VARCHAR(64) PRIMARY KEY,
    cve_id VARCHAR(64) NOT NULL,
    device_model VARCHAR(64) NOT NULL,
    affected_version VARCHAR(32) NOT NULL,
    fixed_version VARCHAR(32) NOT NULL,
    cvss_base_score FLOAT NOT NULL,
    severity VARCHAR(32) NOT NULL,
    description TEXT NOT NULL,
    active BOOLEAN DEFAULT 1,
    published_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS ix_advisories_advisory_id ON advisories(advisory_id);
CREATE INDEX IF NOT EXISTS ix_advisories_cve_id ON advisories(cve_id);
CREATE INDEX IF NOT EXISTS ix_advisories_device_model ON advisories(device_model);

-- Table: maintenance_approvals
CREATE TABLE IF NOT EXISTS maintenance_approvals (
    approval_id VARCHAR(64) PRIMARY KEY,
    device_id VARCHAR(64) NOT NULL,
    it_approved BOOLEAN DEFAULT 0,
    clinical_ops_approved BOOLEAN DEFAULT 0,
    approved_by VARCHAR(64),
    approved_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    notes TEXT,
    FOREIGN KEY(device_id) REFERENCES devices(device_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS ix_approvals_device_id ON maintenance_approvals(device_id);

-- Table: telemetry
CREATE TABLE IF NOT EXISTS telemetry (
    telemetry_id VARCHAR(64) PRIMARY KEY,
    device_id VARCHAR(64) NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    firmware_version VARCHAR(32) NOT NULL,
    software_version VARCHAR(32) NOT NULL,
    network_location VARCHAR(64) DEFAULT 'Patient Residence',
    network_type VARCHAR(32) DEFAULT 'Home Wi-Fi NAT',
    connectivity_status VARCHAR(32) DEFAULT 'ONLINE',
    packet_loss FLOAT DEFAULT 0.0,
    telemetry_source VARCHAR(64) DEFAULT 'agent_daemon',
    FOREIGN KEY(device_id) REFERENCES devices(device_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS ix_telemetry_device_id ON telemetry(device_id);
CREATE INDEX IF NOT EXISTS ix_telemetry_timestamp ON telemetry(timestamp);

-- Table: remediations
CREATE TABLE IF NOT EXISTS remediations (
    remediation_id VARCHAR(64) PRIMARY KEY,
    device_id VARCHAR(64) NOT NULL,
    previous_version VARCHAR(32) NOT NULL,
    target_version VARCHAR(32) NOT NULL,
    scheduled_slot VARCHAR(32),
    status VARCHAR(64) NOT NULL,
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    fallback_triggered BOOLEAN DEFAULT 0,
    error_message TEXT,
    FOREIGN KEY(device_id) REFERENCES devices(device_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS ix_remediations_device_id ON remediations(device_id);

-- Table: update_schedules
CREATE TABLE IF NOT EXISTS update_schedules (
    schedule_id VARCHAR(64) PRIMARY KEY,
    device_id VARCHAR(64) NOT NULL,
    scheduled_hour INTEGER NOT NULL,
    priority INTEGER DEFAULT 1,
    risk_score FLOAT DEFAULT 0.0,
    status VARCHAR(32) DEFAULT 'SCHEDULED',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(device_id) REFERENCES devices(device_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS ix_schedules_device_id ON update_schedules(device_id);
CREATE INDEX IF NOT EXISTS ix_schedules_scheduled_hour ON update_schedules(scheduled_hour);
