from datetime import datetime
from sqlalchemy import Column, String, Float, Boolean, DateTime, Integer, Text, ForeignKey
from sqlalchemy.orm import relationship
from app.database import Base


class Device(Base):
    __tablename__ = "devices"

    device_id = Column(String(64), primary_key=True, index=True)
    patient_reference = Column(String(64), nullable=False, index=True)  # Anonymized reference only
    device_model = Column(String(64), nullable=False, index=True)
    serial_number = Column(String(64), unique=True, nullable=False)
    firmware_version = Column(String(32), nullable=False)
    software_version = Column(String(32), nullable=False)
    latest_supported_firmware = Column(String(32), nullable=False)
    latest_supported_software = Column(String(32), nullable=False)
    firmware_status = Column(String(32), default="CURRENT")  # CURRENT, OUTDATED, VULNERABLE, UNSUPPORTED
    software_status = Column(String(32), default="CURRENT")
    network_location = Column(String(64), default="Patient Residence")
    network_type = Column(String(32), default="Home Wi-Fi NAT")  # Cellular Direct, Home Wi-Fi NAT, Hospital Subnet
    telemetry_last_seen = Column(DateTime, default=datetime.utcnow)
    telemetry_status = Column(String(32), default="ONLINE")  # ONLINE, OFFLINE, FLAPPING, MISSING
    version_drift_state = Column(String(32), default="IN_SYNC")  # IN_SYNC, DRIFTED, CRITICAL_DRIFT, UNKNOWN
    current_risk_score = Column(Float, default=0.0)
    risk_status = Column(String(32), default="LOW")  # LOW, MEDIUM, HIGH, CRITICAL
    fallback_status = Column(String(32), default="NONE")  # NONE, UNTRUSTED_FALLBACK, MANUAL_REVIEW, FIELD_DISPATCH
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    approvals = relationship("MaintenanceApproval", back_populates="device", cascade="all, delete-orphan")
    telemetries = relationship("Telemetry", back_populates="device", cascade="all, delete-orphan")
    remediations = relationship("Remediation", back_populates="device", cascade="all, delete-orphan")
    schedules = relationship("UpdateSchedule", back_populates="device", cascade="all, delete-orphan")


class Advisory(Base):
    __tablename__ = "advisories"

    advisory_id = Column(String(64), primary_key=True, index=True)
    cve_id = Column(String(64), nullable=False, index=True)
    device_model = Column(String(64), nullable=False, index=True)
    affected_version = Column(String(32), nullable=False)
    fixed_version = Column(String(32), nullable=False)
    cvss_base_score = Column(Float, nullable=False)
    severity = Column(String(32), nullable=False)  # LOW, MEDIUM, HIGH, CRITICAL
    description = Column(Text, nullable=False)
    active = Column(Boolean, default=True)
    published_at = Column(DateTime, default=datetime.utcnow)


class MaintenanceApproval(Base):
    __tablename__ = "maintenance_approvals"

    approval_id = Column(String(64), primary_key=True, index=True)
    device_id = Column(String(64), ForeignKey("devices.device_id"), nullable=False, index=True)
    it_approved = Column(Boolean, default=False)
    clinical_ops_approved = Column(Boolean, default=False)
    approved_by = Column(String(64), nullable=True)
    approved_at = Column(DateTime, default=datetime.utcnow)
    notes = Column(Text, nullable=True)

    device = relationship("Device", back_populates="approvals")


class Telemetry(Base):
    __tablename__ = "telemetry"

    telemetry_id = Column(String(64), primary_key=True, index=True)
    device_id = Column(String(64), ForeignKey("devices.device_id"), nullable=False, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    firmware_version = Column(String(32), nullable=False)
    software_version = Column(String(32), nullable=False)
    network_location = Column(String(64), default="Patient Residence")
    network_type = Column(String(32), default="Home Wi-Fi NAT")
    connectivity_status = Column(String(32), default="ONLINE")  # ONLINE, OFFLINE, FLAPPING, DEGRADED
    packet_loss = Column(Float, default=0.0)
    telemetry_source = Column(String(64), default="agent_daemon")

    device = relationship("Device", back_populates="telemetries")


class Remediation(Base):
    __tablename__ = "remediations"

    remediation_id = Column(String(64), primary_key=True, index=True)
    device_id = Column(String(64), ForeignKey("devices.device_id"), nullable=False, index=True)
    previous_version = Column(String(32), nullable=False)
    target_version = Column(String(32), nullable=False)
    scheduled_slot = Column(String(32), nullable=True)
    status = Column(String(64), nullable=False)  # SAFE_TO_REMEDIATE, SCHEDULED, REMEDIATED, BLOCKED_APPROVAL, UNTRUSTED_FALLBACK, CAPACITY_QUEUED, NETWORK_FAILURE, UNSUPPORTED_VERSION
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    fallback_triggered = Column(Boolean, default=False)
    error_message = Column(Text, nullable=True)

    device = relationship("Device", back_populates="remediations")


class UpdateSchedule(Base):
    __tablename__ = "update_schedules"

    schedule_id = Column(String(64), primary_key=True, index=True)
    device_id = Column(String(64), ForeignKey("devices.device_id"), nullable=False, index=True)
    scheduled_hour = Column(Integer, nullable=False, index=True)  # Hour index (e.g. 1, 2, 3...)
    priority = Column(Integer, default=1)
    risk_score = Column(Float, default=0.0)
    status = Column(String(32), default="SCHEDULED")  # QUEUED, SCHEDULED, COMPLETED, CANCELLED
    created_at = Column(DateTime, default=datetime.utcnow)

    device = relationship("Device", back_populates="schedules")
