from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field


# --- Telemetry Ingestion Schemas ---
class TelemetryIngestRequest(BaseModel):
    device_id: str
    firmware_version: str
    software_version: str
    network_location: Optional[str] = "Patient Residence"
    network_type: Optional[str] = "Home Wi-Fi NAT"
    connectivity_status: Optional[str] = "ONLINE"
    packet_loss: Optional[float] = 0.0
    telemetry_source: Optional[str] = "agent_daemon"


class TelemetryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    telemetry_id: str
    device_id: str
    timestamp: datetime
    firmware_version: str
    software_version: str
    network_location: str
    network_type: str
    connectivity_status: str
    packet_loss: float
    telemetry_source: str


# --- Maintenance Approval Schemas ---
class MaintenanceApprovalRequest(BaseModel):
    device_id: str
    it_approved: bool
    clinical_ops_approved: bool
    approved_by: Optional[str] = "Fleet_Operator"
    notes: Optional[str] = None


class MaintenanceApprovalResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    approval_id: str
    device_id: str
    it_approved: bool
    clinical_ops_approved: bool
    approved_by: Optional[str]
    approved_at: datetime
    notes: Optional[str]
    is_conflicting: bool


# --- Risk Calculation Details ---
class RiskBreakdown(BaseModel):
    device_id: str
    cve_id: Optional[str] = None
    cvss_base_score: float = 0.0
    network_type: str
    network_multiplier: float
    versions_behind: int
    version_lag_penalty: float
    raw_risk_score: float
    final_risk_score: float
    risk_category: str
    risk_reasons: List[str]
    is_vulnerable: bool
    is_unsupported: bool
    fallback_triggered: bool
    fallback_reasons: List[str]


# --- Device Schemas ---
class DeviceBase(BaseModel):
    device_id: str
    patient_reference: str
    device_model: str
    serial_number: str
    firmware_version: str
    software_version: str
    latest_supported_firmware: str
    latest_supported_software: str
    firmware_status: str
    software_status: str
    network_location: str
    network_type: str
    telemetry_last_seen: datetime
    telemetry_status: str
    version_drift_state: str
    current_risk_score: float
    risk_status: str
    fallback_status: str


class DeviceInventoryItem(DeviceBase):
    model_config = ConfigDict(from_attributes=True)

    it_approved: bool = False
    clinical_ops_approved: bool = False
    approval_status: str = "PENDING"
    cve_id: Optional[str] = None
    cvss_base_score: float = 0.0
    version_lag: int = 0
    risk_breakdown: Optional[RiskBreakdown] = None


class FleetInventoryResponse(BaseModel):
    total_devices: int
    devices: List[DeviceInventoryItem]
    disclaimer: str


# --- Update Scheduling Schemas ---
class ScheduleBatchRequest(BaseModel):
    device_ids: Optional[List[str]] = None  # If None, automatically select eligible devices
    force_reschedule: Optional[bool] = False


class ScheduledItem(BaseModel):
    schedule_id: str
    device_id: str
    device_model: str
    scheduled_hour: int
    priority: int
    risk_score: float
    status: str


class ScheduleResponse(BaseModel):
    message: str
    total_requested: int
    total_scheduled: int
    total_queued: int
    total_blocked: int
    schedules: List[ScheduledItem]
    hourly_distribution: dict


class CapacityStatusResponse(BaseModel):
    max_hourly_capacity: int
    hours: dict  # {hour_number: {"used": int, "remaining": int, "devices": [...]}}
    total_queued: int


# --- Remediation Schemas ---
class RemediationRequest(BaseModel):
    override_fallback: Optional[bool] = False


class RemediationResponse(BaseModel):
    remediation_id: Optional[str] = None
    device_id: str
    status: str
    previous_version: str
    target_version: str
    fallback_triggered: bool
    error_message: Optional[str] = None
    new_risk_score: float
    new_risk_status: str
    operational_message: str


# --- Advisory Schemas ---
class AdvisoryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    advisory_id: str
    cve_id: str
    device_model: str
    affected_version: str
    fixed_version: str
    cvss_base_score: float
    severity: str
    description: str
    active: bool
    published_at: datetime
