"""
Formal Mathematical Risk Engine & Safe Fallback Detector
Operational device support only — this system does not provide medical advice or clinical recommendations.

MATHEMATICAL SPECIFICATION:
===========================
1. Base Risk:
   Base Risk = CVSS Base Score ∈ [0.0, 10.0]
   Derived from the highest active advisory matching (device_model, affected_version).
   If no advisory matches: CVSS Base Score = 0.0.

2. Network Multiplier:
   Cellular Direct = 1.2  (Higher attack surface directly exposed to cellular carriers)
   Home Wi-Fi NAT  = 1.0  (Standard residential NAT network)
   Hospital Subnet = 0.8  (Managed, monitored clinical subnet)

3. Version Lag Penalty:
   Version Lag Penalty = min(2.0, number_of_versions_behind * 0.5)
   If fully current: Version Lag Penalty = 0.0.

4. Final Risk Score:
   FINAL_RISK_SCORE = min(10.0, (CVSS_BASE_SCORE * NETWORK_MULTIPLIER) + VERSION_LAG_PENALTY)

5. Risk Classification:
   [0.0, 3.0]  -> LOW
   (3.0, 6.0]  -> MEDIUM
   (6.0, 8.0]  -> HIGH
   (8.0, 10.0] -> CRITICAL

6. Safe Fallback Triggers (UNTRUSTED_FALLBACK):
   Condition 1: Missing telemetry (>48h stale or drift state UNKNOWN)
   Condition 2: Conflicting maintenance approvals (it_approved != clinical_ops_approved)
   Condition 3: Network flapping / instability (connectivity_status == 'FLAPPING' or packet_loss > 15%)
"""

from datetime import datetime, timedelta
from typing import List, Optional, Tuple
from app.config import (
    NETWORK_MULTIPLIERS,
    VERSION_LAG_STEP_PENALTY,
    MAX_VERSION_LAG_PENALTY,
    MAX_RISK_SCORE,
    TELEMETRY_STALE_HOURS,
    PACKET_LOSS_FLAPPING_THRESHOLD,
)
from app.models import Device, Advisory, MaintenanceApproval, Telemetry
from app.schemas import RiskBreakdown


def parse_version_tuple(v_str: str) -> Tuple[int, ...]:
    """Parse semver string like 'v2.1.0' or '2.1' or '2' into a numeric tuple."""
    if not v_str:
        return (0, 0, 0)
    cleaned = v_str.lower().lstrip("v").strip()
    parts = []
    for p in cleaned.split("."):
        try:
            parts.append(int(p))
        except ValueError:
            parts.append(0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])


def calculate_version_lag(current_ver: str, latest_ver: str) -> int:
    """
    Calculate the number of releases/versions a device is behind.
    Returns 0 if current >= latest.
    """
    curr = parse_version_tuple(current_ver)
    latest = parse_version_tuple(latest_ver)

    if curr >= latest:
        return 0

    # Major diff * 3 + Minor diff * 1 + Patch diff * 0.5 rounded
    major_diff = max(0, latest[0] - curr[0])
    minor_diff = max(0, latest[1] - curr[1])
    patch_diff = max(0, latest[2] - curr[2])

    steps = (major_diff * 3) + minor_diff + (1 if patch_diff > 0 else 0)
    return max(1, steps)


def get_network_multiplier(network_type: str) -> float:
    """Return multiplier for given network type."""
    return NETWORK_MULTIPLIERS.get(network_type, 1.0)


def calculate_version_lag_penalty(versions_behind: int) -> float:
    """Version Lag Penalty = min(2.0, number_of_versions_behind * 0.5)."""
    if versions_behind <= 0:
        return 0.0
    return min(MAX_VERSION_LAG_PENALTY, versions_behind * VERSION_LAG_STEP_PENALTY)


def classify_risk(score: float) -> str:
    """Map numeric score into LOW, MEDIUM, HIGH, CRITICAL."""
    if score <= 3.0:
        return "LOW"
    elif score <= 6.0:
        return "MEDIUM"
    elif score <= 8.0:
        return "HIGH"
    else:
        return "CRITICAL"


def evaluate_device_risk(
    device: Device,
    advisories: List[Advisory],
    approval: Optional[MaintenanceApproval] = None,
    latest_telemetry: Optional[Telemetry] = None,
    current_time: Optional[datetime] = None,
) -> RiskBreakdown:
    """
    Evaluate device risk according to formal mathematical formulation
    and evaluate safe fallback conditions.
    """
    now = current_time or datetime.utcnow()

    # 1. Advisory & CVSS matching
    matched_advisories = [
        adv for adv in advisories
        if adv.active
        and adv.device_model == device.device_model
        and (adv.affected_version == device.firmware_version or adv.affected_version == "*")
    ]

    highest_advisory: Optional[Advisory] = None
    cvss_base_score = 0.0
    cve_id = None
    is_vulnerable = False

    if matched_advisories:
        highest_advisory = max(matched_advisories, key=lambda a: a.cvss_base_score)
        cvss_base_score = highest_advisory.cvss_base_score
        cve_id = highest_advisory.cve_id
        is_vulnerable = True

    # 2. Network Multiplier
    net_multiplier = get_network_multiplier(device.network_type)

    # 3. Version Lag
    fw_lag = calculate_version_lag(device.firmware_version, device.latest_supported_firmware)
    sw_lag = calculate_version_lag(device.software_version, device.latest_supported_software)
    versions_behind = max(fw_lag, sw_lag)
    is_unsupported = (device.firmware_status == "UNSUPPORTED" or device.software_status == "UNSUPPORTED")

    # 4. Version Lag Penalty
    version_penalty = calculate_version_lag_penalty(versions_behind)

    # 5. Final Risk Score calculation
    # FINAL_RISK_SCORE = min(10.0, (CVSS_BASE_SCORE * NETWORK_MULTIPLIER) + VERSION_LAG_PENALTY)
    raw_score = (cvss_base_score * net_multiplier) + version_penalty
    final_score = round(min(MAX_RISK_SCORE, raw_score), 2)
    risk_category = classify_risk(final_score)

    # Risk Explanation construction
    risk_reasons = []
    if is_vulnerable and highest_advisory:
        risk_reasons.append(
            f"Vulnerability match: {highest_advisory.cve_id} (CVSS {highest_advisory.cvss_base_score}) on {device.device_model}"
        )
    if net_multiplier != 1.0:
        risk_reasons.append(f"Network topology factor: {device.network_type} ({net_multiplier}x)")
    if versions_behind > 0:
        risk_reasons.append(
            f"Version lag: {versions_behind} version(s) behind latest supported (Penalty: +{version_penalty:.1f})"
        )
    if is_unsupported:
        risk_reasons.append("Device firmware or software reached End-Of-Support (Unsupported)")
    if not risk_reasons:
        risk_reasons.append("Device firmware is current and no active CVE advisories matched")

    # 6. Fallback Triggers Evaluation
    fallback_triggered = False
    fallback_reasons = []

    # Condition 1: Missing telemetry / stale telemetry (>48h) or UNKNOWN drift
    telemetry_time = device.telemetry_last_seen
    if latest_telemetry and latest_telemetry.timestamp:
        telemetry_time = max(telemetry_time or datetime.min, latest_telemetry.timestamp)

    if telemetry_time is None or (now - telemetry_time) > timedelta(hours=TELEMETRY_STALE_HOURS):
        hours_stale = round((now - telemetry_time).total_seconds() / 3600, 1) if telemetry_time else 999.0
        fallback_triggered = True
        fallback_reasons.append(
            f"Missing/stale telemetry: Last reported {hours_stale} hours ago (exceeds {TELEMETRY_STALE_HOURS}h threshold)"
        )

    if device.version_drift_state == "UNKNOWN" or device.telemetry_status == "MISSING":
        fallback_triggered = True
        fallback_reasons.append("Version drift state is UNKNOWN / Telemetry is MISSING")

    # Condition 2: Conflicting maintenance approvals
    if approval:
        if approval.it_approved != approval.clinical_ops_approved:
            fallback_triggered = True
            fallback_reasons.append(
                f"Conflicting approvals: IT_Approved={approval.it_approved}, Clinical_Ops_Approved={approval.clinical_ops_approved}"
            )
        elif not approval.it_approved and not approval.clinical_ops_approved:
            # Both false is pending, not necessarily conflicting, but not approved
            pass

    # Condition 3: Network Flapping / Instability
    packet_loss = 0.0
    conn_status = device.telemetry_status
    if latest_telemetry:
        packet_loss = latest_telemetry.packet_loss or 0.0
        conn_status = latest_telemetry.connectivity_status or conn_status

    if conn_status == "FLAPPING" or device.telemetry_status == "FLAPPING":
        fallback_triggered = True
        fallback_reasons.append("Network flapping detected: continuous/intermittent connect-disconnect cycles")
    elif packet_loss > PACKET_LOSS_FLAPPING_THRESHOLD:
        fallback_triggered = True
        fallback_reasons.append(
            f"High packet loss ({packet_loss}% > {PACKET_LOSS_FLAPPING_THRESHOLD}% threshold): network link unstable"
        )

    return RiskBreakdown(
        device_id=device.device_id,
        cve_id=cve_id,
        cvss_base_score=cvss_base_score,
        network_type=device.network_type,
        network_multiplier=net_multiplier,
        versions_behind=versions_behind,
        version_lag_penalty=version_penalty,
        raw_risk_score=raw_score,
        final_risk_score=final_score,
        risk_category=risk_category,
        risk_reasons=risk_reasons,
        is_vulnerable=is_vulnerable,
        is_unsupported=is_unsupported,
        fallback_triggered=fallback_triggered,
        fallback_reasons=fallback_reasons,
    )
