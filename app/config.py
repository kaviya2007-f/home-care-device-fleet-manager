import os
from typing import Dict

# Database Configuration
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./fleet_management.db")

# Capacity Guardrails
MAX_HOURLY_UPDATES = 50

# Safe Fallback Thresholds
TELEMETRY_STALE_HOURS = 48
PACKET_LOSS_FLAPPING_THRESHOLD = 15.0  # > 15% packet loss triggers unstable/flapping status

# Network Risk Multipliers
NETWORK_MULTIPLIERS: Dict[str, float] = {
    "Cellular Direct": 1.2,
    "Home Wi-Fi NAT": 1.0,
    "Hospital Subnet": 0.8,
}

# Version Lag Penalty constants
VERSION_LAG_STEP_PENALTY = 0.5
MAX_VERSION_LAG_PENALTY = 2.0
MAX_RISK_SCORE = 10.0

# Medical Disclaimer
MEDICAL_DISCLAIMER = (
    "Operational device support only — this system does not provide medical advice or clinical recommendations."
)
