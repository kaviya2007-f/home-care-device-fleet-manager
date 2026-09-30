# Failure-Mode Analysis & Operational Safeguards Specification

> **CRITICAL DISCLAIMER:** *Operational device support only — this system does not provide medical advice or clinical recommendations.*

---

## 1. Executive Summary

In home-care remote patient monitoring fleets, automated over-the-air (OTA) firmware deployments introduce significant operational failure modes if executed without stringent deterministic guardrails. A failed firmware update on a remote patient device can cause device bricking, loss of patient vital sign telemetry, or uncoordinated service disruption.

This document details the deterministic failure modes analyzed, the detection mechanisms implemented, expected vs actual behaviors, and safety fallbacks verified through automated testing.

---

## 2. Failure Mode Analysis Matrix

| Failure Mode | Root Cause | Detection Mechanism | Expected Behavior | Actual Measured Behavior | Operational Risk | Mitigation Strategy | Fallback State / Action | Automated Test Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **1. Network Flapping & Packet Loss** | Unstable cellular tower handoffs or weak home Wi-Fi signal causing intermittent packet drops (>15% packet loss) and rapid connect/disconnect cycles. | Evaluated in `app/risk_engine.py` via `telemetry.connectivity_status == 'FLAPPING'` or `telemetry.packet_loss > 15.0%`. | Abort OTA deployment instantly. Isolate device into safe mode. Prevent OTA binary corruption. | Immediately returns `UNTRUSTED_FALLBACK` / `NETWORK_FAILURE` status; blocks automated OTA transfer. | Firmware corruption mid-flash resulting in an unrecoverable hard-bricked device. | Enforce network stability check before payload dispatch; require link stability confirmation. | Set `fallback_status = 'UNTRUSTED_FALLBACK'`. Display *"Network unstable — Manual Field Dispatch required"*. | **PASSED** (`test_fallback_network_flapping_and_packet_loss`) |
| **2. Conflicting Governance Approvals** | IT Engineering approves patch rollout (`IT=True`), but Clinical Operations holds approval (`Clinical=False`) due to scheduled patient monitoring regimes. | Evaluated in `app/risk_engine.py` via `approval.it_approved != approval.clinical_ops_approved`. | Detect organizational governance conflict; freeze OTA deployment; do not remediate. | Returns `BLOCKED_APPROVAL` / `UNTRUSTED_FALLBACK`; logs discrepancy audit entry. | Applying updates during active patient monitoring windows, interrupting vital transmissions. | Mandate dual cryptographic sign-off (`IT=True AND Clinical=True`) before scheduling OTA slot. | Set `fallback_status = 'UNTRUSTED_FALLBACK'`. Display *"Blocked — conflicting maintenance approvals"*. | **PASSED** (`test_fallback_conflicting_maintenance_approvals`) |
| **3. Capacity Guardrail Exhaustion (>50 updates/hr)** | Simultaneous outbreak of critical CVE advisories flagging >50 devices for immediate firmware remediation. | Evaluated in `app/scheduler.py` via hourly slot bucket counter (`count < MAX_HOURLY_UPDATES = 50`). | Cap Slot 1 at exactly 50 devices. Automatically queue overflow devices into Hour 2, Hour 3, etc. | First 50 devices assigned to Hour 1; 51st device allocated to Hour 2. No slot ever exceeds 50. | Cellular carrier rate-limiting, local network congestion, and customer support desk overload. | Hard-coded strict slot threshold (50/hr); priority queue sorted by contextual risk score. | Assign overflow to `QUEUED` state in subsequent hour slots with explicit ETA and priority rank. | **PASSED** (`test_schedule_51_devices_overflow_guardrail`) |
| **4. Missing / Stale Telemetry (>48 Hours)** | Patient power disconnect, router change, or dead battery causing device daemon to drop offline for extended duration. | Evaluated in `app/risk_engine.py` via `(now - telemetry_last_seen) > 48h` or `version_drift_state == 'UNKNOWN'`. | Flag device as untrusted telemetry state; refuse blind OTA updates; require manual review. | Marks device in `UNTRUSTED_FALLBACK`; blocks OTA requests; logs stale duration. | Attempting blind OTA push to unreachable or unverified firmware baseline. | Stale telemetry threshold (48h); verify telemetry heartbeat before initiating flash sequence. | Set `fallback_status = 'UNTRUSTED_FALLBACK'`. Display *"Fallback — telemetry unavailable >48 hours"*. | **PASSED** (`test_fallback_missing_telemetry_over_48h`) |

---

## 3. Detailed Failure Scenario Walkthroughs

### 3.1 Network Flapping Walkthrough
* **Simulation:** Injected 38.5% packet loss on device `DEV-CARD-0012` located at *Rural Clinic Satellite-A*.
* **System Reaction:**
  1. Telemetry ingestion daemon tags connection as `FLAPPING`.
  2. `evaluate_device_risk()` appends `High packet loss (38.5% > 15% threshold): network link unstable` to fallback diagnostics.
  3. `remediation.py` halts execution and records audit log `NETWORK_FAILURE`.
  4. Operator UI renders warning badge: *"Blocked: Network unstable (Flapping/Packet Loss). Manual field dispatch required."*

### 3.2 Conflicting Approvals Walkthrough
* **Simulation:** Set `it_approved = True` and `clinical_ops_approved = False` on `DEV-OXIP-0044`.
* **System Reaction:**
  1. `evaluate_device_risk()` evaluates boolean XOR on approvals and asserts conflict.
  2. Fallback trigger activated: `Conflicting approvals: IT_Approved=True, Clinical_Ops_Approved=False`.
  3. Scheduler skips device during batch update generation.
  4. Operator UI displays: *"Blocked — conflicting maintenance approvals"*.

### 3.3 Capacity Guardrail Stress Test Walkthrough
* **Simulation:** 63 eligible devices submitted to batch scheduler simultaneously.
* **System Reaction:**
  1. Scheduler orders devices by priority weight: `(Risk Score * 10) + (Vulnerability bonus) + Version Lag`.
  2. Devices ranked 1 to 50 allocated to **Hour 1** (Utilization: 50/50, 100%).
  3. Devices ranked 51 to 63 allocated to **Hour 2** (Utilization: 13/50, 26%).
  4. 0 devices allocated above 50 limit in any single slot.

---

## 4. Verification and Audit Logging

Every fallback activation generates a durable record in the `remediations` database table with:
* `status`: Detailed reason code (`UNTRUSTED_FALLBACK`, `BLOCKED_APPROVAL`, `NETWORK_FAILURE`, `UNSUPPORTED_VERSION`)
* `fallback_triggered`: `True`
* `started_at` & `completed_at`: UTC Timestamps
* `error_message`: Complete human-readable technical rationale.
