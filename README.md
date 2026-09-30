# Home-Care Device Fleet Monitoring & Firmware Governance Prototype

> ⚠️ **CRITICAL OPERATIONAL DISCLAIMER:**  
> **Operational device support only — this system does not provide medical advice or clinical recommendations.**

---

## 1. Problem Statement
Home-care healthcare providers lend remote physiological monitoring devices (e.g., pulse oximeters, ECG monitors, IoT telemetry gateways) to patients. Because these devices operate on varied remote networks (cellular, home Wi-Fi, clinic subnets), firmware version tracking is frequently inconsistent. This creates significant operational risks:
* Inability to rapidly identify unsupported or vulnerable devices affected by active CVEs.
* Disagreements between IT Engineering and Clinical Operations regarding maintenance windows.
* Dangerous attempts to flash firmware over unstable or flapping connections, risking device bricking.
* Exceeding cellular carrier bandwidth capacity during uncoordinated mass rollouts.

---

## 2. Objective
This project implements a field-ready, production-grade operational prototype that continuously ingests telemetry, tracks version drift, calculates contextual CVSS risk scores, detects governance approval conflicts, enforces safe fallbacks, and executes capacity-aware batch remediation.

---

## 3. Architecture & Repository Structure
```
HOME CARE DEVICE MANAGER/
│
├── app/
│   ├── __init__.py           # Package initialization & operational disclaimer
│   ├── config.py             # System thresholds, capacity limits, network multipliers
│   ├── database.py           # SQLAlchemy engine, session lifecycle, table init
│   ├── models.py             # SQLAlchemy models (Device, Advisory, Approval, Telemetry, etc.)
│   ├── schemas.py            # Pydantic v2 data models for API requests/responses
│   ├── risk_engine.py        # Formal mathematical risk formula & fallback detector
│   ├── scheduler.py          # Capacity-aware batch scheduler (<= 50 updates/hr)
│   ├── remediation.py        # Remediation execution workflow & safety verification
│   ├── telemetry.py          # Telemetry ingestion daemon & failure simulators
│   └── main.py               # FastAPI backend application & REST endpoints
│
├── dashboard.py              # Full-featured Streamlit operational dashboard
├── data_generator.py         # Synthetic generator seeding 500+ realistic devices
├── experiment_analysis.py    # Benchmark engine comparing Baseline vs. Contextual Engine
├── requirements.txt          # Pinned project dependencies
├── run.sh                    # Linux/macOS/Bash execution script
├── run.py                    # Cross-platform Python execution script
├── schema.sql                # SQL DDL matching SQLAlchemy schema
├── README.md                 # Complete technical guide & quickstart
├── TECHNICAL_DOCUMENTATION.md# System architecture, formal equations, workflows
├── FAILURE_MODE_ANALYSIS.md  # Detailed failure mode analysis & mitigations matrix
├── USER_VALIDATION.md        # Simulated stakeholder walkthrough & usability validation
├── EXPERIMENT_RESULTS.md     # Empirical experiment benchmark results
├── experiment_error_analysis.csv  # Itemized discrepancy report
├── experiment_error_analysis.json # Structured discrepancy export
│
└── tests/
    ├── test_risk_engine.py   # Unit tests for CVSS, multipliers, and lag penalties
    ├── test_fallback.py      # Unit tests for 4 safe fallback triggers
    ├── test_scheduler.py     # Unit tests for 50 updates/hr capacity limits
    ├── test_api.py           # Integration tests for FastAPI endpoints
    └── test_end_to_end.py    # Complete end-to-end lifecycle integration test
```

---

## 4. Formal Mathematical Risk Formulation
The risk engine calculates an explainable risk score for every device in the fleet:

$$\mathbf{\text{Final Risk Score}} = \min\left(10.0, (\text{CVSS Base Score} \times \text{Network Multiplier}) + \text{Version Lag Penalty}\right)$$

### Parameters:
1. **CVSS Base Score $\in [0.0, 10.0]$**: Extracted from active security advisories matching device model and affected version.
2. **Network Multiplier**:
   * **Cellular Direct = 1.2** (Exposed public cellular network)
   * **Home Wi-Fi NAT = 1.0** (Standard residential NAT)
   * **Hospital Subnet = 0.8** (Secured clinical network)
3. **Version Lag Penalty**: $\min(2.0, \text{Versions Behind} \times 0.5)$
4. **Risk Classification**:
   * `[0.0, 3.0]` $\rightarrow$ **LOW**
   * `(3.0, 6.0]` $\rightarrow$ **MEDIUM**
   * `(6.0, 8.0]` $\rightarrow$ **HIGH**
   * `(8.0, 10.0]` $\rightarrow$ **CRITICAL**

---

## 5. Safe Fallback Guardrails (`UNTRUSTED_FALLBACK`)
Automated OTA remediation is immediately halted if any of these deterministic safety triggers fire:
* **Missing Telemetry:** Last telemetry reported $>48$ hours ago or drift state is `UNKNOWN`.
* **Conflicting Approvals:** Disagreement between IT and Clinical Operations (`IT_Approved != Clinical_Approved`).
* **Network Flapping / Instability:** Connection status is `FLAPPING` or packet loss exceeds $15.0\%$.

When triggered, the device is isolated in `UNTRUSTED_FALLBACK` mode and the UI prompts for **Manual Field Dispatch**.

---

## 6. Capacity Limit Guardrail
* **Maximum OTA Updates = 50 devices per hour slot.**
* Batch scheduler allocates devices sequentially into hourly slots based on descending risk priority.
* Under no circumstances can any slot exceed 50 updates.

---

## 7. Installation & Quickstart

### Prerequisites
* Python 3.10+ (Tested on Python 3.11)

### Setup & Run
```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Seed database with 500+ realistic devices
python data_generator.py

# 3. Run empirical baseline benchmark analysis
python experiment_analysis.py

# 4. Run automated test suite
python -m pytest tests/ -v

# 5. Start the complete application
python run.py
```
*(Or use `./run.sh` on Unix/Bash environments).*

---

## 8. Service URLs
* **FastAPI Backend:** [http://localhost:8000](http://localhost:8000)
* **Interactive Swagger UI:** [http://localhost:8000/docs](http://localhost:8000/docs)
* **Streamlit Operational Dashboard:** [http://localhost:8501](http://localhost:8501)

---

## 9. Empirical Experiment Benchmark Summary

| Metric | Simple Version-Matching Baseline | Contextual Risk Engine (Prototype) | Difference |
| :--- | :--- | :--- | :--- |
| **Unnecessary Field Dispatches Avoided** | 0 | 187 | **+187 avoided** |
| **MTTR (Critical Assets)** | 4.06 hrs | 1.00 hrs | **-3.06 hrs** |
| **Remediation Accuracy** | 45.48% | 100.0% | **+54.52%** |
| **False Positive Rate** | 69.39% | 0.0% | **-69.39%** |
| **Fallback Detection Accuracy** | 0.0% | 100.0% | **+100.0%** |
| **Capacity Compliance (<=50/hr)** | 0.0% | 100.0% | **+100.0%** |

*(Full details in [EXPERIMENT_RESULTS.md](file:///c:/Users/fdkav/OneDrive/%E6%96%87%E4%BB%B6/HOME%20CARE%20DEVICE%20MANAGER/EXPERIMENT_RESULTS.md)).*

---

## 10. Limitations & Future Roadmap
* **Simulated OTA Execution:** Demonstrates end-to-end governance and safety checks using deterministic simulation; physical hardware flashing is not performed.
* **Database:** SQLite is used for prototype portability. Production deployments should utilize PostgreSQL with high availability.
* **Authentication:** Future iterations should add mTLS hardware device certificates and OAuth2/SAML RBAC for hospital personnel.
