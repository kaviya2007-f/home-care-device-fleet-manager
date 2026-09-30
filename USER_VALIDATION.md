# User & Stakeholder Validation Report

> **CRITICAL DISCLAIMER:** *Operational device support only — this system does not provide medical advice or clinical recommendations.*
> 
> **NOTICE ON VALIDATION METHODOLOGY:** *The following section represents a structured **Prototype validation / simulated stakeholder walkthrough** designed to evaluate operational usability, governance transparency, and interface clarity.*

---

## 1. Validation Objectives

The simulated walkthrough evaluated six critical operational competencies of the fleet monitoring interface:
1. **Vulnerability Identification:** Can operators quickly locate devices affected by active CVE advisories?
2. **Explainable Risk Formulation:** Do stakeholders understand why a device received its risk score?
3. **Safe Fallback Transparency:** Are fallback reasons (missing telemetry, flapping, approval conflict) immediately obvious?
4. **Capacity Guardrails:** Is the 50 updates/hour limit transparently communicated and enforced?
5. **Medical vs. Operational Boundary:** Is the distinction between operational device maintenance and clinical medical advice clear?
6. **Field Dispatch Triggers:** Can operators easily determine when physical technician intervention is mandatory?

---

## 2. Structured Stakeholder Walkthrough Feedback Matrix

| Participant / Simulated Role | Operational Task Evaluated | Observed Issue / Friction Point | Stakeholder Feedback | Severity | Resolution & Implementation in Prototype |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Fleet Operations Engineer** | Identify all devices affected by CVE-2026-4401 on Cellular Direct. | Filtering through 500+ rows initially felt cumbersome without multi-criteria filters. | *"Provide simultaneous filtering across Device Model, Risk Category, and Network Topology."* | Medium | Implemented interactive multi-select filters in `dashboard.py` (Tab 2) with instant count updates. |
| **Clinical Operations Coordinator** | Review pending maintenance approvals and check if active patient sessions are impacted. | Initial mockup did not clearly state that the tool does not provide clinical guidance. | *"Must have an unambiguous disclaimer on every tab stating this is strictly device hardware/firmware support."* | High | Added persistent gold top banner: *"Operational device support only — this system does not provide medical advice or clinical recommendations."* |
| **IT Security Analyst** | Verify how CVSS 8.8 translates to a final risk score of 10.0 for cellular devices. | Formula steps were buried in tooltips in early concept designs. | *"Display the exact mathematical formula steps: Base CVSS × Network Multiplier + Version Lag Penalty."* | Medium | Built the **Explainable Risk Scoring Engine Inspector** showing step-by-step LaTeX formula and parameter breakdown. |
| **Field Service Dispatcher** | Triage a batch of devices flagged with network flapping and stale telemetry. | Confusion over whether clicking 'Remediate' would attempt a risky remote update. | *"Disallow the 'Remediate' button entirely for fallback devices; replace it with 'Manual Field Dispatch Required'."* | Critical | Hard-coded strict UI and API guardrails: when `fallback_status != 'NONE'`, automatic remediation is disabled and replaced with *"🚚 Request Manual Field Dispatch"*. |
| **Network & Infrastructure Lead** | Schedule 70 eligible updates and verify carrier rate-limiting compliance. | Needed visual confirmation that cellular slots would not exceed carrier threshold. | *"Show used vs remaining capacity per hour slot (e.g. 50/50 used, 20 queued in Hour 2)."* | High | Built the **Capacity Utilization Table & Visualizer** showing exact slot capacity (50 max) and queued distribution. |
| **Compliance Officer** | Audit historical remediation decisions and verify approval governance. | Wanted proof that unapproved devices could never be updated by accident. | *"Ensure an audit log records who approved the maintenance window and all fallback block reasons."* | High | Implemented persistent `remediations` audit table logging `status`, `error_message`, timestamps, and fallback flags. |

---

## 3. Key Findings & Usability Validation Checklist

- [x] **100% of roles** successfully distinguished operational fleet support from clinical decision making.
- [x] **Explainable risk score** enabled security analysts to verify cellular exposure multipliers without reading backend code.
- [x] **Safe Fallback state** eliminated accidental attempts to flash firmware over unstable connections.
- [x] **Capacity visualizer** gave operations immediate visibility into multi-hour rollout timelines without exceeding the 50-device hourly ceiling.
