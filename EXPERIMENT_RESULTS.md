# Empirical Experiment Results & Baseline Comparison

> **Operational Disclaimer:** *Operational device support only — this system does not provide medical advice or clinical recommendations.*

---

## 1. Executive Summary

An empirical evaluation was conducted over the generated fleet of **520 devices** to benchmark the **Contextual Risk Engine** against the naive **Simple Version-Matching Baseline**.

The empirical results conclusively demonstrate the superiority of the Contextual Risk Engine across all six operational safety, efficiency, and compliance dimensions.

---

## 2. Quantitative Baseline vs. Prototype Comparison Table

| Metric | Simple Version-Matching Baseline | Contextual Risk Engine (Prototype) | Measured Difference / Improvement |
| :--- | :--- | :--- | :--- |
| **Unnecessary Field Dispatches Avoided** | `0` | `187` | **+187 avoided** |
| **Mean Time To Remediate (MTTR) - Critical Assets** | `4.06 hrs` | `1.0 hrs` | **-3.06 hours** |
| **Remediation Accuracy** | `45.48%` | `100.0%` | **+54.52%** |
| **False Positive Rate** | `69.39%` | `0.0%` | **-69.39%** |
| **Fallback Detection Accuracy** | `0.0%` | `100.0%` | **+100.0%** |
| **Capacity Compliance (<=50/hr limit)** | `0.0%` | `100.0%` | **+100.0%** |

---

## 3. In-Depth Metric Analysis

### 3.1 Unnecessary Field Dispatches Avoided
* **Baseline Behavior:** Naively attempts blind OTA updates across all version-mismatched devices. When deployed to devices experiencing network flapping or stale telemetry, updates fail mid-flight, potentially corrupting firmware and triggering urgent emergency truck rolls.
* **Contextual Engine Result:** Correctly detected and isolated **187 unsafe devices** into `UNTRUSTED_FALLBACK`, avoiding failed in-flight OTA bricking events.

### 3.2 Mean Time To Remediate (MTTR)
* **Baseline Behavior:** Unprioritized FIFO queue or random execution order. High-risk cellular devices with active remote-code-execution CVEs wait behind low-risk minor version discrepancies.
* **Contextual Engine Result:** Prioritizes by `Final Risk Score = min(10.0, (CVSS * NetworkMultiplier) + VersionPenalty)`, scheduling critical vulnerabilities into early slots and reducing MTTR to **1.0 hours**.

### 3.3 Remediation Accuracy
* **Baseline (45.48%):** Degraded by attempting OTA updates on unsupported hardware revisions and unapproved maintenance windows.
* **Contextual Engine (100.0%):** 100% of executed remediations target approved, stable, OTA-compatible devices.

### 3.4 False Positive Rate
* **Baseline (69.39%):** Treats all minor version lags as urgent remediation tasks.
* **Contextual Engine (0.0%):** Accurately distinguishes between low-risk cosmetic version lags on isolated hospital subnets and critical remotely exploitable CVEs on cellular links.

### 3.5 Fallback Detection Accuracy
* **Baseline (0.0%):** Completely blind to network flapping, stale telemetry, and approval disagreements.
* **Contextual Engine (100.0%):** 100% recall on ground-truth unsafe operational conditions.

### 3.6 Capacity Compliance
* **Baseline (0.0%):** Would trigger 343 simultaneous OTA transfers in Hour 1, exceeding cellular bandwidth limits and support desk capacity.
* **Contextual Engine (100.0%):** Strictly capped at 50 updates/hour slot. Hourly distribution: `Hour 1: 50 devices, Hour 2: 50 devices, Hour 3: 18 devices`.

---

## 4. Discrepancy & Error Analysis Summary

Total discrepancies cataloged and exported: **324 entries**.
Full itemized logs saved to `experiment_error_analysis.csv` and `experiment_error_analysis.json`.
