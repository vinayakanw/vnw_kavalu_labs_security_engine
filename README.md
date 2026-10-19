# Kavalu Labs Security Engine

<div align="center">

![Platform](https://img.shields.io/badge/Platform-Web%20Security%20Engine-FF0000?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python)
![OWASP](https://img.shields.io/badge/OWASP-Top%2010%3A2021-orange?style=for-the-badge)
![License](https://img.shields.io/badge/License-Proprietary-black?style=for-the-badge)

**Automated Web Application Attack Surface Discovery, Vulnerability Assessment & Verification Platform**

[Official Portal](https://kavalu-labs.nayaka100.in/) · [Author Portfolio](https://www.nayaka100.in/)

</div>

---

> [!IMPORTANT]
> **Legal & Ethical Notice:** Kavalu Labs Security Engine is designed exclusively for authorized penetration testing, security auditing, and verification of systems that you own or have explicit written permission to assess. Unauthorized scanning of third-party networks is strictly prohibited.

---

## Overview

**Kavalu Labs Security Engine** is a high-assurance, automated web application security testing platform. It performs non-destructive attack-surface discovery, active vulnerability probes, TLS/cryptographic analysis, and security header evaluations against target domains.

Results are mapped directly to the **OWASP Top 10:2021** standard, evaluated with an explainable 0–100 risk scoring algorithm, and compiled into a single print-ready **Executive PDF** audit deliverable.

---

## Key Features

- **Multi-Vector Modular Probing:** 6 independent scanning modules selectable per engagement:
  - **Reconnaissance & Attribution:** Target hosting, IP resolution, ASN, web server headers, and public developer attribution discovery.
  - **OWASP Top 10 Injection Probes:** Active, non-destructive SQL Injection (SQLi), Cross-Site Scripting (XSS), Command Injection, Host-Header Injection, and Open Redirect checks.
  - **SSL / TLS Cryptography:** Live socket inspection verifying certificate validity, expiry, supported TLS protocols, cipher suites, and HSTS enforcement.
  - **Modern Browser Automation (DOM / SPA):** Headless browser simulation evaluating client-side DOM rendering, console security violations, and Single Page Application state.
  - **Misconfiguration & Secret Leaks:** Probing for exposed `.git`, `.env`, backup files, dangerous HTTP methods, CORS wildcards, missing security headers, and cookie flag weaknesses (`Secure`, `HttpOnly`, `SameSite`).
  - **Burp Suite Proxy Integration:** Optional upstream HTTP proxy bridging to Burp Suite Professional / Community for centralized traffic capture.
- **Explainable Risk Scoring:** Computes a reproducible 0–100 risk score and letter grade (A through F) with diminishing returns per repeated vulnerability severity (`Critical: 40`, `High: 22`, `Medium: 10`, `Low: 4`).
- **OWASP Top 10:2021 Mapping:** Every detected finding is classified under its canonical OWASP category (`A01`–`A10`) and associated with Common Weakness Enumeration (CWE) identifiers.
- **Multi-Tenant Client Privacy:** Scan history is stored entirely in the visitor's local browser storage (`localStorage`). The backend never exposes a global scan history across users — it only keeps a per-scan state file (in `logs/scan_state/`) so a finished scan can still be re-rendered into a PDF report.
- **Real-Time Telemetry:** Live scan status is pushed via Server-Sent Events (SSE) with an automatic polling fallback.
- **Enterprise Audit Deliverable — Executive PDF Report:** The single report format the engine produces. It is written to the `reports/` directory and contains the risk score, OWASP coverage matrix, target attribution, verified findings with evidence and remediation, and a prioritized remediation roadmap. No HTML or JSON report file is ever written to disk.

---

## Architecture & Codebase Structure

```text
kavalu_labs_security_engine/
├── app.py                      # Flask application, CORS setup, REST & SSE streaming endpoints
├── index.html                  # Cyber-themed operational dashboard and client-side application
├── requirements.txt            # Python dependencies (Flask, Requests, Selenium, ReportLab, etc.)
├── core/
│   ├── scanner.py              # Central scan orchestrator, domain pre-validation & status manager
│   ├── vulnerability_scanner.py# Active OWASP injection probes, secret leaks & misconfig checks
│   ├── tls_scanner.py          # Direct TLS socket inspector, certificate validator & protocol checker
│   ├── recon_attribution.py    # Infrastructure, DNS, ASN, geolocation & metadata discovery
│   ├── selenium_scanner.py     # Headless browser automation for client-side DOM & console auditing
│   ├── burp_integration.py     # Upstream HTTP/HTTPS proxy integration for Burp Suite
│   ├── detection_engine.py     # Weighted risk scoring engine & letter grade computation
│   ├── owasp_mapping.py        # Canonical OWASP Top 10:2021 definitions & CWE mapping
│   ├── report_generator.py     # ReportLab PDF engine (the only report format)
│   ├── paths.py                # Central filesystem layout (reports / scan-state / logs)
│   └── plugin_model.py         # Extensible hook for external ML model verification endpoints
├── reports/                    # Deliverable output directory — PDF reports ONLY
└── logs/                       # Runtime logs and internal per-scan state (not deliverables)
    └── scan_state/             # One JSON state file per scan (engine bookkeeping)
```

---

## Quick Start

### 1. Prerequisites
- **Python 3.10+**
- *(Optional)* Google Chrome & ChromeDriver (for headless browser DOM analysis)
- *(Optional)* Burp Suite (if routing traffic through an upstream proxy)

### 2. Installation

Clone or download the repository, then install required dependencies:

```bash
cd kavalu_labs_security_engine
pip install -r requirements.txt
```

### 3. Launching the Engine

Start the local security engine server:

```bash
python app.py
```

Open your web browser and navigate to:
```text
http://127.0.0.1:5000
```

---

## API Reference

The engine provides a clean RESTful and streaming interface:

| Endpoint | Method | Description |
|---|---|---|
| `/` | `GET` | Serves the web-based interactive security dashboard |
| `/api/scan` | `POST` | Initiates a security audit. Accepts JSON: `{"url": "...", "scan_types": ["recon", "owasp", "tls", "browser", "misconfig", "burp"]}` |
| `/api/scan/status/<scan_id>` | `GET` | Retrieves current scan state, progress percentage, findings, risk score, and attribution |
| `/api/scan/stream/<scan_id>` | `GET` | Server-Sent Events (SSE) live progress stream |
| `/api/report/<scan_id>` | `GET` | Downloads the Executive PDF audit report. Query parameter: `?format=pdf` (default and only supported format; any other value returns `400`) |
| `/api/owasp-top10` | `GET` | Returns canonical OWASP Top 10:2021 reference metadata and categories |
| `/api/history` | `GET` | Returns scan history (returns `[]` on server; history is securely isolated to browser `localStorage`) |

---

## OWASP Top 10:2021 Coverage

| Code | Category | Automated Detection Coverage |
| :---: | :--- | :--- |
| **A01:2021** | **Broken Access Control** | Exposed `.git`/`.env` repositories, administrative path discovery, CORS wildcard misconfigurations, dangerous HTTP verbs, and unvalidated open redirects. |
| **A02:2021** | **Cryptographic Failures** | TLS protocol obsolescence (SSLv3, TLS 1.0/1.1), expired/untrusted certificates, weak cipher suites, missing HSTS, and missing `Secure` cookie attributes. |
| **A03:2021** | **Injection** | Reflected Cross-Site Scripting (XSS), SQL error/boolean heuristic probes, Host-Header injection, Command Injection probes, and client-side DOM sinks. |
| **A04:2021** | **Insecure Design** | Evaluated via architecture reconnaissance; flagged for manual threat modeling where business-logic controls are required. |
| **A05:2021** | **Security Misconfiguration** | Missing HTTP defense headers (`CSP`, `X-Content-Type-Options`, `X-Frame-Options`), server banner disclosures, and verbose debug stack traces. |
| **A06:2021** | **Vulnerable & Outdated Components**| Identification of outdated client-side JavaScript libraries and disclosed third-party framework versions. |
| **A07:2021** | **Identification & Authentication** | Weak cookie parameters (`SameSite`, `HttpOnly`), unencrypted credentials in forms, and basic session hygiene. |
| **A08:2021** | **Software & Data Integrity** | Detection of externally loaded scripts lacking Subresource Integrity (`integrity`/`crossorigin` attributes). |
| **A09:2021** | **Security Logging & Monitoring** | Monitored through server error disclosure handling and response behaviors. |
| **A10:2021** | **Server-Side Request Forgery (SSRF)**| Active heuristics identifying request parameters that accept external URLs and webhooks. |

---

## Risk Scoring Methodology

The platform calculates risk deterministically using a weighted scoring model:

$$\text{Score} = \min\left(100, \sum \text{BaseWeight} \times 0.6^n\right)$$

- **Base Weights:**
  - `Critical`: **40 points**
  - `High`: **22 points**
  - `Medium`: **10 points**
  - `Low`: **4 points**
  - `Info`: **0 points**
- **Diminishing Returns:** Each subsequent finding of the same severity tier scales down by a decay factor ($0.6^n$), preventing duplicate low-risk alerts from overshadowing major vulnerabilities.
- **Letter Grades:**
  - **A (0–15):** Secure / Minimal Risk
  - **B (16–35):** Low Risk / Good Posture
  - **C (36–55):** Moderate Risk / Attention Needed
  - **D (56–75):** High Risk / Immediate Review
  - **F (76–100):** Critical Vulnerabilities Detected

---

## Author & Platform Attribution

- **Platform:** [Kavalu Labs Security Engine](https://kavalu-labs.nayaka100.in/)
- **Author:** [Vinayaka N Walshettar](https://www.nayaka100.in/)
- **Organization:** Kavalu Labs
