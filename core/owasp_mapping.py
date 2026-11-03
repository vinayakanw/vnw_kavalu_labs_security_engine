"""OWASP Top 10:2021 categories and the mapping from finding types to them.

``TYPE_TO_OWASP`` maps every finding ``type`` the engine can emit to an OWASP
category and CWE identifiers. This module is plain data plus lookups, with no
network calls, so the scanner, the scoring and the reports can all use it safely.
"""

__author__ = "Kavalu Labs"

from typing import Dict, List, Any

# ---------------------------------------------------------------------------
# Canonical OWASP Top 10:2021 categories
# ---------------------------------------------------------------------------
OWASP_TOP_10 = {
    "A01": {
        "code": "A01:2021",
        "name": "Broken Access Control",
        "short": "Access Control",
        "description": (
            "Restrictions on what authenticated or anonymous users are allowed to do are not properly enforced."
        ),
    },
    "A02": {
        "code": "A02:2021",
        "name": "Cryptographic Failures",
        "short": "Cryptography",
        "description": (
            "Failures related to cryptography (or lack of it), which often lead "
            "to exposure of sensitive data in transit or at rest."
        ),
    },
    "A03": {
        "code": "A03:2021",
        "name": "Injection",
        "short": "Injection",
        "description": (
            "User-supplied data is not validated, filtered, or sanitized, "
            "allowing hostile data to be interpreted as part of a command or query."
        ),
    },
    "A04": {
        "code": "A04:2021",
        "name": "Insecure Design",
        "short": "Insecure Design",
        "description": (
            "Missing or ineffective control design — risks that no amount of implementation-level fixing will resolve."
        ),
    },
    "A05": {
        "code": "A05:2021",
        "name": "Security Misconfiguration",
        "short": "Misconfiguration",
        "description": (
            "Missing hardening, unnecessary features enabled, default accounts, "
            "overly informative error messages, or misconfigured headers."
        ),
    },
    "A06": {
        "code": "A06:2021",
        "name": "Vulnerable and Outdated Components",
        "short": "Outdated Components",
        "description": (
            "Using components (libraries, frameworks, server software) with "
            "known vulnerabilities or that are out of date / unsupported."
        ),
    },
    "A07": {
        "code": "A07:2021",
        "name": "Identification and Authentication Failures",
        "short": "Auth Failures",
        "description": (
            "Confirmation of user identity, authentication, and session management is implemented incorrectly."
        ),
    },
    "A08": {
        "code": "A08:2021",
        "name": "Software and Data Integrity Failures",
        "short": "Integrity Failures",
        "description": (
            "Code and infrastructure that does not protect against integrity "
            "violations, such as unsigned/unverified updates or scripts."
        ),
    },
    "A09": {
        "code": "A09:2021",
        "name": "Security Logging and Monitoring Failures",
        "short": "Logging & Monitoring",
        "description": (
            "Insufficient logging, detection, monitoring, and active response "
            "that would allow breaches to be detected and contained."
        ),
    },
    "A10": {
        "code": "A10:2021",
        "name": "Server-Side Request Forgery (SSRF)",
        "short": "SSRF",
        "description": (
            "A web application fetches a remote resource without validating "
            "the user-supplied URL, letting an attacker coerce requests."
        ),
    },
}

# ---------------------------------------------------------------------------
# finding['type'] -> (OWASP key, [CWE ids])
# Every scanner module should emit a 'type' present in this table so results
# roll up into the coverage matrix. Unknown types fall back to 'A05'.
# ---------------------------------------------------------------------------
TYPE_TO_OWASP: Dict[str, Dict[str, Any]] = {
    # --- A01: Broken Access Control ---
    "missing_csrf": {"owasp": "A01", "cwe": ["CWE-352"]},
    "csrf": {"owasp": "A01", "cwe": ["CWE-352"]},
    "open_redirect": {"owasp": "A01", "cwe": ["CWE-601"]},
    "exposed_path": {"owasp": "A01", "cwe": ["CWE-538", "CWE-200"]},
    "directory_listing": {"owasp": "A01", "cwe": ["CWE-548"]},
    "cors_misconfiguration": {"owasp": "A01", "cwe": ["CWE-942"]},
    "clickjacking": {"owasp": "A01", "cwe": ["CWE-1021"]},
    "http_method": {"owasp": "A01", "cwe": ["CWE-650"]},
    "admin_path_exposed": {"owasp": "A01", "cwe": ["CWE-284"]},
    "path_traversal": {"owasp": "A01", "cwe": ["CWE-22"]},
    "lfi": {"owasp": "A01", "cwe": ["CWE-22"]},
    # --- A02: Cryptographic Failures ---
    "tls_version": {"owasp": "A02", "cwe": ["CWE-326"]},
    "tls_certificate": {"owasp": "A02", "cwe": ["CWE-295"]},
    "tls_cipher": {"owasp": "A02", "cwe": ["CWE-327"]},
    "no_https": {"owasp": "A02", "cwe": ["CWE-319"]},
    "mixed_content": {"owasp": "A02", "cwe": ["CWE-319"]},
    "insecure_cookie": {"owasp": "A02", "cwe": ["CWE-614", "CWE-1004"]},
    "hsts": {"owasp": "A02", "cwe": ["CWE-319"]},
    "insecure_form": {"owasp": "A02", "cwe": ["CWE-319"]},
    # --- A03: Injection ---
    "xss": {"owasp": "A03", "cwe": ["CWE-79"]},
    "sql_injection": {"owasp": "A03", "cwe": ["CWE-89"]},
    "host_header_injection": {"owasp": "A03", "cwe": ["CWE-644"]},
    "command_injection": {"owasp": "A03", "cwe": ["CWE-78"]},
    "template_injection": {"owasp": "A03", "cwe": ["CWE-1336"]},
    "dom_xss": {"owasp": "A03", "cwe": ["CWE-79"]},
    # --- A04: Insecure Design ---
    "rate_limiting": {"owasp": "A04", "cwe": ["CWE-307"]},
    "insecure_design": {"owasp": "A04", "cwe": ["CWE-657"]},
    # --- A05: Security Misconfiguration ---
    "security_header": {"owasp": "A05", "cwe": ["CWE-16"]},
    "debug_exposure": {"owasp": "A05", "cwe": ["CWE-489", "CWE-209"]},
    "server_fingerprint": {"owasp": "A05", "cwe": ["CWE-200"]},
    "info_disclosure": {"owasp": "A05", "cwe": ["CWE-200"]},
    "error": {"owasp": "A05", "cwe": ["CWE-209"]},
    "misconfiguration": {"owasp": "A05", "cwe": ["CWE-16"]},
    # --- A06: Vulnerable and Outdated Components ---
    "outdated_component": {"owasp": "A06", "cwe": ["CWE-1104", "CWE-937"]},
    "vulnerable_library": {"owasp": "A06", "cwe": ["CWE-1104", "CWE-937"]},
    "missing_sri": {"owasp": "A08", "cwe": ["CWE-494"]},
    # --- A07: Identification and Authentication Failures ---
    "weak_auth": {"owasp": "A07", "cwe": ["CWE-287"]},
    "session_management": {"owasp": "A07", "cwe": ["CWE-613"]},
    "default_credentials": {"owasp": "A07", "cwe": ["CWE-521", "CWE-798"]},
    # --- A08: Software and Data Integrity Failures ---
    "subresource_integrity": {"owasp": "A08", "cwe": ["CWE-494"]},
    "unsigned_update": {"owasp": "A08", "cwe": ["CWE-494"]},
    # --- A09: Security Logging and Monitoring Failures ---
    "logging_monitoring": {"owasp": "A09", "cwe": ["CWE-778"]},
    # --- A10: Server-Side Request Forgery ---
    "ssrf_candidate": {"owasp": "A10", "cwe": ["CWE-918"]},
    # --- Informational / non-OWASP findings (attribution, recon, browser) ---
    "deployment_infrastructure": {"owasp": None, "cwe": []},
    "developer_identity": {"owasp": None, "cwe": []},
    "info": {"owasp": None, "cwe": []},
    "browser_automation": {"owasp": None, "cwe": []},
    "external_model": {"owasp": None, "cwe": []},
    "burp": {"owasp": None, "cwe": []},
}


def classify(finding_type: str) -> Dict[str, Any]:
    """Return {'owasp': 'A03', 'owasp_name': 'Injection', 'cwe': [...]} for a finding type.

    Falls back to A05 (Security Misconfiguration) — the OWASP catch-all for
    generic hardening issues — for any unrecognized type, and to None for
    types explicitly marked informational-only.
    """
    entry = TYPE_TO_OWASP.get(finding_type)
    if entry is None:
        entry = {"owasp": "A05", "cwe": []}

    owasp_key = entry.get("owasp")
    if owasp_key is None:
        return {"owasp": None, "owasp_code": None, "owasp_name": None, "cwe": entry.get("cwe", [])}

    cat = OWASP_TOP_10[owasp_key]
    return {
        "owasp": owasp_key,
        "owasp_code": cat["code"],
        "owasp_name": cat["name"],
        "cwe": entry.get("cwe", []),
    }


def tag_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Mutate-and-return a finding dict, adding owasp/cwe metadata in place."""
    info = classify(finding.get("type", ""))
    finding["owasp"] = info["owasp"]
    finding["owasp_code"] = info["owasp_code"]
    finding["owasp_name"] = info["owasp_name"]
    finding["cwe"] = info["cwe"]
    return finding


def build_coverage_matrix(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Build the OWASP Top 10 coverage matrix used by the UI and the report.

    Every one of the 10 categories is always present in the output (even with
    zero findings) so the report can show "tested, no issues" vs "not
    applicable" vs "issues found" for each category.
    """
    buckets: Dict[str, List[Dict[str, Any]]] = {k: [] for k in OWASP_TOP_10}

    for f in findings:
        owasp_key = f.get("owasp")
        if not owasp_key:
            info = classify(f.get("type", ""))
            owasp_key = info["owasp"]
        if owasp_key and owasp_key in buckets:
            buckets[owasp_key].append(f)

    matrix = []
    for key, cat in OWASP_TOP_10.items():
        items = buckets[key]
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in items:
            sev = f.get("severity", "info")
            if sev in counts:
                counts[sev] += 1

        actionable = counts["critical"] + counts["high"] + counts["medium"] + counts["low"]
        if counts["critical"] > 0:
            status = "critical"
        elif counts["high"] > 0:
            status = "high"
        elif counts["medium"] or counts["low"]:
            status = "attention"
        elif items:
            status = "clear"
        else:
            status = "not_tested"

        matrix.append(
            {
                "key": key,
                "code": cat["code"],
                "name": cat["name"],
                "short": cat["short"],
                "description": cat["description"],
                "counts": counts,
                "total_findings": len(items),
                "actionable_findings": actionable,
                "status": status,
            }
        )

    return matrix
