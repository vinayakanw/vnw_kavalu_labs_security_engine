"""Risk scoring: a 0-100 score, a letter grade and a breakdown for a list of findings.

This is a fixed, documented formula (see docs/architecture.md), not a
machine-learning model. The same findings always give the same score, and every
point of the score can be traced back to a finding.
"""

__author__ = "Kavalu Labs"

from typing import Dict, List, Any

# Base severity weights (impact), 0-100 scale contribution per finding before
# diminishing returns is applied.
SEVERITY_WEIGHT = {
    "critical": 40,
    "high": 22,
    "medium": 10,
    "low": 4,
    "info": 0,
}

# Grade bands for the overall 0-100 risk score (higher score = worse).
GRADE_BANDS = [
    (80, "F", "Critical Risk"),
    (60, "D", "High Risk"),
    (40, "C", "Elevated Risk"),
    (20, "B", "Moderate Risk"),
    (0, "A", "Low Risk"),
]


def _grade_for_score(score: float) -> Dict[str, str]:
    for threshold, grade, label in GRADE_BANDS:
        if score >= threshold:
            return {"grade": grade, "label": label}
    return {"grade": "A", "label": "Low Risk"}


def score_findings(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Compute an overall risk score (0-100), letter grade, and a
    finding-by-finding explainable contribution list.

    Diminishing returns: the Nth finding of the same severity contributes
    less than the first, so ten "low" findings don't outweigh one
    "critical" the way naive summation would — mirroring how a human
    triager reads a long tail of minor issues.
    """
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    contributions = []
    raw_total = 0.0

    # Track how many of each severity we've already scored, for the decay.
    seen_of_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    for f in findings:
        sev = f.get("severity", "info")
        if sev not in SEVERITY_WEIGHT:
            sev = "info"
        severity_counts[sev] += 1

        base = SEVERITY_WEIGHT[sev]
        if base == 0:
            contributions.append({"title": f.get("title", "Finding"), "severity": sev, "contribution": 0.0})
            continue

        n = seen_of_severity[sev]
        decay = 0.6**n  # each additional same-severity finding counts for 60% of the prior one
        contribution = round(base * decay, 2)
        seen_of_severity[sev] += 1

        raw_total += contribution
        contributions.append(
            {
                "title": f.get("title", "Finding"),
                "severity": sev,
                "contribution": contribution,
            }
        )

    score = min(100.0, round(raw_total, 1))
    grading = _grade_for_score(score)

    contributions.sort(key=lambda c: c["contribution"], reverse=True)

    return {
        "score": score,
        "grade": grading["grade"],
        "label": grading["label"],
        "severity_counts": severity_counts,
        "top_contributors": [c for c in contributions if c["contribution"] > 0][:10],
        "methodology": (
            "Weighted severity scoring with diminishing returns per repeated "
            "severity (critical=40, high=22, medium=10, low=4, info=0; each "
            "additional finding of the same severity contributes 60% of the "
            "previous one). Deterministic and fully reproducible from the "
            "finding list — not a black-box model."
        ),
    }


def summarize_engine_modules(scan_types: List[str], used_external_model: bool) -> List[Dict[str, Any]]:
    """Describe which detection modules actually ran, for the report's
    'Engine & Methodology' section — keeps the report honest about what was
    and wasn't executed for a given scan.
    """
    modules = [
        {
            "name": "Recon & Attribution",
            "ran": ("recon" in scan_types or "all" in scan_types),
            "description": "Deployment platform, hosting, and public developer-attribution discovery.",
        },
        {
            "name": "OWASP Top 10 Injection Audit",
            "ran": ("owasp" in scan_types or "vulnerabilities" in scan_types or "all" in scan_types),
            "description": "Active non-destructive SQLi, XSS, Command Injection, and Path Traversal probes.",
        },
        {
            "name": "SSL / TLS Cryptography",
            "ran": ("tls" in scan_types or "all" in scan_types),
            "description": "Certificate validity/expiry, cipher suites, protocol version, and HSTS checks.",
        },
        {
            "name": "Browser Automation (Selenium)",
            "ran": ("browser" in scan_types or "all" in scan_types),
            "description": "Headless-browser DOM/console checks where available in the deploy target.",
        },
        {
            "name": "Misconfiguration & Secrets Audit",
            "ran": ("misconfig" in scan_types or "vulnerabilities" in scan_types or "all" in scan_types),
            "description": "Exposed .env, .git, backup archives, CORS, cookies, and HTTP methods audit.",
        },
        {
            "name": "Burp Suite Proxy Analysis",
            "ran": ("burp" in scan_types or "all" in scan_types),
            "description": "Traffic forwarding and analysis via a local Burp Suite proxy.",
        },
        {
            "name": "Kavalu Detection Engine",
            "ran": True,
            "description": "Deterministic weighted risk-scoring and OWASP Top 10:2021 mapping of every finding above.",
        },
    ]
    if used_external_model:
        modules.insert(
            6,
            {
                "name": "External Model Plugin",
                "ran": True,
                "description": (
                    "Bring-your-own inference endpoint for source/code-level ML vulnerability classification."
                ),
            },
        )
    return modules
