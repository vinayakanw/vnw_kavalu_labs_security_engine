"""Shared fixtures.

Design rules for this suite (see CONTRIBUTING.md):
  * No test may reach the public internet. Anything that would (the recon
    module's third-party IP lookup, for example) is stubbed.
  * No test may write into the real ``reports/`` or ``logs/`` directories.
    The ``isolated_data_dirs`` fixture is autouse for that reason.
"""

from __future__ import annotations

import pytest

from core import paths
from tests.vulnerable_server import running_server


@pytest.fixture(autouse=True)
def isolated_data_dirs(tmp_path, monkeypatch):
    """Redirect report + scan-state output to a per-test temp directory."""
    reports = tmp_path / "reports"
    state = tmp_path / "logs" / "scan_state"
    reports.mkdir(parents=True)
    state.mkdir(parents=True)
    monkeypatch.setattr(paths, "REPORTS_DIR", str(reports))
    monkeypatch.setattr(paths, "SCAN_STATE_DIR", str(state))
    return tmp_path


@pytest.fixture(scope="session")
def vulnerable_url():
    """Base URL of the deliberately vulnerable local target (ends with '/')."""
    with running_server() as url:
        yield url


@pytest.fixture()
def client():
    """Flask test client for the real application object."""
    import app as app_module

    app_module.app.config["TESTING"] = True
    with app_module.app.test_client() as test_client:
        yield test_client


@pytest.fixture()
def sample_scan_state():
    """A realistic, fully-populated scan result (no network needed)."""
    from core import detection_engine, owasp_mapping

    findings = [
        {
            "type": "sql_injection",
            "severity": "critical",
            "title": "SQL Injection Vulnerability",
            "description": "Database error leaked.",
            "details": {"parameter": "id", "payload": "'"},
            "remediation": "Use parameterized queries.",
        },
        {
            "type": "xss",
            "severity": "high",
            "title": "Reflected XSS Vulnerability",
            "description": "Input reflected unescaped.",
            "details": {"parameter": "q"},
            "remediation": "Encode output.",
        },
        {
            "type": "security_header",
            "severity": "medium",
            "title": "Missing Content-Security-Policy",
            "description": "CSP header missing.",
            "details": {"header": "Content-Security-Policy"},
        },
        {
            "type": "missing_sri",
            "severity": "low",
            "title": "Missing Subresource Integrity",
            "description": "No SRI.",
            "details": {},
        },
        {"type": "info", "severity": "info", "title": "Target Response", "description": "HTTP 200.", "details": {}},
    ]
    for finding in findings:
        owasp_mapping.tag_finding(finding)

    risk = detection_engine.score_findings(findings)
    return {
        "scan_id": "11111111-2222-3333-4444-555555555555",
        "target_url": "http://example.test/",
        "status": "completed",
        "progress": 100,
        "scan_types": ["all"],
        "start_time": "2026-01-01T10:00:00",
        "end_time": "2026-01-01T10:00:05",
        "findings": findings,
        "risk": risk,
        "owasp_coverage": owasp_mapping.build_coverage_matrix(findings),
        "owasp_ran": True,
        "engine_modules": detection_engine.summarize_engine_modules(["all"], False),
        "stats": {
            "critical": 1,
            "high": 1,
            "medium": 1,
            "low": 1,
            "info": 1,
            "total_requests": 5,
            "vulnerabilities_found": 4,
        },
        "deployment_info": {
            "platform": "Unit Test Server",
            "ip_address": "203.0.113.7",
            "location": "Unknown",
            "server_header": "test",
        },
        "developer_info": {
            "developer_name": "Not disclosed in public metadata",
            "organization": "Not disclosed in public metadata",
            "confidence": "Low",
            "social_footprint": [],
        },
    }
