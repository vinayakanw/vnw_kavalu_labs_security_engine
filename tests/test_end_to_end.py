"""Full scan lifecycle: start -> background run -> persisted state -> report.

Runs the real SecurityScanner against the local vulnerable target. The only
stub is the recon module's third-party IP-geolocation lookup, which would
otherwise make an outbound request to a public service.
"""

import time

import pytest

from core import scanner as scanner_module
from core.scanner import SecurityScanner

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def no_outbound_attribution(monkeypatch):
    monkeypatch.setattr(
        scanner_module.TargetAttribution,
        "analyze",
        staticmethod(lambda url, proxies=None: {"deployment": {"platform": "stub"}, "developer": {}}),
    )


def run_scan(url, scan_types, timeout=60):
    engine = SecurityScanner()
    started = engine.scan(url, scan_types, use_burp=False, use_selenium=False)
    assert started["status"] == "started"
    deadline = time.time() + timeout
    while time.time() < deadline:
        state = engine.get_scan_status(started["scan_id"])
        if state.get("status") in ("completed", "error"):
            return engine, state
        time.sleep(0.2)
    pytest.fail("scan did not finish in time")


def test_full_scan_produces_scored_owasp_mapped_findings(vulnerable_url):
    _, state = run_scan(vulnerable_url, ["recon", "owasp", "tls", "misconfig"])

    assert state["status"] == "completed"
    assert state["progress"] == 100

    types = {f["type"] for f in state["findings"]}
    assert {"sql_injection", "no_https", "exposed_path", "security_header", "insecure_cookie"} <= types

    # Every non-informational finding is tagged, and the score reflects a critical issue.
    for f in state["findings"]:
        if f["severity"] != "info":
            assert f["owasp_code"], f
    assert state["risk"]["grade"] == "F"
    assert state["stats"]["critical"] >= 1

    # The coverage matrix always lists all ten categories.
    assert len(state["owasp_coverage"]) == 10
    a03 = next(row for row in state["owasp_coverage"] if row["key"] == "A03")
    assert a03["status"] == "critical"


def test_module_selection_is_respected(vulnerable_url):
    """Without 'recon' the security-header checks do not run (headers belong to the recon module)."""
    _, state = run_scan(vulnerable_url, ["tls"])
    types = {f["type"] for f in state["findings"]}
    assert "no_https" in types
    assert "security_header" not in types
    assert "sql_injection" not in types


def test_state_is_persisted_so_a_new_process_can_read_it(vulnerable_url):
    engine, state = run_scan(vulnerable_url, ["tls"])
    fresh = SecurityScanner()  # simulates a restart: empty in-memory state
    assert fresh.get_scan_status(state["scan_id"])["scan_id"] == state["scan_id"]


def test_sse_stream_ends_with_a_done_event(vulnerable_url):
    engine, state = run_scan(vulnerable_url, ["tls"])
    events = "".join(engine.stream_scan_events(state["scan_id"], poll_interval=0.01, max_seconds=5))
    assert "event: done" in events
    assert '"done": true' in events


def test_report_can_be_built_from_a_finished_scan(vulnerable_url):
    from core.report_generator import ReportGenerator

    _, state = run_scan(vulnerable_url, ["tls", "misconfig"])
    path = ReportGenerator.generate_report(state["scan_id"], "pdf")
    with open(path, "rb") as fh:
        assert fh.read(5) == b"%PDF-"
