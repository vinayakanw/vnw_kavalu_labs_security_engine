#!/usr/bin/env python3
"""Regenerate docs/assets/sample-report.pdf.

Runs a real scan of the deliberately vulnerable local target (never a third
party) and saves the resulting PDF. Re-run after changing the report layout:

    python scripts/generate_sample_report.py

Output goes to a temporary data directory, so your real ``reports/`` and
``logs/`` are untouched. The recon module's outbound IP lookup is replaced by
static, clearly-labelled sample data.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "docs" / "assets" / "sample-report.pdf"

# Must be set BEFORE importing anything from core (paths are resolved at import).
DATA_DIR = tempfile.mkdtemp(prefix="kavalu-sample-")
os.environ["KAVALU_DATA_DIR"] = DATA_DIR
sys.path.insert(0, str(ROOT))

from core import scanner as scanner_module  # noqa: E402
from core.report_generator import ReportGenerator  # noqa: E402
from tests.vulnerable_server import running_server  # noqa: E402

SAMPLE_ATTRIBUTION = {
    "deployment": {
        "platform": "Practice target (tests/vulnerable_server.py)",
        "ip_address": "127.0.0.1",
        "reverse_dns": "localhost",
        "location": "Local machine",
        "hosting_org": "N/A (sample data)",
        "isp": "N/A (sample data)",
        "asn": "N/A",
        "server_header": "BaseHTTP (sample)",
        "detected_headers": [],
    },
    "developer": {
        "developer_name": "Not disclosed in public metadata",
        "organization": "Not disclosed in public metadata",
        "confidence": "Low",
        "discovery_source": "None",
        "meta_author": None,
        "copyright": None,
        "humans_txt_data": None,
        "social_footprint": [],
    },
}


def main() -> int:
    scanner_module.TargetAttribution.analyze = staticmethod(lambda url, proxies=None: SAMPLE_ATTRIBUTION)
    engine = scanner_module.SecurityScanner()

    with running_server() as base_url:
        started = engine.scan(
            base_url + "?id=1", ["recon", "owasp", "tls", "misconfig"], use_burp=False, use_selenium=False
        )
        deadline = time.time() + 120
        state = {}
        while time.time() < deadline:
            state = engine.get_scan_status(started["scan_id"])
            if state.get("status") in ("completed", "error"):
                break
            time.sleep(0.25)
        if state.get("status") != "completed":
            print(f"scan did not complete: {state.get('status')}", file=sys.stderr)
            return 1

    pdf_path = ReportGenerator.generate_report(started["scan_id"], "pdf")
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(pdf_path, OUTPUT)
    shutil.rmtree(DATA_DIR, ignore_errors=True)
    print(
        f"Wrote {OUTPUT.relative_to(ROOT)} ({OUTPUT.stat().st_size:,} bytes), "
        f"grade {state['risk']['grade']} / score {state['risk']['score']}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
