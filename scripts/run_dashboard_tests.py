#!/usr/bin/env python3
"""Run the browser-level dashboard test (tests/dashboard/dashboard.test.mjs).

Starts everything the test needs on free local ports, runs it with Node.js,
then shuts everything down:

  * the real Flask app (a separate process, with a temporary data directory)
  * the deliberately vulnerable local target (tests/vulnerable_server.py)

One-time setup:  npm ci --prefix tests/dashboard      (needs Node.js 22.22.2 or newer)
Run:             python scripts/run_dashboard_tests.py   (or: make test-ui)

The application itself never needs Node.js; this is development tooling only.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TEST_DIR = ROOT / "tests" / "dashboard"
sys.path.insert(0, str(ROOT))

from tests.vulnerable_server import running_server  # noqa: E402


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_until_ready(url: str, timeout: float = 30.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            urllib.request.urlopen(url, timeout=2).read()
            return
        except OSError:
            time.sleep(0.3)
    raise RuntimeError(f"The app did not start: {url}")


def main() -> int:
    if shutil.which("node") is None:
        print("Node.js is required for the dashboard tests (version 22.22.2 or newer).", file=sys.stderr)
        return 2
    if not (TEST_DIR / "node_modules").is_dir():
        print("Install the test dependencies first:  npm ci --prefix tests/dashboard", file=sys.stderr)
        return 2

    port = free_port()
    data_dir = tempfile.mkdtemp(prefix="kavalu-ui-test-")
    env = {**os.environ, "PORT": str(port), "KAVALU_DATA_DIR": data_dir}
    app = subprocess.Popen(
        [sys.executable, "app.py"], cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    try:
        app_url = f"http://127.0.0.1:{port}/"
        wait_until_ready(app_url + "api/history")
        with running_server() as target:
            test_env = {**os.environ, "APP_URL": app_url, "TARGET_URL": target + "?id=1"}
            result = subprocess.run(["node", "dashboard.test.mjs"], cwd=TEST_DIR, env=test_env, check=False)
            return result.returncode
    finally:
        app.terminate()
        try:
            app.wait(timeout=10)
        except subprocess.TimeoutExpired:
            app.kill()
        shutil.rmtree(data_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
