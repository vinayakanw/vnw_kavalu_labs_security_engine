"""
Filesystem Layout
-----------------
Single source of truth for every directory the engine writes to.

  REPORTS_DIR     Deliverable output directory. Contains PDF reports ONLY —
                  no HTML, no JSON, no other artifact is ever written here.
  SCAN_STATE_DIR  Internal engine state (one JSON state file per scan) used to
                  re-render a report or resume status polling for a finished
                  scan. This is engine bookkeeping, not a deliverable, so it
                  lives outside REPORTS_DIR.
  LOGS_DIR        Runtime logs.

All paths are absolute so the engine keeps working regardless of the process
working directory (Flask dev server, gunicorn, systemd, etc.). On read-only
filesystems (serverless platforms) the reports directory falls back to a
writable temporary directory so PDF generation still succeeds.
"""

__author__ = "Vinayaka N Walshettar"

import os
import tempfile

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))

#: Deliverable reports — PDF only.
REPORTS_DIR = os.path.join(PROJECT_ROOT, 'reports')

#: Internal per-scan state (not a report deliverable).
SCAN_STATE_DIR = os.path.join(PROJECT_ROOT, 'logs', 'scan_state')

#: Runtime logs.
LOGS_DIR = os.path.join(PROJECT_ROOT, 'logs')


def _is_writable(directory: str) -> bool:
    """True when the directory exists (or can be created) and accepts writes."""
    try:
        os.makedirs(directory, exist_ok=True)
        probe = os.path.join(directory, '.write_probe')
        with open(probe, 'w', encoding='utf-8') as probe_file:
            probe_file.write('ok')
        os.remove(probe)
        return True
    except Exception:
        return False


def _resolve_reports_dir() -> str:
    """Return the reports directory, falling back to a temp dir if read-only."""
    if _is_writable(REPORTS_DIR):
        return REPORTS_DIR
    fallback = os.path.join(tempfile.gettempdir(), 'kavalu_labs_security_engine', 'reports')
    os.makedirs(fallback, exist_ok=True)
    return fallback


# Resolved at import time so every writer agrees on one location.
REPORTS_DIR = _resolve_reports_dir()


def ensure_dirs() -> None:
    """Create every engine directory if possible. Never raises."""
    for directory in (REPORTS_DIR, SCAN_STATE_DIR, LOGS_DIR):
        try:
            os.makedirs(directory, exist_ok=True)
        except Exception:
            pass


def report_path(filename: str) -> str:
    """Absolute path for a file inside the reports directory."""
    return os.path.join(REPORTS_DIR, filename)


def scan_state_path(scan_id: str) -> str:
    """Absolute path of the state file backing a given scan id."""
    return os.path.join(SCAN_STATE_DIR, f'scan_{scan_id}.json')
