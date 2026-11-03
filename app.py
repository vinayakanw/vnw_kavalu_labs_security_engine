"""Kavalu Security Engine: web dashboard and JSON API.

This module only handles HTTP. All scanning logic lives in the ``core`` package.
"""

__author__ = "Vinayaka N Walshettar"

import io
import os
import secrets

from flask import Flask, Response, jsonify, render_template, request, send_file

from core.owasp_mapping import OWASP_TOP_10
from core.paths import ensure_dirs
from core.report_generator import SUPPORTED_FORMATS, ReportGenerator
from core.scanner import SecurityScanner

# index.html sits in the project root, next to this file.
app = Flask(__name__, template_folder=".")

# The app keeps no user sessions, so a new random key on each start is fine.
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

scanner = SecurityScanner()

# Create the output directories however the app is started (flask, gunicorn, waitress).
ensure_dirs()

CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type,Authorization",
    "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS",
}

# The dashboard loads nothing from other websites and uses no inline scripts or
# styles, so a strict policy is possible. It limits the damage if a scanned
# site ever managed to get markup into the page.
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; "
        "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
}


@app.before_request
def handle_preflight():
    """Answer CORS preflight requests without running a route."""
    if request.method == "OPTIONS":
        response = app.make_default_options_response()
        response.headers.update(CORS_HEADERS)
        return response
    return None


@app.after_request
def add_response_headers(response):
    """Add the CORS and security headers to every response."""
    response.headers.update(CORS_HEADERS)
    for name, value in SECURITY_HEADERS.items():
        response.headers.setdefault(name, value)
    return response


@app.route("/")
def index():
    """Serve the dashboard page."""
    return render_template("index.html")


@app.route("/api/scan", methods=["POST", "OPTIONS"])
def start_scan():
    """Start a scan in the background and return its ``scan_id`` immediately."""
    data = request.json or {}
    target_url = (data.get("url") or "").strip()
    scan_types = data.get("scan_types", ["all"])
    use_burp = data.get("use_burp", False)
    use_selenium = data.get("use_selenium", True)

    if not target_url:
        return jsonify({"error": "Target URL is required. Please enter a valid website address."}), 400

    # Check upfront that the target resolves and answers, so a typo fails fast.
    is_valid, error_message, http_code = scanner.validate_target(target_url)
    if not is_valid:
        return jsonify({"error": error_message, "status_code": http_code, "target_valid": False}), 400

    try:
        results = scanner.scan(
            target_url=target_url,
            scan_types=scan_types,
            use_burp=use_burp,
            use_selenium=use_selenium,
        )
        return jsonify(results)
    except Exception as error:
        return jsonify({"error": str(error)}), 500


@app.route("/api/scan/status/<scan_id>")
def scan_status(scan_id):
    """Return the current state and results of a scan (one-shot poll)."""
    return jsonify(scanner.get_scan_status(scan_id))


@app.route("/api/scan/stream/<scan_id>")
def scan_stream(scan_id):
    """Stream scan progress as Server-Sent Events.

    Clients that cannot use SSE poll ``/api/scan/status/<scan_id>`` instead.
    """
    return Response(
        scanner.stream_scan_events(scan_id),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@app.route("/api/owasp-top10")
def owasp_top10():
    """List the OWASP Top 10:2021 categories every finding is mapped to."""
    return jsonify(list(OWASP_TOP_10.values()))


@app.route("/api/report/<scan_id>")
def generate_report(scan_id):
    """Download the report for a scan as ``?format=pdf`` (default), ``html`` or ``json``.

    PDF is written to the reports directory and served from disk. HTML and JSON
    are built in memory and streamed as downloads; they never touch the disk.
    """
    format_type = (request.args.get("format") or "pdf").strip().lower()

    if format_type not in SUPPORTED_FORMATS:
        return (
            jsonify(
                {
                    "error": f"Unsupported report format '{format_type}'.",
                    "supported_formats": list(SUPPORTED_FORMATS),
                }
            ),
            400,
        )

    try:
        if format_type == "pdf":
            report_file = ReportGenerator.generate_report(scan_id, "pdf")
            return send_file(report_file, mimetype="application/pdf", as_attachment=True)

        filename, mimetype, payload = ReportGenerator.build_download(scan_id, format_type)
        return send_file(io.BytesIO(payload), mimetype=mimetype, as_attachment=True, download_name=filename)
    except ValueError as error:  # unknown scan_id
        return jsonify({"error": str(error)}), 404
    except Exception as error:
        return jsonify({"error": str(error)}), 500


@app.route("/api/history")
def scan_history():
    """Return the server-side scan history (always empty) and serve as the health check."""
    return jsonify(scanner.get_scan_history())


if __name__ == "__main__":
    # threaded=True is required: each open progress stream holds a connection
    # for the whole scan, and without threads it would block every other request.
    # This dev server binds to all interfaces. To keep the scanner private, use
    # `flask --app app run --host 127.0.0.1` instead (see docs/deployment.md).
    # In production run ONE worker with several threads: scan state lives in
    # the memory of a single process. PORT is set by most hosting platforms.
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), threaded=True)
