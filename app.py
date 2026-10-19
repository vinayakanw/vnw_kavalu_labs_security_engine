"""
Kavalu Labs Security Engine
High-assurance web application security testing tool using Requests, Selenium, and Burp Suite integration.
"""

__author__ = "Vinayaka N Walshettar"

from flask import Flask, render_template, request, jsonify, send_file, Response
from datetime import datetime
import io
import json
import os
import secrets
from core.scanner import SecurityScanner
from core.report_generator import ReportGenerator
from core.owasp_mapping import OWASP_TOP_10
from core.paths import ensure_dirs

app = Flask(__name__, template_folder='.')
# Read secret key from environment variable in production.
# Falls back to a secure random value for local development — each restart
# regenerates the key, which is fine since this app uses no server-side sessions.
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
scanner = SecurityScanner()

# Make sure the output directories exist before the first request lands
# (works for `python app.py`, gunicorn, waitress, or a WSGI server).
ensure_dirs()

@app.before_request
def handle_preflight():
    if request.method == 'OPTIONS':
        res = app.make_default_options_response()
        res.headers['Access-Control-Allow-Origin'] = '*'
        res.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization'
        res.headers['Access-Control-Allow-Methods'] = 'GET,POST,PUT,DELETE,OPTIONS'
        return res

@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization'
    response.headers['Access-Control-Allow-Methods'] = 'GET,POST,PUT,DELETE,OPTIONS'
    return response

@app.route('/')
def index():
    """Main dashboard page."""
    return render_template('index.html')

@app.route('/api/scan', methods=['POST', 'OPTIONS'])
def start_scan():
    """Start a security scan."""
    data = request.json or {}
    target_url = (data.get('url') or '').strip()
    scan_types = data.get('scan_types', ['all'])
    use_burp = data.get('use_burp', False)
    use_selenium = data.get('use_selenium', True)
    
    if not target_url:
        return jsonify({'error': 'Target URL is required. Please enter a valid website address.'}), 400
    
    # Pre-validate domain resolution and reachability upfront
    is_valid, error_msg, http_code = scanner.validate_target(target_url)
    if not is_valid:
        return jsonify({
            'error': error_msg,
            'status_code': http_code,
            'target_valid': False
        }), 400

    try:
        results = scanner.scan(
            target_url=target_url,
            scan_types=scan_types,
            use_burp=use_burp,
            use_selenium=use_selenium
        )
        return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/status/<scan_id>')
def scan_status(scan_id):
    """Get scan status (one-shot poll)."""
    status = scanner.get_scan_status(scan_id)
    return jsonify(status)

@app.route('/api/scan/stream/<scan_id>')
def scan_stream(scan_id):
    """Real-time scan progress via Server-Sent Events.
    Falls back gracefully: if SSE isn't supported by the client/host, the
    frontend keeps using /api/scan/status polling automatically."""
    def generate():
        for event in scanner.stream_scan_events(scan_id):
            yield event
    return Response(
        generate(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',
            'Connection': 'keep-alive',
        }
    )

@app.route('/api/owasp-top10')
def owasp_top10():
    """Reference listing of the OWASP Top 10:2021 categories the engine maps
    every finding against (used to render the coverage matrix client-side
    even before a scan has completed)."""
    return jsonify(list(OWASP_TOP_10.values()))

@app.route('/api/report/<scan_id>')
def generate_report(scan_id):
    """Generate and download the report for a scan.

    PDF is the engine's deliverable format: it is written to the reports
    directory and served from disk. HTML and JSON are rendered in memory and
    streamed straight to the browser as downloads — they are never written to
    the reports directory (or to disk at all).
    """
    format_type = (request.args.get('format') or 'pdf').strip().lower()

    if format_type == 'pdf':
        try:
            report_file = ReportGenerator.generate_report(scan_id, 'pdf')
            return send_file(report_file, mimetype='application/pdf', as_attachment=True)
        except ValueError as e:
            return jsonify({'error': str(e)}), 404
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    if format_type in ('html', 'json'):
        try:
            filename, mimetype, payload = ReportGenerator.build_download(scan_id, format_type)
            return send_file(
                io.BytesIO(payload),
                mimetype=mimetype,
                as_attachment=True,
                download_name=filename,
            )
        except ValueError as e:
            return jsonify({'error': str(e)}), 404
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    return jsonify({
        'error': f"Unsupported report format '{format_type}'.",
        'supported_formats': ['pdf', 'html', 'json']
    }), 400

@app.route('/api/history')
def scan_history():
    """Get scan history."""
    history = scanner.get_scan_history()
    return jsonify(history)

if __name__ == '__main__':
    ensure_dirs()
    # threaded=True matters here: the SSE progress stream (/api/scan/stream)
    # holds its connection open for the duration of a scan. Without
    # threading, Werkzeug's dev server would serialize requests and that one
    # open connection would block every other request (including the
    # polling fallback) until it finished. For a real deployment, run this
    # behind a proper WSGI server (gunicorn/waitress) with multiple workers
    # instead of the Flask dev server — see VERCEL_DEPLOY.md.
    app.run(host='0.0.0.0', port=5000, threaded=True)
