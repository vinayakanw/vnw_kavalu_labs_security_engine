# API reference

Base URL: wherever you run the engine, e.g. `http://127.0.0.1:5000`.
In local mode, responses carry `Access-Control-Allow-Origin: *`. Public mode omits CORS headers.

> Local mode has no authentication. Public mode requires HTTP Basic authentication. Read
> [SECURITY.md](../SECURITY.md#deploying-safely) before exposing the service beyond localhost.

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/` | Web dashboard |
| `GET` | `/static/<file>` | Dashboard script, stylesheet and icon |
| `POST` | `/api/scan` | [Start a scan](#start-a-scan) |
| `GET` | `/api/scan/status/<scan_id>` | [Poll scan state and results](#scan-status) |
| `GET` | `/api/scan/stream/<scan_id>` | [Live progress (SSE)](#live-progress-sse) |
| `GET` | `/api/report/<scan_id>` | [Download a report](#download-a-report) |
| `GET` | `/api/owasp-top10` | OWASP Top 10:2021 reference data |
| `GET` | `/api/history` | Always `[]` |
| `GET` | `/healthz` | Minimal liveness response; does not expose scan data |

## Response headers

Responses carry `Access-Control-Allow-Origin: *` only in local mode, and include these security headers:

| Header | Value |
|---|---|
| `Content-Security-Policy` | `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'` |
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `Referrer-Policy` | `no-referrer` |

## Start a scan

`POST /api/scan` with a JSON body:

| Field | Type | Default | Notes |
|---|---|---|---|
| `url` | string | **required** | `https://` is assumed when no scheme is given. |
| `scan_types` | array of string | `["all"]` | `recon`, `owasp`, `tls`, `browser`, `misconfig`, `burp`, `vulnerabilities` (= `owasp` + `misconfig`), `all`. See [architecture](architecture.md#scan-lifecycle). |
| `use_selenium` | bool | `true` locally, `false` in public mode | Needed for the `browser` module, which is disabled in public mode. |
| `use_burp` | bool | `false` | Needed for the `burp` module. |

```bash
curl -s -X POST http://127.0.0.1:5000/api/scan \
  -H 'Content-Type: application/json' \
  -d '{"url": "https://staging.example.com/?id=1", "scan_types": ["recon", "owasp", "tls", "misconfig"], "use_selenium": false}'
```

```json
{ "message": "Scan initiated successfully", "scan_id": "c056d986-bb39-4888-a333-1ab790b67ac2", "status": "started" }
```

> **Give the scanner something to test.** It examines the single page you supply and does **not** crawl.
> Reflected-XSS, command-injection and path-traversal probes run against **query parameters already present in the URL**
> and against form fields found on that page. `https://site.example/` alone will not be tested for XSS; `https://site.example/search?q=test` will.

Errors:

| Status | Body | Cause |
|---|---|---|
| `400` | `{"error": "Target URL is required. …"}` | Missing or empty `url` |
| `400` | `{"error": "…", "status_code": 503, "target_valid": false}` | Pre-flight failed: DNS failure, connection refused, timeout, HTTP 5xx, or HTTP 404 on `/`. A site with an invalid TLS certificate is **allowed** (that is something to audit). |
| `500` | `{"error": "…"}` | Unexpected server error |

## Scan status

`GET /api/scan/status/<scan_id>`

```json
{
  "scan_id": "c056d986-…",
  "status": "completed",
  "progress": 100,
  "current_message": "Scan complete.",
  "target_url": "http://127.0.0.1:8765/",
  "scan_types": ["recon", "owasp", "tls", "misconfig"],
  "start_time": "2026-10-31T14:39:58.139718",
  "end_time": "2026-10-31T14:39:58.299403",
  "stats": { "critical": 1, "high": 2, "medium": 7, "low": 3, "info": 5,
             "total_requests": 18, "vulnerabilities_found": 10 },
  "risk": { "score": 100.0, "grade": "F", "label": "Critical Risk",
            "severity_counts": { "…": 0 }, "top_contributors": [ { "title": "…", "severity": "critical", "contribution": 40.0 } ],
            "methodology": "…" },
  "owasp_coverage": [ { "key": "A03", "code": "A03:2021", "name": "Injection", "status": "critical",
                        "total_findings": 1, "actionable_findings": 1, "counts": { "critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0 } } ],
  "findings": [ "…see below…" ],
  "deployment_info": { "platform": "…", "ip_address": "…", "…": "…" },
  "developer_info":  { "developer_name": "…", "confidence": "Low", "…": "…" },
  "engine_modules":  [ { "name": "Recon & Attribution", "ran": true, "description": "…" } ]
}
```

`status` is one of `started`, `running`, `completed`, `error`.
`owasp_coverage[].status` is one of `critical`, `high`, `attention`, `clear`, `not_tested`.

> **Quirk:** an unknown `scan_id` returns **HTTP 200** with `{"error": "Scan not found"}` (not 404).
> Check for the `error` key. Changing this would break existing clients; it is listed in the [roadmap](../ROADMAP.md).

### Finding object

```json
{
  "type": "sql_injection",
  "severity": "critical",
  "title": "SQL Injection Vulnerability",
  "description": "Potential SQL injection found in parameter \"id\". …",
  "details": { "parameter": "id", "payload": "'", "url": "http://…/?id=%27",
               "evidence": "Database error pattern detected: SQL syntax.*MySQL" },
  "remediation": "Use parameterized queries / prepared statements exclusively. …",
  "owasp": "A03", "owasp_code": "A03:2021", "owasp_name": "Injection",
  "cwe": ["CWE-89"]
}
```

`severity` ∈ `critical | high | medium | low | info`. `owasp` is `null` for purely informational types.
Every `type` the engine can emit is catalogued in [checks.md](checks.md).

## Live progress (SSE)

`GET /api/scan/stream/<scan_id>` → `Content-Type: text/event-stream`.

```text
data: {"status": "running", "progress": 28, "current_message": "Running OWASP Top 10 injection probes (SQLi, XSS, Command, LFI)...", "stats": {…}}

data: {"status": "completed", "progress": 100, "current_message": "Scan complete.", "stats": {…}}

event: done
data: {"status": "completed", "done": true}
```

Progress milestones (`progress`): 5 validating target → 10 recon → 28 OWASP probes → 45 TLS → 55 external model → 65 browser → 78 misconfiguration → 86 Burp → 94 scoring → 100 done. Modules you did not select are skipped, so values jump.

| Event | Meaning |
|---|---|
| *(default `message`)* | Progress changed. Emitted only when something changed. |
| `done` | Scan finished (`completed` or `error`). The stream then closes. |
| `error` | `{"error": "scan not found"}` |
| `timeout` | The stream window (60 s) elapsed before the scan finished. **Reconnect or fall back to polling** `/api/scan/status/<id>`; the scan itself keeps running. |

## Download a report

`GET /api/report/<scan_id>?format=pdf|html|json` (default `pdf`). Always returned as an attachment.

| `format` | Content-Type | Notes |
|---|---|---|
| `pdf` | `application/pdf` | Written to `reports/` and served from disk. The primary deliverable. |
| `html` | `text/html` | Generated in memory; never stored. All finding text is HTML-escaped. |
| `json` | `application/json` | Generated in memory. Top-level keys: `report_metadata`, `scan`, `executive_summary`, `risk`, `stats`, `owasp_coverage`, `attribution`, `findings`, `findings_by_owasp`, `remediation_roadmap`, `engine_modules`. |

| Status | Cause |
|---|---|
| `404` | `{"error": "…"}`: no saved state for that `scan_id` |
| `400` | `{"error": "Unsupported report format 'xml'.", "supported_formats": ["pdf","html","json"]}` |
| `500` | Report generation failed |

## Quick end-to-end example

```bash
SID=$(curl -s -X POST localhost:5000/api/scan -H 'Content-Type: application/json' \
      -d '{"url":"https://staging.example.com/?q=test","scan_types":["owasp","tls"],"use_selenium":false}' \
      | python -c 'import sys,json; print(json.load(sys.stdin)["scan_id"])')

until [ "$(curl -s localhost:5000/api/scan/status/$SID | python -c 'import sys,json; print(json.load(sys.stdin).get("status"))')" = completed ]; do sleep 2; done

curl -s -OJ "localhost:5000/api/report/$SID?format=pdf"
```
