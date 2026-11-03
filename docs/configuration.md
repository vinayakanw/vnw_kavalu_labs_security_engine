# Configuration

The engine needs **no configuration** to run. Everything below is optional.

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `SECRET_KEY` | random per start | Flask signing key. The app keeps no user sessions, so a random key is fine; set it anyway in production. |
| `PORT` | `5000` (`python app.py`); `10000` (Docker image); injected by most hosts | Port for `python app.py`. Gunicorn uses its own `--bind`. |
| `KAVALU_DATA_DIR` | project root | Root for `reports/` and `logs/`. Point it at a persistent volume in production. |
| `EXTERNAL_MODEL_URL` | *(unset = plugin off)* | Endpoint of an optional ML model service. |
| `EXTERNAL_MODEL_API_KEY` | *(unset)* | Sent as `Authorization: Bearer <key>` when set. |
| `EXTERNAL_MODEL_TIMEOUT` | `8` | Seconds to wait for the model service. |

The app does **not** read `.env` files by itself. Copy [`.env.example`](../.env.example) and load it
yourself: `set -a; source .env; set +a`, or `docker run --env-file .env …`.

`CHROME_BIN` and `CHROMEDRIVER_PATH` are set inside the Docker image for the Chromium toolchain; the
Python code does not read them.

## Data directories

```text
$KAVALU_DATA_DIR/            (default: the project root)
├── reports/                 PDF reports only
└── logs/
    └── scan_state/          one scan_<id>.json per scan
```

Both directories grow without limit. Prune old files periodically (a cron job on `find … -mtime +30 -delete` is enough).

## Hard-wired settings (not configurable today)

These are constants in code; making them configurable is on the [roadmap](../ROADMAP.md).

| Setting | Value | Where |
|---|---|---|
| Burp proxy address | `127.0.0.1:8080` | `core/burp_integration.py` |
| Burp REST API | not reachable: no code path sets credentials | `core/burp_integration.py` |
| Target pre-flight timeout | 8 s | `core/scanner.py` |
| Browser-module time budget | 5 s | `core/scanner.py` |
| SSE stream window | 60 s | `core/scanner.py` |
| Cert-expiry warning window | 30 days | `core/tls_scanner.py` |

## External ML model plugin

Disabled unless `EXTERNAL_MODEL_URL` is set. When enabled, the scanner sends up to 10 inline `<script>` bodies
(each truncated to 4,000 characters) from the target page and merges the model's verdicts into the normal findings.
An unreachable or failing endpoint is a silent no-op, never a scan error.

```http
POST {EXTERNAL_MODEL_URL}
Authorization: Bearer <EXTERNAL_MODEL_API_KEY>      (only if set)
Content-Type: application/json

{ "source": "<script text>", "language": "javascript" }
```

```json
{ "findings": [
    { "title": "…", "severity": "high", "description": "…",
      "category": "command_injection", "confidence": 0.82 } ] }
```

`category` is translated to an engine finding type: `buffer_overflow→misconfiguration`, `command_injection`,
`sql_injection`, `weak_crypto→tls_cipher`, `hardcoded_secret→info_disclosure`, `xss`, `path_traversal→exposed_path`,
`ssrf→ssrf_candidate` (see `_CATEGORY_TO_TYPE` in `core/plugin_model.py`).

> Script contents leave the engine and are sent to whatever URL you configure. Only point it at a service you control.

## Running under a production server

State is per-process, so use **one worker and many threads**:

```bash
gunicorn --bind 0.0.0.0:$PORT --workers 1 --threads 16 --timeout 300 app:app
```

See [deployment.md](deployment.md) for Render, Docker and Windows (`waitress`) instructions.
