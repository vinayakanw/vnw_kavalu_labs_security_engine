# Troubleshooting

Find your symptom, apply the fix. If you are still stuck, see [SUPPORT.md](../SUPPORT.md).

## The dashboard says the engine is not reachable

The status line under the page title shows "Engine not reachable", or starting a scan says "Cannot reach the Security Engine".

The dashboard sends its requests to the **same server that served the page**, on whatever port that is.
So the usual cause is simply that the engine is not running. Start it with `make run`
(or `flask --app app run`) and reload the page.

If you opened `index.html` straight from disk, or you serve the page with some other tool (for example a
live-reload server on another port), the page cannot find the engine on its own. Tell it where the engine is by
adding `?api=` to the address:

```text
http://127.0.0.1:5500/index.html?api=http://127.0.0.1:5000
```

For safety this option only accepts `127.0.0.1` or `localhost`, so a crafted link cannot make the page send your scan targets to another host.
(A page opened with `file://` automatically uses `http://127.0.0.1:5000`.)

## "Scan not found" while a scan was running

The scan's state lives in the memory of one process. Either the service restarted, or you are running **more than one worker/instance**.
Run exactly one worker: `gunicorn --workers 1 --threads 16 …`. See [deployment](deployment.md#production-server-settings-explained).

## The live progress stream stops after about a minute

The SSE stream has a 60 s window and then sends a `timeout` event. The scan itself keeps running.
The dashboard falls back to polling automatically; API clients should poll `GET /api/scan/status/<id>` ([API](api.md#live-progress-sse)).

## A scan finished but XSS / injection was not tested

The scanner tests the **parameters in the URL you give it** and the **forms on that one page**. It does not crawl.
Scan `https://site.example/search?q=test` rather than `https://site.example/`.

## Every sensitive file (`.env`, `.git/HEAD`, …) is reported as exposed

The target probably answers HTTP 200 for every path (a single-page app, or a custom "not found" page that is not a 404).
These findings are false positives for such sites. See [checks.md → blind spots](checks.md#known-blind-spots).

## "Browser Automation Notice" and no browser findings

1. Is Chromium installed? The plain Python runtime has none; use the [Docker image](deployment.md#docker).
2. Did you send `use_selenium: true` and include `browser` (or `all`) in `scan_types`?
3. If Chromium *is* present, the orchestrator waits only **5 seconds** for the browser module, and a real run usually needs longer.
   The notice then says the check "completed within execution window" even though its findings were discarded. This is a known limitation in the [roadmap](../ROADMAP.md).

## Burp says "Not Available"

The engine looks for Burp's proxy at `127.0.0.1:8080` (hard-coded) and tests it by fetching `http://httpbin.org/get` *through* the proxy,
so Burp must be on the same machine as the engine **and** that machine needs outbound internet.

## "Target domain could not be resolved" / "Connection refused" / "timed out"

These come from the pre-flight check (DNS, then one GET with an 8 s timeout). Check the spelling, that the site is up, and that the
machine running the engine (not your laptop) can reach it. Sites with an invalid TLS certificate are accepted; HTTP 5xx and HTTP 404 on `/` are rejected.

## Reports or history disappeared

Reports and scan state live in `reports/` and `logs/` under `KAVALU_DATA_DIR`. On Render's free tier or any ephemeral container they are wiped on each deploy or restart. Use a persistent disk or volume ([deployment](deployment.md)).
Browser-side scan history lives in that browser's `localStorage`; clearing site data removes it.

## `gunicorn: command not found` on Windows

Gunicorn does not run on Windows. Use `waitress-serve --listen=127.0.0.1:5000 --threads=16 app:app` ([deployment](deployment.md#local)).

## `RequestsDependencyWarning` about chardet / charset_normalizer

Reinstall from the pinned file in a clean virtual environment: `pip install -r requirements.txt`. The pinned set is warning-free.
