# Deployment

> **Read [SECURITY.md → Deploying safely](../SECURITY.md#deploying-safely) first.**
> The engine has **no authentication** and can be pointed at any host, including your private network.
> Do not expose it to the open internet as-is.

- [Why a long-lived server (not serverless)](#why-a-long-lived-server-not-serverless)
- [Local](#local)
- [Docker](#docker)
- [Render](#render)
- [Production server settings explained](#production-server-settings-explained)
- [Operating notes](#operating-notes)

## Why a long-lived server (not serverless)

Scans run in a **background thread of the Flask process**, their state lives in that process's memory, and the SSE
stream holds a connection open for up to 60 s. Serverless platforms (Vercel, Lambda, …) freeze the function once the
response is returned, so a scan would never finish and a later poll would reach an instance that has never heard of the `scan_id`.
Use a platform that runs a long-lived container or VM.

## Local

```bash
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
flask --app app run --host 127.0.0.1 --port 5000        # same as: make run
```

Open <http://127.0.0.1:5000>.

`python app.py` also works, but it binds to **all interfaces** (`0.0.0.0`), which exposes the unauthenticated scanner to your whole network.
Prefer the command above, or `make run`.

Production-style, single worker (Linux/macOS):

```bash
gunicorn --bind 127.0.0.1:5000 --workers 1 --threads 16 --timeout 300 app:app
```

Windows has no gunicorn; use waitress:

```bash
pip install waitress
waitress-serve --listen=127.0.0.1:5000 --threads=16 app:app
```

## Docker

The image bundles headless Chromium, so the **browser module works** (the plain Python runtime has no Chrome).

```bash
make docker-build
make docker-run          # http://127.0.0.1:5000
```

or by hand:

```bash
docker build -t kavalu-security-engine .
docker run --rm -p 127.0.0.1:5000:10000 kavalu-security-engine
```

- The container listens on port `10000`. `-p 127.0.0.1:5000:10000` publishes it on your machine's port 5000, and the `127.0.0.1` part keeps it private.
- Persist reports and state with a volume: `-v kavalu-data:/data -e KAVALU_DATA_DIR=/data`.
- Pass settings with `--env-file .env` ([configuration](configuration.md)).
- The image has a `HEALTHCHECK` against `/api/history`.
- The container runs as root. Do not switch to a non-root user while writing to a Render persistent disk without testing it; disk mounts are root-owned.

## Render

One Render Web Service serves **both** the dashboard and the API.

1. Push the repository to GitHub.
2. Render Dashboard → **New** → **Blueprint** → select the repository → **Apply**. Render reads [`render.yaml`](../render.yaml) and creates the service, disk and environment variables.
3. Wait for the build. You get a URL like `https://kavalu-security-engine.onrender.com`. That single URL is the dashboard and the API.

> **The region is fixed at creation.** `render.yaml` uses `singapore`. Change it *before* the first apply if you prefer another.

### What `render.yaml` sets, and why

| Setting | Reason |
|---|---|
| `PYTHON_VERSION: 3.12.11` | Pins a version the project's CI tests (3.10 – 3.12) so builds are reproducible. |
| `--workers 1` | Scan state is in process memory. A second worker would answer "Scan not found" mid-scan. |
| `--threads 16` | Every open SSE stream occupies a thread for the length of the scan. |
| `--timeout 300` | Scans of slow targets can take minutes. |
| `numInstances: 1` | A service with a persistent disk cannot scale out, and the engine is single-instance by design. |
| `disk` + `KAVALU_DATA_DIR=/var/data` | Keeps PDFs and per-scan state across deploys. Without a disk both are wiped on every deploy. |
| `maxShutdownDelaySeconds: 120` | Lets an in-flight scan finish during a rolling deploy. |
| `healthCheckPath: /api/history` | Cheap endpoint proving the app, not just the port, is alive. |

### Enabling the browser module on Render

The native Python runtime has no Chrome, so the browser module records a "Browser Automation Notice" and the rest of the scan continues.
To get real DOM/console testing, switch to the container image: in `render.yaml` change `runtime: python` to `runtime: docker` and remove the `buildCommand` line.

### Free tier

Persistent disks are paid-only. For the free plan set `plan: free`, delete the `disk:` block and the `KAVALU_DATA_DIR` variable.
You give up: files survive neither deploys nor restarts; the instance sleeps after 15 idle minutes (a scan running at that moment is lost);
512 MB RAM is too small for the browser module; and the instance-hour quota is limited.

## Production server settings explained

```text
gunicorn --bind 0.0.0.0:$PORT --workers 1 --threads 16 --timeout 300 app:app
```

Use **one worker**: scan state is per-process. Scale concurrency with **threads**, never with workers or multiple instances.

## Operating notes

- **Restarting kills running scans.** State for in-flight scans is in memory; the browser will show "Scan not found". Finished scans survive (their JSON state file is on disk).
- **Files accumulate** in `reports/` and `logs/scan_state/`. Prune old ones periodically.
- **Burp** is only reachable if it runs on the same machine as the engine (`127.0.0.1:8080`). A Burp on your laptop is not reachable from Render.
- **`SECRET_KEY`** is generated for you by the Blueprint. The app keeps no sessions, so it is not critical, but keep it set.
