# Kavalu Labs Security Engine — Deploy to Render
**Kavalu Labs Security Engine**

One Render Web Service serves **both** the dashboard and the API — Flask renders
`index.html` itself (`app.py`), so there is no separate frontend to host and
nothing to split.

---

## Why Render (and not Vercel)

Scans run in a **background thread of the Flask process** (`core/scanner.py`),
the scan state lives in that process's memory, and the SSE progress stream
holds a connection open for up to 60s. Serverless platforms freeze the
function once the response is returned, so a scan would never finish and the
status poll would hit an instance that has never heard of the `scan_id`.
Render runs a long-lived container, which is what this engine needs.

---

## Prerequisites

1. A Render account (https://render.com)
2. The project pushed to a Git repository (GitHub / GitLab / Bitbucket)

---

## Deployment

### 1. Push the project to Git

```bash
git init
git add .
git commit -m "Kavalu Labs Security Engine"
git branch -M main
git remote add origin <your-repo-url>
git push -u origin main
```

### 2. Create the Blueprint

Render Dashboard → **New** → **Blueprint** → select the repository → **Apply**.

Render reads `render.yaml` from the repository root and creates the service
with the right runtime, plan, disk and environment variables.

> **Region is fixed at creation.** `render.yaml` uses `singapore` (the closest
> Render region to India). Change it in the Blueprint *before* the first apply
> if you prefer another region.

### 3. Wait for the deploy

The first build installs the Python dependencies. When it finishes, Render
gives you a URL like:

```text
https://kavalu-labs-security-engine.onrender.com
```

Open it — that single URL is the dashboard *and* the API. The scan history
stays in the visitor's browser (`localStorage`), so no cross-user data is ever
exposed.

---

## What `render.yaml` configures and why

| Setting | Reason |
|---|---|
| `PYTHON_VERSION: 3.12.11` | Render's default is now Python 3.14. The pinned `lxml==5.2.1` has no 3.13/3.14 wheels and would compile from source and fail the build. |
| `--workers 1` | Scan state is held in the process (`scanner.active_scans`). A second worker would not know the `scan_id` and the status poll would return "Scan not found" mid-scan. |
| `--threads 16` | Each SSE progress connection (`/api/scan/stream`) occupies a thread for the length of the scan. |
| `--timeout 300` | Scans against slow targets can run for minutes. |
| `numInstances: 1` | A service with a persistent disk cannot be scaled beyond one instance, and the engine is single-instance by design. |
| `disk` + `KAVALU_DATA_DIR` | Keeps generated PDFs and per-scan state across redeploys. Without it, both are wiped on every deploy. |
| `maxShutdownDelaySeconds: 120` | Lets an in-flight scan finish during a rolling deploy instead of being killed. |
| `healthCheckPath: /api/history` | Cheap endpoint that proves the app (not just the port) is alive. |

---

## Enabling the Selenium browser module (optional)

The native Python runtime has no Chrome, so the browser module reports a
"Browser Automation Notice" finding and the rest of the scan continues. To
enable real DOM/console testing, use the included container image:

1. In `render.yaml`, change `runtime: python` to `runtime: docker`
2. Keep the `buildCommand` line removed (Docker builds the image itself)
3. Deploy

The `Dockerfile` installs `chromium` + `chromium-driver` and pins Python 3.12.
The image is larger and the build takes longer, but every module works.

---

## Free tier (if you don't want to pay)

Persistent disks are paid-only. To use the free plan:

- change `plan: 1c-2g` to `plan: free`
- delete the whole `disk:` block
- delete the `KAVALU_DATA_DIR` environment variable

What you give up:

| Limitation | Effect |
|---|---|
| **Ephemeral filesystem** | `reports/` and `logs/` are wiped on every deploy and every restart. PDFs are still downloadable during the session that generated them. |
| **Sleeps after 15 min idle** | The next request takes ~30-60s to wake the instance. A scan running when the instance sleeps is lost. |
| **512 MB RAM** | The Selenium browser module will not fit. Use the Docker image or a paid plan. |
| **750 instance-hours/month** | The service is deleted after that. |

---

## Operating notes

- **Reports** are written to `reports/` (PDF only) and per-scan state to
  `logs/scan_state/`. Both live on the persistent disk. They accumulate —
  add a cleanup cron job or prune old files periodically.
- **Restarting the service kills running scans.** The scan state is in
  memory; a restart mid-scan leaves the browser showing "Scan not found".
- **`SECRET_KEY`** is generated automatically by the Blueprint. The app does
  not use server-side sessions, so it is not critical, but keep it set.
- **Burp Suite integration** only works if the engine can reach a Burp
  instance over the network. A Burp running on your laptop is not reachable
  from Render — the module will be skipped.

---

## Security before going public

The engine has **no authentication** and sends
`Access-Control-Allow-Origin: *`, so anybody with the URL can make it scan
any target they like, using your server and your IP. Before exposing it:

1. Put it behind an authenticating reverse proxy, or add an auth layer to
   the Flask app.
2. Restrict the targets it may scan (an allow-list beats an open proxy for
   a security tool).
3. Add rate limiting.

---

## Local development

```bash
pip install -r requirements.txt
python app.py
```

Run the same way Render does (any WSGI server, Linux/macOS):

```bash
gunicorn --bind 0.0.0.0:5000 --workers 1 --threads 16 --timeout 300 app:app
```

On Windows, gunicorn is not available — use `waitress` instead:

```bash
waitress-serve --listen=127.0.0.1:5000 --threads=16 app:app
```
