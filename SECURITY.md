# Security Policy

Kavalu Security Engine is a security tool, so we take its own security seriously, and we are
upfront about what it does and does not protect against.

## Reporting a vulnerability

**Please do not open a public issue, discussion or pull request for a security problem.**

Report it privately through GitHub:

1. Go to the repository's **Security** tab.
2. Click **Report a vulnerability** (direct link: <https://github.com/vinayakanw/vnw_kavalu_security_engine/security/advisories/new>).
3. Describe the issue (see the checklist below).

If you cannot use GitHub's private reporting, contact the maintainer through the details on
<https://www.nayaka100.in/> and ask for a private channel *before* sending any technical detail.

### What to include

- The affected file, endpoint or module, and the version or commit
- Steps to reproduce, ideally a minimal proof of concept
- The impact as you understand it (what can an attacker do?)
- Any suggested fix

### What to expect

This is a small, maintainer-run project. We aim to:

| Step | Target |
|---|---|
| Acknowledge your report | within 5 business days |
| Confirm whether it is a valid vulnerability | within 14 days |
| Ship a fix or mitigation | depends on severity and complexity; critical issues first |
| Credit you in the release notes | if you want it, once a fix is released |

We follow **coordinated disclosure**: please give us a reasonable period to release a fix before publishing details.

## Supported versions

Only the latest release and the `main` branch receive security fixes.

| Version | Supported |
|---|---|
| `main` / latest release | Yes |
| anything older | No |

## Scope

**In scope** (vulnerabilities in this project's own code):

- The Flask app, API endpoints, SSE stream and the dashboard (`app.py`, `index.html`)
- Report generation (`core/report_generator.py`), for example injection into a report from attacker-controlled scan content
- Path handling, state files and anything that could read or write outside the data directory
- Dependency vulnerabilities that actually affect this project
- The `Dockerfile` and deployment files

**Out of scope:**

- Findings the engine produces about *someone else's* website (report those to that site's owner)
- False positives and false negatives in detection checks (open a normal issue or pull request instead)
- Issues that require the attacker to already control the server or the operator's machine
- The [documented limitations](#deploying-safely) below, unless you have a way to exploit them beyond what is described

## Responsible use

This engine sends active payloads (SQL injection, XSS, command injection, path traversal) and submits forms.
**Only run it against systems you own or have explicit written permission to test.**
Unauthorised scanning can be illegal and can cause real damage (corrupted or created data, triggered alerts, denial of service).
The authors accept no liability for misuse; see the [LICENSE](LICENSE).

## Deploying safely

These are properties of the current design, not bugs to report. They determine how you should run it:

| Property | Consequence | What to do |
|---|---|---|
| **No authentication or authorisation** | Anyone who can reach the API can start scans from your machine and read results for any scan ID. | Keep it on `127.0.0.1`, or put it behind an authenticating reverse proxy or VPN. |
| **Any target is allowed, including private ones** | The scanner will happily probe `localhost`, RFC 1918 ranges and cloud metadata endpoints (for example `169.254.169.254`) **from the server it runs on**: server-side request forgery by design. | Never expose it to untrusted users. Add an egress firewall or a target allow-list before multi-user use. |
| **`Access-Control-Allow-Origin: *`** | Any web page a user visits can call a locally running engine through their browser. | Run locally only on loopback, and do not browse untrusted sites while a local instance is running, or restrict origins at your proxy. |
| **`python app.py` binds to `0.0.0.0`** | The unauthenticated scanner is reachable from your whole network. | Use `flask --app app run --host 127.0.0.1` or `make run`. |
| **No rate limiting; scans are never evicted from memory** | A caller can exhaust CPU, threads or memory. | Rate-limit at the proxy; restart periodically. |
| **Reports and state files contain target data** | PDFs and `logs/scan_state/*.json` include URLs, findings and evidence. | Treat `reports/` and `logs/` as confidential; set `KAVALU_DATA_DIR` to a protected volume; prune regularly. |
| **TLS verification is disabled for probes** (`verify=False`) | Required to audit sites with broken TLS, but means probe traffic can be intercepted on a hostile network. | Run the engine from a trusted network. |

The dashboard and the API send a strict `Content-Security-Policy` (own files only, no inline scripts or styles) together with `X-Content-Type-Options`, `X-Frame-Options` and `Referrer-Policy`. Scan results come from websites you do not control, so the dashboard shows them as plain text only and never as HTML.

### Data sent to third parties

| When | To | What |
|---|---|---|
| `recon` module | `http://ip-api.com` (plain HTTP) | The target's resolved **IP address**, for geolocation and ISP data |
| `burp` module | `http://httpbin.org` (through the Burp proxy) | A connectivity probe; no scan data |
| `EXTERNAL_MODEL_URL` is set | The URL you configured | Up to 10 inline `<script>` bodies from the target page |

Nothing else leaves the machine; there is no telemetry. The dashboard itself loads nothing from other websites: no fonts, icons, scripts or analytics.

## Dependency security

- `requirements.txt` is fully pinned and checked with `pip-audit` in CI ([security workflow](.github/workflows/security.yml)).
- Dependabot opens pull requests for outdated dependencies, Docker base images and GitHub Actions.
- Run `make audit` locally at any time.

## Hardening backlog

Known security improvements are tracked openly in the [roadmap](ROADMAP.md#security-hardening). Contributions are welcome.
