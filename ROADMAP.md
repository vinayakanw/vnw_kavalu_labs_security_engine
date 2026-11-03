# Roadmap and known issues

An honest list of what is **known to be imperfect** and where help is most welcome.
Everything here was found by reading and running the code. Items labelled *good first issue* are a good place to start.

Want to take one? Comment on (or open) an issue first, then follow [CONTRIBUTING.md](CONTRIBUTING.md).

- [Known bugs and limitations](#known-bugs-and-limitations)
- [Security hardening](#security-hardening)
- [Housekeeping](#housekeeping)
- [Ideas](#ideas-not-commitments)

## Known bugs and limitations

| Label | Issue | Where | Notes |
|---|---|---|---|
| bug | **Sensitive-path check has no soft-404 guard**, so catch-all servers (SPAs) get every path flagged. A code comment promises the guard. | `vulnerability_scanner._test_sensitive_paths` | Fix idea: request a random non-existent path first and compare status/body. |
| bug | **Browser module is limited to 5 s**; on overrun its results are discarded and the notice says it "completed within execution window". | `scanner._run_scan` | Fix: configurable budget; honest notice; collect partial results. |
| good first issue | **Three finding types are unmapped** and fall back to A05: `burp_issue`, `client_storage`, `password_security`. | `owasp_mapping.TYPE_TO_OWASP` | Add them, then delete them from `KNOWN_UNMAPPED` in `tests/test_owasp_mapping.py`. |
| good first issue | **Clickjacking check is a placeholder** (always an info note). | `selenium_scanner._test_clickjacking` | Can be done without a browser from `X-Frame-Options` / CSP `frame-ancestors`. |
| good first issue | **Three `SENSITIVE_PATHS` entries are never reported** (`.well-known/security.txt`, `swagger.json`, `api-docs`): they have no description. | `vulnerability_scanner.SENSITIVE_PATHS` | Decide whether each should be a finding or an info note. |
| good first issue | **Progress text mentions TLS "ciphers"**, but only the negotiated protocol is inspected. The `tls_cipher` type is never emitted. | `scanner._run_scan`, `tls_scanner` | Either implement cipher-suite checks or fix the wording. |
| good first issue | **Unknown scan IDs return HTTP 200** with `{"error": "Scan not found"}`. | `scanner.get_scan_status` / `app.py` | Return 404 (with a deprecation note, since clients may rely on today's behaviour). |
| good first issue | **PDF has no document metadata** (viewers show "anonymous"). | `report_generator._generate_pdf` | Set title/author/subject. |
| | **Burp**: address is hard-coded to `127.0.0.1:8080`, the REST-API path cannot receive credentials, and the connectivity check calls `httpbin.org`. | `burp_integration.py` | Make host/port configurable; drop the external dependency. |
| | **Not covered at all:** A04, A07, A09; no authenticated scanning; no crawling. | see [checks.md](docs/checks.md) | Large features; discuss first. |

## Security hardening

Tracked from [SECURITY.md](SECURITY.md#deploying-safely). Contributions here are especially valued.

- [ ] Optional **authentication** (API key or basic auth from an environment variable)
- [ ] **Target policy:** block loopback, link-local (`169.254.0.0/16`) and RFC 1918 targets by default, with an explicit opt-in
- [ ] **Configurable CORS origins** instead of `*`
- [ ] **Rate limiting** and a cap on concurrent scans
- [ ] **Evict finished scans** from `active_scans` (currently grows until restart)
- [ ] Validate `scan_id` as a UUID before using it in a file name (no traversal is possible today, verified by tests; this is defence in depth)
- [ ] Bind `python app.py` to `127.0.0.1` by default
- [ ] Run the Docker image as a non-root user (**test with a Render persistent disk first**; mounts are root-owned)
- [ ] Replace the plain-HTTP IP geolocation call (`ip-api.com`) or make it opt-in

## Housekeeping

- [ ] Remove unused dependencies: **`lxml`** and **`webdriver-manager`** are pinned but never imported
- [ ] Add type hints throughout and a `mypy` CI job
- [ ] Split `report_generator.py` (PDF/HTML/JSON) and `vulnerability_scanner.py` (900+ lines) into smaller modules
- [ ] Add a real screenshot of the dashboard to the README (`docs/assets/`). The layout was checked with a simulated browser and a layout renderer only, never in a full browser, so look at it in one first
- [ ] Publish a container image to GHCR on release

## Ideas (not commitments)

These are directions, not promises. Open a discussion before building any of them.

- Bounded, same-origin crawling to find more parameters and forms
- Authenticated scanning (session cookie / header supplied per scan)
- SARIF and CSV export for CI pipelines; a headless CLI mode
- A stable plugin API for third-party checks
- Baseline comparison: "what changed since the last scan?"
