# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Add your entry under **Unreleased** in the same pull request as your change.

## [Unreleased]

## [2.0.0] - 2026-11-01

First public release. The engine itself is version 2.0 (it identifies as such in its User-Agent and in every
report); this release adds the project infrastructure around it, rebuilds the dashboard, and fixes the problems
found while documenting and testing it.

### Added
- Test suite: offline, running on Python 3.10, 3.11 and 3.12. Includes a deliberately vulnerable local target
  (`tests/vulnerable_server.py`, also runnable with `make demo-target`) so detection logic is tested end to end
  without touching the internet.
- Browser-level dashboard test (`make test-ui`): loads the real page in a simulated browser, runs a real scan and checks
  the results, hostile-data handling, the polling fallback and error messages.
- Tests that keep the documentation true to the code (finding types, environment variables, scoring, links and anchors)
  and that enforce the dashboard rules (no external files, no inline scripts, readable colours).
- Security headers on every response: a strict `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`.
- Continuous integration: lint and formatting, tests on three Python versions, the dashboard test, dependency audit,
  CodeQL, Docker build with smoke test, DCO check, tag-driven releases, Dependabot.
- Community files: `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`, `SUPPORT.md`, `LICENSE` (MIT), `DCO`, `ROADMAP.md`,
  issue forms and a pull request template.
- Documentation: architecture, API reference, configuration, detection catalog, "adding a check" guide, deployment, troubleshooting.
- Developer tooling: `Makefile`, `pyproject.toml`, `requirements-dev.txt`, `.editorconfig`, `.gitattributes`,
  `.pre-commit-config.yaml`, `.prettierrc.json`, `.env.example`.
- `scripts/check_dco.py` (sign-off check), `scripts/generate_sample_report.py`, `scripts/run_dashboard_tests.py`.
- Docker image: OCI labels and a `HEALTHCHECK`.

### Changed
- **Project renamed from "Kavalu Labs Security Engine" to "Kavalu Security Engine".** Kavalu Labs remains the credited
  maker. The name changed in the dashboard, both report formats (the PDF title and the `report_metadata.engine` value
  in the JSON report), the documentation, the Docker image tag (`kavalu-security-engine`) and the Render service name.
  The scanner's User-Agent is now `KavaluSecurityEngine/2.0 (+https://kavalu-labs.nayaka100.in/)`. It no longer says
  "Non-destructive scanner" (the probes are active) and no longer points at a domain that is not ours.
- **Dashboard rebuilt** as three small files (`index.html`, `static/style.css`, `static/app.js`, about 1,400 lines in total
  instead of one file of 2,300). Plain layout, system fonts only, nothing loaded from other websites, keyboard and screen-reader friendly.
  Descriptions now match what the engine really does. Selecting no checks is now an error instead of silently running everything.
  Existing scan history saved in the browser keeps working.
- **Reports** (PDF and HTML) use the same plain palette as the dashboard. Every text colour now meets the 4.5:1 contrast
  minimum (several status colours were nearly invisible on the white PDF page). Status labels are plain sentences ("No findings",
  not "NOT APPLICABLE"). The HTML report is a clean white page that prints well.
- All Python code formatted with `ruff format` and linted with a 120-character line limit (previously about 425 lines were longer).
  A syntax-tree comparison confirmed the formatting changed layout only. Module docstrings rewritten to be short and accurate.
- **Security:** upgraded 9 pinned dependencies that had known advisories (`flask`, `werkzeug`, `jinja2`, `requests`,
  `urllib3`, `certifi`, `idna`, `h11`, `lxml`). `pip-audit` now reports none. Scan results and all three report formats were
  verified identical before and after.
- README rewritten to match the code. Corrected: letter-grade bands, available report formats (PDF, HTML and JSON, not PDF only),
  OWASP coverage (A04, A07 and A09 have no automated checks), TLS capabilities (no cipher-suite enumeration), and the quick-start commands.
- `RENDER_DEPLOY.md` moved to `docs/deployment.md` and extended with local and Docker instructions.

### Fixed
- The dashboard only reached its API when served on port 5000 (or 80/443); on any other port, including the Docker image's
  port 10000, it failed. It now always talks to the server that served it.
- **Security:** the old dashboard put developer "social profile" links from a scanned website's metadata into the page without
  escaping, so a hostile site could run script in the scanner's own page. The new dashboard never inserts scan data as HTML.
- A comment in `app.py` told operators to deploy with several workers, which would break scans (state is per process).
- A PDF summary label was cut off ("Low / Inf").
- `dom_xss` and `insecure_form` findings from the browser module were classified as A05; they are now A03 (CWE-79) and A02 (CWE-319).
- The informational `burp` finding type no longer counts toward an OWASP category.
- The Laravel "Whoops" debug-page pattern contained stray backslashes and could never match.
- Dead code in the placeholder clickjacking check removed.

### Security
- Documented the engine's deployment risks (no authentication, scans any target including private addresses, wildcard CORS,
  dev server listens on all interfaces) and the third-party services it contacts. See `SECURITY.md`.

[Unreleased]: https://github.com/vinayakanw/vnw_kavalu_security_engine/compare/v2.0.0...HEAD
[2.0.0]: https://github.com/vinayakanw/vnw_kavalu_security_engine/releases/tag/v2.0.0
