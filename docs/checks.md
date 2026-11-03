# Detection catalog

What the engine checks, how, and (just as important) what it does **not** check.
Everything here was verified against the code; `tests/test_docs.py` fails if a new finding type is added to the
engine without being listed in the [finding types](#finding-types) table.

- [How the probes work](#how-the-probes-work)
- [Checks by module](#checks-by-module)
- [OWASP Top 10:2021 coverage](#owasp-top-102021-coverage)
- [Finding types](#finding-types)
- [Known blind spots](#known-blind-spots)

## How the probes work

- The scanner examines **one page**, the URL you give it. It does not crawl or spider.
- Parameter-based probes (XSS, command injection, path traversal) use the **query parameters already in the URL**
  plus **form fields found on that page**. SQL injection additionally tries a default `id` parameter when the URL has none.
- The probes are *active*: they send payloads and submit forms. If a target is vulnerable, a payload can run
  (for example `; whoami` or `| id`), and a form POST can create data. Only scan systems you are authorised to test.
- Requests use short timeouts and `verify=False`, so sites with broken TLS can still be audited.
  Probe traffic identifies itself with the User-Agent `KavaluSecurityEngine/2.0 (+https://kavalu-labs.nayaka100.in/)`,
  which site operators can use to recognise it in their logs.

## Checks by module

### Reconnaissance: `recon`

| Check | Finding type | Severity |
|---|---|---|
| Hosting platform, IP, reverse DNS, ASN, ISP, geolocation | `deployment_infrastructure` | info |
| Public developer attribution: `meta author`, copyright, `humans.txt`, social links | `developer_identity` | info |
| Target response summary and forms detected | `info` | info |
| Six security headers: `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options` (medium if missing); `X-Content-Type-Options`, `Referrer-Policy` (low); `Permissions-Policy` (info) | `security_header` | per header |
| Target unreachable during recon | `error` | high |

Header checks only run when `recon` is selected.

### Injection probes: `owasp`

| Check | Finding type | Severity |
|---|---|---|
| Reflected XSS in URL parameters (first 3 of 9 payloads) | `xss` | high |
| XSS in form fields | `xss` | high |
| SQL injection: database error patterns; time-based blind; form fields | `sql_injection` | critical |
| OS command injection (`; whoami`, `\| id`, …) in parameters and form fields | `command_injection` | critical |
| Path traversal / local file inclusion (`../../../../etc/passwd`, `…/windows/win.ini`) | `path_traversal` | critical |
| Open redirect via parameters named `url`, `redirect`, `return`, `return_url`, `next`, `goto`, `redir`, `continue`, `dest` | `open_redirect` | medium |
| Host-header injection (reflected host) | `host_header_injection` | medium |
| Forms without an anti-CSRF token | `csrf` | medium |
| Sensitive keywords inside HTML comments | `info_disclosure` | low |
| Parameters whose *names* suggest server-side URL fetching (`url`, `uri`, `path`, `fetch`, `src`, `target`, `proxy`, `callback`, `webhook`). **Heuristic only**: no SSRF request is attempted | `ssrf_candidate` | info |

### Transport security: `tls`

| Check | Finding type | Severity |
|---|---|---|
| Target is plain HTTP (the handshake is skipped) | `no_https` | high |
| Negotiated protocol is current (TLS 1.2/1.3) | `tls_version` | info |
| TLS 1.2+ handshake fails (a deprecated version may be required; not confirmed) | `tls_version` | info |
| Certificate expired | `tls_certificate` | critical |
| Certificate fails verification | `tls_certificate` | critical |
| Certificate expires within 30 days | `tls_certificate` | medium |
| Certificate valid; certificate details; handshake could not complete | `tls_certificate` | info |

It performs **one** handshake with TLS 1.2 as the minimum and records the negotiated protocol. It does **not** retry with deprecated TLS versions or enumerate cipher suites.

### Misconfiguration and exposure: `misconfig`

| Check | Finding type | Severity |
|---|---|---|
| Sensitive files returning HTTP 200 with content: `.git/HEAD`, `.env`, `database.sql` (**high**); `wp-config.php.bak`, `config.php.bak`, `.DS_Store`, `backup.zip`, `server-status`, `phpinfo.php` (**medium**) | `exposed_path` | high / medium |
| CORS: wildcard origin together with credentials; or arbitrary `Origin` reflected | `cors_misconfiguration` | high |
| `OPTIONS` response advertises `PUT`, `DELETE`, `TRACE` or `CONNECT` (the methods are *not* actually invoked) | `http_method` | medium |
| Cookies missing `Secure` / `HttpOnly` / `SameSite` | `insecure_cookie` | medium |
| Stack traces and debug pages (Python, Laravel Whoops, Java, .NET, PHP, Django, Flask/Werkzeug, generic server error) triggered by a malformed probe | `debug_exposure` | medium |
| Outdated front-end libraries by version in the script URL: jQuery < 3.5.0, Bootstrap < 4.3.1, AngularJS < 1.8.0, lodash < 4.17.21, Moment.js < 2.29.4 | `outdated_component` | medium |
| Cross-origin `<script>` tags without Subresource Integrity | `missing_sri` | low |
| Connection problem while auditing | `error` | info |

### Browser automation: `browser`

Requires headless Chromium and Selenium, plus `use_selenium: true`. The orchestrator waits at most **5 seconds**
for this module; see [Known blind spots](#known-blind-spots).

| Check | Finding type | Severity |
|---|---|---|
| DOM XSS through the location hash | `dom_xss` | critical |
| Mixed content (HTTP resources on an HTTPS page) | `mixed_content` | medium |
| Form that submits to an `http://` action | `insecure_form` | high |
| Password field with autocomplete enabled | `password_security` | low |
| Potentially sensitive data in `localStorage`/`sessionStorage` | `client_storage` | medium |
| Clickjacking: **placeholder**, currently always an informational note | `clickjacking` | info |

### Burp Suite: `burp`

Routes the scanner's HTTP traffic through a Burp proxy at `127.0.0.1:8080` and reports whether the proxy answered
(`burp`, info). A REST-API path exists in code (`burp_issue`), but nothing can set the credentials it needs, so it never runs.

### External ML plugin

Optional ([configuration](configuration.md#external-ml-model-plugin)). Verdicts appear as `external_model` findings.

## OWASP Top 10:2021 coverage

"Automated checks" means a built-in check that emits a finding mapped to that category. **Three categories have none.**

| Category | Automated checks | Built-in coverage |
|---|---|---|
| **A01** Broken Access Control | Yes | Exposed files, CORS, risky `Allow` methods, open redirect, path traversal, CSRF, clickjacking *(placeholder)* |
| **A02** Cryptographic Failures | Yes | No HTTPS, deprecated TLS, certificate problems, cookie flags, mixed content, insecure forms |
| **A03** Injection | Yes | XSS, SQLi, command injection, host-header injection, DOM XSS |
| **A04** Insecure Design | No | None. Needs human threat modelling. |
| **A05** Security Misconfiguration | Yes | Security headers, debug output, HTML-comment leakage |
| **A06** Vulnerable and Outdated Components | Yes (narrow) | Five JavaScript libraries only; not a CVE database |
| **A07** Identification and Authentication Failures | No | None. (The password-autocomplete check is currently unmapped, so it lands in A05.) |
| **A08** Software and Data Integrity Failures | Yes (narrow) | Missing Subresource Integrity only |
| **A09** Security Logging and Monitoring Failures | No | None. Not observable from outside. |
| **A10** Server-Side Request Forgery | Heuristic only | Flags parameter names only; never attempts SSRF |

A passing scan therefore does **not** mean "secure". It means "none of these checks found anything".

## Finding types

Every `type` the engine can emit. The OWASP/CWE tags come from `TYPE_TO_OWASP` in `core/owasp_mapping.py`.
`—` = informational, no OWASP category.

| Type | OWASP | CWE | Module |
|---|:---:|---|---|
| `browser_automation` | — | — | scanner |
| `burp` | — | — | burp |
| `burp_issue` | *(unmapped → A05)* | — | burp (dormant) |
| `clickjacking` | A01 | CWE-1021 | browser |
| `client_storage` | *(unmapped → A05)* | — | browser |
| `command_injection` | A03 | CWE-78 | owasp |
| `cors_misconfiguration` | A01 | CWE-942 | misconfig |
| `csrf` | A01 | CWE-352 | owasp |
| `debug_exposure` | A05 | CWE-489, CWE-209 | misconfig |
| `deployment_infrastructure` | — | — | recon |
| `developer_identity` | — | — | recon |
| `dom_xss` | A03 | CWE-79 | browser |
| `error` | A05 | CWE-209 | all |
| `exposed_path` | A01 | CWE-538, CWE-200 | misconfig |
| `external_model` | — | — | plugin |
| `host_header_injection` | A03 | CWE-644 | owasp |
| `http_method` | A01 | CWE-650 | misconfig |
| `info` | — | — | recon, browser |
| `info_disclosure` | A05 | CWE-200 | owasp |
| `insecure_cookie` | A02 | CWE-614, CWE-1004 | misconfig |
| `insecure_form` | A02 | CWE-319 | browser |
| `missing_sri` | A08 | CWE-494 | misconfig |
| `mixed_content` | A02 | CWE-319 | browser |
| `no_https` | A02 | CWE-319 | tls |
| `open_redirect` | A01 | CWE-601 | owasp |
| `outdated_component` | A06 | CWE-1104, CWE-937 | misconfig |
| `password_security` | *(unmapped → A05)* | — | browser |
| `path_traversal` | A01 | CWE-22 | owasp |
| `security_header` | A05 | CWE-16 | recon |
| `sql_injection` | A03 | CWE-89 | owasp |
| `ssrf_candidate` | A10 | CWE-918 | owasp |
| `tls_certificate` | A02 | CWE-295 | tls |
| `tls_version` | A02 | CWE-326 | tls |
| `xss` | A03 | CWE-79 | owasp |

The three *unmapped* types are tracked as good first issues in the [roadmap](../ROADMAP.md).

## Known blind spots

Be honest with your stakeholders about these:

- **Single page, no crawling.** Anything not reachable from the URL you supply is not tested.
- **No authentication support.** The scanner cannot log in, so authenticated areas are out of scope.
- **Catch-all servers cause false positives.** The sensitive-path check flags any HTTP 200 with a body. A single-page app that
  returns its `index.html` for every path will appear to expose every file in the list. (The code comment mentions a soft-404 guard; none exists yet.)
- **Browser module is time-boxed to 5 s.** A real browser run usually needs longer. When it overruns, its findings are discarded and an informational notice is recorded.
- **Heuristics, not proof.** SQL injection is judged from error text and timing; XSS from payload reflection. Treat results as leads to verify.
- **Library version detection** reads versions from script URLs only.
