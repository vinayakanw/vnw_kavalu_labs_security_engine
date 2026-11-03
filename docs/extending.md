# Adding a detection check

A new check is a small, self-contained change. The engine already tags, scores, reports and renders anything that
follows the [finding schema](#1-the-finding-schema), so you only write the detection logic.

> **Before you start:** open a [new-check proposal](https://github.com/vinayakanw/vnw_kavalu_security_engine/issues/new/choose)
> and read the safety rules in [CONTRIBUTING.md](../CONTRIBUTING.md#safety-rules-for-checks).

## 1. The finding schema

A check returns a `list` of plain `dict`s:

```python
{
    "type": "directory_listing",  # required: lowercase snake_case, see step 3
    "severity": "medium",  # required: critical | high | medium | low | info
    "title": "Directory Listing Enabled",  # required: short, specific
    "description": "…what was found and why it matters…",
    "details": {"url": "…", "evidence": "…"},  # structured evidence for the report
    "remediation": "…the concrete fix…",
}
```

Do **not** set `owasp`, `owasp_code`, `owasp_name` or `cwe`; the orchestrator adds them from the mapping table (step 3).

Choosing a severity: `critical` = remote compromise or mass data exposure is likely if the issue is real;
`high` = serious, directly exploitable weakness; `medium` = exploitable with conditions or limited impact;
`low` = hardening gap; `info` = context that carries **no** score.

## 2. Write the check

Add a method to the class in the right module and call it from the module's entry point. For an HTTP probe that means
`core/vulnerability_scanner.py`: `scan_owasp()` for injection-style probes, `scan_misconfig()` for configuration and exposure.

```python
# core/vulnerability_scanner.py


def _test_directory_listing(self, target_url: str, proxies: Optional[Dict]) -> List[Dict]:
    findings = []
    try:
        resp = self.session.get(target_url, proxies=proxies, timeout=8)  # always set a timeout
        if "<title>Index of /" in resp.text:
            findings.append(
                {
                    "type": "directory_listing",
                    "severity": "medium",
                    "title": "Directory Listing Enabled",
                    "description": "The server lists directory contents, exposing file names and structure.",
                    "details": {"url": target_url},
                    "remediation": "Disable automatic directory indexing in the web-server configuration.",
                }
            )
    except requests.exceptions.RequestException:
        pass  # a failed probe is "no finding", never a crash
    return findings
```

then, inside `scan_misconfig()`:

```python
findings.extend(self._test_directory_listing(target_url, proxies))
```

Rules of thumb:

- **Always** pass `timeout=` and `proxies=proxies` (the proxy argument is how Burp routing works).
- **Catch `requests.exceptions.RequestException`**; never let one probe abort the scan.
- **Be deterministic.** No randomness, no wall-clock dependence in the verdict.
- **Never build a string by appending to a triple-quoted literal that is sent to a browser or a database.**
  Comments added "inside" such a literal become part of the payload.

## 3. Map it to OWASP and CWE

Add one line to `TYPE_TO_OWASP` in `core/owasp_mapping.py`:

```python
"directory_listing": {"owasp": "A05", "cwe": ["CWE-548"]},
```

Use `"owasp": None` for purely informational types. If you forget, `tests/test_owasp_mapping.py::test_every_emitted_finding_type_is_mapped`
fails and tells you exactly which type is missing. (Unmapped types silently fall back to A05, which hides coverage gaps.)

## 4. Test it, offline

Tests must never touch the public internet. Add a behaviour to the local target in `tests/vulnerable_server.py`
(for example a route that returns an `Index of /` page), then assert on it in `tests/test_vulnerability_scanner.py`:

```python
def test_directory_listing_is_flagged(vuln_scanner, vulnerable_url):
    findings = vuln_scanner.scan_misconfig(vulnerable_url + "listing/")
    assert "directory_listing" in {f["type"] for f in findings}
```

Also add a test for the **negative** case: a normal page must not trigger it.

## 5. Document it

1. Add the type to the table in [checks.md](checks.md#finding-types) and the check to its module table.
   `tests/test_docs.py` fails if a type is missing.
2. Add a line under `## [Unreleased]` in [CHANGELOG.md](../CHANGELOG.md).

## 6. Run everything

```bash
make check      # ruff + the whole test suite
```

## Adding a whole new module

Create `core/<name>_scanner.py` with a class exposing `scan(target_url) -> List[Dict]`, instantiate it in
`SecurityScanner.__init__`, add a `scan_types` branch in `_run_scan()` (and a progress milestone), and register it in
`detection_engine.summarize_engine_modules()` so it appears in reports. Open a proposal first; module changes touch the orchestrator.
