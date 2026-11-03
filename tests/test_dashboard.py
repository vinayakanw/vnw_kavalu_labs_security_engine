"""Static rules for the dashboard (index.html, static/app.js, static/style.css).

Fast checks that need no browser. The behaviour of the page is covered by the
browser-level test in tests/dashboard/ (run it with `make test-ui`).

The rules exist because the dashboard displays data from websites we scan,
and the scanner itself must be a safe page to look at:

  * nothing is loaded from other websites (no CDN, no web fonts)
  * no inline scripts, inline styles or inline event handlers (so a strict
    Content-Security-Policy works)
  * scan data is never inserted as HTML
  * text colours stay readable (WCAG AA contrast)
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from core import report_generator

ROOT = Path(__file__).resolve().parent.parent
HTML = (ROOT / "index.html").read_text(encoding="utf-8")
JS = (ROOT / "static" / "app.js").read_text(encoding="utf-8")
CSS = (ROOT / "static" / "style.css").read_text(encoding="utf-8")


def without_comments(source: str) -> str:
    source = re.sub(r"/\*.*?\*/", "", source, flags=re.S)
    return re.sub(r"(?m)^\s*//.*$", "", source)


# ------------------------------------------------------------------ the page


def test_page_loads_only_its_own_static_files():
    loaded = re.findall(r'<(?:script|link|img)\b[^>]*?(?:src|href)="([^"]+)"', HTML)
    assert loaded, "index.html loads no assets at all"
    assert all(url.startswith("/static/") for url in loaded), loaded


def test_page_has_no_inline_scripts_styles_or_event_handlers():
    assert not re.search(r"<script(?![^>]*\bsrc=)[^>]*>\s*\S", HTML, re.IGNORECASE), "inline <script> found"
    assert "<style" not in HTML, "inline <style> found"
    assert not re.search(r"\sstyle=", HTML), "inline style attribute found"
    assert not re.search(r"\son[a-z]+=", HTML), "inline event handler found"


def test_inline_script_check_is_case_insensitive():
    assert re.search(r"<script(?![^>]*\bsrc=)[^>]*>\s*\S", "<SCRIPT>alert(1)</SCRIPT>", re.IGNORECASE)


def test_page_basics_for_accessibility():
    assert '<html lang="en">' in HTML
    assert 'name="viewport"' in HTML
    assert "<main" in HTML and "<h1>" in HTML
    for field_id in ("target-url",):
        assert f'<label for="{field_id}">' in HTML


# ---------------------------------------------------------------- the script


def test_script_never_writes_html():
    code = without_comments(JS)
    for forbidden in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
        assert forbidden not in code, f"static/app.js must not use {forbidden}"


def test_every_element_id_the_script_uses_exists_in_the_page():
    ids_in_page = set(re.findall(r'\bid="([^"]+)"', HTML))
    ids_used = set(re.findall(r"\$\('([^']+)'\)", JS))
    ids_used |= {f"download-{fmt}" for fmt in ("pdf", "html", "json")}  # built from a template string
    missing = sorted(ids_used - ids_in_page)
    assert not missing, f"app.js uses ids that index.html does not define: {missing}"


def test_every_module_value_is_one_the_api_accepts():
    values = set(re.findall(r'name="module" value="([^"]+)"', HTML))
    assert values == {"recon", "owasp", "tls", "misconfig", "browser", "burp"}


# ------------------------------------------------------------- the stylesheet


def test_stylesheet_uses_system_fonts_only():
    assert "@font-face" not in CSS and "@import" not in CSS and "url(" not in CSS
    for decorative in ("Anton", "Space Mono", "Inter", "Impact", "Google"):
        assert decorative not in CSS, f"decorative font {decorative!r} in style.css"
    assert "system-ui" in CSS


def luminance(hex_colour: str) -> float:
    channels = [int(hex_colour.lstrip("#")[i : i + 2], 16) / 255 for i in (0, 2, 4)]
    linear = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def contrast(first: str, second: str) -> float:
    bright, dark = sorted((luminance(first), luminance(second)), reverse=True)
    return (bright + 0.05) / (dark + 0.05)


def css_palette() -> dict[str, str]:
    return dict(re.findall(r"--([a-z]+):\s*(#[0-9a-fA-F]{6})", CSS))


@pytest.mark.parametrize("name", ["text", "muted", "accent", "critical", "high", "medium", "low", "info", "ok"])
@pytest.mark.parametrize("background", ["surface", "bg"])
def test_dashboard_text_colours_meet_wcag_aa(name, background):
    palette = css_palette()
    assert contrast(palette[name], palette[background]) >= 4.5, (name, palette[name], background)


@pytest.mark.parametrize("name", sorted(report_generator.SEVERITY_COLOR_HEX))
def test_report_severity_colours_are_readable_on_white(name):
    assert contrast(report_generator.SEVERITY_COLOR_HEX[name], "#FFFFFF") >= 4.5, name


@pytest.mark.parametrize("name", sorted(report_generator.STATUS_COLOR_HEX))
def test_report_status_colours_are_readable_on_white(name):
    assert contrast(report_generator.STATUS_COLOR_HEX[name], "#FFFFFF") >= 4.5, name


def test_dashboard_and_reports_share_one_palette():
    palette = css_palette()
    for severity in ("critical", "high", "medium", "low", "info"):
        assert report_generator.SEVERITY_COLOR_HEX[severity].lower() == palette[severity].lower(), severity


# ------------------------------------------------------------- served by Flask


@pytest.mark.parametrize("path", ["/", "/static/app.js", "/static/style.css", "/api/history"])
def test_security_headers_are_sent(client, path):
    headers = client.get(path).headers
    policy = headers["Content-Security-Policy"]
    assert "default-src 'none'" in policy and "script-src 'self'" in policy
    assert "frame-ancestors 'none'" in policy
    assert "unsafe-inline" not in policy and "unsafe-eval" not in policy
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["Referrer-Policy"] == "no-referrer"


def test_static_files_are_served_with_the_right_types(client):
    assert client.get("/static/app.js").mimetype in ("text/javascript", "application/javascript")
    assert client.get("/static/style.css").mimetype == "text/css"
    assert client.get("/static/favicon.svg").mimetype == "image/svg+xml"
    assert client.get("/static/does-not-exist.js").status_code == 404


def test_dashboard_text_matches_the_engine_not_marketing():
    """The page must not claim checks the engine does not perform."""
    for claim in ("cipher suite", "HSTS enforcement", "boolean blind", "Independent Target"):
        assert claim.lower() not in HTML.lower() + JS.lower(), claim
