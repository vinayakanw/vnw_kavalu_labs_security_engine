"""Documentation must stay true to the code and internally consistent.

These tests exist because stale docs are the most common way a project loses
trust. They check, mechanically:

  * every finding type the engine can emit is catalogued in docs/checks.md
  * every environment variable the code reads is documented
  * the grade bands and severity weights in the docs match detection_engine.py
  * every relative link and #anchor in every Markdown file resolves
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

from core.detection_engine import GRADE_BANDS, SEVERITY_WEIGHT, _grade_for_score
from tests.test_owasp_mapping import emitted_finding_types

ROOT = Path(__file__).resolve().parent.parent
MARKDOWN_FILES = sorted([*ROOT.glob("*.md"), *(ROOT / "docs").glob("*.md"), *(ROOT / ".github").glob("*.md")])

FENCE = re.compile(r"^(```|~~~)")
INLINE_LINK = re.compile(r"(?<!\!)\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
HTML_SRC = re.compile(r"""<img[^>]+src=["']([^"']+)["']""")
REPO_BLOB = re.compile(r"github\.com/vinayakanw/vnw_kavalu_security_engine/blob/main/([^)#\s\"']+)")


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


# --------------------------------------------------------------------------- code <-> docs


def test_every_finding_type_is_catalogued_in_checks_md():
    doc = read("docs/checks.md")
    missing = sorted(t for t in emitted_finding_types() if f"`{t}`" not in doc)
    assert not missing, f"Add these finding types to the table in docs/checks.md: {missing}"


def environment_variables_read_by_code() -> set[str]:
    names = set()
    for path in [ROOT / "app.py", *sorted((ROOT / "core").glob("*.py"))]:
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                is_environ_get = node.func.attr == "get" and ast.unparse(node.func.value) == "os.environ"
                is_getenv = ast.unparse(node.func) == "os.getenv"
                if (is_environ_get or is_getenv) and node.args and isinstance(node.args[0], ast.Constant):
                    names.add(node.args[0].value)
    return names


def test_environment_variables_found_by_the_scan_are_the_expected_ones():
    """Guards the scan itself, so the next test cannot pass vacuously."""
    assert {"PORT", "KAVALU_DATA_DIR", "SECRET_KEY", "EXTERNAL_MODEL_URL"} <= environment_variables_read_by_code()


@pytest.mark.parametrize("document", ["docs/configuration.md", ".env.example"])
def test_every_environment_variable_is_documented(document):
    text = read(document)
    missing = sorted(name for name in environment_variables_read_by_code() if name not in text)
    assert not missing, f"{document} does not mention: {missing}"


@pytest.mark.parametrize("document", ["README.md", "docs/architecture.md"])
def test_grade_labels_match_the_code(document):
    text = read(document)
    for threshold, *_ in GRADE_BANDS:
        band = _grade_for_score(threshold)
        assert f"**{band['grade']}**" in text, f"{document}: grade {band['grade']} missing"
        assert band["label"] in text, f"{document}: label {band['label']!r} missing"


@pytest.mark.parametrize("document", ["README.md", "docs/architecture.md"])
def test_severity_weights_match_the_code(document):
    text = read(document)
    for severity, weight in SEVERITY_WEIGHT.items():
        assert re.search(rf"\|\s*{severity}\s*\|\s*{weight}\s*\|", text), (
            f"{document}: row for {severity} = {weight} not found"
        )


# --------------------------------------------------------------------------- links


def github_slug(heading: str) -> str:
    """Approximate GitHub's heading-to-anchor algorithm."""
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", heading)  # [text](url) -> text
    text = re.sub(r"<[^>]+>", "", text)  # strip inline HTML
    text = text.replace("`", "").replace("*", "")
    text = text.strip().lower()
    text = re.sub(r"[^\w\- ]", "", text, flags=re.UNICODE)  # drop punctuation, emoji, dashes like "—"
    return text.replace(" ", "-")


def parse_markdown(path: Path):
    """Return (anchors, links) for a Markdown file, ignoring fenced code blocks."""
    anchors, links, seen, in_fence = set(), [], {}, False
    for line in path.read_text(encoding="utf-8").splitlines():
        if FENCE.match(line.strip()):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        heading = re.match(r"^#{1,6}\s+(.*?)\s*#*\s*$", line)
        if heading:
            slug = github_slug(heading.group(1))
            count = seen.get(slug, 0)
            anchors.add(slug if count == 0 else f"{slug}-{count}")
            seen[slug] = count + 1
        for match in INLINE_LINK.finditer(line):
            links.append(match.group(1))
        for match in HTML_SRC.finditer(line):
            links.append(match.group(1))
    return anchors, links


ANCHORS = {path: parse_markdown(path)[0] for path in MARKDOWN_FILES}


def test_every_markdown_file_was_found():
    names = {p.name for p in MARKDOWN_FILES}
    assert {
        "README.md",
        "CONTRIBUTING.md",
        "SECURITY.md",
        "CHANGELOG.md",
        "ROADMAP.md",
        "checks.md",
        "api.md",
        "PULL_REQUEST_TEMPLATE.md",
    } <= names


@pytest.mark.parametrize("path", MARKDOWN_FILES, ids=lambda p: str(p.relative_to(ROOT)))
def test_relative_links_and_anchors_resolve(path):
    problems = []
    for target in parse_markdown(path)[1]:
        if re.match(r"^[a-z][a-z0-9+.-]*:", target):  # http:, https:, mailto:
            blob = REPO_BLOB.search(target)
            if blob and not (ROOT / blob.group(1)).exists():
                problems.append(f"{target} -> repository file does not exist")
            continue
        file_part, _, anchor = target.partition("#")
        destination = path if not file_part else (path.parent / file_part).resolve()
        if not destination.exists():
            problems.append(
                f"{target} -> {destination.relative_to(ROOT) if ROOT in destination.parents else destination} not found"
            )
            continue
        if anchor and destination.suffix == ".md":
            known = ANCHORS.get(destination) or parse_markdown(destination)[0]
            if anchor not in known:
                problems.append(f"{target} -> no heading '#{anchor}' in {destination.relative_to(ROOT)}")
    assert not problems, f"{path.relative_to(ROOT)}:\n  " + "\n  ".join(problems)


# --------------------------------------------------------------------------- naming

PRODUCT_NAME = "Kavalu Security Engine"
RETIRED_NAMES = ("Kavalu Labs Security Engine", "KavaluLabsSecurityEngine")
TEXT_SUFFIXES = {
    ".md",
    ".py",
    ".js",
    ".mjs",
    ".css",
    ".html",
    ".yml",
    ".yaml",
    ".toml",
    ".svg",
    ".json",
    ".example",
    "",
}


def project_text_files():
    skipped_dirs = {".git", "node_modules", ".ruff_cache", ".pytest_cache", "__pycache__", ".venv"}
    for path in sorted(ROOT.rglob("*")):
        if path.is_file() and path.suffix in TEXT_SUFFIXES and not (set(path.relative_to(ROOT).parts) & skipped_dirs):
            if path.name not in {"package-lock.json"}:
                yield path


def test_the_retired_project_name_is_not_used_anywhere():
    """The project was renamed to 'Kavalu Security Engine'. CHANGELOG.md may describe the rename."""
    offenders = []
    for path in project_text_files():
        if path.name in {"CHANGELOG.md", "test_docs.py"}:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        offenders += [f"{path.relative_to(ROOT)}: {name}" for name in RETIRED_NAMES if name in text]
    assert not offenders, offenders


@pytest.mark.parametrize(
    "relative", ["README.md", "index.html", "app.py", "CONTRIBUTING.md", "SECURITY.md", "docs/assets/banner.svg"]
)
def test_the_current_project_name_is_used(relative):
    assert PRODUCT_NAME in read(relative)


def test_the_name_in_reports_and_the_user_agent_matches():
    from core.report_generator import ENGINE_NAME
    from core.vulnerability_scanner import VulnerabilityScanner

    assert ENGINE_NAME == PRODUCT_NAME
    assert "KavaluSecurityEngine/" in VulnerabilityScanner().session.headers["User-Agent"]
