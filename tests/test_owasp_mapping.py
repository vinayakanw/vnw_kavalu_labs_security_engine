"""OWASP Top 10:2021 / CWE mapping, including a contract test over the source."""

import ast
import pathlib

import pytest

from core.owasp_mapping import OWASP_TOP_10, TYPE_TO_OWASP, build_coverage_matrix, classify, tag_finding
from core.plugin_model import _CATEGORY_TO_TYPE

CORE_DIR = pathlib.Path(__file__).resolve().parent.parent / "core"

# Finding types that are emitted today but not yet in TYPE_TO_OWASP, so they
# fall back to A05. Fix one by adding it to TYPE_TO_OWASP, then REMOVE it here
# (test_known_unmapped_list_has_no_stale_entries enforces that).
# Tracked in ROADMAP.md as a good first contribution.
KNOWN_UNMAPPED = {"burp_issue", "client_storage", "password_security"}


def emitted_finding_types():
    """Every constant ``'type'`` of a finding-shaped dict literal in core/*.py.

    A "finding-shaped" dict has both a ``type`` and a ``severity`` key, which
    excludes unrelated dicts such as browser resource records.
    """
    types = set()
    for path in sorted(CORE_DIR.glob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if not isinstance(node, ast.Dict):
                continue
            keys = {k.value: v for k, v in zip(node.keys, node.values) if isinstance(k, ast.Constant)}
            if "type" in keys and "severity" in keys and isinstance(keys["type"], ast.Constant):
                types.add(keys["type"].value)
    return types


def test_there_are_exactly_ten_categories_a01_to_a10():
    assert list(OWASP_TOP_10) == [f"A{n:02d}" for n in range(1, 11)]
    assert all(cat["code"].endswith(":2021") for cat in OWASP_TOP_10.values())


def test_every_mapping_points_at_a_real_category():
    for finding_type, entry in TYPE_TO_OWASP.items():
        assert entry["owasp"] is None or entry["owasp"] in OWASP_TOP_10, finding_type


def test_every_emitted_finding_type_is_mapped():
    """Guards against the bug this test was written for: a new check emits a
    type that is silently bucketed under A05 because nobody mapped it."""
    unmapped = emitted_finding_types() - set(TYPE_TO_OWASP) - KNOWN_UNMAPPED
    assert not unmapped, (
        f"Finding type(s) {sorted(unmapped)} are emitted but missing from TYPE_TO_OWASP "
        "in core/owasp_mapping.py. Add them (see docs/extending.md)."
    )


def test_known_unmapped_list_has_no_stale_entries():
    stale = KNOWN_UNMAPPED & set(TYPE_TO_OWASP)
    assert not stale, f"Now mapped, remove from KNOWN_UNMAPPED: {sorted(stale)}"
    assert KNOWN_UNMAPPED <= emitted_finding_types(), "KNOWN_UNMAPPED lists a type nothing emits"


def test_external_model_categories_resolve_to_mapped_types():
    for finding_type in _CATEGORY_TO_TYPE.values():
        assert finding_type in TYPE_TO_OWASP, finding_type


@pytest.mark.parametrize(
    ("finding_type", "owasp", "cwe"),
    [
        ("sql_injection", "A03", "CWE-89"),
        ("xss", "A03", "CWE-79"),
        ("dom_xss", "A03", "CWE-79"),  # regression: used to fall back to A05
        ("insecure_form", "A02", "CWE-319"),  # regression: used to fall back to A05
        ("path_traversal", "A01", "CWE-22"),
        ("outdated_component", "A06", None),
        ("missing_sri", "A08", None),
        ("ssrf_candidate", "A10", None),
    ],
)
def test_classification_of_known_types(finding_type, owasp, cwe):
    result = classify(finding_type)
    assert result["owasp"] == owasp
    if cwe:
        assert cwe in result["cwe"]


def test_unknown_type_falls_back_to_a05():
    result = classify("brand_new_check")
    assert result["owasp"] == "A05"
    assert result["owasp_name"] == OWASP_TOP_10["A05"]["name"]


def test_informational_types_have_no_owasp_category():
    for finding_type in ("info", "burp", "deployment_infrastructure"):
        assert classify(finding_type)["owasp"] is None


def test_tag_finding_adds_metadata_in_place():
    finding = {"type": "sql_injection", "severity": "critical"}
    returned = tag_finding(finding)
    assert returned is finding
    assert finding["owasp_code"] == "A03:2021"
    assert finding["owasp_name"] == "Injection"


def test_coverage_matrix_always_has_all_ten_categories():
    assert [row["key"] for row in build_coverage_matrix([])] == list(OWASP_TOP_10)


def test_coverage_matrix_status_precedence():
    findings = [
        {"type": "sql_injection", "severity": "critical"},  # A03 critical
        {"type": "csrf", "severity": "medium"},  # A01 attention
        {"type": "exposed_path", "severity": "high"},  # A01 high wins over medium
        {"type": "outdated_component", "severity": "low"},  # A06 attention
        {"type": "security_header", "severity": "info"},  # A05 clear (info only)
    ]
    status = {row["key"]: row["status"] for row in build_coverage_matrix(findings)}
    assert status["A03"] == "critical"
    assert status["A01"] == "high"
    assert status["A06"] == "attention"
    assert status["A05"] == "clear"
    assert status["A04"] == "not_tested"
