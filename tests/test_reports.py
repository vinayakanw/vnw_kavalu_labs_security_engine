"""Report generation (PDF / HTML / JSON) from a persisted scan state file."""

import json

import pytest

from core import paths
from core.report_generator import ReportGenerator


@pytest.fixture()
def saved_scan(sample_scan_state):
    with open(paths.scan_state_path(sample_scan_state["scan_id"]), "w", encoding="utf-8") as fh:
        json.dump(sample_scan_state, fh)
    return sample_scan_state


def test_pdf_report_is_written_to_the_reports_dir_and_is_a_real_pdf(saved_scan, isolated_data_dirs):
    path = ReportGenerator.generate_report(saved_scan["scan_id"], "pdf")
    assert path.startswith(str(isolated_data_dirs / "reports"))
    with open(path, "rb") as fh:
        assert fh.read(5) == b"%PDF-"


def test_html_report_is_streamed_not_written_to_disk(saved_scan, isolated_data_dirs):
    filename, mimetype, payload = ReportGenerator.build_download(saved_scan["scan_id"], "html")
    assert filename.endswith(".html")
    assert mimetype.startswith("text/html")
    assert b"http://example.test/" in payload
    assert list((isolated_data_dirs / "reports").iterdir()) == []


def test_json_report_round_trips_and_keeps_the_findings(saved_scan):
    filename, mimetype, payload = ReportGenerator.build_download(saved_scan["scan_id"], "json")
    assert filename.endswith(".json")
    assert mimetype == "application/json"
    data = json.loads(payload)
    assert data["report_metadata"]["format"] == "json"
    assert data["scan"]["scan_id"] == saved_scan["scan_id"]
    assert data["scan"]["target_url"] == "http://example.test/"
    assert len(data["findings"]) == len(saved_scan["findings"])
    assert data["risk"]["grade"] == saved_scan["risk"]["grade"]
    assert len(data["owasp_coverage"]) == 10
    # Most severe first.
    assert data["findings"][0]["severity"] == "critical"


def test_html_report_escapes_attacker_controlled_text(saved_scan):
    """A target controls finding text (titles, evidence). It must never become live markup in the report."""
    saved_scan["findings"][0]["title"] = "<script>alert('pwned')</script>"
    saved_scan["findings"][0]["details"]["evidence"] = "<img src=x onerror=alert(1)>"
    with open(paths.scan_state_path(saved_scan["scan_id"]), "w", encoding="utf-8") as fh:
        json.dump(saved_scan, fh)

    _, _, payload = ReportGenerator.build_download(saved_scan["scan_id"], "html")
    html = payload.decode()
    assert "<script>alert('pwned')</script>" not in html
    assert "<img src=x onerror=alert(1)>" not in html
    assert "&lt;script&gt;" in html


def test_unknown_scan_raises_value_error():
    with pytest.raises(ValueError):
        ReportGenerator.generate_report("no-such-scan", "pdf")
    with pytest.raises(ValueError):
        ReportGenerator.build_download("no-such-scan", "html")


def test_download_endpoint_serves_all_three_formats(client, saved_scan):
    sid = saved_scan["scan_id"]
    expected = {"pdf": "application/pdf", "html": "text/html", "json": "application/json"}
    for fmt, mimetype in expected.items():
        response = client.get(f"/api/report/{sid}?format={fmt}")
        assert response.status_code == 200, fmt
        assert response.mimetype == mimetype
        assert "attachment" in response.headers["Content-Disposition"]


def test_default_report_format_is_pdf(client, saved_scan):
    assert client.get(f"/api/report/{saved_scan['scan_id']}").mimetype == "application/pdf"


def test_html_report_is_self_contained_and_uses_system_fonts(saved_scan):
    """An offline report must not call out to other websites or depend on installed fonts."""
    _, _, payload = ReportGenerator.build_download(saved_scan["scan_id"], "html")
    html = payload.decode()
    assert "<link" not in html and "@import" not in html and "url(" not in html
    assert "src=" not in html.replace("<script", "")  # no remote images or scripts
    for decorative in ("Anton", "Space Mono", "Inter,"):
        assert decorative not in html, decorative
    assert "system-ui" in html


def test_report_status_labels_are_plain_sentence_case():
    from core.report_generator import STATUS_LABEL

    assert STATUS_LABEL["not_tested"] == "No findings"
    assert all(
        label == label.capitalize() or label[0].isupper() and label[1:].islower() for label in STATUS_LABEL.values()
    )
