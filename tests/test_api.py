"""HTTP API contract, exercised through Flask's test client (no real server)."""

import pytest

import app as app_module


def test_dashboard_is_served(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"Kavalu" in response.data


def test_owasp_reference_endpoint_lists_all_ten_categories(client):
    data = client.get("/api/owasp-top10").get_json()
    assert [c["code"] for c in data] == [f"A{n:02d}:2021" for n in range(1, 11)]


def test_history_endpoint_is_intentionally_empty(client):
    """The server stores no global history (privacy by design); it doubles as the health check."""
    assert client.get("/api/history").get_json() == []


def test_cors_headers_are_present_on_normal_responses(client):
    assert client.get("/api/history").headers["Access-Control-Allow-Origin"] == "*"


def test_preflight_request_is_answered_without_hitting_a_route_handler(client):
    response = client.options("/api/scan")
    assert response.headers["Access-Control-Allow-Origin"] == "*"
    assert "POST" in response.headers["Access-Control-Allow-Methods"]


@pytest.mark.parametrize("body", [{}, {"url": ""}, {"url": "   "}])
def test_scan_requires_a_url(client, body):
    response = client.post("/api/scan", json=body)
    assert response.status_code == 400
    assert "required" in response.get_json()["error"].lower()


def test_scan_rejects_an_invalid_target_with_a_helpful_body(client, monkeypatch):
    monkeypatch.setattr(app_module.scanner, "validate_target", lambda url: (False, "DNS failed", None))
    response = client.post("/api/scan", json={"url": "nope.invalid"})
    assert response.status_code == 400
    assert response.get_json() == {"error": "DNS failed", "status_code": None, "target_valid": False}


def test_scan_start_passes_options_through_and_returns_the_scan_id(client, monkeypatch):
    captured = {}

    def fake_scan(**kwargs):
        captured.update(kwargs)
        return {"scan_id": "abc", "status": "started", "message": "Scan initiated successfully"}

    monkeypatch.setattr(app_module.scanner, "validate_target", lambda url: (True, "", 200))
    monkeypatch.setattr(app_module.scanner, "scan", fake_scan)

    response = client.post(
        "/api/scan",
        json={"url": " https://example.com ", "scan_types": ["owasp"], "use_burp": True, "use_selenium": False},
    )
    assert response.status_code == 200
    assert response.get_json()["scan_id"] == "abc"
    assert captured == {
        "target_url": "https://example.com",
        "scan_types": ["owasp"],
        "use_burp": True,
        "use_selenium": False,
    }


def test_scan_defaults_are_all_modules_selenium_on_burp_off(client, monkeypatch):
    captured = {}
    monkeypatch.setattr(app_module.scanner, "validate_target", lambda url: (True, "", 200))
    monkeypatch.setattr(app_module.scanner, "scan", lambda **kw: captured.update(kw) or {"scan_id": "x"})
    client.post("/api/scan", json={"url": "https://example.com"})
    assert (captured["scan_types"], captured["use_burp"], captured["use_selenium"]) == (["all"], False, True)


def test_unexpected_scanner_error_is_logged_and_returns_a_generic_500(client, monkeypatch, caplog):
    monkeypatch.setattr(app_module.scanner, "validate_target", lambda url: (True, "", 200))

    def explode(**kwargs):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(app_module.scanner, "scan", explode)
    response = client.post("/api/scan", json={"url": "https://example.com"})
    assert response.status_code == 500
    assert response.get_json() == {"error": "An unexpected error occurred while starting the scan."}
    assert "Unexpected error while starting scan" in caplog.text


def test_unknown_scan_status_is_http_200_with_an_error_body(client):
    """Documented quirk (see docs/api.md): not-found is signalled in the body, not the status code."""
    response = client.get("/api/scan/status/does-not-exist")
    assert response.status_code == 200
    assert response.get_json() == {"error": "Scan not found"}


def test_stream_for_unknown_scan_emits_an_error_event(client):
    response = client.get("/api/scan/stream/does-not-exist")
    assert response.mimetype == "text/event-stream"
    body = response.get_data(as_text=True)
    assert body.startswith("event: error")
    assert "scan not found" in body


def test_report_for_unknown_scan_is_404_for_every_format(client):
    for fmt in ("pdf", "html", "json"):
        assert client.get(f"/api/report/missing?format={fmt}").status_code == 404


def test_unsupported_report_format_lists_the_supported_ones(client):
    response = client.get("/api/report/anything?format=xml")
    assert response.status_code == 400
    assert response.get_json()["supported_formats"] == ["pdf", "html", "json"]


@pytest.mark.parametrize(
    "evil_id",
    ["..%2F..%2Fetc%2Fpasswd", "..%5C..%5Cwindows%5Cwin.ini", "%00", "....//....//etc/passwd"],
)
@pytest.mark.parametrize("route", ["/api/report/", "/api/scan/status/", "/api/scan/stream/"])
def test_scan_id_cannot_be_used_for_path_traversal(client, route, evil_id):
    """Scan IDs are used to build file names, so hostile IDs must never read other files."""
    response = client.get(route + evil_id)
    body = response.get_data(as_text=True)
    assert "root:" not in body and "[extensions]" not in body
    # Either the router rejects it (404) or the handler reports "not found".
    assert response.status_code in (200, 400, 404)
    if response.status_code == 200:
        assert "not found" in body.lower()
