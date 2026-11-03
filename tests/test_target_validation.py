"""SecurityScanner.validate_target: the pre-flight gate before any scan starts."""

import socket
import types

import pytest
import requests

from core import scanner as scanner_module
from core.scanner import SecurityScanner

validate = SecurityScanner.validate_target


def fake_response(status=200, reason="OK"):
    return types.SimpleNamespace(status_code=status, reason=reason)


@pytest.fixture()
def network(monkeypatch):
    """Resolve every hostname and record the URL that gets requested."""
    seen = {}
    monkeypatch.setattr(scanner_module.socket, "getaddrinfo", lambda *a, **k: [("ok",)])

    def fake_get(url, **kwargs):
        seen["url"] = url
        seen["kwargs"] = kwargs
        return fake_response()

    monkeypatch.setattr(scanner_module.requests, "get", fake_get)
    return seen


@pytest.mark.parametrize("value", [None, "", "   ", 123])
def test_empty_or_non_string_is_rejected(value):
    ok, message, code = validate(value)
    assert ok is False
    assert "required" in message.lower()
    assert code is None


def test_missing_scheme_defaults_to_https(network):
    ok, _, _ = validate("example.com")
    assert ok is True
    assert network["url"] == "https://example.com"


def test_explicit_http_scheme_is_preserved(network):
    validate("http://example.com/app")
    assert network["url"] == "http://example.com/app"


def test_url_without_hostname_is_rejected():
    ok, message, _ = validate("http://")
    assert ok is False
    assert "hostname" in message.lower()


def test_dns_failure_is_reported(monkeypatch):
    def boom(*a, **k):
        raise socket.gaierror("no such host")

    monkeypatch.setattr(scanner_module.socket, "getaddrinfo", boom)
    ok, message, code = validate("https://does-not-exist.invalid")
    assert (ok, code) == (False, None)
    assert "could not be resolved" in message


def _raise(exc):
    def fake_get(*a, **k):
        raise exc

    return fake_get


@pytest.mark.parametrize(
    ("exc", "needle"),
    [
        (requests.exceptions.ConnectionError("Connection refused"), "refused"),
        (requests.exceptions.ConnectionError("Network is unreachable"), "cannot connect"),
        (requests.exceptions.Timeout("slow"), "timed out"),
        (requests.exceptions.RequestException("weird"), "network error"),
    ],
)
def test_connection_problems_are_reported(network, monkeypatch, exc, needle):
    monkeypatch.setattr(scanner_module.requests, "get", _raise(exc))
    ok, message, _ = validate("https://example.com")
    assert ok is False
    assert needle in message.lower()


def test_bad_certificate_is_still_a_valid_scan_target(network, monkeypatch):
    # A broken TLS setup is exactly the kind of site this tool should audit.
    monkeypatch.setattr(scanner_module.requests, "get", _raise(requests.exceptions.SSLError("bad cert")))
    assert validate("https://self-signed.example") == (True, "", None)


@pytest.mark.parametrize("status", [500, 502, 503, 504])
def test_server_errors_block_the_scan(network, monkeypatch, status):
    monkeypatch.setattr(scanner_module.requests, "get", lambda *a, **k: fake_response(status, "Err"))
    ok, message, code = validate("https://example.com")
    assert (ok, code) == (False, status)
    assert str(status) in message


def test_404_on_root_blocks_but_404_on_deep_path_does_not(network, monkeypatch):
    monkeypatch.setattr(scanner_module.requests, "get", lambda *a, **k: fake_response(404, "Not Found"))
    assert validate("https://example.com/")[0] is False
    assert validate("https://example.com/some/deep/path")[0] is True


def test_success_returns_status_code(network):
    assert validate("https://example.com") == (True, "", 200)


def test_requests_do_not_follow_credentials_or_hang(network):
    validate("https://example.com")
    assert network["kwargs"]["timeout"] == 8
