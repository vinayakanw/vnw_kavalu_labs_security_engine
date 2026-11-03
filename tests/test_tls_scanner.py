"""TLS checks that can be verified without opening a socket."""

from datetime import datetime, timedelta, timezone

import pytest

from core import tls_scanner as tls_scanner_module
from core.tls_scanner import CERT_EXPIRY_WARNING_DAYS, WEAK_PROTOCOLS, TLSScanner

scanner = TLSScanner()


def cert_expiring_in(days):
    expiry = datetime.now(timezone.utc) + timedelta(days=days, hours=1)
    return {
        "notAfter": expiry.strftime("%b %d %H:%M:%S %Y GMT"),
        "issuer": ((("organizationName", "Test CA"),),),
        "subject": ((("commonName", "example.test"),),),
        "serialNumber": "ABC123",
    }


def severities(findings):
    return {f["severity"] for f in findings}


def test_plain_http_target_is_a_high_finding_and_skips_the_handshake():
    findings = scanner.scan("http://example.test/")
    assert [f["type"] for f in findings] == ["no_https"]
    assert findings[0]["severity"] == "high"


def test_public_tls_scan_connects_to_pinned_ip_and_preserves_hostname_sni(monkeypatch):
    connection = {}

    class FakeSocket:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

    class FakeSSLSocket(FakeSocket):
        def getpeercert(self):
            return {}

        def version(self):
            return "TLSv1.3"

    class FakeContext:
        def wrap_socket(self, sock, server_hostname):
            connection["server_hostname"] = server_hostname
            return FakeSSLSocket()

    context = FakeContext()

    def connect(address, port, timeout=None):
        connection["address"] = address
        connection["port"] = port
        return FakeSocket()

    monkeypatch.setattr(tls_scanner_module, "validate_target_url", lambda url: ("93.184.216.34",))
    monkeypatch.setattr(tls_scanner_module, "connect_validated_address", connect)
    monkeypatch.setattr(tls_scanner_module.ssl, "create_default_context", lambda: context)

    findings = TLSScanner().scan("https://safe.example/")

    assert context.minimum_version == tls_scanner_module.ssl.TLSVersion.TLSv1_2
    assert connection == {
        "address": "93.184.216.34",
        "port": 443,
        "server_hostname": "safe.example",
    }
    assert findings[0]["type"] == "tls_version"


def test_tls_protocol_failure_does_not_retry_with_legacy_protocols(monkeypatch):
    class FakeSocket:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

    class FakeContext:
        def wrap_socket(self, sock, server_hostname):
            raise tls_scanner_module.ssl.SSLError("legacy protocol detail")

    context = FakeContext()
    monkeypatch.setattr(tls_scanner_module, "validate_target_url", lambda url: None)
    monkeypatch.setattr(tls_scanner_module.socket, "create_connection", lambda *args, **kwargs: FakeSocket())
    monkeypatch.setattr(tls_scanner_module.ssl, "create_default_context", lambda: context)

    (finding,) = TLSScanner().scan("https://safe.example/")

    assert context.minimum_version == tls_scanner_module.ssl.TLSVersion.TLSv1_2
    assert finding["type"] == "tls_version"
    assert finding["details"] == {
        "minimum_protocol": "TLSv1.2",
        "legacy_protocol_confirmed": False,
    }
    assert "legacy protocol detail" not in repr(finding)


@pytest.mark.parametrize("protocol", sorted(WEAK_PROTOCOLS))
def test_deprecated_protocols_are_high(protocol):
    (finding,) = scanner._check_protocol(protocol)
    assert finding["severity"] == "high"
    assert protocol in finding["title"]


@pytest.mark.parametrize("protocol", ["TLSv1.2", "TLSv1.3"])
def test_modern_protocols_are_informational(protocol):
    (finding,) = scanner._check_protocol(protocol)
    assert finding["severity"] == "info"


def test_empty_protocol_yields_nothing():
    assert scanner._check_protocol("") == []


def test_expired_certificate_is_critical():
    findings = scanner._check_certificate(cert_expiring_in(-5), "example.test")
    assert "critical" in severities(findings)
    assert any("Expired" in f["title"] for f in findings)


def test_certificate_expiring_soon_is_medium():
    findings = scanner._check_certificate(cert_expiring_in(CERT_EXPIRY_WARNING_DAYS - 5), "example.test")
    assert "medium" in severities(findings)
    assert "critical" not in severities(findings)


def test_certificate_with_plenty_of_life_is_informational_only():
    findings = scanner._check_certificate(cert_expiring_in(CERT_EXPIRY_WARNING_DAYS + 60), "example.test")
    assert severities(findings) == {"info"}


def test_unparseable_expiry_does_not_crash():
    cert = cert_expiring_in(90)
    cert["notAfter"] = "not a date"
    assert severities(scanner._check_certificate(cert, "example.test")) == {"info"}


def test_empty_certificate_yields_nothing():
    assert scanner._check_certificate({}, "example.test") == []
