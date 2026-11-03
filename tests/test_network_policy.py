import socket
from urllib.parse import urlsplit

import pytest
import requests

from core import network_policy
from core.network_policy import GuardedSession, TargetPolicyError, _PinnedAddressAdapter, validate_target_url


def _dns_record(address):
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    sockaddr = (address, 443, 0, 0) if family == socket.AF_INET6 else (address, 443)
    return (family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", sockaddr)


def _enable_public_mode(monkeypatch, target="safe.example"):
    monkeypatch.setenv("KAVALU_PUBLIC_MODE", "true")
    monkeypatch.setenv("KAVALU_ALLOWED_TARGETS", target)


def test_target_validation_returns_only_allowlisted_public_addresses(monkeypatch):
    _enable_public_mode(monkeypatch)
    monkeypatch.setattr(
        network_policy.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [_dns_record("93.184.216.34")],
    )
    assert validate_target_url("https://safe.example/") == ("93.184.216.34",)


def test_bracketed_ipv6_allowlist_entries_support_explicit_ports(monkeypatch):
    monkeypatch.setenv("KAVALU_ALLOWED_TARGETS", "[2606:4700:4700::1111]:8443")
    assert network_policy.configured_targets() == frozenset({("2606:4700:4700::1111", 8443)})


def test_public_target_rejects_port_zero(monkeypatch):
    _enable_public_mode(monkeypatch)
    with pytest.raises(TargetPolicyError, match="Target port"):
        validate_target_url("http://safe.example:0/")


@pytest.mark.parametrize(
    "address",
    ["10.0.0.8", "127.0.0.1", "169.254.169.254", "224.0.0.1", "255.255.255.255", "::1", "ff02::1", "fe80::1"],
)
def test_target_validation_rejects_nonpublic_dns_answers(monkeypatch, address):
    _enable_public_mode(monkeypatch)
    monkeypatch.setattr(
        network_policy.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [_dns_record(address)],
    )
    with pytest.raises(TargetPolicyError, match="non-public or non-unicast"):
        validate_target_url("https://safe.example/")


def test_public_mode_never_allows_private_addresses_from_environment(monkeypatch):
    _enable_public_mode(monkeypatch)
    monkeypatch.setenv("KAVALU_ALLOW_PRIVATE_TARGETS", "true")
    monkeypatch.setattr(
        network_policy.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [_dns_record("127.0.0.1")],
    )
    with pytest.raises(TargetPolicyError, match="non-public or non-unicast"):
        validate_target_url("https://safe.example/")


def test_http_connection_uses_checked_ip_without_resolving_target_again(monkeypatch, vulnerable_url):
    port = urlsplit(vulnerable_url).port
    _enable_public_mode(monkeypatch, target=f"safe.example:{port}")
    real_getaddrinfo = socket.getaddrinfo
    target_lookups = []
    connected_addresses = []

    def fake_getaddrinfo(host, port, *args, **kwargs):
        if host == "safe.example":
            target_lookups.append(host)
            resolved_ip = "93.184.216.34" if len(target_lookups) == 1 else "203.0.113.99"
            return [_dns_record(resolved_ip)]
        return real_getaddrinfo(host, port, *args, **kwargs)

    def fake_connect(address, port, timeout=None, source_address=None, socket_options=None):
        connected_addresses.append(address)
        return socket.create_connection(("127.0.0.1", port), timeout=timeout)

    monkeypatch.setattr(network_policy.socket, "getaddrinfo", fake_getaddrinfo)
    monkeypatch.setattr(network_policy, "connect_validated_address", fake_connect)
    with GuardedSession() as session:
        response = session.get(f"http://safe.example:{port}/", timeout=3)

    assert response.status_code == 200
    assert target_lookups == ["safe.example"]
    assert connected_addresses == ["93.184.216.34"]


def test_numeric_connection_does_not_call_dns(monkeypatch):
    connected = {}

    class FakeSocket:
        def setsockopt(self, *args):
            pass

        def settimeout(self, timeout):
            pass

        def bind(self, address):
            pass

        def connect(self, address):
            connected["address"] = address

        def close(self):
            pass

    monkeypatch.setattr(network_policy.socket, "socket", lambda *args: FakeSocket())
    monkeypatch.setattr(
        network_policy.socket,
        "getaddrinfo",
        lambda *args, **kwargs: pytest.fail("numeric connections must not perform DNS lookups"),
    )

    network_policy.connect_validated_address("93.184.216.34", 443, timeout=1)

    assert connected["address"] == ("93.184.216.34", 443)


def test_public_mode_rejects_explicit_proxies(monkeypatch):
    _enable_public_mode(monkeypatch)
    with GuardedSession() as session, pytest.raises(TargetPolicyError, match="Proxies are disabled"):
        session.get(
            "https://safe.example/",
            proxies={"https": "http://127.0.0.1:8080"},
            timeout=1,
        )


def test_https_adapter_keeps_hostname_for_sni_and_pins_the_validated_ip(monkeypatch):
    _enable_public_mode(monkeypatch)
    monkeypatch.setattr(network_policy, "_resolve_public_target", lambda url: ("93.184.216.34",))
    request = requests.Request("GET", "https://safe.example/").prepare()
    adapter = _PinnedAddressAdapter()
    pool = adapter.get_connection_with_tls_context(request, verify=True)
    connection = pool._new_conn()

    assert pool.host == "safe.example"
    assert connection.host == "safe.example"
    assert connection.pinned_addresses == ("93.184.216.34",)
    pool.close()
    adapter.close()


def test_pinned_connection_pool_is_reused_only_for_the_same_checked_addresses(monkeypatch):
    _enable_public_mode(monkeypatch)
    addresses = iter(
        [
            ("93.184.216.34",),
            ("93.184.216.34",),
            ("8.8.8.8",),
        ]
    )
    monkeypatch.setattr(network_policy, "_resolve_public_target", lambda url: next(addresses))
    request = requests.Request("GET", "https://safe.example/").prepare()
    adapter = _PinnedAddressAdapter()

    first_pool = adapter.get_connection_with_tls_context(request, verify=True)
    reused_pool = adapter.get_connection_with_tls_context(request, verify=True)
    changed_ip_pool = adapter.get_connection_with_tls_context(request, verify=True)

    assert reused_pool is first_pool
    assert changed_ip_pool is not first_pool
    adapter.close()


def test_public_mode_forces_redirects_off(monkeypatch):
    _enable_public_mode(monkeypatch)
    captured = {}

    def fake_request(self, method, url, **kwargs):
        captured["allow_redirects"] = kwargs["allow_redirects"]
        return "response"

    monkeypatch.setattr(requests.Session, "request", fake_request)
    with GuardedSession() as session:
        response = session.get("https://safe.example/", allow_redirects=True)

    assert response == "response"
    assert captured["allow_redirects"] is False
