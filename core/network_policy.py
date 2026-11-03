"""Network safeguards for publicly exposed scanner deployments."""

import ipaddress
import os
import re
import socket
import threading
from collections import OrderedDict
from urllib.parse import urlsplit

import requests
from requests.adapters import HTTPAdapter
from requests.models import PreparedRequest
from requests.utils import select_proxy
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool
from urllib3.exceptions import ConnectTimeoutError, NewConnectionError


class TargetPolicyError(ValueError):
    """Raised when a requested target is outside the configured scan policy."""


def public_mode_enabled() -> bool:
    return os.environ.get("KAVALU_PUBLIC_MODE", "").strip().lower() == "true"


def configured_targets() -> frozenset[tuple[str, int | None]]:
    """Return exact hostname/IP entries; an omitted port means HTTP or HTTPS."""
    entries = os.environ.get("KAVALU_ALLOWED_TARGETS", "")
    targets = set()
    for entry in entries.split(","):
        value = entry.strip()
        if not value:
            continue

        if value.startswith("["):
            closing_bracket = value.find("]")
            if closing_bracket < 0:
                raise ValueError("Bracketed IPv6 targets must have a closing bracket.")
            host = value[1:closing_bracket]
            suffix = value[closing_bracket + 1 :]
            if suffix and not suffix.startswith(":"):
                raise ValueError("Allowed targets must be hostnames or IP addresses with optional numeric ports.")
            port_text = suffix[1:] if suffix else None
            if port_text is None:
                port = None
            else:
                if not port_text.isdigit():
                    raise ValueError("Allowed targets must be hostnames or IP addresses with optional numeric ports.")
                port = int(port_text)
        else:
            if value.count(":") > 1:
                host, port = value, None
            else:
                host, separator, port_text = value.rpartition(":")
                if not separator:
                    host, port = value, None
                else:
                    if not port_text.isdigit():
                        raise ValueError(
                            "Allowed targets must be hostnames or IP addresses with optional numeric ports."
                        )
                    port = int(port_text)

        if port is not None and not 1 <= port <= 65535:
            raise ValueError("Allowed target ports must be between 1 and 65535.")

        host = host.strip().rstrip(".").lower()
        try:
            normalized_host = str(ipaddress.ip_address(host))
        except ValueError:
            try:
                normalized_host = host.encode("idna").decode("ascii")
            except UnicodeError as error:
                raise ValueError("Allowed targets must contain valid hostnames or IP addresses.") from error
            if len(normalized_host) > 253 or not all(
                re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in normalized_host.split(".")
            ):
                raise ValueError("Allowed targets must contain valid hostnames or IP addresses.")
        targets.add((normalized_host, port))
    return frozenset(targets)


def _host_is_allowed(host: str, port: int, targets: frozenset[tuple[str, int | None]]) -> bool:
    try:
        normalized_host = str(ipaddress.ip_address(host))
    except ValueError:
        normalized_host = host.rstrip(".").lower()
    return (normalized_host, port) in targets or (normalized_host, None) in targets and port in (80, 443)


def _is_public_unicast(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return (
        address.is_global
        and not address.is_multicast
        and not address.is_unspecified
        and not address.is_loopback
        and not address.is_link_local
        and not address.is_reserved
    )


def _resolve_public_target(url: str) -> tuple[str, ...]:
    """Validate and resolve a public-mode target, returning only checked IP literals."""
    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as error:
        raise TargetPolicyError("Target URL is invalid.") from error

    if parsed.scheme not in ("http", "https") or not hostname or parsed.username or parsed.password:
        raise TargetPolicyError("Only credential-free HTTP or HTTPS target URLs are allowed.")
    if port is None:
        port = 443 if parsed.scheme == "https" else 80
    elif not 1 <= port <= 65535:
        raise TargetPolicyError("Target port must be between 1 and 65535.")

    targets = configured_targets()
    if not targets:
        raise TargetPolicyError("Target scanning is disabled until KAVALU_ALLOWED_TARGETS is configured.")
    if not _host_is_allowed(hostname, port, targets):
        raise TargetPolicyError("Target host and port are not on the configured allow-list.")

    try:
        try:
            address = ipaddress.ip_address(hostname)
            addresses = [address]
        except ValueError:
            results = socket.getaddrinfo(hostname, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
            addresses = [ipaddress.ip_address(result[4][0]) for result in results]
    except (OSError, ValueError, IndexError) as error:
        raise TargetPolicyError("Target host could not be safely resolved.") from error

    if not addresses:
        raise TargetPolicyError("Target host did not resolve to an address.")
    if any(not _is_public_unicast(address) for address in addresses):
        raise TargetPolicyError("Targets resolving to non-public or non-unicast addresses are blocked.")
    return tuple(dict.fromkeys(str(address) for address in addresses))


def validate_target_url(url: str) -> tuple[str, ...] | None:
    """Validate a URL, returning pinned addresses in public mode."""
    if not public_mode_enabled():
        return None
    return _resolve_public_target(url)


def connect_validated_address(
    address: str,
    port: int,
    timeout: float | None = None,
    source_address: tuple[str, int] | None = None,
    socket_options: tuple[tuple[int, int, int], ...] | None = None,
) -> socket.socket:
    """Connect to a numeric address without performing hostname resolution."""
    ip_address = ipaddress.ip_address(address)
    family = socket.AF_INET if ip_address.version == 4 else socket.AF_INET6
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        for option in socket_options or ():
            sock.setsockopt(*option)
        if timeout is not None:
            sock.settimeout(timeout)
        if source_address:
            sock.bind(source_address)
        sockaddr = (str(ip_address), port) if ip_address.version == 4 else (str(ip_address), port, 0, 0)
        sock.connect(sockaddr)
        return sock
    except OSError:
        sock.close()
        raise


def _connect_pinned_addresses(connection, addresses: tuple[str, ...]) -> socket.socket:
    last_error = None
    for address in addresses:
        try:
            return connect_validated_address(
                address,
                connection.port,
                timeout=connection.timeout,
                source_address=connection.source_address,
                socket_options=connection.socket_options,
            )
        except OSError as error:
            last_error = error
    if isinstance(last_error, socket.timeout):
        raise ConnectTimeoutError(connection, f"Connection to {connection.host} timed out.") from last_error
    raise NewConnectionError(
        connection, f"Could not connect to any validated address for {connection.host}."
    ) from last_error


class _PinnedHTTPConnection(HTTPConnection):
    def __init__(self, *args, pinned_addresses: tuple[str, ...], **kwargs):
        self.pinned_addresses = pinned_addresses
        super().__init__(*args, **kwargs)

    def _new_conn(self):
        return _connect_pinned_addresses(self, self.pinned_addresses)


class _PinnedHTTPSConnection(HTTPSConnection):
    def __init__(self, *args, pinned_addresses: tuple[str, ...], **kwargs):
        self.pinned_addresses = pinned_addresses
        super().__init__(*args, **kwargs)

    def _new_conn(self):
        return _connect_pinned_addresses(self, self.pinned_addresses)


class _PinnedHTTPConnectionPool(HTTPConnectionPool):
    ConnectionCls = _PinnedHTTPConnection


class _PinnedHTTPSConnectionPool(HTTPSConnectionPool):
    ConnectionCls = _PinnedHTTPSConnection


class _PinnedAddressAdapter(HTTPAdapter):
    """Keep the original host for HTTP Host/SNI while connecting to checked IPs."""

    def __init__(self):
        super().__init__()
        self._pinned_pools = OrderedDict()
        self._pinned_pool_lock = threading.Lock()

    def get_connection_with_tls_context(
        self,
        request: PreparedRequest,
        verify,
        proxies=None,
        cert=None,
    ):
        if not public_mode_enabled():
            return super().get_connection_with_tls_context(request, verify, proxies, cert)
        if select_proxy(request.url, proxies):
            raise TargetPolicyError("Proxies are disabled in public mode.")

        addresses = validate_target_url(request.url)
        parsed = urlsplit(request.url)
        hostname = parsed.hostname
        if not addresses or not hostname:
            raise TargetPolicyError("Target host could not be safely resolved.")

        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        pool_class = _PinnedHTTPSConnectionPool if parsed.scheme == "https" else _PinnedHTTPConnectionPool
        key = (parsed.scheme, hostname, port, addresses)
        with self._pinned_pool_lock:
            pool = self._pinned_pools.pop(key, None)
            if pool is None:
                pool = pool_class(
                    host=hostname,
                    port=port,
                    pinned_addresses=addresses,
                    maxsize=self._pool_maxsize,
                    block=self._pool_block,
                )
            self._pinned_pools[key] = pool
            while len(self._pinned_pools) > self._pool_connections:
                _, expired_pool = self._pinned_pools.popitem(last=False)
                expired_pool.close()
        return pool

    def close(self):
        with self._pinned_pool_lock:
            pools = tuple(self._pinned_pools.values())
            self._pinned_pools.clear()
        for pool in pools:
            pool.close()
        super().close()


def guarded_request(method: str, url: str, **kwargs):
    """Issue a target request only after enforcing public-mode egress rules."""
    if public_mode_enabled():
        kwargs["allow_redirects"] = False

    requester = getattr(GuardedSession, method.lower(), None)
    if requester is None:
        raise ValueError(f"Unsupported HTTP method: {method}")
    with GuardedSession() as session:
        return getattr(session, method.lower())(url, **kwargs)


class GuardedSession(requests.Session):
    """Requests session that enforces the target policy and blocks redirects."""

    def __init__(self):
        super().__init__()
        self.trust_env = not public_mode_enabled()
        self.mount("http://", _PinnedAddressAdapter())
        self.mount("https://", _PinnedAddressAdapter())

    def request(self, method, url, **kwargs):
        if public_mode_enabled():
            kwargs["allow_redirects"] = False
        return super().request(method, url, **kwargs)
