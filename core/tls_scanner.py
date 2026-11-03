"""TLS checks: is HTTPS used, which protocol version is negotiated, is the certificate valid.

Opens one ordinary TLS handshake, as a browser would, and reads back what the
server discloses. It does not list cipher suites. The HSTS header check lives
in the recon module. Uses only the standard library (``ssl`` and ``socket``).
"""

__author__ = "Kavalu Labs"

import socket
import ssl
from datetime import datetime, timezone
from typing import Dict, List, Any
from urllib.parse import urlparse

# Protocol versions considered weak/deprecated as of 2026.
WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}

CERT_EXPIRY_WARNING_DAYS = 30


class TLSScanner:
    """Performs a lightweight TLS handshake against the target host and
    reports on certificate health and negotiated protocol version."""

    def scan(self, target_url: str, timeout: float = 6.0) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        parsed = urlparse(target_url)

        if parsed.scheme != "https":
            findings.append(
                {
                    "type": "no_https",
                    "severity": "high",
                    "title": "Target Not Served Over HTTPS",
                    "description": (
                        "The target URL uses plain HTTP. All traffic, including any "
                        "credentials or session identifiers, is transmitted unencrypted "
                        "and can be intercepted or modified in transit (e.g. on shared "
                        "Wi-Fi or by a network-level attacker)."
                    ),
                    "details": {"scheme": parsed.scheme or "http"},
                    "remediation": "Serve the site exclusively over HTTPS and redirect all HTTP "
                    "requests to HTTPS with a permanent (301) redirect.",
                }
            )
            return findings

        hostname = parsed.hostname
        port = parsed.port or 443

        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    protocol = ssock.version()

            findings.extend(self._check_protocol(protocol))
            findings.extend(self._check_certificate(cert, hostname))

        except ssl.SSLCertVerificationError as e:
            findings.append(
                {
                    "type": "tls_certificate",
                    "severity": "critical",
                    "title": "TLS Certificate Verification Failed",
                    "description": (
                        "The server's TLS certificate failed standard browser-style "
                        "verification. Visitors will see a security warning, and the "
                        "channel cannot be trusted to be free of interception."
                    ),
                    "details": {"error": str(e)},
                    "remediation": "Install a valid certificate from a trusted CA covering the "
                    "exact hostname, and ensure the full chain (including "
                    "intermediates) is served.",
                }
            )
        except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as e:
            findings.append(
                {
                    "type": "tls_certificate",
                    "severity": "info",
                    "title": "TLS Handshake Could Not Be Completed",
                    "description": f"Unable to establish a TLS connection to verify certificate health: {str(e)}",
                    "details": {"error": str(e)},
                }
            )
        except Exception as e:
            findings.append(
                {
                    "type": "tls_certificate",
                    "severity": "info",
                    "title": "TLS Check Skipped",
                    "description": f"TLS inspection did not complete: {str(e)}",
                    "details": {"error": str(e)},
                }
            )

        return findings

    def _check_protocol(self, protocol: str) -> List[Dict[str, Any]]:
        findings = []
        if not protocol:
            return findings

        if protocol in WEAK_PROTOCOLS:
            findings.append(
                {
                    "type": "tls_version",
                    "severity": "high",
                    "title": f"Deprecated TLS Protocol Negotiated ({protocol})",
                    "description": (
                        f"The server negotiated {protocol}, a deprecated protocol version "
                        "with known cryptographic weaknesses. Modern browsers are phasing "
                        "out support for it, and it should not be relied upon for "
                        "confidentiality."
                    ),
                    "details": {"negotiated_protocol": protocol},
                    "remediation": "Disable TLS 1.0/1.1 and SSLv2/v3 on the server; require TLS 1.2 "
                    "as a minimum, with TLS 1.3 preferred.",
                }
            )
        else:
            findings.append(
                {
                    "type": "tls_version",
                    "severity": "info",
                    "title": f"TLS Protocol In Use: {protocol}",
                    "description": f"The server negotiated {protocol}, which is considered current.",
                    "details": {"negotiated_protocol": protocol},
                }
            )
        return findings

    def _check_certificate(self, cert: Dict[str, Any], hostname: str) -> List[Dict[str, Any]]:
        findings = []
        if not cert:
            return findings

        not_after = cert.get("notAfter")
        if not_after:
            try:
                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days_left = (expiry - datetime.now(timezone.utc)).days

                if days_left < 0:
                    findings.append(
                        {
                            "type": "tls_certificate",
                            "severity": "critical",
                            "title": "TLS Certificate Has Expired",
                            "description": f"The TLS certificate expired on {not_after}. Browsers will "
                            "block or warn users before they can reach the site.",
                            "details": {"expired_on": not_after, "days_expired": abs(days_left)},
                            "remediation": "Renew the TLS certificate immediately and automate renewal "
                            "(e.g. via ACME/Let's Encrypt) to prevent recurrence.",
                        }
                    )
                elif days_left <= CERT_EXPIRY_WARNING_DAYS:
                    findings.append(
                        {
                            "type": "tls_certificate",
                            "severity": "medium",
                            "title": f"TLS Certificate Expiring Soon ({days_left} days)",
                            "description": f"The TLS certificate expires on {not_after}. Plan renewal "
                            "before it lapses to avoid a service-impacting outage.",
                            "details": {"expires_on": not_after, "days_remaining": days_left},
                            "remediation": "Renew the certificate and set up automated renewal with "
                            "monitoring/alerting on expiry windows.",
                        }
                    )
                else:
                    findings.append(
                        {
                            "type": "tls_certificate",
                            "severity": "info",
                            "title": "TLS Certificate Valid",
                            "description": f"Certificate is valid until {not_after} ({days_left} days remaining).",
                            "details": {"expires_on": not_after, "days_remaining": days_left},
                        }
                    )
            except ValueError:
                pass

        issuer = dict(x[0] for x in cert.get("issuer", []))
        subject = dict(x[0] for x in cert.get("subject", []))
        findings.append(
            {
                "type": "tls_certificate",
                "severity": "info",
                "title": "TLS Certificate Details",
                "description": (
                    f"Certificate issued by {issuer.get('organizationName', issuer.get('commonName', 'Unknown CA'))}."
                ),
                "details": {
                    "subject_cn": subject.get("commonName", hostname),
                    "issuer": issuer.get("organizationName", issuer.get("commonName", "Unknown")),
                    "serial_number": cert.get("serialNumber", "N/A"),
                },
            }
        )
        return findings
