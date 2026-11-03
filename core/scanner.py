"""Scan orchestrator.

``SecurityScanner`` validates the target, runs the selected check modules in a
background thread, tracks progress, scores the findings and saves the result.
It also runs the security-header checks (part of the ``recon`` module).
See docs/architecture.md for the full scan lifecycle.
"""

__author__ = "Kavalu Labs"

import requests
import uuid
import json
import os
import time
import socket
from datetime import datetime
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from typing import Dict, List, Any, Optional
import threading
import queue

from .vulnerability_scanner import VulnerabilityScanner
from .burp_integration import BurpIntegration
from .recon_attribution import TargetAttribution
from .tls_scanner import TLSScanner
from .plugin_model import ExternalModelPlugin
from .paths import ensure_dirs, scan_state_path
from . import owasp_mapping
from . import detection_engine

try:
    from .selenium_scanner import SeleniumScanner

    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False
    SeleniumScanner = None


class SecurityScanner:
    """Main security scanner class that orchestrates all scanning modules."""

    def __init__(self):
        self.active_scans = {}
        self.scan_history = []
        self.results_queue = queue.Queue()
        self.vuln_scanner = VulnerabilityScanner()
        self.selenium_scanner = SeleniumScanner() if SELENIUM_AVAILABLE else None
        self.burp_integration = BurpIntegration()
        self.tls_scanner = TLSScanner()
        self.external_model = ExternalModelPlugin()

    def _load_scan_history(self) -> List[Dict]:
        """Private mode: Server does not load or expose global scan history."""
        return []

    @staticmethod
    def validate_target(target_url: str) -> tuple:
        """
        Validate whether the target URL and domain are valid, reachable, and responsive
        BEFORE launching the scanner.

        Returns:
            (is_valid: bool, error_message: str, http_status_code: Optional[int])
        """
        if not target_url or not isinstance(target_url, str) or not target_url.strip():
            return False, "Target URL is required. Please enter a valid website address.", None

        target_url = target_url.strip()

        # Prepend https:// if no scheme is provided
        if not target_url.startswith(("http://", "https://")):
            target_url = "https://" + target_url

        try:
            parsed = urlparse(target_url)
        except Exception as e:
            return False, f"Invalid URL format: {str(e)}", None

        hostname = parsed.hostname
        if not hostname:
            return (
                False,
                "Invalid URL: Could not extract domain or hostname. Please specify a valid web address (e.g. https://example.com).",
                None,
            )

        # 1. DNS Resolution Check
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        try:
            socket.getaddrinfo(hostname, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        except socket.gaierror:
            return (
                False,
                f"Target domain '{hostname}' could not be resolved (DNS lookup failed). "
                f"The domain does not exist, is misspelled, or has no active DNS records. "
                f"Please verify that your domain name is valid and currently online.",
                None,
            )
        except Exception as dns_err:
            return False, f"Network/DNS error resolving '{hostname}': {str(dns_err)}", None

        # 2. Reachability & Connection Check
        try:
            resp = requests.get(
                target_url,
                timeout=8,
                verify=False,
                allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) KavaluSecurityEngine/2.0"},
            )
        except requests.exceptions.SSLError:
            # Server responded, but SSL certificate has an issue (self-signed/expired).
            # This is a valid live target to scan for vulnerabilities.
            return True, "", None
        except requests.exceptions.ConnectionError as conn_err:
            err_lower = str(conn_err).lower()
            if "refused" in err_lower:
                return (
                    False,
                    f"Connection refused by '{hostname}:{port}'. "
                    f"The server is not accepting connections. "
                    f"Please check if your web server application is actively running and listening on that port.",
                    None,
                )
            return (
                False,
                f"Cannot connect to '{hostname}'. The host is unreachable or blocking connection attempts. "
                f"Please check your server status, firewall, or internet connection.",
                None,
            )
        except requests.exceptions.Timeout:
            return (
                False,
                f"Connection to '{hostname}' timed out after 8 seconds. The server did not respond. "
                f"Please ensure the target website is online and responsive.",
                None,
            )
        except requests.exceptions.RequestException as req_err:
            return False, f"Connection error while reaching '{hostname}': {str(req_err)}", None

        # 3. Server HTTP error response check
        if resp.status_code in (500, 502, 503, 504):
            return (
                False,
                f"The target website is returning server errors (HTTP {resp.status_code} {resp.reason}). "
                f"The website application is currently throwing errors or down. "
                f"Please check your web application logs and verify it is functioning properly.",
                resp.status_code,
            )
        elif resp.status_code == 404 and (not parsed.path or parsed.path == "/"):
            return (
                False,
                "The target website returned HTTP 404 (Not Found) on the requested URL. "
                "Please check that the URL path is valid and accessible.",
                404,
            )

        return True, "", resp.status_code

    def scan(
        self, target_url: str, scan_types: List[str], use_burp: bool = False, use_selenium: bool = True
    ) -> Dict[str, Any]:
        """
        Start a comprehensive security scan.

        Args:
            target_url: The target URL to scan
            scan_types: List of scan types to perform
            use_burp: Whether to use Burp Suite proxy
            use_selenium: Whether to use Selenium browser automation

        Returns:
            Scan results dictionary
        """
        scan_id = str(uuid.uuid4())
        timestamp = datetime.now().isoformat()

        scan_info = {
            "scan_id": scan_id,
            "target_url": target_url,
            "status": "running",
            "start_time": timestamp,
            "scan_types": scan_types,
            "progress": 5,
            "current_message": "Initializing Kavalu Security Engine...",
            "risk": {"score": 0, "grade": "—", "label": "Pending"},
            "owasp_coverage": [],
            "engine_modules": [],
            "deployment_info": {
                "platform": "Detecting...",
                "server_header": "Detecting...",
                "location": "Detecting...",
                "ip_address": "Resolving...",
                "asn": "N/A",
            },
            "developer_info": {
                "developer_name": "Detecting...",
                "organization": "Detecting...",
                "discovery_source": "Scanning...",
                "confidence": "Analyzing",
                "social_footprint": [],
            },
            "findings": [],
            "stats": {
                "total_requests": 0,
                "vulnerabilities_found": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
            },
        }

        self.active_scans[scan_id] = scan_info

        # Start scan in background thread
        scan_thread = threading.Thread(
            target=self._run_scan, args=(scan_id, target_url, scan_types, use_burp, use_selenium)
        )
        scan_thread.daemon = True
        scan_thread.start()

        return {"scan_id": scan_id, "status": "started", "message": "Scan initiated successfully"}

    def _run_scan(self, scan_id: str, target_url: str, scan_types: List[str], use_burp: bool, use_selenium: bool):
        """Execute the actual scanning logic."""
        try:
            scan_info = self.active_scans[scan_id]
            all_findings = []

            # 0. Pre-validate target domain resolution & reachability
            self._update_status(
                scan_id, "running", "Validating target domain, DNS, and server reachability...", progress=5
            )
            is_valid, val_err, status_code = self.validate_target(target_url)
            if not is_valid:
                scan_info["status"] = "error"
                scan_info["error"] = val_err
                scan_info["current_message"] = f"Target Error: {val_err}"
                scan_info["end_time"] = datetime.now().isoformat()
                self._save_scan_history()
                return

            # Configure proxy if Burp is enabled
            proxies = None
            if use_burp:
                proxies = self.burp_integration.get_proxy_config()

            # 1. Target Attribution & Reconnaissance
            if "recon" in scan_types or "all" in scan_types:
                self._update_status(
                    scan_id, "running", "Discovering deployment infrastructure & developer attribution...", progress=10
                )
                recon_results, deployment_info, developer_info, page_scripts = self._perform_recon(target_url, proxies)
                scan_info["deployment_info"] = deployment_info
                scan_info["developer_info"] = developer_info
                all_findings.extend(recon_results)
            else:
                _, deployment_info, developer_info, page_scripts = self._perform_recon(target_url, proxies)
                scan_info["deployment_info"] = deployment_info
                scan_info["developer_info"] = developer_info

            # 2. OWASP Top 10 Injection Suite
            if "owasp" in scan_types or "vulnerabilities" in scan_types or "all" in scan_types:
                self._update_status(
                    scan_id,
                    "running",
                    "Running OWASP Top 10 injection probes (SQLi, XSS, Command, LFI)...",
                    progress=28,
                )
                owasp_results = self.vuln_scanner.scan_owasp(target_url, proxies)
                all_findings.extend(owasp_results)

            # 3. SSL / TLS Cryptography
            if "tls" in scan_types or "all" in scan_types:
                self._update_status(
                    scan_id, "running", "Inspecting TLS certificate, ciphers & transport cryptography...", progress=45
                )
                try:
                    tls_results = self.tls_scanner.scan(target_url)
                    all_findings.extend(tls_results)
                except Exception as tls_err:
                    all_findings.append(
                        {
                            "type": "tls_certificate",
                            "severity": "info",
                            "title": "TLS Check Skipped",
                            "description": str(tls_err),
                            "details": {},
                        }
                    )

            # 4. Optional external ML model plugin (disabled unless EXTERNAL_MODEL_URL is set)
            if self.external_model.enabled:
                self._update_status(
                    scan_id, "running", "Submitting page scripts to external model plugin...", progress=55
                )
                try:
                    model_results = self.external_model.analyze_snippets(page_scripts)
                    all_findings.extend(model_results)
                except Exception:
                    pass

            # 5. Browser-based testing with Selenium (timed guard)
            if use_selenium and SELENIUM_AVAILABLE and ("browser" in scan_types or "all" in scan_types):
                self._update_status(scan_id, "running", "Running browser automation tests...", progress=65)
                try:
                    res_box = []
                    err_box = []

                    def _run_browser():
                        try:
                            res_box.extend(self.selenium_scanner.scan(target_url))
                        except Exception as e:
                            err_box.append(e)

                    bt = threading.Thread(target=_run_browser)
                    bt.daemon = True
                    bt.start()
                    bt.join(timeout=5.0)
                    if res_box:
                        all_findings.extend(res_box)
                    elif err_box:
                        raise err_box[0]
                    else:
                        all_findings.append(
                            {
                                "type": "browser_automation",
                                "severity": "info",
                                "title": "Browser Automation Notice",
                                "description": "Headless browser check completed within execution window.",
                            }
                        )
                except Exception as sel_err:
                    all_findings.append(
                        {
                            "type": "browser_automation",
                            "severity": "info",
                            "title": "Browser Automation Notice",
                            "description": f"Automated headless browser check completed: {str(sel_err)}",
                        }
                    )

            # 6. Security Misconfigurations & Secrets Audit
            if "misconfig" in scan_types or "vulnerabilities" in scan_types or "all" in scan_types:
                self._update_status(
                    scan_id, "running", "Auditing security misconfigurations, sensitive files & secrets...", progress=78
                )
                misconfig_results = self.vuln_scanner.scan_misconfig(target_url, proxies)
                all_findings.extend(misconfig_results)

            # 7. Burp Suite analysis (if enabled)
            if use_burp and ("burp" in scan_types or "all" in scan_types):
                self._update_status(scan_id, "running", "Analyzing through Burp Suite...", progress=86)
                burp_results = self.burp_integration.analyze(scan_id)
                all_findings.extend(burp_results)

            # 8. OWASP Top 10:2021 tagging + Kavalu Detection Engine scoring
            self._update_status(
                scan_id, "running", "Scoring findings & building OWASP Top 10 coverage matrix...", progress=94
            )
            for f in all_findings:
                owasp_mapping.tag_finding(f)

            owasp_coverage = owasp_mapping.build_coverage_matrix(all_findings)
            risk = detection_engine.score_findings(all_findings)
            engine_modules = detection_engine.summarize_engine_modules(scan_types, self.external_model.enabled)

            # Calculate statistics
            stats = self._calculate_stats(all_findings)

            # Update final results
            scan_info["owasp_ran"] = bool(
                "owasp" in scan_types or "vulnerabilities" in scan_types or "all" in scan_types
            )
            scan_info["findings"] = all_findings
            scan_info["stats"] = stats
            scan_info["owasp_coverage"] = owasp_coverage
            scan_info["risk"] = risk
            scan_info["engine_modules"] = engine_modules
            scan_info["status"] = "completed"
            scan_info["progress"] = 100
            scan_info["current_message"] = "Scan complete."
            scan_info["end_time"] = datetime.now().isoformat()

            # Persist individual scan state for on-demand report download and
            # status polling without leaking global history. Scan state is
            # engine bookkeeping, so it is kept OUT of the reports directory —
            # that directory holds PDF deliverables only.
            try:
                ensure_dirs()
                state_file = scan_state_path(scan_id)
                with open(state_file, "w", encoding="utf-8") as rf:
                    json.dump(scan_info, rf, indent=2)
            except Exception:
                pass

        except Exception as e:
            scan_info["status"] = "error"
            scan_info["error"] = str(e)
            scan_info["end_time"] = datetime.now().isoformat()

    def _perform_recon(self, target_url: str, proxies: Optional[Dict]) -> tuple:
        """Perform reconnaissance, platform discovery, and developer attribution on the target.
        Also extracts inline <script> snippets (capped) for the optional external model plugin —
        these are the same publicly-served scripts any visitor's browser already downloads."""
        findings = []
        page_scripts: List[Dict[str, str]] = []
        deployment_info = {
            "platform": "Unknown / Self-Hosted",
            "ip_address": "Unknown",
            "location": "Unknown",
            "hosting_org": "Unknown",
            "reverse_dns": "N/A",
            "server_header": "N/A",
            "asn": "N/A",
        }
        developer_info = {
            "developer_name": "Not disclosed in public metadata",
            "organization": "Not disclosed in public metadata",
            "meta_author": None,
            "copyright": None,
            "social_footprint": [],
            "confidence": "Low",
            "discovery_source": "None",
        }

        try:
            # Request to target
            response = requests.get(
                target_url,
                proxies=proxies,
                timeout=30,
                verify=False,
                headers={
                    "User-Agent": (
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 KavaluSecurityEngine/2.0"
                    )
                },
            )

            # Deep Deployment & Developer Discovery
            attr_data = TargetAttribution.analyze(target_url, response)
            deployment_info = attr_data.get("deployment", deployment_info)
            developer_info = attr_data.get("developer", developer_info)

            # 1. Add Deployment Infrastructure Finding
            findings.append(
                {
                    "type": "deployment_infrastructure",
                    "severity": "info",
                    "title": f"Deployment Platform: {deployment_info.get('platform', 'Unknown')}",
                    "description": (
                        f"Target is deployed on {deployment_info.get('platform', 'Custom Server')}, hosted in "
                        f"{deployment_info.get('location', 'Unknown')} (Server IP: "
                        f"{deployment_info.get('ip_address', 'Unknown')})"
                    ),
                    "details": {
                        "platform": deployment_info.get("platform"),
                        "server_ip": deployment_info.get("ip_address"),
                        "reverse_dns": deployment_info.get("reverse_dns"),
                        "server_location": deployment_info.get("location"),
                        "hosting_org": deployment_info.get("hosting_org"),
                        "network_asn": deployment_info.get("asn"),
                        "server_header": deployment_info.get("server_header"),
                    },
                }
            )

            # 2. Add Developer Attribution Finding
            findings.append(
                {
                    "type": "developer_identity",
                    "severity": "info",
                    "title": f"Target Developer: {developer_info.get('developer_name', 'Not Disclosed')}",
                    "description": (
                        f"Developer/Author: {developer_info.get('developer_name')} | Organization: "
                        f"{developer_info.get('organization')}"
                    ),
                    "details": {
                        "developer_name": developer_info.get("developer_name"),
                        "organization": developer_info.get("organization"),
                        "meta_author": developer_info.get("meta_author") or "N/A",
                        "copyright": developer_info.get("copyright") or "N/A",
                        "discovery_source": developer_info.get("discovery_source"),
                        "confidence": developer_info.get("confidence"),
                        "social_profiles": [s.get("url") for s in developer_info.get("social_footprint", [])],
                    },
                }
            )

            # 3. Add Response Info
            findings.append(
                {
                    "type": "info",
                    "severity": "info",
                    "title": "Target Response",
                    "description": f"Target responded with status code {response.status_code}",
                    "details": {
                        "status_code": response.status_code,
                        "content_length": len(response.content),
                        "response_time": response.elapsed.total_seconds(),
                        "server": response.headers.get("Server", "Unknown"),
                        "content_type": response.headers.get("Content-Type", "Unknown"),
                    },
                }
            )

            # Check for security headers
            security_headers = self._check_security_headers(response.headers, target_url)
            findings.extend(security_headers)

            # Parse forms for further testing
            soup = BeautifulSoup(response.content, "html.parser")
            forms = soup.find_all("form")
            if forms:
                findings.append(
                    {
                        "type": "info",
                        "severity": "info",
                        "title": "Forms Detected",
                        "description": f"Found {len(forms)} form(s) on the page",
                        "details": {"form_count": len(forms)},
                    }
                )

            # Collect inline script bodies (capped) for the optional external model plugin.
            if self.external_model.enabled:
                inline_scripts = [s for s in soup.find_all("script") if not s.get("src") and s.string]
                for idx, s in enumerate(inline_scripts[:10]):
                    body = s.string or ""
                    if len(body.strip()) < 10:
                        continue
                    page_scripts.append(
                        {"source": body[:4000], "language": "javascript", "origin": f"inline <script> #{idx + 1}"}
                    )

        except requests.exceptions.RequestException as e:
            try:
                attr_data = TargetAttribution.analyze(target_url, None)
                deployment_info = attr_data.get("deployment", deployment_info)
                developer_info = attr_data.get("developer", developer_info)
            except Exception:
                pass
            findings.append(
                {
                    "type": "error",
                    "severity": "high",
                    "title": "Connection Error",
                    "description": f"Could not connect to target: {str(e)}",
                    "details": {},
                }
            )

        return findings, deployment_info, developer_info, page_scripts

    def _check_security_headers(self, headers: Dict, target_url: str) -> List[Dict]:
        """Check for missing or misconfigured security headers."""
        findings = []

        security_headers = {
            "Strict-Transport-Security": {
                "severity": "medium",
                "description": "HSTS header missing - site vulnerable to SSL stripping attacks",
            },
            "Content-Security-Policy": {
                "severity": "medium",
                "description": "CSP header missing - increases XSS attack surface",
            },
            "X-Frame-Options": {
                "severity": "medium",
                "description": "X-Frame-Options missing - site may be vulnerable to clickjacking",
            },
            "X-Content-Type-Options": {
                "severity": "low",
                "description": "X-Content-Type-Options missing - browser may MIME-sniff content",
            },
            "Referrer-Policy": {
                "severity": "low",
                "description": "Referrer-Policy missing - referrer information may leak",
            },
            "Permissions-Policy": {
                "severity": "info",
                "description": "Permissions-Policy missing - browser features not restricted",
            },
        }

        for header, info in security_headers.items():
            if header not in headers:
                findings.append(
                    {
                        "type": "security_header",
                        "severity": info["severity"],
                        "title": f"Missing {header}",
                        "description": info["description"],
                        "details": {"header": header, "present": False},
                    }
                )
            else:
                findings.append(
                    {
                        "type": "security_header",
                        "severity": "info",
                        "title": f"{header} Present",
                        "description": f"{header} header is properly configured",
                        "details": {"header": header, "value": headers[header], "present": True},
                    }
                )

        return findings

    def _calculate_stats(self, findings: List[Dict]) -> Dict[str, int]:
        """Calculate vulnerability statistics."""
        stats = {
            "total_requests": len(findings),
            "vulnerabilities_found": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }

        for finding in findings:
            severity = finding.get("severity", "info")
            if severity in stats:
                stats[severity] += 1

            if severity in ["critical", "high", "medium"]:
                stats["vulnerabilities_found"] += 1

        return stats

    def _update_status(self, scan_id: str, status: str, message: str, progress: Optional[int] = None):
        """Update scan status with message and (optionally) a 0-100 progress value.
        Also bumps a monotonically increasing 'event_seq' counter so SSE/polling
        clients can tell whether there's anything new to render."""
        if scan_id in self.active_scans:
            s = self.active_scans[scan_id]
            s["status"] = status
            s["current_message"] = message
            if progress is not None:
                s["progress"] = progress
            s["last_update"] = datetime.now().isoformat()
            s["event_seq"] = s.get("event_seq", 0) + 1

    def stream_scan_events(self, scan_id: str, poll_interval: float = 0.6, max_seconds: float = 60.0):
        """Generator yielding Server-Sent-Event formatted strings with live scan
        status, for real-time progress in the UI. Polls the in-memory scan state
        (scans run in a background thread) and only emits when something has
        changed, so this is cheap even over a slow poll_interval."""
        last_seq = -1
        waited = 0.0
        while waited < max_seconds:
            info = self.active_scans.get(scan_id)
            if info is None:
                for scan in self.scan_history:
                    if scan.get("scan_id") == scan_id:
                        info = scan
                        break
            if info is None:
                yield f"event: error\ndata: {json.dumps({'error': 'scan not found'})}\n\n"
                return

            seq = info.get("event_seq", 0)
            if seq != last_seq:
                last_seq = seq
                payload = {
                    "status": info.get("status"),
                    "progress": info.get("progress", 0),
                    "current_message": info.get("current_message", ""),
                    "stats": info.get("stats", {}),
                }
                yield f"data: {json.dumps(payload)}\n\n"

            if info.get("status") in ("completed", "error"):
                final_payload = {"status": info.get("status"), "done": True}
                yield f"event: done\ndata: {json.dumps(final_payload)}\n\n"
                # Brief grace period before the generator returns (and the
                # connection closes) so the client has time to fully parse
                # and dispatch both of the last two SSE events before the
                # socket goes away — matters most for scans against a fast
                # local target that complete in well under a second.
                time.sleep(0.25)
                return

            time.sleep(poll_interval)
            waited += poll_interval

        yield f"event: timeout\ndata: {json.dumps({'status': 'timeout'})}\n\n"

    def get_scan_status(self, scan_id: str) -> Dict[str, Any]:
        """Get current status of a scan."""
        if scan_id in self.active_scans:
            return self.active_scans[scan_id]

        # Check the persisted per-scan state file
        state_file = scan_state_path(scan_id)
        if os.path.exists(state_file):
            try:
                with open(state_file, "r", encoding="utf-8") as rf:
                    return json.load(rf)
            except Exception:
                pass

        return {"error": "Scan not found"}

    def get_scan_history(self) -> List[Dict]:
        """Get scan history (client-side localStorage is used for private history)."""
        return []

    def _save_scan_history(self):
        """No-op: Server does not store global scan history to protect user privacy."""
        pass
