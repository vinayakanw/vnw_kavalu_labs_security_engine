"""Optional external ML model plugin.

Off unless ``EXTERNAL_MODEL_URL`` is set. When on, inline ``<script>`` bodies from the
target page are sent to a model service that you host, and its verdicts are merged
into the normal findings. A missing or failing service is ignored, never an error.

Environment variables (all optional):
    EXTERNAL_MODEL_URL       for example http://localhost:8000/analyze
    EXTERNAL_MODEL_API_KEY   sent as ``Authorization: Bearer <key>`` when set
    EXTERNAL_MODEL_TIMEOUT   seconds to wait, default 8

The request and response format is described in docs/configuration.md.
"""

__author__ = "Kavalu Labs"

import os
from typing import Dict, List, Any, Optional

import requests

_CATEGORY_TO_TYPE = {
    "buffer_overflow": "misconfiguration",
    "command_injection": "command_injection",
    "sql_injection": "sql_injection",
    "weak_crypto": "tls_cipher",
    "hardcoded_secret": "info_disclosure",
    "xss": "xss",
    "path_traversal": "exposed_path",
    "ssrf": "ssrf_candidate",
}


class ExternalModelPlugin:
    """Thin, fail-safe client for an optional self-hosted ML inference service."""

    def __init__(self):
        self.url: Optional[str] = os.environ.get("EXTERNAL_MODEL_URL") or None
        self.api_key: Optional[str] = os.environ.get("EXTERNAL_MODEL_API_KEY") or None
        try:
            self.timeout: float = float(os.environ.get("EXTERNAL_MODEL_TIMEOUT", "8"))
        except ValueError:
            self.timeout = 8.0

    @property
    def enabled(self) -> bool:
        return bool(self.url)

    def analyze_snippets(self, snippets: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        """snippets: [{'source': '<code>', 'language': 'javascript', 'origin': 'inline <script> #2'}]
        Returns findings in the standard Kavalu finding schema. Never
        raises — any failure degrades to an empty list plus one informational
        finding noting the plugin was unreachable, so a scan never fails
        because the optional model endpoint is down.
        """
        if not self.enabled or not snippets:
            return []

        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        findings: List[Dict[str, Any]] = []
        for snippet in snippets[:20]:  # cap per-scan calls
            try:
                resp = requests.post(
                    self.url,
                    json={"source": snippet.get("source", ""), "language": snippet.get("language", "javascript")},
                    headers=headers,
                    timeout=self.timeout,
                )
                if resp.status_code != 200:
                    continue
                payload = resp.json()
                for item in payload.get("findings", []):
                    category = item.get("category", "misconfiguration")
                    findings.append(
                        {
                            "type": "external_model",
                            "severity": item.get("severity", "info"),
                            "title": f"[External Model] {item.get('title', 'Code pattern flagged')}",
                            "description": item.get("description", ""),
                            "details": {
                                "origin": snippet.get("origin", "unknown"),
                                "model_category": category,
                                "confidence": item.get("confidence"),
                                "mapped_type": _CATEGORY_TO_TYPE.get(category, "misconfiguration"),
                            },
                            "remediation": item.get("remediation", "Review the flagged code pattern manually."),
                        }
                    )
            except requests.exceptions.RequestException:
                continue

        if not findings and self.enabled:
            findings.append(
                {
                    "type": "external_model",
                    "severity": "info",
                    "title": "External Model Plugin Configured But Returned No Findings",
                    "description": f"EXTERNAL_MODEL_URL is set ({self.url}) but the service returned no "
                    "findings or was unreachable during this scan.",
                    "details": {"endpoint": self.url},
                }
            )

        return findings
