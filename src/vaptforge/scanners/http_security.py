from __future__ import annotations

from collections.abc import Mapping
from urllib.parse import urlparse

import httpx

from vaptforge.core.targets import http_url_from_target
from vaptforge.models.finding import AssetRef, Evidence, Finding, Severity
from vaptforge.models.scope import AuthorizedScope
from vaptforge.scanners.base import Scanner


HEADER_CHECKS: dict[str, tuple[str, Severity, str]] = {
    "content-security-policy": (
        "Content Security Policy header missing",
        Severity.LOW,
        "Define a restrictive Content-Security-Policy appropriate for the application.",
    ),
    "x-content-type-options": (
        "X-Content-Type-Options header missing",
        Severity.LOW,
        "Set X-Content-Type-Options: nosniff.",
    ),
    "referrer-policy": (
        "Referrer-Policy header missing",
        Severity.INFO,
        "Set an application-appropriate Referrer-Policy.",
    ),
}


def analyze_headers(target: str, headers: Mapping[str, str]) -> list[Finding]:
    lower = {key.lower(): value for key, value in headers.items()}
    parsed = urlparse(target)
    host = parsed.hostname or target
    port = parsed.port
    findings: list[Finding] = []

    for header, (title, severity, remediation) in HEADER_CHECKS.items():
        if header in lower:
            continue
        findings.append(
            Finding(
                title=title,
                severity=severity,
                asset=AssetRef(target=target, host=host, port=port, protocol=parsed.scheme),
                source="vaptforge-http",
                description=f"The HTTP response did not include the {header} security header.",
                location=target,
                evidence=[
                    Evidence(
                        source="vaptforge-http",
                        summary=f"Response header '{header}' was not present",
                    )
                ],
                cwes=["CWE-693"],
                owasp=["A05:2021 Security Misconfiguration"],
                remediation=remediation,
                tags=["headers", "misconfiguration"],
            )
        )

    server = lower.get("server")
    if server:
        findings.append(
            Finding(
                title="Server software information disclosed",
                severity=Severity.INFO,
                asset=AssetRef(target=target, host=host, port=port, protocol=parsed.scheme),
                source="vaptforge-http",
                description=(
                    "The response advertises server software information in the Server header."
                ),
                location=target,
                evidence=[Evidence(source="vaptforge-http", summary=f"Server: {server}")],
                remediation=(
                    "Minimize unnecessary server version/product disclosure where practical."
                ),
                tags=["headers", "information-disclosure"],
            )
        )

    return findings


class HttpSecurityScanner(Scanner):
    name = "http"

    def scan(self, target: str, scope: AuthorizedScope) -> list[Finding]:
        scope.require_authorized(target)
        url = http_url_from_target(target)
        with httpx.Client(
            follow_redirects=True,
            timeout=10.0,
            headers={"User-Agent": "VAPTForge/0.1 authorized-security-assessment"},
        ) as client:
            response = client.get(url)
        return analyze_headers(str(response.url), response.headers)
