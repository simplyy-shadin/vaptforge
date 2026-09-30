from __future__ import annotations

from collections.abc import Mapping
from urllib.parse import urlparse

import httpx

from vaptforge.core.targets import http_url_from_target
from vaptforge.models.finding import AssetRef, Evidence, Finding, FindingStatus, Severity
from vaptforge.models.scope import AuthorizedScope
from vaptforge.scanners.base import Scanner

CORS_TEST_ORIGIN = "https://vaptforge.invalid"
SENSITIVE_COOKIE_MARKERS = ("session", "auth", "token", "jwt", "sid")

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


def _asset(target: str) -> AssetRef:
    parsed = urlparse(target)
    return AssetRef(
        target=target,
        host=parsed.hostname or target,
        port=parsed.port,
        protocol=parsed.scheme or None,
    )


def analyze_headers(target: str, headers: Mapping[str, str]) -> list[Finding]:
    lower = {key.lower(): value for key, value in headers.items()}
    findings: list[Finding] = []

    for header, (title, severity, remediation) in HEADER_CHECKS.items():
        if header in lower:
            continue
        findings.append(
            Finding(
                title=title,
                severity=severity,
                asset=_asset(target),
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
                asset=_asset(target),
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


def _cookie_parts(raw_cookie: str) -> tuple[str, set[str]]:
    parts = [part.strip() for part in raw_cookie.split(";") if part.strip()]
    name = parts[0].split("=", maxsplit=1)[0].strip() if parts else ""
    attributes = {
        part.split("=", maxsplit=1)[0].strip().lower()
        for part in parts[1:]
    }
    return name, attributes


def analyze_cookies(target: str, set_cookie_headers: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    is_https = urlparse(target).scheme.lower() == "https"

    for raw_cookie in set_cookie_headers:
        name, attributes = _cookie_parts(raw_cookie)
        if not name:
            continue
        sensitive = any(marker in name.lower() for marker in SENSITIVE_COOKIE_MARKERS)

        if is_https and "secure" not in attributes:
            findings.append(
                Finding(
                    title=f"Cookie '{name}' missing Secure attribute",
                    severity=Severity.MEDIUM if sensitive else Severity.LOW,
                    asset=_asset(target),
                    source="vaptforge-http",
                    status=FindingStatus.POTENTIAL,
                    description=(
                        "A cookie set over HTTPS does not include the Secure attribute."
                    ),
                    location=target,
                    cwes=["CWE-614"],
                    evidence=[
                        Evidence(
                            source="vaptforge-http",
                            summary=f"Set-Cookie for '{name}' omitted Secure",
                        )
                    ],
                    remediation="Add the Secure attribute to cookies intended for HTTPS use.",
                    tags=["cookies", "session-management"],
                )
            )

        if sensitive and "httponly" not in attributes:
            findings.append(
                Finding(
                    title=f"Sensitive cookie '{name}' missing HttpOnly attribute",
                    severity=Severity.MEDIUM,
                    asset=_asset(target),
                    source="vaptforge-http",
                    status=FindingStatus.POTENTIAL,
                    description=(
                        "A session- or authentication-like cookie is accessible to client-side "
                        "script because HttpOnly is not present."
                    ),
                    location=target,
                    cwes=["CWE-1004"],
                    evidence=[
                        Evidence(
                            source="vaptforge-http",
                            summary=f"Set-Cookie for '{name}' omitted HttpOnly",
                        )
                    ],
                    remediation="Add HttpOnly to cookies that do not require JavaScript access.",
                    tags=["cookies", "session-management"],
                )
            )

        if sensitive and "samesite" not in attributes:
            findings.append(
                Finding(
                    title=f"Sensitive cookie '{name}' missing SameSite attribute",
                    severity=Severity.LOW,
                    asset=_asset(target),
                    source="vaptforge-http",
                    status=FindingStatus.POTENTIAL,
                    description=(
                        "A session- or authentication-like cookie does not explicitly define "
                        "SameSite behavior."
                    ),
                    location=target,
                    cwes=["CWE-1275"],
                    evidence=[
                        Evidence(
                            source="vaptforge-http",
                            summary=f"Set-Cookie for '{name}' omitted SameSite",
                        )
                    ],
                    remediation=(
                        "Set SameSite=Lax or SameSite=Strict unless cross-site use is required."
                    ),
                    tags=["cookies", "csrf"],
                )
            )

    return findings


def analyze_cors(target: str, headers: Mapping[str, str]) -> list[Finding]:
    lower = {key.lower(): value.strip() for key, value in headers.items()}
    allow_origin = lower.get("access-control-allow-origin", "")
    allow_credentials = lower.get("access-control-allow-credentials", "").lower() == "true"

    if allow_origin != CORS_TEST_ORIGIN:
        return []

    severity = Severity.HIGH if allow_credentials else Severity.MEDIUM
    description = (
        "The application reflected an arbitrary Origin supplied by the assessment request."
    )
    if allow_credentials:
        description += " It also permits credentialed cross-origin requests."

    return [
        Finding(
            title="Arbitrary CORS origin reflection detected",
            severity=severity,
            asset=_asset(target),
            source="vaptforge-http",
            status=FindingStatus.POTENTIAL,
            description=description,
            location=target,
            cwes=["CWE-942"],
            evidence=[
                Evidence(
                    source="vaptforge-http",
                    summary=(
                        f"Origin {CORS_TEST_ORIGIN} was reflected as "
                        f"Access-Control-Allow-Origin; credentials={allow_credentials}"
                    ),
                )
            ],
            remediation=(
                "Use an explicit allow-list of trusted origins and enable credentials only "
                "where required."
            ),
            tags=["cors", "access-control"],
        )
    ]


def analyze_methods(target: str, headers: Mapping[str, str]) -> list[Finding]:
    allow = headers.get("allow") or headers.get("Allow") or ""
    methods = {method.strip().upper() for method in allow.split(",") if method.strip()}
    if "TRACE" not in methods:
        return []

    return [
        Finding(
            title="HTTP TRACE method advertised",
            severity=Severity.LOW,
            asset=_asset(target),
            source="vaptforge-http",
            status=FindingStatus.POTENTIAL,
            description=(
                "The server advertises TRACE support. TRACE is rarely required by applications "
                "and can increase unnecessary HTTP attack surface."
            ),
            location=target,
            cwes=["CWE-749"],
            evidence=[
                Evidence(
                    source="vaptforge-http",
                    summary=f"OPTIONS response Allow header: {allow}",
                )
            ],
            remediation="Disable TRACE unless it is explicitly required.",
            tags=["http-methods", "misconfiguration"],
        )
    ]


class HttpSecurityScanner(Scanner):
    name = "http"

    def scan(self, target: str, scope: AuthorizedScope) -> list[Finding]:
        scope.require_authorized(target)
        url = http_url_from_target(target)
        request_headers = {
            "User-Agent": "VAPTForge/0.2 authorized-security-assessment",
        }
        with httpx.Client(
            follow_redirects=True,
            timeout=10.0,
            headers=request_headers,
        ) as client:
            response = client.get(url)
            findings = analyze_headers(str(response.url), response.headers)
            findings.extend(
                analyze_cookies(str(response.url), response.headers.get_list("set-cookie"))
            )

            options = client.options(
                str(response.url),
                headers={
                    "Origin": CORS_TEST_ORIGIN,
                    "Access-Control-Request-Method": "GET",
                },
            )
            findings.extend(analyze_cors(str(options.url), options.headers))
            findings.extend(analyze_methods(str(options.url), options.headers))

        return findings
