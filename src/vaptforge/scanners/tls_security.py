from __future__ import annotations

import socket
import ssl
from datetime import UTC, datetime
from urllib.parse import urlparse

from vaptforge.models.finding import AssetRef, Evidence, Finding, FindingStatus, Severity
from vaptforge.models.scope import AuthorizedScope
from vaptforge.scanners.base import Scanner

OUTDATED_TLS = {"TLSv1", "TLSv1.1"}
WEAK_CIPHER_MARKERS = ("RC4", "3DES", "DES-", "NULL", "EXPORT")


def analyze_tls_snapshot(
    target: str,
    *,
    tls_version: str | None,
    cipher: str | None,
    certificate_not_after: datetime | None = None,
    validation_error: str | None = None,
    now: datetime | None = None,
) -> list[Finding]:
    parsed = urlparse(target)
    asset = AssetRef(
        target=target,
        host=parsed.hostname,
        port=parsed.port or 443,
        protocol="https",
        service="https",
    )
    findings: list[Finding] = []

    if validation_error:
        findings.append(
            Finding(
                title="TLS certificate validation failed",
                severity=Severity.HIGH,
                asset=asset,
                source="vaptforge-tls",
                status=FindingStatus.POTENTIAL,
                description=(
                    "The server certificate could not be validated with the system trust store "
                    "and hostname validation."
                ),
                location=f"{parsed.hostname}:{parsed.port or 443}",
                evidence=[
                    Evidence(source="vaptforge-tls", summary=validation_error)
                ],
                cwes=["CWE-295"],
                remediation=(
                    "Deploy a certificate issued by a trusted CA for the correct hostname and "
                    "include the required certificate chain."
                ),
                tags=["tls", "certificate"],
            )
        )

    if tls_version in OUTDATED_TLS:
        findings.append(
            Finding(
                title=f"Deprecated TLS protocol negotiated ({tls_version})",
                severity=Severity.HIGH,
                asset=asset,
                source="vaptforge-tls",
                status=FindingStatus.POTENTIAL,
                description="The TLS connection negotiated a deprecated protocol version.",
                location=f"{parsed.hostname}:{parsed.port or 443}",
                evidence=[
                    Evidence(
                        source="vaptforge-tls",
                        summary=f"Negotiated protocol: {tls_version}",
                    )
                ],
                cwes=["CWE-326"],
                remediation="Disable TLS 1.0/1.1 and require TLS 1.2 or newer.",
                tags=["tls", "protocol"],
            )
        )

    cipher_upper = (cipher or "").upper()
    if cipher and any(marker in cipher_upper for marker in WEAK_CIPHER_MARKERS):
        findings.append(
            Finding(
                title="Weak TLS cipher negotiated",
                severity=Severity.HIGH,
                asset=asset,
                source="vaptforge-tls",
                status=FindingStatus.POTENTIAL,
                description="The TLS handshake negotiated a cipher with a weak algorithm marker.",
                location=f"{parsed.hostname}:{parsed.port or 443}",
                evidence=[
                    Evidence(source="vaptforge-tls", summary=f"Negotiated cipher: {cipher}")
                ],
                cwes=["CWE-327"],
                remediation="Prefer modern AEAD cipher suites and disable legacy ciphers.",
                tags=["tls", "cipher"],
            )
        )

    if certificate_not_after is not None:
        current = now or datetime.now(UTC)
        not_after = certificate_not_after.astimezone(UTC)
        days_remaining = int((not_after - current).total_seconds() // 86400)
        if days_remaining < 0:
            severity = Severity.HIGH
            title = "TLS certificate has expired"
        elif days_remaining <= 30:
            severity = Severity.LOW
            title = "TLS certificate expires soon"
        else:
            return findings

        findings.append(
            Finding(
                title=title,
                severity=severity,
                asset=asset,
                source="vaptforge-tls",
                status=FindingStatus.POTENTIAL,
                description=f"Certificate validity ends in {days_remaining} day(s).",
                location=f"{parsed.hostname}:{parsed.port or 443}",
                evidence=[
                    Evidence(
                        source="vaptforge-tls",
                        summary=f"Certificate notAfter: {not_after.isoformat()}",
                    )
                ],
                remediation="Renew and deploy the certificate before it expires.",
                tags=["tls", "certificate"],
            )
        )

    return findings


class TlsSecurityScanner(Scanner):
    name = "tls"

    def scan(self, target: str, scope: AuthorizedScope) -> list[Finding]:
        scope.require_authorized(target)
        parsed = urlparse(target)
        if parsed.scheme.lower() != "https" or not parsed.hostname:
            return []

        host = parsed.hostname
        port = parsed.port or 443
        validation_error: str | None = None
        tls_version: str | None = None
        cipher: str | None = None
        certificate_not_after: datetime | None = None

        context = ssl.create_default_context()
        try:
            with (
                socket.create_connection((host, port), timeout=10) as raw_socket,
                context.wrap_socket(raw_socket, server_hostname=host) as tls_socket,
            ):
                tls_version = tls_socket.version()
                cipher_info = tls_socket.cipher()
                cipher = cipher_info[0] if cipher_info else None
                certificate = tls_socket.getpeercert()
                not_after = certificate.get("notAfter")
                if not_after:
                    timestamp = ssl.cert_time_to_seconds(not_after)
                    certificate_not_after = datetime.fromtimestamp(timestamp, tz=UTC)
        except ssl.SSLCertVerificationError as exc:
            validation_error = str(exc)
            fallback = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            fallback.check_hostname = False
            fallback.verify_mode = ssl.CERT_NONE
            with (
                socket.create_connection((host, port), timeout=10) as raw_socket,
                fallback.wrap_socket(raw_socket, server_hostname=host) as tls_socket,
            ):
                tls_version = tls_socket.version()
                cipher_info = tls_socket.cipher()
                cipher = cipher_info[0] if cipher_info else None

        return analyze_tls_snapshot(
            target,
            tls_version=tls_version,
            cipher=cipher,
            certificate_not_after=certificate_not_after,
            validation_error=validation_error,
        )
