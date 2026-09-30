from datetime import UTC, datetime, timedelta

from vaptforge.models.finding import Severity
from vaptforge.scanners.tls_security import analyze_tls_snapshot


def test_certificate_validation_failure_is_high() -> None:
    findings = analyze_tls_snapshot(
        "https://lab.example.test/",
        tls_version="TLSv1.3",
        cipher="TLS_AES_256_GCM_SHA384",
        validation_error="self-signed certificate",
    )
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


def test_deprecated_tls_and_weak_cipher_are_reported() -> None:
    findings = analyze_tls_snapshot(
        "https://lab.example.test/",
        tls_version="TLSv1.1",
        cipher="DES-CBC3-SHA",
    )
    titles = {finding.title for finding in findings}
    assert "Deprecated TLS protocol negotiated (TLSv1.1)" in titles
    assert "Weak TLS cipher negotiated" in titles


def test_expiring_certificate_is_reported() -> None:
    now = datetime(2026, 9, 30, tzinfo=UTC)
    findings = analyze_tls_snapshot(
        "https://lab.example.test/",
        tls_version="TLSv1.3",
        cipher="TLS_AES_256_GCM_SHA384",
        certificate_not_after=now + timedelta(days=10),
        now=now,
    )
    assert len(findings) == 1
    assert findings[0].severity == Severity.LOW


def test_healthy_tls_snapshot_produces_no_findings() -> None:
    now = datetime(2026, 9, 30, tzinfo=UTC)
    findings = analyze_tls_snapshot(
        "https://lab.example.test/",
        tls_version="TLSv1.3",
        cipher="TLS_AES_256_GCM_SHA384",
        certificate_not_after=now + timedelta(days=120),
        now=now,
    )
    assert findings == []
