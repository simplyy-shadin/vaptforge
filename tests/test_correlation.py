from vaptforge.correlation.engine import correlate_findings
from vaptforge.models.finding import AssetRef, Evidence, Finding, FindingStatus, Severity


def test_correlation_merges_duplicate_evidence_and_keeps_highest_severity() -> None:
    base = dict(
        title="Example issue",
        asset=AssetRef(target="127.0.0.1", host="127.0.0.1", port=80),
        location="127.0.0.1:80",
    )
    one = Finding(
        **base,
        severity=Severity.LOW,
        source="scanner-a",
        evidence=[Evidence(source="scanner-a", summary="first")],
    )
    two = Finding(
        **base,
        severity=Severity.HIGH,
        source="scanner-b",
        status=FindingStatus.POTENTIAL,
        evidence=[Evidence(source="scanner-b", summary="second")],
    )
    result = correlate_findings([one, two])

    assert len(result) == 1
    assert result[0].severity == Severity.HIGH
    assert result[0].status == FindingStatus.POTENTIAL
    assert len(result[0].evidence) == 2
    assert result[0].metadata["sources"] == ["scanner-a", "scanner-b"]


def test_correlation_uses_cve_to_merge_cross_scanner_findings() -> None:
    first = Finding(
        title="Product version appears vulnerable",
        severity=Severity.MEDIUM,
        asset=AssetRef(target="10.0.0.8", host="10.0.0.8", port=443),
        source="nuclei",
        location="https://10.0.0.8/",
        cves=["CVE-2025-12345"],
    )
    second = Finding(
        title="Legacy component advisory",
        severity=Severity.HIGH,
        asset=AssetRef(target="10.0.0.8", host="10.0.0.8", port=443),
        source="nikto",
        location="https://10.0.0.8/legacy",
        cves=["CVE-2025-12345"],
    )

    result = correlate_findings([first, second])

    assert len(result) == 1
    assert result[0].severity == Severity.HIGH
    assert result[0].metadata["sources"] == ["nikto", "nuclei"]


def test_correlation_deduplicates_identical_evidence() -> None:
    evidence = Evidence(source="scanner-a", summary="same evidence")
    one = Finding(
        title="Duplicate",
        asset=AssetRef(target="127.0.0.1"),
        source="scanner-a",
        evidence=[evidence],
    )
    two = Finding(
        title="Duplicate",
        asset=AssetRef(target="127.0.0.1"),
        source="scanner-a",
        evidence=[evidence],
    )

    result = correlate_findings([one, two])

    assert len(result[0].evidence) == 1
