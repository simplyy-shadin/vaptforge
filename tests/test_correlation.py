from vaptforge.correlation.engine import correlate_findings
from vaptforge.models.finding import AssetRef, Evidence, Finding, Severity


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
        evidence=[Evidence(source="scanner-b", summary="second")],
    )
    result = correlate_findings([one, two])
    assert len(result) == 1
    assert result[0].severity == Severity.HIGH
    assert len(result[0].evidence) == 2
    assert result[0].metadata["sources"] == ["scanner-a", "scanner-b"]
