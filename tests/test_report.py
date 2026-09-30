from vaptforge.models.finding import AssetRef, Finding, Severity
from vaptforge.reporting.markdown import render_markdown_report


def test_report_contains_summary_and_finding() -> None:
    finding = Finding(
        title="Test finding",
        severity=Severity.HIGH,
        asset=AssetRef(target="127.0.0.1"),
        source="unit-test",
    )
    report = render_markdown_report("Demo", "127.0.0.1", [finding])
    assert "# VAPT Assessment Report" in report
    assert "Test finding" in report
    assert "HIGH" in report
