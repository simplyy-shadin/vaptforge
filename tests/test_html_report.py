from vaptforge.models.finding import AssetRef, Finding, Severity
from vaptforge.reporting.html import render_html_report


def test_html_report_contains_metrics_and_escapes_content() -> None:
    finding = Finding(
        title="<script>alert(1)</script>",
        severity=Severity.HIGH,
        asset=AssetRef(target="http://127.0.0.1"),
        source="unit-test",
    )

    html = render_html_report("Demo", "127.0.0.1", [finding])

    assert "<!doctype html>" in html
    assert "&lt;script&gt;" in html
    assert "<script>alert(1)</script>" not in html
    assert "HIGH" in html
