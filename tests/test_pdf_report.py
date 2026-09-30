from pathlib import Path

from vaptforge.models.finding import AssetRef, Finding, Severity
from vaptforge.reporting.pdf import write_pdf_report


def test_pdf_report_is_generated(tmp_path: Path) -> None:
    output = tmp_path / "report.pdf"
    finding = Finding(
        title="Example finding",
        severity=Severity.MEDIUM,
        asset=AssetRef(target="127.0.0.1"),
        source="unit-test",
        description="Example report content.",
    )

    write_pdf_report(output, "Demo", "127.0.0.1", [finding])

    assert output.exists()
    assert output.read_bytes().startswith(b"%PDF")
