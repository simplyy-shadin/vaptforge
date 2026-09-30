from pathlib import Path

from vaptforge.models.finding import FindingStatus
from vaptforge.parsers.nikto_json import parse_nikto_json


def test_nikto_parser_marks_output_for_validation_and_extracts_cve() -> None:
    text = Path("tests/fixtures/nikto.json").read_text(encoding="utf-8")
    findings = parse_nikto_json(text, target="http://127.0.0.1:3000")

    assert len(findings) == 1
    assert findings[0].status == FindingStatus.POTENTIAL
    assert findings[0].cves == ["CVE-2024-12345"]
    assert findings[0].location.endswith("/legacy")
