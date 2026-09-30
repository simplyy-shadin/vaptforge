from pathlib import Path

from vaptforge.models.finding import Severity
from vaptforge.parsers.nuclei_jsonl import parse_nuclei_jsonl


def test_nuclei_parser_normalizes_finding() -> None:
    text = Path("tests/fixtures/nuclei.jsonl").read_text(encoding="utf-8")
    findings = parse_nuclei_jsonl(text, target="http://127.0.0.1:3000")
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == Severity.MEDIUM
    assert "CWE-693" in finding.cwes
    assert finding.metadata["template_id"] == "missing-csp"
