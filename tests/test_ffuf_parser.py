from pathlib import Path

from vaptforge.models.finding import FindingStatus, Severity
from vaptforge.parsers.ffuf_json import parse_ffuf_json


def test_ffuf_parser_normalizes_results_and_flags_sensitive_paths() -> None:
    text = Path("tests/fixtures/ffuf.json").read_text(encoding="utf-8")
    findings = parse_ffuf_json(text, target="http://127.0.0.1:3000")

    assert len(findings) == 2
    env_finding = next(item for item in findings if "/.env" in item.location)
    assert env_finding.severity == Severity.MEDIUM
    assert env_finding.status == FindingStatus.POTENTIAL
