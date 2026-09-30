from pathlib import Path

from vaptforge.models.finding import Severity
from vaptforge.parsers.httpx_jsonl import parse_httpx_jsonl


def test_httpx_parser_preserves_recon_metadata() -> None:
    text = Path("tests/fixtures/httpx.jsonl").read_text(encoding="utf-8")
    findings = parse_httpx_jsonl(text, target="127.0.0.1")

    assert len(findings) == 1
    assert findings[0].severity == Severity.INFO
    assert findings[0].metadata["technologies"] == ["Express", "Node.js"]
    assert findings[0].metadata["status_code"] == 200
