from pathlib import Path

from vaptforge.parsers.nmap_xml import parse_nmap_xml


def test_nmap_parser_returns_only_open_ports() -> None:
    xml = Path("tests/fixtures/nmap.xml").read_text(encoding="utf-8")
    findings = parse_nmap_xml(xml, target="127.0.0.1")
    assert len(findings) == 1
    assert findings[0].asset.port == 80
    assert findings[0].metadata["product"] == "Apache httpd"
