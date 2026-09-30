from pathlib import Path

from vaptforge.parsers.nmap_xml import parse_nmap_xml


def test_nmap_parser_returns_only_open_ports() -> None:
    xml = Path("tests/fixtures/nmap.xml").read_text(encoding="utf-8")
    findings = parse_nmap_xml(xml, target="127.0.0.1")
    assert len(findings) == 1
    assert findings[0].asset.port == 80
    assert findings[0].metadata["product"] == "Apache httpd"
    assert findings[0].asset.service == "http"


def test_nmap_parser_does_not_present_table_hint_as_identified_service() -> None:
    xml = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="3000">
        <state state="open" reason="syn-ack"/>
        <service name="ppp" method="table" conf="3"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""
    findings = parse_nmap_xml(xml, target="http://127.0.0.1:3000")

    assert len(findings) == 1
    finding = findings[0]
    assert finding.title == "Open TCP port 3000"
    assert finding.asset.service is None
    assert finding.metadata["service_name"] == "ppp"
    assert finding.metadata["service_method"] == "table"
    assert finding.metadata["service_confidence"] == "3"
    assert finding.metadata["service_identified"] is False
    assert "not a verified service identification" in finding.description


def test_nmap_parser_keeps_probed_service_identity() -> None:
    xml = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="135">
        <state state="open" reason="syn-ack"/>
        <service name="msrpc" product="Microsoft Windows RPC" method="probed" conf="10"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""
    finding = parse_nmap_xml(xml, target="127.0.0.1")[0]

    assert finding.title == "Open TCP port 135 (msrpc)"
    assert finding.asset.service == "msrpc"
    assert finding.metadata["service_identified"] is True
    assert "Microsoft Windows RPC" in finding.description
