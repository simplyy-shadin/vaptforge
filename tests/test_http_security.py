from vaptforge.models.finding import Severity
from vaptforge.scanners.http_security import analyze_headers


def test_header_analyzer_detects_missing_controls_and_server_disclosure() -> None:
    findings = analyze_headers(
        "http://127.0.0.1:3000/",
        {
            "Server": "ExampleServer/1.0",
            "X-Content-Type-Options": "nosniff",
        },
    )
    titles = {item.title for item in findings}
    assert "Content Security Policy header missing" in titles
    assert "Referrer-Policy header missing" in titles
    assert "X-Content-Type-Options header missing" not in titles
    assert "Server software information disclosed" in titles
    assert any(item.severity == Severity.LOW for item in findings)
