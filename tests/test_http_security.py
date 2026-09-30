from vaptforge.models.finding import Severity
from vaptforge.scanners.http_security import (
    CORS_TEST_ORIGIN,
    analyze_cookies,
    analyze_cors,
    analyze_headers,
    analyze_methods,
)


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


def test_sensitive_cookie_controls_are_reported() -> None:
    findings = analyze_cookies(
        "https://lab.example.test/",
        ["sessionid=abc123; Path=/"],
    )
    titles = {item.title for item in findings}
    assert "Cookie 'sessionid' missing Secure attribute" in titles
    assert "Sensitive cookie 'sessionid' missing HttpOnly attribute" in titles
    assert "Sensitive cookie 'sessionid' missing SameSite attribute" in titles


def test_non_sensitive_http_cookie_is_not_overreported() -> None:
    findings = analyze_cookies(
        "http://lab.example.test/",
        ["theme=dark; Path=/"],
    )
    assert findings == []


def test_arbitrary_credentialed_cors_reflection_is_high() -> None:
    findings = analyze_cors(
        "https://lab.example.test/",
        {
            "Access-Control-Allow-Origin": CORS_TEST_ORIGIN,
            "Access-Control-Allow-Credentials": "true",
        },
    )
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


def test_fixed_cors_origin_is_not_flagged() -> None:
    findings = analyze_cors(
        "https://lab.example.test/",
        {"Access-Control-Allow-Origin": "https://trusted.example.test"},
    )
    assert findings == []


def test_trace_method_is_reported() -> None:
    findings = analyze_methods(
        "https://lab.example.test/",
        {"Allow": "GET, HEAD, OPTIONS, TRACE"},
    )
    assert len(findings) == 1
    assert "TRACE" in findings[0].title
