from __future__ import annotations

import httpx

from vaptforge.models.finding import FindingConfidence, FindingStatus, Severity
from vaptforge.scanners.deep_web import analyze_reflection, analyze_sql_error


def _response(
    text: str,
    *,
    status: int = 200,
    content_type: str = "text/html",
) -> httpx.Response:
    return httpx.Response(
        status,
        headers={"content-type": content_type},
        text=text,
        request=httpx.Request("GET", "http://127.0.0.1:3000/search"),
    )


def test_reflection_analysis_marks_unencoded_html_reflection_as_potential() -> None:
    marker = "VFREFL_123_<>\"'&"
    finding = analyze_reflection(
        target="http://127.0.0.1:3000",
        endpoint="http://127.0.0.1:3000/search",
        parameter="q",
        baseline=_response("<html>search</html>"),
        mutated=_response(f"<html>result: {marker}</html>"),
        marker=marker,
    )

    assert finding is not None
    assert finding.status == FindingStatus.POTENTIAL
    assert finding.severity == Severity.LOW
    assert finding.confidence == FindingConfidence.MEDIUM
    assert finding.metadata["requires_manual_validation"] is True


def test_reflection_analysis_ignores_encoded_or_absent_marker() -> None:
    marker = "VFREFL_123_<>\"'&"
    finding = analyze_reflection(
        target="http://127.0.0.1:3000",
        endpoint="http://127.0.0.1:3000/search",
        parameter="q",
        baseline=_response("<html>search</html>"),
        mutated=_response("<html>VFREFL_123_&lt;&gt;&quot;&#x27;&amp;</html>"),
        marker=marker,
    )

    assert finding is None


def test_sql_error_analysis_requires_new_database_specific_error() -> None:
    finding = analyze_sql_error(
        target="http://127.0.0.1:3000",
        endpoint="http://127.0.0.1:3000/item",
        parameter="id",
        baseline=_response("<html>Item 1</html>"),
        mutated=_response(
            "<html>You have an error in your SQL syntax near quote</html>",
            status=500,
        ),
    )

    assert finding is not None
    assert finding.status == FindingStatus.POTENTIAL
    assert finding.severity == Severity.MEDIUM
    assert finding.confidence == FindingConfidence.HIGH
    assert finding.cwes == ["CWE-89"]


def test_sql_error_analysis_does_not_repeat_baseline_text() -> None:
    baseline = _response("<html>MariaDB documentation link</html>")
    mutated = _response("<html>MariaDB documentation link</html>", status=500)

    assert (
        analyze_sql_error(
            target="http://127.0.0.1:3000",
            endpoint="http://127.0.0.1:3000/item",
            parameter="id",
            baseline=baseline,
            mutated=mutated,
        )
        is None
    )
