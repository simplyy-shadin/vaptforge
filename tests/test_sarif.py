from vaptforge.models.finding import AssetRef, Finding, FindingStatus, Severity
from vaptforge.parsers.sarif import parse_sarif
from vaptforge.reporting.sarif import findings_to_sarif


def test_sarif_export_and_import_preserve_security_context() -> None:
    finding = Finding(
        title="Example SQL Injection",
        severity=Severity.HIGH,
        asset=AssetRef(target="http://127.0.0.1:3000"),
        source="unit-test",
        status=FindingStatus.VERIFIED,
        description="A sanitized test finding.",
        location="http://127.0.0.1:3000/item?id=1",
        cves=["CVE-2099-0001"],
        cwes=["CWE-89"],
        owasp=["A03:2021 Injection"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        cvss_score=9.1,
    )

    document = findings_to_sarif([finding])
    result = document["runs"][0]["results"][0]

    assert document["version"] == "2.1.0"
    assert result["ruleId"] == "CVE-2099-0001"
    assert result["level"] == "error"

    imported = parse_sarif(document, default_target="http://127.0.0.1:3000")
    assert len(imported) == 1
    assert imported[0].severity == Severity.HIGH
    assert imported[0].status == FindingStatus.VERIFIED
    assert imported[0].cwes == ["CWE-89"]
    assert imported[0].cvss_score == 9.1
