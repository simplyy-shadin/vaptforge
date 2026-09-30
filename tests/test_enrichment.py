from vaptforge.enrichment.owasp import enrich_owasp
from vaptforge.models.finding import AssetRef, Finding


def test_cwe_mapping_adds_owasp_category_without_losing_existing_data() -> None:
    finding = Finding(
        title="SQL injection",
        asset=AssetRef(target="http://lab.test"),
        source="unit-test",
        cwes=["CWE-89"],
        owasp=["Custom mapping"],
    )

    enriched = enrich_owasp(finding)

    assert "A03:2021 Injection" in enriched.owasp
    assert "Custom mapping" in enriched.owasp
    assert finding.owasp == ["Custom mapping"]
