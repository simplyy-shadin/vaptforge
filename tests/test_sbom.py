from vaptforge.reporting.sbom import build_cyclonedx_sbom


def test_cyclonedx_sbom_contains_application_and_components() -> None:
    document = build_cyclonedx_sbom(
        [
            ("fastapi", "1.2.3"),
            ("httpx", "4.5.6"),
        ]
    )

    assert document["bomFormat"] == "CycloneDX"
    assert document["specVersion"] == "1.5"
    assert document["metadata"]["component"]["name"] == "vaptforge"
    assert [item["name"] for item in document["components"]] == ["fastapi", "httpx"]
    assert document["components"][0]["purl"] == "pkg:pypi/fastapi@1.2.3"
