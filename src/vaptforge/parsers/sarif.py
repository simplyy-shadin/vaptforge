from __future__ import annotations

from typing import Any

from vaptforge.models.finding import (
    AssetRef,
    Evidence,
    Finding,
    FindingStatus,
    Severity,
)

_LEVEL_SEVERITY = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "note": Severity.LOW,
    "none": Severity.INFO,
}


def _rule_lookup(run: dict[str, Any]) -> dict[str, dict[str, Any]]:
    driver = run.get("tool", {}).get("driver", {})
    return {
        str(rule.get("id")): rule
        for rule in driver.get("rules", [])
        if rule.get("id")
    }


def parse_sarif(document: dict[str, Any], *, default_target: str) -> list[Finding]:
    findings: list[Finding] = []

    for run in document.get("runs", []):
        driver = run.get("tool", {}).get("driver", {})
        tool_name = str(driver.get("name") or "unknown")
        rules = _rule_lookup(run)

        for result in run.get("results", []):
            rule_id = str(result.get("ruleId") or "sarif-finding")
            rule = rules.get(rule_id, {})
            properties = result.get("properties", {}) or {}
            location_nodes = result.get("locations", []) or []
            uri = default_target
            if location_nodes:
                uri = (
                    location_nodes[0]
                    .get("physicalLocation", {})
                    .get("artifactLocation", {})
                    .get("uri")
                    or default_target
                )

            severity_text = properties.get("severity")
            severity = (
                Severity.from_text(str(severity_text))
                if severity_text
                else _LEVEL_SEVERITY.get(str(result.get("level", "none")), Severity.INFO)
            )
            status_text = str(properties.get("status") or FindingStatus.DISCOVERED.value)
            try:
                status = FindingStatus(status_text)
            except ValueError:
                status = FindingStatus.DISCOVERED

            title = (
                rule.get("shortDescription", {}).get("text")
                or rule.get("name")
                or rule_id
            )
            message = result.get("message", {}).get("text") or title

            findings.append(
                Finding(
                    title=str(title),
                    severity=severity,
                    asset=AssetRef(target=default_target),
                    source=f"sarif:{tool_name}",
                    status=status,
                    description=str(message),
                    location=str(uri),
                    cves=[str(value) for value in properties.get("cves", [])],
                    cwes=[str(value) for value in properties.get("cwes", [])],
                    owasp=[str(value) for value in properties.get("owasp", [])],
                    cvss_vector=properties.get("cvssVector"),
                    cvss_score=properties.get("cvssScore"),
                    evidence=[
                        Evidence(
                            source=f"sarif:{tool_name}",
                            summary=f"Imported SARIF rule {rule_id} at {uri}",
                        )
                    ],
                    metadata={
                        "sarif_rule_id": rule_id,
                        "sarif_tool": tool_name,
                    },
                )
            )

    return findings
