from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from vaptforge import __version__
from vaptforge.models.finding import Finding, Severity


def _sarif_level(severity: Severity) -> str:
    if severity >= Severity.HIGH:
        return "error"
    if severity == Severity.MEDIUM:
        return "warning"
    return "note"


def _rule_id(finding: Finding) -> str:
    if finding.cves:
        return finding.cves[0].upper()
    template_id = finding.metadata.get("template_id")
    if template_id:
        return str(template_id)
    slug = re.sub(r"[^a-z0-9]+", "-", finding.title.lower()).strip("-")
    return f"{finding.source}:{slug[:64] or 'finding'}"


def findings_to_sarif(findings: list[Finding]) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for finding in findings:
        rule_id = _rule_id(finding)
        if rule_id not in rules:
            rule: dict[str, Any] = {
                "id": rule_id,
                "name": finding.title,
                "shortDescription": {"text": finding.title},
                "properties": {
                    "source": finding.source,
                    "cwes": finding.cwes,
                    "owasp": finding.owasp,
                },
            }
            if finding.description:
                rule["fullDescription"] = {"text": finding.description}
            if finding.references:
                rule["helpUri"] = finding.references[0]
            rules[rule_id] = rule

        uri = finding.location or finding.asset.target
        results.append(
            {
                "ruleId": rule_id,
                "level": _sarif_level(finding.severity),
                "message": {"text": finding.description or finding.title},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": uri},
                        }
                    }
                ],
                "partialFingerprints": {
                    "vaptforgeFingerprint": finding.fingerprint,
                },
                "properties": {
                    "severity": finding.severity.label(),
                    "status": finding.status.value,
                    "source": finding.source,
                    "cves": finding.cves,
                    "cwes": finding.cwes,
                    "owasp": finding.owasp,
                    "cvssVector": finding.cvss_vector,
                    "cvssScore": finding.cvss_score,
                },
            }
        )

    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "VAPTForge",
                        "version": __version__,
                        "informationUri": "https://github.com/simplyy-shadin/vaptforge",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def write_sarif(path: str | Path, findings: list[Finding]) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(findings_to_sarif(findings), indent=2),
        encoding="utf-8",
    )
