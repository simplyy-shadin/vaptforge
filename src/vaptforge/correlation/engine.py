from __future__ import annotations

from collections import OrderedDict

from vaptforge.models.finding import Finding


def correlate_findings(findings: list[Finding]) -> list[Finding]:
    correlated: OrderedDict[str, Finding] = OrderedDict()

    for finding in findings:
        key = finding.fingerprint
        if key not in correlated:
            correlated[key] = finding.model_copy(deep=True)
            continue

        current = correlated[key]
        if finding.severity > current.severity:
            current.severity = finding.severity
        current.evidence.extend(finding.evidence)
        current.cves = sorted(set(current.cves + finding.cves))
        current.cwes = sorted(set(current.cwes + finding.cwes))
        current.references = sorted(set(current.references + finding.references))
        current.tags = sorted(set(current.tags + finding.tags))
        sources = set(current.metadata.get("sources", [current.source]))
        sources.add(finding.source)
        current.metadata["sources"] = sorted(sources)

    return list(correlated.values())
