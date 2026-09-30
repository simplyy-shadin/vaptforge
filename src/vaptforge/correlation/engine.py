from __future__ import annotations

from collections import OrderedDict

from vaptforge.models.finding import Evidence, Finding, FindingStatus

STATUS_RANK = {
    FindingStatus.DISCOVERED: 0,
    FindingStatus.POTENTIAL: 1,
    FindingStatus.VERIFIED: 2,
    FindingStatus.REMEDIATED: 3,
    FindingStatus.RETESTED: 4,
    FindingStatus.FALSE_POSITIVE: 5,
}


def correlation_key(finding: Finding) -> str:
    if finding.cves:
        host = (finding.asset.host or finding.asset.target).strip().lower()
        cves = ",".join(sorted(cve.upper() for cve in finding.cves))
        return f"cve|{host}|{finding.asset.port or ''}|{cves}"
    return finding.fingerprint


def _deduplicate_evidence(evidence: list[Evidence]) -> list[Evidence]:
    unique: list[Evidence] = []
    seen: set[tuple[str, str, str | None]] = set()
    for item in evidence:
        key = (item.source, item.summary, item.raw)
        if key not in seen:
            seen.add(key)
            unique.append(item)
    return unique


def correlate_findings(findings: list[Finding]) -> list[Finding]:
    correlated: OrderedDict[str, Finding] = OrderedDict()

    for finding in findings:
        key = correlation_key(finding)
        if key not in correlated:
            copy = finding.model_copy(deep=True)
            copy.metadata["sources"] = sorted(
                set(copy.metadata.get("sources", [])) | {copy.source}
            )
            correlated[key] = copy
            continue

        current = correlated[key]
        if finding.severity > current.severity:
            current.severity = finding.severity
        if STATUS_RANK[finding.status] > STATUS_RANK[current.status]:
            current.status = finding.status

        current.evidence = _deduplicate_evidence(current.evidence + finding.evidence)
        current.cves = sorted(set(current.cves + finding.cves))
        current.cwes = sorted(set(current.cwes + finding.cwes))
        current.owasp = sorted(set(current.owasp + finding.owasp))
        current.references = sorted(set(current.references + finding.references))
        current.tags = sorted(set(current.tags + finding.tags))

        sources = set(current.metadata.get("sources", [current.source]))
        sources.add(finding.source)
        current.metadata["sources"] = sorted(sources)

    return list(correlated.values())
