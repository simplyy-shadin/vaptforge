from __future__ import annotations

import json

from vaptforge.models.finding import AssetRef, Evidence, Finding, Severity


def parse_nuclei_jsonl(text: str, *, target: str) -> list[Finding]:
    findings: list[Finding] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        info = item.get("info", {})
        classification = info.get("classification", {}) or {}
        cves = classification.get("cve-id", []) or []
        cwes = classification.get("cwe-id", []) or []
        if isinstance(cves, str):
            cves = [cves]
        if isinstance(cwes, str):
            cwes = [cwes]

        matched_at = item.get("matched-at") or item.get("host") or target
        findings.append(
            Finding(
                title=info.get("name") or item.get("template-id") or "Nuclei finding",
                severity=Severity.from_text(info.get("severity")),
                asset=AssetRef(target=target, host=item.get("host") or target),
                source="nuclei",
                description=info.get("description"),
                location=matched_at,
                cves=[str(v) for v in cves],
                cwes=[str(v) for v in cwes],
                references=[str(v) for v in (info.get("reference") or [])],
                tags=(
                    [str(v) for v in (info.get("tags") or [])]
                    if isinstance(info.get("tags"), list)
                    else []
                ),
                evidence=[
                    Evidence(
                        source="nuclei",
                        summary=(
                            f"Template {item.get('template-id', 'unknown')} "
                            f"matched at {matched_at}"
                        ),
                    )
                ],
                metadata={"template_id": item.get("template-id"), "type": item.get("type")},
            )
        )
    return findings
