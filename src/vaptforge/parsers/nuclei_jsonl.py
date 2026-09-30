from __future__ import annotations

import json

from vaptforge.models.finding import AssetRef, Evidence, Finding, Severity
from vaptforge.risk.cvss import CvssVectorError, score_cvss_v31


def _cvss_data(classification: dict[str, object]) -> tuple[str | None, float | None]:
    raw_vector = classification.get("cvss-metrics")
    vector = str(raw_vector) if raw_vector else None

    raw_score = classification.get("cvss-score")
    score: float | None = None
    if isinstance(raw_score, (int, float)):
        score = float(raw_score)
    elif isinstance(raw_score, str):
        try:
            score = float(raw_score)
        except ValueError:
            score = None

    if score is None and vector:
        try:
            score = score_cvss_v31(vector)
        except CvssVectorError:
            score = None
    return vector, score


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

        vector, score = _cvss_data(classification)
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
                cvss_vector=vector,
                cvss_score=score,
                metadata={"template_id": item.get("template-id"), "type": item.get("type")},
            )
        )
    return findings
