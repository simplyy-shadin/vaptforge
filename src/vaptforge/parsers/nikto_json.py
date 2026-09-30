from __future__ import annotations

import json
import re
from urllib.parse import urlparse

from vaptforge.models.finding import AssetRef, Evidence, Finding, FindingStatus, Severity

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def _nikto_items(payload: object) -> list[dict[str, object]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if not isinstance(payload, dict):
        return []
    for key in ("vulnerabilities", "items", "findings"):
        value = payload.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    return []


def parse_nikto_json(text: str, *, target: str) -> list[Finding]:
    payload = json.loads(text)
    parsed_target = urlparse(target if "://" in target else f"http://{target}")
    findings: list[Finding] = []

    for item in _nikto_items(payload):
        message = str(item.get("msg") or item.get("message") or "Nikto observation")
        path = str(item.get("url") or item.get("uri") or "/")
        if path.startswith("http://") or path.startswith("https://"):
            location = path
        else:
            location = target.rstrip("/") + "/" + path.lstrip("/")

        references = item.get("references") or item.get("reference") or []
        if isinstance(references, str):
            references = [references]
        cves = sorted(set(CVE_PATTERN.findall(message + " " + " ".join(map(str, references)))))

        findings.append(
            Finding(
                title=f"Nikto observation: {str(item.get('id') or message)[:80]}",
                severity=Severity.LOW,
                asset=AssetRef(
                    target=target,
                    host=parsed_target.hostname,
                    port=parsed_target.port,
                    protocol=parsed_target.scheme or None,
                    service="http",
                ),
                source="nikto",
                status=FindingStatus.POTENTIAL,
                description=message,
                location=location,
                cves=[cve.upper() for cve in cves],
                references=[str(reference) for reference in references],
                evidence=[
                    Evidence(
                        source="nikto",
                        summary=(
                            f"method={item.get('method') or 'GET'}; "
                            f"id={item.get('id') or 'unknown'}"
                        ),
                    )
                ],
                tags=["web-server", "nikto"],
                remediation=(
                    "Review the reported condition, validate impact, and apply the relevant "
                    "server or application hardening guidance."
                ),
                metadata={
                    "nikto_id": item.get("id"),
                    "method": item.get("method"),
                },
            )
        )

    return findings
