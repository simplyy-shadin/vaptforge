from __future__ import annotations

import json
from urllib.parse import urlparse

from vaptforge.models.finding import AssetRef, Evidence, Finding, FindingStatus, Severity

SENSITIVE_PATH_MARKERS = (
    "/.env",
    "/.git",
    "/backup",
    "/config",
    "/phpinfo",
    "/.ds_store",
)


def parse_ffuf_json(text: str, *, target: str) -> list[Finding]:
    payload = json.loads(text)
    findings: list[Finding] = []

    for item in payload.get("results", []):
        url = str(item.get("url") or target)
        parsed = urlparse(url)
        status_code = int(item.get("status") or 0)
        lower_path = parsed.path.lower()
        sensitive = status_code in {200, 206} and any(
            marker in lower_path for marker in SENSITIVE_PATH_MARKERS
        )
        word = (item.get("input") or {}).get("FUZZ") or parsed.path or "/"
        severity = Severity.MEDIUM if sensitive else Severity.INFO
        status = FindingStatus.POTENTIAL if sensitive else FindingStatus.DISCOVERED
        title = (
            f"Potentially sensitive path exposed: {parsed.path}"
            if sensitive
            else f"Web content discovered: {word}"
        )

        findings.append(
            Finding(
                title=title,
                severity=severity,
                asset=AssetRef(
                    target=target,
                    host=parsed.hostname,
                    port=parsed.port,
                    protocol=parsed.scheme or None,
                    service="http",
                ),
                source="ffuf",
                status=status,
                description=(
                    "ffuf discovered an HTTP resource that requires manual review before "
                    "classification as a vulnerability."
                ),
                location=url,
                evidence=[
                    Evidence(
                        source="ffuf",
                        summary=(
                            f"HTTP {status_code}; length={item.get('length')}; "
                            f"words={item.get('words')}; lines={item.get('lines')}"
                        ),
                    )
                ],
                tags=["content-discovery"],
                remediation=(
                    "Remove unintended sensitive resources from the web root or restrict access."
                    if sensitive
                    else None
                ),
                metadata={
                    "status_code": status_code,
                    "length": item.get("length"),
                    "words": item.get("words"),
                    "lines": item.get("lines"),
                },
            )
        )

    return findings
