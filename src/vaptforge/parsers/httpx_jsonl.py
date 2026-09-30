from __future__ import annotations

import json
from urllib.parse import urlparse

from vaptforge.models.finding import AssetRef, Evidence, Finding, Severity


def parse_httpx_jsonl(text: str, *, target: str) -> list[Finding]:
    findings: list[Finding] = []

    for line in text.splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        url = str(item.get("url") or item.get("input") or target)
        parsed = urlparse(url if "://" in url else f"http://{url}")
        status_code = item.get("status_code")
        technologies = item.get("tech") or []
        if isinstance(technologies, str):
            technologies = [technologies]

        summary_bits = [f"status={status_code}"]
        if item.get("title"):
            summary_bits.append(f"title={item['title']}")
        if item.get("webserver"):
            summary_bits.append(f"server={item['webserver']}")
        if technologies:
            summary_bits.append(f"tech={','.join(str(value) for value in technologies)}")

        findings.append(
            Finding(
                title=f"HTTP endpoint discovered ({status_code or 'unknown status'})",
                severity=Severity.INFO,
                asset=AssetRef(
                    target=target,
                    host=parsed.hostname,
                    port=parsed.port,
                    protocol=parsed.scheme or None,
                    service="http",
                ),
                source="httpx",
                description="httpx identified a reachable HTTP service and collected metadata.",
                location=url,
                evidence=[
                    Evidence(
                        source="httpx",
                        summary="; ".join(summary_bits),
                    )
                ],
                tags=["recon", "http"],
                metadata={
                    "status_code": status_code,
                    "title": item.get("title"),
                    "technologies": technologies,
                    "webserver": item.get("webserver"),
                    "ip": item.get("host") or item.get("ip"),
                    "location": item.get("location"),
                },
            )
        )

    return findings
