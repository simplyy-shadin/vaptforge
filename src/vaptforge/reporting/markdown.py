from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime

from vaptforge.models.finding import Finding, Severity


def render_markdown_report(assessment_name: str, target: str, findings: list[Finding]) -> str:
    ordered = sorted(findings, key=lambda item: int(item.severity), reverse=True)
    counts = Counter(f.severity.label() for f in ordered)
    generated = datetime.now(UTC).isoformat(timespec="seconds")

    lines = [
        f"# VAPT Assessment Report — {assessment_name}",
        "",
        f"**Target:** `{target}`  ",
        f"**Generated:** {generated}  ",
        "**Scope:** Authorized assessment only",
        "",
        "## Executive Summary",
        "",
        f"VAPTForge normalized **{len(ordered)}** findings from the configured assessment tools.",
        "Scanner output should be manually validated before a finding is marked VERIFIED.",
        "",
        "## Risk Summary",
        "",
        "| Severity | Count |",
        "|---|---:|",
    ]
    severities = [
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFO,
    ]
    for severity in severities:
        lines.append(f"| {severity.label()} | {counts.get(severity.label(), 0)} |")

    lines.extend(["", "## Technical Findings", ""])
    if not ordered:
        lines.append("No findings were produced by the selected scanners.")
        return "\n".join(lines) + "\n"

    for index, finding in enumerate(ordered, start=1):
        lines.extend(
            [
                f"### VF-{index:03d}: {finding.title}",
                "",
                f"- **Severity:** {finding.severity.label()}",
                f"- **Status:** {finding.status.value}",
                *(
                    [f"- **Confidence:** {finding.confidence.value}"]
                    if finding.confidence is not None
                    else []
                ),
                f"- **Asset:** `{finding.asset.host or finding.asset.target}`",
                f"- **Location:** `{finding.location or 'N/A'}`",
                f"- **Source:** {finding.source}",
                f"- **Fingerprint:** `{finding.fingerprint}`",
            ]
        )
        if finding.cvss_score is not None:
            lines.append(f"- **CVSS:** {finding.cvss_score:.1f}")
        if finding.cvss_vector:
            lines.append(f"- **CVSS Vector:** `{finding.cvss_vector}`")
        if finding.cves:
            lines.append(f"- **CVE:** {', '.join(finding.cves)}")
        if finding.cwes:
            lines.append(f"- **CWE:** {', '.join(finding.cwes)}")
        if finding.owasp:
            lines.append(f"- **OWASP:** {', '.join(finding.owasp)}")
        lines.extend(["", finding.description or "No description supplied.", "", "**Evidence**"])
        for evidence in finding.evidence:
            detail = f"- `{evidence.source}` — {evidence.summary}"
            if evidence.attachment_path:
                detail += f" (attachment: `{evidence.attachment_path}`)"
            lines.append(detail)
        if finding.remediation:
            lines.extend(["", "**Remediation**", "", finding.remediation])
        lines.append("")

    return "\n".join(lines)
