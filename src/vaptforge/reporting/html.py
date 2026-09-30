from __future__ import annotations

from html import escape

from vaptforge.models.finding import Finding
from vaptforge.reporting.metrics import finding_metrics

CSS = """
body { font-family: Arial, sans-serif; margin: 36px; color: #111827; }
h1, h2, h3 { color: #0f172a; }
.meta { color: #475569; margin-bottom: 24px; }
.cards { display: flex; gap: 12px; flex-wrap: wrap; margin: 20px 0; }
.card { border: 1px solid #cbd5e1; border-radius: 8px; padding: 12px 16px; min-width: 110px; }
.finding { border-top: 2px solid #e2e8f0; padding-top: 16px; margin-top: 24px; }
code { background: #f1f5f9; padding: 2px 4px; }
ul { line-height: 1.5; }
"""


def _finding_html(index: int, finding: Finding) -> str:
    evidence = "".join(
        f"<li><code>{escape(item.source)}</code> - {escape(item.summary)}</li>"
        for item in finding.evidence
    )
    mappings: list[str] = []
    if finding.cves:
        mappings.append(f"<li><strong>CVE:</strong> {escape(', '.join(finding.cves))}</li>")
    if finding.cwes:
        mappings.append(f"<li><strong>CWE:</strong> {escape(', '.join(finding.cwes))}</li>")
    if finding.owasp:
        mappings.append(
            f"<li><strong>OWASP:</strong> {escape(', '.join(finding.owasp))}</li>"
        )
    if finding.cvss_score is not None:
        mappings.append(f"<li><strong>CVSS:</strong> {finding.cvss_score:.1f}</li>")

    return f"""
<section class="finding">
  <h3>VF-{index:03d}: {escape(finding.title)}</h3>
  <ul>
    <li><strong>Severity:</strong> {escape(finding.severity.label())}</li>
    <li><strong>Status:</strong> {escape(finding.status.value)}</li>
    <li><strong>Asset:</strong> <code>{escape(finding.asset.host or finding.asset.target)}</code></li>
    <li><strong>Location:</strong> <code>{escape(finding.location or "N/A")}</code></li>
    {''.join(mappings)}
  </ul>
  <p>{escape(finding.description or "No description supplied.")}</p>
  <h4>Evidence</h4>
  <ul>{evidence or "<li>No evidence supplied.</li>"}</ul>
  <h4>Remediation</h4>
  <p>{escape(finding.remediation or "No remediation supplied.")}</p>
</section>
"""


def render_html_report(
    assessment_name: str,
    target: str,
    findings: list[Finding],
) -> str:
    metrics = finding_metrics(findings)
    severity = metrics["severity"]
    cards = [
        f'<div class="card"><strong>Total</strong><br>{metrics["total"]}</div>'
    ]
    for label in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = severity.get(label, 0)
        cards.append(f'<div class="card"><strong>{label}</strong><br>{count}</div>')

    finding_sections = "".join(
        _finding_html(index, finding)
        for index, finding in enumerate(
            sorted(findings, key=lambda item: int(item.severity), reverse=True),
            start=1,
        )
    )
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>VAPT Report - {escape(assessment_name)}</title>
<style>{CSS}</style>
</head>
<body>
<h1>VAPT Assessment Report</h1>
<div class="meta">
  <strong>Assessment:</strong> {escape(assessment_name)}<br>
  <strong>Target:</strong> <code>{escape(target)}</code><br>
  <strong>Scope:</strong> Authorized assessment only
</div>
<h2>Executive Summary</h2>
<div class="cards">{''.join(cards)}</div>
<p>Scanner observations require manual validation before VERIFIED status.</p>
<h2>Technical Findings</h2>
{finding_sections or "<p>No findings were produced.</p>"}
</body>
</html>
"""
