from __future__ import annotations

from io import BytesIO
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from vaptforge.models.finding import Finding
from vaptforge.reporting.metrics import finding_metrics


def render_pdf_bytes(
    assessment_name: str,
    target: str,
    findings: list[Finding],
) -> bytes:
    buffer = BytesIO()
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title=f"VAPT Assessment Report - {assessment_name}",
    )

    metrics = finding_metrics(findings)
    severity = metrics["severity"]
    story = [
        Paragraph("VAPT Assessment Report", styles["Title"]),
        Spacer(1, 8),
        Paragraph(
            f"<b>Assessment:</b> {escape(assessment_name)}",
            styles["BodyText"],
        ),
        Paragraph(f"<b>Target:</b> {escape(target)}", styles["BodyText"]),
        Paragraph("<b>Scope:</b> Authorized assessment only", styles["BodyText"]),
        Spacer(1, 12),
        Paragraph("Executive Summary", styles["Heading2"]),
    ]

    summary_data = [
        ["Total", "Critical", "High", "Medium", "Low", "Info"],
        [
            str(metrics["total"]),
            str(severity.get("CRITICAL", 0)),
            str(severity.get("HIGH", 0)),
            str(severity.get("MEDIUM", 0)),
            str(severity.get("LOW", 0)),
            str(severity.get("INFO", 0)),
        ],
    ]
    table = Table(summary_data, repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ]
        )
    )
    story.extend(
        [
            table,
            Spacer(1, 10),
            Paragraph(
                "Scanner observations require manual validation before VERIFIED status.",
                styles["BodyText"],
            ),
            Spacer(1, 12),
            Paragraph("Technical Findings", styles["Heading2"]),
        ]
    )

    for index, finding in enumerate(
        sorted(findings, key=lambda item: int(item.severity), reverse=True),
        start=1,
    ):
        story.extend(
            [
                Paragraph(
                    f"VF-{index:03d}: {escape(finding.title)}",
                    styles["Heading3"],
                ),
                Paragraph(
                    f"<b>Severity:</b> {escape(finding.severity.label())} | "
                    f"<b>Status:</b> {escape(finding.status.value)}"
                    + (
                        f" | <b>Confidence:</b> {escape(finding.confidence.value)}"
                        if finding.confidence is not None
                        else ""
                    ),
                    styles["BodyText"],
                ),
                Paragraph(
                    "<b>Asset:</b> "
                    f"{escape(finding.asset.host or finding.asset.target)}",
                    styles["BodyText"],
                ),
                Paragraph(
                    f"<b>Location:</b> {escape(finding.location or 'N/A')}",
                    styles["BodyText"],
                ),
            ]
        )
        if finding.cvss_score is not None:
            story.append(
                Paragraph(
                    f"<b>CVSS:</b> {finding.cvss_score:.1f}",
                    styles["BodyText"],
                )
            )
        story.append(
            Paragraph(
                escape(finding.description or "No description supplied."),
                styles["BodyText"],
            )
        )
        if finding.evidence:
            story.append(Paragraph("<b>Evidence</b>", styles["BodyText"]))
            for evidence in finding.evidence:
                story.append(
                    Paragraph(
                        f"- {escape(evidence.source)}: {escape(evidence.summary)}",
                        styles["BodyText"],
                    )
                )
        if finding.remediation:
            story.extend(
                [
                    Paragraph("<b>Remediation</b>", styles["BodyText"]),
                    Paragraph(escape(finding.remediation), styles["BodyText"]),
                ]
            )
        story.append(Spacer(1, 10))

    doc.build(story)
    return buffer.getvalue()


def write_pdf_report(
    path: str | Path,
    assessment_name: str,
    target: str,
    findings: list[Finding],
) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(render_pdf_bytes(assessment_name, target, findings))
