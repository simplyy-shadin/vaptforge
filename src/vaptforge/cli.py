from __future__ import annotations

import json
import shutil
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from vaptforge import __version__
from vaptforge.correlation.engine import correlate_findings
from vaptforge.enrichment.owasp import enrich_owasp
from vaptforge.models.finding import Evidence, Finding, FindingStatus
from vaptforge.models.scope import AuthorizedScope
from vaptforge.persistence.store import AssessmentStore, InvalidStatusTransition
from vaptforge.reporting.markdown import render_markdown_report
from vaptforge.scanners.base import Scanner
from vaptforge.scanners.ffuf import FfufScanner
from vaptforge.scanners.http_security import HttpSecurityScanner
from vaptforge.scanners.httpx_probe import HttpxScanner
from vaptforge.scanners.nikto import NiktoScanner
from vaptforge.scanners.nmap import NmapScanner
from vaptforge.scanners.nuclei import NucleiScanner
from vaptforge.scanners.tls_security import TlsSecurityScanner

app = typer.Typer(no_args_is_help=True, help="Authorized VAPT orchestration and reporting.")
console = Console()


def _scanner_registry() -> dict[str, Scanner]:
    return {
        "http": HttpSecurityScanner(),
        "tls": TlsSecurityScanner(),
        "httpx": HttpxScanner(),
        "nmap": NmapScanner(),
        "nuclei": NucleiScanner(),
        "nikto": NiktoScanner(),
        "ffuf": FfufScanner(),
    }


@app.command()
def version() -> None:
    """Print the VAPTForge version."""
    console.print(f"VAPTForge {__version__}")


@app.command()
def doctor() -> None:
    """Check whether optional external scanners are available."""
    table = Table(title="VAPTForge Tool Check")
    table.add_column("Tool")
    table.add_column("Status")
    for tool in ["nmap", "nuclei", "nikto", "ffuf", "httpx"]:
        table.add_row(tool, "available" if shutil.which(tool) else "not installed")
    console.print(table)


@app.command("scope-check")
def scope_check(
    target: str = typer.Argument(..., help="Host, IP, CIDR member, or URL to validate."),
    scope_file: Path = typer.Option(..., "--scope", exists=True, readable=True),
) -> None:
    """Verify that a target is explicitly authorized by a scope file."""
    scope = AuthorizedScope.from_json_file(scope_file)
    if scope.is_authorized(target):
        console.print(f"[green]AUTHORIZED[/green] — {target}")
    else:
        console.print(f"[red]NOT AUTHORIZED[/red] — {target}")
        raise typer.Exit(code=2)


@app.command()
def scan(
    target: str = typer.Argument(...),
    scope_file: Path = typer.Option(..., "--scope", exists=True, readable=True),
    scanners: str = typer.Option(
        "http,tls",
        "--scanners",
        help="Comma-separated scanner names.",
    ),
    output: Path = typer.Option(Path("assessment-report.md"), "--output"),
    json_output: Path | None = typer.Option(None, "--json-output"),
    database: Path | None = typer.Option(None, "--db"),
    assessment_id: str | None = typer.Option(None, "--assessment-id"),
) -> None:
    """Run selected scanners and optionally persist the assessment to SQLite."""
    scope = AuthorizedScope.from_json_file(scope_file)
    scope.require_authorized(target)

    registry = _scanner_registry()
    selected = [name.strip().lower() for name in scanners.split(",") if name.strip()]
    unknown = sorted(set(selected) - set(registry))
    if unknown:
        raise typer.BadParameter(f"Unknown scanners: {', '.join(unknown)}")

    findings: list[Finding] = []
    for name in selected:
        console.print(f"[cyan]Running {name}[/cyan] against {target}")
        findings.extend(registry[name].scan(target, scope))

    findings = [enrich_owasp(item) for item in correlate_findings(findings)]
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        render_markdown_report(scope.assessment_name, target, findings),
        encoding="utf-8",
    )

    if json_output:
        json_output.parent.mkdir(parents=True, exist_ok=True)
        json_output.write_text(
            json.dumps([item.model_dump(mode="json") for item in findings], indent=2),
            encoding="utf-8",
        )

    if database:
        with AssessmentStore(database) as store:
            if assessment_id:
                assessment = store.get_assessment(assessment_id)
                if assessment is None:
                    raise typer.BadParameter(f"Assessment not found: {assessment_id}")
            else:
                assessment = store.create_assessment(
                    name=scope.assessment_name,
                    authorization_reference=scope.authorization_reference,
                    target=target,
                )
            store.save_findings(assessment.id, findings)
            console.print(f"Assessment ID: [bold]{assessment.id}[/bold]")

    console.print(f"[green]Completed[/green] — {len(findings)} normalized findings")
    console.print(f"Report: {output}")


@app.command("assessment-list")
def assessment_list(
    database: Path = typer.Option(Path("vaptforge.db"), "--db"),
) -> None:
    """List persisted assessments."""
    with AssessmentStore(database) as store:
        assessments = store.list_assessments()

    table = Table(title="VAPTForge Assessments")
    table.add_column("ID")
    table.add_column("Name")
    table.add_column("Target")
    table.add_column("Updated")
    for assessment in assessments:
        table.add_row(
            assessment.id,
            assessment.name,
            assessment.target,
            assessment.updated_at.isoformat(timespec="seconds"),
        )
    console.print(table)


@app.command("finding-list")
def finding_list(
    assessment_id: str = typer.Argument(...),
    database: Path = typer.Option(Path("vaptforge.db"), "--db"),
) -> None:
    """List persisted findings for an assessment."""
    with AssessmentStore(database) as store:
        findings = store.list_findings(assessment_id)

    table = Table(title=f"Findings — {assessment_id}")
    table.add_column("ID")
    table.add_column("Severity")
    table.add_column("Status")
    table.add_column("Title")
    for stored in findings:
        table.add_row(
            stored.id,
            stored.finding.severity.label(),
            stored.finding.status.value,
            stored.finding.title,
        )
    console.print(table)


@app.command("finding-transition")
def finding_transition(
    finding_id: str = typer.Argument(...),
    status: FindingStatus = typer.Argument(...),
    database: Path = typer.Option(Path("vaptforge.db"), "--db"),
    note: str | None = typer.Option(None, "--note"),
) -> None:
    """Transition a finding through the validation/remediation lifecycle."""
    try:
        with AssessmentStore(database) as store:
            store.transition_finding(finding_id, status, note=note)
    except (KeyError, InvalidStatusTransition) as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=2) from exc
    console.print(f"[green]Updated[/green] {finding_id} -> {status.value}")


@app.command("finding-note")
def finding_note(
    finding_id: str = typer.Argument(...),
    note: str = typer.Option(..., "--note"),
    database: Path = typer.Option(Path("vaptforge.db"), "--db"),
) -> None:
    """Attach a manual validation note to a finding."""
    try:
        with AssessmentStore(database) as store:
            store.add_validation_note(finding_id, note)
    except KeyError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=2) from exc
    console.print(f"[green]Note added[/green] to {finding_id}")


@app.command("finding-evidence")
def finding_evidence(
    finding_id: str = typer.Argument(...),
    source: str = typer.Option("manual", "--source"),
    summary: str = typer.Option(..., "--summary"),
    attachment: Path | None = typer.Option(None, "--attachment"),
    database: Path = typer.Option(Path("vaptforge.db"), "--db"),
) -> None:
    """Attach manual evidence metadata to a persisted finding."""
    if attachment is not None and not attachment.exists():
        raise typer.BadParameter(f"Attachment does not exist: {attachment}")

    evidence = Evidence(
        source=source,
        summary=summary,
        attachment_path=str(attachment) if attachment else None,
    )
    try:
        with AssessmentStore(database) as store:
            store.add_evidence(finding_id, evidence)
    except KeyError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=2) from exc
    console.print(f"[green]Evidence added[/green] to {finding_id}")


if __name__ == "__main__":
    app()
