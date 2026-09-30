from __future__ import annotations

import json
import shutil
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from vaptforge import __version__
from vaptforge.correlation.engine import correlate_findings
from vaptforge.models.finding import Finding
from vaptforge.models.scope import AuthorizedScope
from vaptforge.reporting.markdown import render_markdown_report
from vaptforge.scanners.http_security import HttpSecurityScanner
from vaptforge.scanners.nmap import NmapScanner
from vaptforge.scanners.nuclei import NucleiScanner

app = typer.Typer(no_args_is_help=True, help="Authorized VAPT orchestration and reporting.")
console = Console()


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
    for tool in ["nmap", "nuclei", "nikto", "ffuf"]:
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
        "http,nmap,nuclei", "--scanners", help="Comma-separated scanner names."
    ),
    output: Path = typer.Option(Path("assessment-report.md"), "--output"),
    json_output: Path | None = typer.Option(None, "--json-output"),
) -> None:
    """Run selected non-destructive scanners against an explicitly authorized target."""
    scope = AuthorizedScope.from_json_file(scope_file)
    scope.require_authorized(target)

    registry = {"http": HttpSecurityScanner(), "nmap": NmapScanner(), "nuclei": NucleiScanner()}
    selected = [name.strip().lower() for name in scanners.split(",") if name.strip()]
    unknown = sorted(set(selected) - set(registry))
    if unknown:
        raise typer.BadParameter(f"Unknown scanners: {', '.join(unknown)}")

    findings: list[Finding] = []
    for name in selected:
        console.print(f"[cyan]Running {name}[/cyan] against {target}")
        findings.extend(registry[name].scan(target, scope))

    findings = correlate_findings(findings)
    output.write_text(
        render_markdown_report(scope.assessment_name, target, findings),
        encoding="utf-8",
    )
    if json_output:
        json_output.write_text(
            json.dumps([item.model_dump(mode="json") for item in findings], indent=2),
            encoding="utf-8",
        )

    console.print(f"[green]Completed[/green] — {len(findings)} normalized findings")
    console.print(f"Report: {output}")


if __name__ == "__main__":
    app()
