from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from vaptforge import __version__
from vaptforge.correlation.engine import correlate_findings
from vaptforge.enrichment.owasp import enrich_owasp
from vaptforge.jobs.worker import AssessmentWorker
from vaptforge.models.finding import Evidence, Finding, FindingStatus
from vaptforge.models.scope import AuthorizedScope, ScopeEntry
from vaptforge.parsers.sarif import parse_sarif
from vaptforge.persistence.jobs import JobStore, WorkerBusyError
from vaptforge.persistence.migrations import SCHEMA_VERSION
from vaptforge.persistence.store import AssessmentStore, InvalidStatusTransition
from vaptforge.reporting.html import render_html_report
from vaptforge.reporting.markdown import render_markdown_report
from vaptforge.reporting.pdf import write_pdf_report
from vaptforge.reporting.retest_markdown import render_retest_markdown
from vaptforge.reporting.sarif import write_sarif
from vaptforge.reporting.sbom import write_sbom
from vaptforge.retest.engine import compare_findings
from vaptforge.scanners.base import Scanner
from vaptforge.scanners.registry import ScannerPluginError, discover_scanners
from vaptforge.ux.guided import discover_scope_files, safe_scope_filename, target_suggestions
from vaptforge.ux.platform import run_platform
from vaptforge.ux.profiles import PROFILES, resolve_profile_scanners
from vaptforge.ux.tooling import probe_scanner_tool

app = typer.Typer(
    no_args_is_help=True,
    help="Authorized VAPT assessment platform with guided and advanced workflows.",
    context_settings={"help_option_names": ["-h", "--help"]},
    rich_markup_mode="rich",
    epilog=(
        "[bold]Recommended:[/bold] run [cyan]vaptforge start[/cyan] for the guided launcher. "
        "Advanced users can continue using scan, queue-assessment, worker, and API commands."
    ),
)
console = Console()


def _scanner_registry() -> dict[str, Scanner]:
    try:
        return discover_scanners()
    except ScannerPluginError as exc:
        raise typer.BadParameter(str(exc)) from exc


def _prompt_choice(prompt: str, count: int, *, default: int = 1) -> int:
    while True:
        raw = typer.prompt(prompt, default=str(default))
        try:
            value = int(raw)
        except ValueError:
            console.print("[red]Enter the number of one of the choices.[/red]")
            continue
        if 1 <= value <= count:
            return value
        console.print(f"[red]Choose a number between 1 and {count}.[/red]")


def _create_scope_file() -> Path:
    console.print(
        Panel(
            "Create an authorization scope. Only add systems you own or have explicit "
            "permission to test.",
            title="New Scope",
        )
    )
    if not typer.confirm("I confirm I am authorized to test the target I will enter"):
        raise typer.Abort()

    assessment_name = typer.prompt("Assessment name", default="Authorized Assessment").strip()
    target = typer.prompt("Authorized target (URL, hostname, or IP)").strip()
    authorization_reference = typer.prompt(
        "Authorization reference / note",
        default="User-confirmed authorized assessment",
    ).strip()

    scope = AuthorizedScope(
        assessment_name=assessment_name,
        authorization_reference=authorization_reference,
        targets=[ScopeEntry(value=target)],
    )
    path = Path("config") / safe_scope_filename(assessment_name)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(scope.model_dump_json(indent=2), encoding="utf-8")
    console.print(f"[green]Scope saved:[/green] {path}")
    return path


def _choose_scope_file() -> Path:
    files = discover_scope_files()
    if not files:
        console.print("[yellow]No scope files found in config/.[/yellow]")
        return _create_scope_file()

    table = Table(title="Authorization Scopes")
    table.add_column("#", justify="right")
    table.add_column("Scope file")
    for index, path in enumerate(files, start=1):
        table.add_row(str(index), str(path))
    table.add_row(str(len(files) + 1), "Create a new authorized scope")
    console.print(table)

    choice = _prompt_choice("Choose scope", len(files) + 1)
    if choice == len(files) + 1:
        return _create_scope_file()
    return files[choice - 1]


def _choose_target(scope: AuthorizedScope) -> str:
    suggestions = target_suggestions(scope)
    if suggestions:
        table = Table(title="Authorized Target Suggestions")
        table.add_column("#", justify="right")
        table.add_column("Target")
        table.add_column("Suggestion")
        for index, (target, label) in enumerate(suggestions, start=1):
            table.add_row(str(index), target, label)
        table.add_row(str(len(suggestions) + 1), "Enter another target", "Must match scope")
        console.print(table)
        choice = _prompt_choice("Choose target", len(suggestions) + 1)
        if choice <= len(suggestions):
            target = suggestions[choice - 1][0]
        else:
            target = typer.prompt("Authorized target").strip()
    else:
        target = typer.prompt("Authorized target covered by this scope").strip()

    scope.require_authorized(target)
    return target


def _choose_profile(registered: set[str]) -> tuple[str, list[str], list[str]]:
    profiles = list(PROFILES.values())
    table = Table(title="Assessment Profiles")
    table.add_column("#", justify="right")
    table.add_column("Profile")
    table.add_column("Purpose")
    table.add_column("Guided mode")
    for index, profile in enumerate(profiles, start=1):
        selected, skipped = resolve_profile_scanners(
            profile.name,
            registered=registered,
            skip_unavailable=True,
        )
        status = f"{len(selected)} ready"
        if skipped:
            status += f", {len(skipped)} skipped"
        table.add_row(str(index), profile.label, profile.description, status)
    console.print(table)

    default = next(
        (index for index, profile in enumerate(profiles, start=1) if profile.name == "web"),
        1,
    )
    while True:
        choice = _prompt_choice("Choose profile", len(profiles), default=default)
        profile = profiles[choice - 1]
        selected, skipped = resolve_profile_scanners(
            profile.name,
            registered=registered,
            skip_unavailable=True,
        )
        if selected:
            return profile.name, selected, skipped
        console.print(
            "[red]None of the scanners in that profile are currently available. "
            "Install the required tools or choose another profile.[/red]"
        )


def _guided_queue(database: Path) -> str:
    scope_file = _choose_scope_file()
    scope = AuthorizedScope.from_json_file(scope_file)
    target = _choose_target(scope)
    registry = _scanner_registry()
    profile, scanners, skipped = _choose_profile(set(registry))

    console.print(
        Panel(
            f"[bold]Target:[/bold] {target}\n"
            f"[bold]Scope:[/bold] {scope_file}\n"
            f"[bold]Profile:[/bold] {profile}\n"
            f"[bold]Scanners:[/bold] {', '.join(scanners)}",
            title="Assessment Plan",
        )
    )
    if skipped:
        console.print("[yellow]Unavailable optional scanners skipped:[/yellow]")
        for item in skipped:
            console.print(f"  - {item}")

    if not typer.confirm("Queue this authorized assessment?", default=True):
        raise typer.Abort()

    database.parent.mkdir(parents=True, exist_ok=True)
    with JobStore(database) as store:
        job = store.enqueue(target, scope, scanners)
    console.print(f"[green]Queued assessment[/green] {job.assessment_id}")
    console.print(f"Job ID: [bold]{job.id}[/bold]")
    return job.id


def _manual_start_help(database: Path) -> None:
    table = Table(title="Manual / Advanced Workflow")
    table.add_column("Task")
    table.add_column("Command")
    table.add_row("Show all commands", "vaptforge -h")
    table.add_row("Check tools", "vaptforge doctor")
    table.add_row("See profiles", "vaptforge profile-list")
    table.add_row(
        "Queue manually",
        "vaptforge queue-assessment <target> --scope <scope.json> --profile web",
    )
    table.add_row("Check a job", f"vaptforge job-status <JOB_ID> --db {database}")
    table.add_row("Direct synchronous scan", "vaptforge scan -h")
    console.print(table)


@app.command()
def start(
    database: Path = typer.Option(Path("data/vaptforge.db"), "--db", help="Platform database."),
    host: str = typer.Option("127.0.0.1", "--host", help="Dashboard/API bind host."),
    port: int = typer.Option(8000, "--port", min=1, max=65535),
    browser: bool = typer.Option(True, "--browser/--no-browser"),
    mode: str | None = typer.Option(
        None,
        "--mode",
        help="guided or manual. Omit this option to choose from the launcher.",
    ),
) -> None:
    """Start VAPTForge using a friendly guided launcher or advanced/manual mode."""
    console.print(
        Panel(
            "[bold]1. Guided / Automatic[/bold] (recommended)\n"
            "Choose an authorized scope, target, and assessment profile. "
            "VAPTForge queues the assessment and starts the worker + dashboard.\n\n"
            "[bold]2. Manual / Advanced[/bold]\n"
            "Start the worker + dashboard only and keep full control of CLI commands.",
            title=f"VAPTForge {__version__}",
            subtitle="Authorized testing only",
        )
    )

    normalized_mode = mode.strip().lower() if mode else None
    if normalized_mode is None:
        choice = _prompt_choice("Choose mode", 2, default=1)
        normalized_mode = "guided" if choice == 1 else "manual"
    if normalized_mode not in {"guided", "manual"}:
        raise typer.BadParameter("--mode must be 'guided' or 'manual'")

    if normalized_mode == "guided":
        _guided_queue(database)
    else:
        _manual_start_help(database)

    console.print()
    console.print("[green]Starting VAPTForge platform...[/green]")
    console.print(f"Dashboard: [link=http://{host}:{port}/]http://{host}:{port}/[/link]")
    console.print("Press Ctrl+C to stop the local platform.")
    try:
        run_platform(database, host=host, port=port, open_browser=browser)
    except RuntimeError as exc:
        raise typer.BadParameter(str(exc)) from exc


@app.command("profile-list")
def profile_list() -> None:
    """Show the simple assessment profiles available to guided and manual users."""
    registered = set(_scanner_registry())
    table = Table(title="VAPTForge Assessment Profiles")
    table.add_column("Profile")
    table.add_column("Scanners")
    table.add_column("Description")
    for profile in PROFILES.values():
        selected, skipped = resolve_profile_scanners(
            profile.name,
            registered=registered,
            skip_unavailable=True,
        )
        scanner_text = ", ".join(selected) or "none available"
        if skipped:
            scanner_text += f"  [yellow](skips: {', '.join(skipped)})[/yellow]"
        table.add_row(profile.name, scanner_text, profile.description)
    console.print(table)


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
    table.add_column("Details")
    for tool in ["nmap", "nuclei", "nikto", "ffuf", "httpx"]:
        probe = probe_scanner_tool(tool)
        table.add_row(
            tool,
            "available" if probe.available else "unavailable",
            probe.detail,
        )
    console.print(table)


@app.command("scope-check")
def scope_check(
    target: str = typer.Argument(..., help="Host, IP, CIDR member, or URL to validate."),
    scope_file: Path = typer.Option(..., "--scope", exists=True, readable=True),
) -> None:
    """Verify that a target is explicitly authorized by a scope file."""
    scope = AuthorizedScope.from_json_file(scope_file)
    if scope.is_authorized(target):
        console.print(f"[green]AUTHORIZED[/green] - {target}")
    else:
        console.print(f"[red]NOT AUTHORIZED[/red] - {target}")
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
    html_output: Path | None = typer.Option(None, "--html-output"),
    pdf_output: Path | None = typer.Option(None, "--pdf-output"),
    sarif_output: Path | None = typer.Option(None, "--sarif-output"),
    database: Path | None = typer.Option(None, "--db"),
    assessment_id: str | None = typer.Option(None, "--assessment-id"),
) -> None:
    """Run selected scanners, report findings, and optionally persist them."""
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
    if html_output:
        html_output.parent.mkdir(parents=True, exist_ok=True)
        html_output.write_text(
            render_html_report(scope.assessment_name, target, findings),
            encoding="utf-8",
        )
    if pdf_output:
        write_pdf_report(pdf_output, scope.assessment_name, target, findings)
    if sarif_output:
        write_sarif(sarif_output, findings)

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

    console.print(f"[green]Completed[/green] - {len(findings)} normalized findings")
    console.print(f"Markdown report: {output}")


@app.command("queue-assessment")
def queue_assessment(
    target: str = typer.Argument(...),
    scope_file: Path = typer.Option(..., "--scope", exists=True, readable=True),
    scanners: str = typer.Option("http,tls", "--scanners"),
    profile: str | None = typer.Option(
        None,
        "--profile",
        help="Use a named profile such as quick, web, network, full, or deep.",
    ),
    database: Path = typer.Option(Path("vaptforge.db"), "--db"),
) -> None:
    """Queue an authorized assessment for the separate local worker."""
    scope = AuthorizedScope.from_json_file(scope_file)
    scope.require_authorized(target)
    registry = _scanner_registry()
    if profile:
        try:
            selected, _skipped = resolve_profile_scanners(
                profile,
                registered=set(registry),
                skip_unavailable=False,
            )
        except ValueError as exc:
            raise typer.BadParameter(str(exc)) from exc
    else:
        selected = [name.strip().lower() for name in scanners.split(",") if name.strip()]
    if not selected or len(selected) != len(set(selected)):
        raise typer.BadParameter("Select at least one scanner, without duplicates")
    unknown = sorted(set(selected) - set(registry))
    if unknown:
        raise typer.BadParameter(f"Unknown scanners: {', '.join(unknown)}")
    with JobStore(database) as store:
        job = store.enqueue(target, scope, selected)
    console.print(f"Queued job: {job.id}\nAssessment ID: {job.assessment_id}")


@app.command("worker")
def worker(
    database: Path = typer.Option(Path("vaptforge.db"), "--db"),
    once: bool = typer.Option(False, "--once", help="Process at most one queued job."),
) -> None:
    """Run the local assessment worker; start separately from the API."""
    try:
        runner = AssessmentWorker(database)
        if once:
            job_id = runner.run_once()
            console.print(f"Processed job: {job_id}" if job_id else "Queue empty")
        else:
            console.print(f"Worker polling {database}; Ctrl+C to stop between jobs")
            runner.run_forever()
    except WorkerBusyError as exc:
        raise typer.BadParameter(str(exc)) from exc


@app.command("job-status")
def job_status(
    job_id: str = typer.Argument(...),
    database: Path = typer.Option(Path("vaptforge.db"), "--db"),
) -> None:
    """Show durable job and per-scanner progress."""
    with JobStore(database) as store:
        job = store.get_job(job_id)
    if job is None:
        raise typer.BadParameter(f"Job not found: {job_id}")
    console.print(f"{job.id}: {job.status.value} (assessment {job.assessment_id})")
    for run in job.scanner_runs:
        console.print(f"  {run.scanner}: {run.status.value} ({run.finding_count} findings)")
    if job.error_message:
        console.print(f"Error: {job.error_message}")


@app.command("scanner-list")
def scanner_list() -> None:
    """List built-in and externally registered scanner plugins."""
    registry = _scanner_registry()
    table = Table(title="VAPTForge Scanner Registry")
    table.add_column("Name")
    table.add_column("Implementation")
    for name, scanner in sorted(registry.items()):
        table.add_row(name, f"{scanner.__class__.__module__}.{scanner.__class__.__name__}")
    console.print(table)


@app.command("db-status")
def db_status(
    database: Path = typer.Option(Path("vaptforge.db"), "--db"),
) -> None:
    """Show the SQLite schema version after applying safe migrations."""
    with AssessmentStore(database) as store:
        console.print(f"Database schema: {store.schema_version}/{SCHEMA_VERSION} ({database})")


@app.command("sarif-import")
def sarif_import(
    sarif_file: Path = typer.Argument(..., exists=True, readable=True),
    target: str = typer.Option("imported://sarif", "--target"),
    output: Path = typer.Option(Path("sarif-findings.json"), "--output"),
) -> None:
    """Normalize a SARIF 2.1.0 document into VAPTForge findings JSON."""
    document = json.loads(sarif_file.read_text(encoding="utf-8"))
    findings = parse_sarif(document, default_target=target)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps([item.model_dump(mode="json") for item in findings], indent=2),
        encoding="utf-8",
    )
    console.print(f"[green]Imported[/green] {len(findings)} SARIF findings -> {output}")


@app.command("sbom")
def sbom(
    output: Path = typer.Option(Path("vaptforge.cdx.json"), "--output"),
) -> None:
    """Generate a CycloneDX JSON SBOM for the installed VAPTForge runtime."""
    write_sbom(output)
    console.print(f"[green]SBOM written[/green] -> {output}")


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

    table = Table(title=f"Findings - {assessment_id}")
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


@app.command("retest")
def retest(
    before_assessment: str = typer.Argument(...),
    after_assessment: str = typer.Argument(...),
    database: Path = typer.Option(Path("vaptforge.db"), "--db"),
    output: Path = typer.Option(Path("retest-report.md"), "--output"),
) -> None:
    """Compare two persisted assessments and classify remediation deltas."""
    with AssessmentStore(database) as store:
        before = store.list_findings(before_assessment)
        after = store.list_findings(after_assessment)
        if store.get_assessment(before_assessment) is None:
            raise typer.BadParameter(f"Assessment not found: {before_assessment}")
        if store.get_assessment(after_assessment) is None:
            raise typer.BadParameter(f"Assessment not found: {after_assessment}")

        results = compare_findings(
            [item.finding for item in before],
            [item.finding for item in after],
        )
        run = store.save_retest(before_assessment, after_assessment, results)

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        render_retest_markdown(before_assessment, after_assessment, results),
        encoding="utf-8",
    )
    console.print(f"[green]Retest complete[/green] - {len(results)} correlated results")
    console.print(f"Retest run ID: {run.id}")
    console.print(f"Retest report: {output}")


if __name__ == "__main__":
    app()
