from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from vaptforge.cli import app
from vaptforge.models.scope import AuthorizedScope, ScopeEntry
from vaptforge.ux.guided import safe_scope_filename, target_suggestions
from vaptforge.ux.platform import build_platform_commands
from vaptforge.ux.profiles import get_profile, resolve_profile_scanners

runner = CliRunner()


def test_root_help_supports_short_h() -> None:
    result = runner.invoke(app, ["-h"])

    assert result.exit_code == 0
    assert "guided" in result.stdout.lower()
    assert "start" in result.stdout


def test_profiles_are_simple_named_scanner_sets(monkeypatch) -> None:
    monkeypatch.setattr(
        "vaptforge.ux.profiles.probe_scanner_tool",
        lambda name: type(
            "Probe",
            (),
            {
                "available": name in {"http", "tls"},
                "detail": "tool not installed",
            },
        )(),
    )

    profile = get_profile("web")
    selected, skipped = resolve_profile_scanners(
        "web",
        registered={"http", "tls", "httpx", "nikto", "nuclei", "ffuf"},
    )

    assert profile.name == "web"
    assert selected == ["http", "tls"]
    assert any("httpx" in item for item in skipped)


def test_local_scope_gets_friendly_lab_suggestions() -> None:
    scope = AuthorizedScope(
        assessment_name="Local lab",
        authorization_reference="Owned lab",
        targets=[ScopeEntry(value="127.0.0.1")],
    )

    suggestions = target_suggestions(scope)
    targets = [target for target, _label in suggestions]

    assert "http://127.0.0.1:3000" in targets
    assert "http://127.0.0.1:4280" in targets


def test_scope_filename_is_safe() -> None:
    assert safe_scope_filename("Client A / Web Test") == "scope.client-a-web-test.json"


def test_manual_profile_can_queue_without_scanner_list(tmp_path: Path) -> None:
    scope_file = tmp_path / "scope.json"
    scope_file.write_text(
        """{
  "assessment_name": "Owned lab",
  "authorization_reference": "AUTH-1",
  "targets": [{"value": "127.0.0.1"}]
}""",
        encoding="utf-8",
    )
    database = tmp_path / "vaptforge.db"

    result = runner.invoke(
        app,
        [
            "queue-assessment",
            "http://127.0.0.1:3000",
            "--scope",
            str(scope_file),
            "--profile",
            "quick",
            "--db",
            str(database),
        ],
    )

    assert result.exit_code == 0
    assert "Queued job" in result.stdout


def test_guided_start_queues_and_launches_platform(tmp_path: Path, monkeypatch) -> None:
    config = tmp_path / "config"
    config.mkdir()
    (config / "scope.example.json").write_text(
        """{
  "assessment_name": "Local lab",
  "authorization_reference": "Owned lab",
  "targets": [{"value": "127.0.0.1"}]
}""",
        encoding="utf-8",
    )
    database = tmp_path / "data" / "vaptforge.db"
    calls: list[tuple[Path, str, int, bool]] = []

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        "vaptforge.cli.run_platform",
        lambda db, host, port, open_browser: calls.append((db, host, port, open_browser)),
    )
    monkeypatch.setattr(
        "vaptforge.ux.profiles.probe_scanner_tool",
        lambda name: type(
            "Probe",
            (),
            {
                "available": name in {"http", "tls"},
                "detail": "tool not installed",
            },
        )(),
    )

    result = runner.invoke(
        app,
        ["start", "--db", str(database), "--no-browser"],
        input="1\n1\n1\n\ny\n",
    )

    assert result.exit_code == 0
    assert "Queued assessment" in result.stdout
    assert "Unavailable optional scanners skipped" in result.stdout
    assert calls == [(database, "127.0.0.1", 8000, False)]


def test_manual_start_only_launches_platform(tmp_path: Path, monkeypatch) -> None:
    database = tmp_path / "vaptforge.db"
    calls: list[Path] = []

    monkeypatch.setattr(
        "vaptforge.cli.run_platform",
        lambda db, host, port, open_browser: calls.append(db),
    )

    result = runner.invoke(
        app,
        ["start", "--mode", "manual", "--db", str(database), "--no-browser"],
    )

    assert result.exit_code == 0
    assert "Manual / Advanced Workflow" in result.stdout
    assert calls == [database]


def test_platform_commands_use_current_python_and_separate_worker(tmp_path: Path) -> None:
    commands = build_platform_commands(tmp_path / "vaptforge.db", host="127.0.0.1", port=8000)

    assert "worker" in commands.worker
    assert "uvicorn" in commands.api
    assert "--host" in commands.api
    assert "127.0.0.1" in commands.api


def test_python_httpx_cli_is_rejected(monkeypatch) -> None:
    from subprocess import CompletedProcess

    from vaptforge.ux.tooling import probe_scanner_tool

    monkeypatch.setattr(
        "vaptforge.ux.tooling.shutil.which",
        lambda name: "C:/venv/Scripts/httpx.exe" if name == "httpx" else None,
    )
    monkeypatch.setattr(
        "vaptforge.ux.tooling.subprocess.run",
        lambda *args, **kwargs: CompletedProcess(
            args[0],
            2,
            stdout="Usage: httpx [OPTIONS] URL",
            stderr="Error: No such option '-e'.",
        ),
    )

    probe = probe_scanner_tool("httpx")

    assert probe.available is False
    assert "Python httpx CLI detected" in probe.detail


def test_projectdiscovery_httpx_is_accepted(monkeypatch) -> None:
    from subprocess import CompletedProcess

    from vaptforge.ux.tooling import probe_scanner_tool

    monkeypatch.setattr(
        "vaptforge.ux.tooling.shutil.which",
        lambda name: "C:/Tools/httpx.exe" if name == "httpx" else None,
    )
    monkeypatch.setattr(
        "vaptforge.ux.tooling.subprocess.run",
        lambda *args, **kwargs: CompletedProcess(
            args[0],
            0,
            stdout="[INF] Current Version: v1.12.0",
            stderr="",
        ),
    )

    probe = probe_scanner_tool("httpx")

    assert probe.available is True
    assert "ProjectDiscovery" in probe.detail


def test_deep_profile_keeps_native_engine_when_optional_tools_are_missing(monkeypatch) -> None:
    monkeypatch.setattr(
        "vaptforge.ux.profiles.probe_scanner_tool",
        lambda name: type(
            "Probe",
            (),
            {
                "available": name in {"http", "tls", "deep-web"},
                "detail": "tool not installed",
            },
        )(),
    )

    selected, skipped = resolve_profile_scanners(
        "deep",
        registered={
            "http",
            "tls",
            "deep-web",
            "httpx",
            "nmap",
            "nikto",
            "nuclei",
            "ffuf",
        },
    )

    assert selected == ["http", "tls", "deep-web"]
    assert any("nuclei" in item for item in skipped)
