from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from vaptforge.cli import app

runner = CliRunner()


def test_session_check_reports_environment_names_without_values(
    tmp_path: Path,
    monkeypatch,
) -> None:
    scope_file = tmp_path / "scope.json"
    scope_file.write_text(
        """{
  "assessment_name": "Authenticated lab",
  "authorization_reference": "AUTH-1",
  "targets": [{"value": "127.0.0.1"}],
  "session": {"cookie_env": "VAPTFORGE_TEST_SESSION"}
}""",
        encoding="utf-8",
    )
    monkeypatch.setenv("VAPTFORGE_TEST_SESSION", "secret-session-value")

    result = runner.invoke(app, ["session-check", "--scope", str(scope_file)])

    assert result.exit_code == 0
    assert "VAPTFORGE_TEST_SESSION" in result.stdout
    assert "available" in result.stdout
    assert "secret-session-value" not in result.stdout


def test_session_check_fails_when_reference_is_missing(
    tmp_path: Path,
    monkeypatch,
) -> None:
    scope_file = tmp_path / "scope.json"
    scope_file.write_text(
        """{
  "assessment_name": "Authenticated lab",
  "authorization_reference": "AUTH-1",
  "targets": [{"value": "127.0.0.1"}],
  "session": {"cookie_env": "VAPTFORGE_MISSING_SESSION"}
}""",
        encoding="utf-8",
    )
    monkeypatch.delenv("VAPTFORGE_MISSING_SESSION", raising=False)

    result = runner.invoke(app, ["session-check", "--scope", str(scope_file)])

    assert result.exit_code == 2
    assert "missing" in result.stdout
