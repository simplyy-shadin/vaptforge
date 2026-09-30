from __future__ import annotations

import json
from pathlib import Path

from vaptforge.core.command import CommandResult
from vaptforge.models.scope import AuthorizedScope, ScopeEntry
from vaptforge.scanners.ffuf import FfufScanner


def test_ffuf_uses_auto_calibration_for_soft_404_routes(monkeypatch) -> None:
    commands: list[list[str]] = []

    def fake_run_command(args: list[str], *, timeout: int = 300) -> CommandResult:
        commands.append(args)
        output_path = Path(args[args.index("-o") + 1])
        output_path.write_text(json.dumps({"results": []}), encoding="utf-8")
        return CommandResult(tuple(args), 0, "", "")

    monkeypatch.setattr("vaptforge.scanners.ffuf.run_command", fake_run_command)

    scope = AuthorizedScope(
        assessment_name="Owned lab",
        authorization_reference="AUTH-1",
        targets=[ScopeEntry(value="127.0.0.1")],
    )

    findings = FfufScanner().scan("http://127.0.0.1:3000", scope)

    assert findings == []
    assert len(commands) == 1
    command = commands[0]
    assert "-ac" in command
    assert command[command.index("-fc") + 1] == "404"
