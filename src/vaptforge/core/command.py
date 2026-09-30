from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass


class ToolNotFoundError(RuntimeError):
    pass


class CommandExecutionError(RuntimeError):
    pass


@dataclass(frozen=True)
class CommandResult:
    command: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str


def run_command(args: list[str], *, timeout: int = 300) -> CommandResult:
    if not args:
        raise ValueError("command args cannot be empty")
    executable = args[0]
    if shutil.which(executable) is None:
        raise ToolNotFoundError(f"Required tool '{executable}' was not found in PATH")

    completed = subprocess.run(  # noqa: S603 - shell=False and args are structured
        args,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        shell=False,
    )
    result = CommandResult(tuple(args), completed.returncode, completed.stdout, completed.stderr)
    if completed.returncode != 0:
        raise CommandExecutionError(
            f"Command failed with exit code {completed.returncode}: {executable}\n{completed.stderr.strip()}"
        )
    return result
