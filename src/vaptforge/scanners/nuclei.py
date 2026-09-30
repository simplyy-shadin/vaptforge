from __future__ import annotations

from vaptforge.core.command import run_command
from vaptforge.models.finding import Finding
from vaptforge.models.scope import AuthorizedScope
from vaptforge.parsers.nuclei_jsonl import parse_nuclei_jsonl
from vaptforge.scanners.base import Scanner


class NucleiScanner(Scanner):
    name = "nuclei"

    def scan(self, target: str, scope: AuthorizedScope) -> list[Finding]:
        scope.require_authorized(target)
        result = run_command(
            [
                "nuclei",
                "-u",
                target,
                "-jsonl",
                "-silent",
                "-severity",
                "info,low,medium,high,critical",
                "-exclude-tags",
                "dos,fuzz,bruteforce",
            ],
            timeout=900,
        )
        return parse_nuclei_jsonl(result.stdout, target=target)
