from __future__ import annotations

from vaptforge.core.command import run_command
from vaptforge.models.finding import Finding
from vaptforge.models.scope import AuthorizedScope
from vaptforge.parsers.httpx_jsonl import parse_httpx_jsonl
from vaptforge.scanners.base import Scanner


class HttpxScanner(Scanner):
    name = "httpx"

    def scan(self, target: str, scope: AuthorizedScope) -> list[Finding]:
        scope.require_authorized(target)
        result = run_command(
            [
                "httpx",
                "-u",
                target,
                "-json",
                "-silent",
                "-status-code",
                "-title",
                "-tech-detect",
                "-web-server",
                "-ip",
                "-location",
            ],
            timeout=180,
        )
        return parse_httpx_jsonl(result.stdout, target=target)
