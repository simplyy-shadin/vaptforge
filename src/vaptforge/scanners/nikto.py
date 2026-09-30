from __future__ import annotations

import tempfile
from pathlib import Path

from vaptforge.core.command import run_command
from vaptforge.core.targets import http_url_from_target
from vaptforge.models.finding import Finding
from vaptforge.models.scope import AuthorizedScope
from vaptforge.parsers.nikto_json import parse_nikto_json
from vaptforge.scanners.base import Scanner


class NiktoScanner(Scanner):
    name = "nikto"

    def scan(self, target: str, scope: AuthorizedScope) -> list[Finding]:
        scope.require_authorized(target)
        url = http_url_from_target(target)

        with tempfile.NamedTemporaryFile(
            suffix=".json",
            delete=False,
        ) as output_file:
            output_path = Path(output_file.name)

        try:
            run_command(
                [
                    "nikto",
                    "-h",
                    url,
                    "-Format",
                    "json",
                    "-output",
                    str(output_path),
                    "-nointeractive",
                    "-maxtime",
                    "5m",
                ],
                timeout=360,
            )
            return parse_nikto_json(output_path.read_text(encoding="utf-8"), target=url)
        finally:
            output_path.unlink(missing_ok=True)
