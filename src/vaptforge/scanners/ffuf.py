from __future__ import annotations

import tempfile
from importlib.resources import as_file, files
from pathlib import Path

from vaptforge.core.command import run_command
from vaptforge.core.targets import http_url_from_target
from vaptforge.models.finding import Finding
from vaptforge.models.scope import AuthorizedScope
from vaptforge.parsers.ffuf_json import parse_ffuf_json
from vaptforge.scanners.base import Scanner


class FfufScanner(Scanner):
    name = "ffuf"

    def scan(self, target: str, scope: AuthorizedScope) -> list[Finding]:
        scope.require_authorized(target)
        base_url = http_url_from_target(target).rstrip("/")
        wordlist_resource = files("vaptforge").joinpath("data/common_paths.txt")

        with tempfile.NamedTemporaryFile(
            suffix=".json",
            delete=False,
        ) as output_file:
            output_path = Path(output_file.name)

        try:
            with as_file(wordlist_resource) as wordlist_path:
                run_command(
                    [
                        "ffuf",
                        "-u",
                        f"{base_url}/FUZZ",
                        "-w",
                        str(wordlist_path),
                        "-of",
                        "json",
                        "-o",
                        str(output_path),
                        "-rate",
                        "20",
                        "-t",
                        "10",
                        "-maxtime",
                        "120",
                        "-fc",
                        "404",
                        "-noninteractive",
                    ],
                    timeout=180,
                )
            return parse_ffuf_json(output_path.read_text(encoding="utf-8"), target=target)
        finally:
            output_path.unlink(missing_ok=True)
