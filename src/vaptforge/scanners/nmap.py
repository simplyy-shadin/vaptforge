from __future__ import annotations

from vaptforge.core.command import run_command
from vaptforge.core.targets import host_from_target
from vaptforge.models.finding import Finding
from vaptforge.models.scope import AuthorizedScope
from vaptforge.parsers.nmap_xml import parse_nmap_xml
from vaptforge.scanners.base import Scanner


class NmapScanner(Scanner):
    name = "nmap"

    def scan(self, target: str, scope: AuthorizedScope) -> list[Finding]:
        scope.require_authorized(target)
        scan_target = host_from_target(target)
        result = run_command(
            [
                "nmap",
                "-sV",
                "--version-light",
                "-T3",
                "--reason",
                "-oX",
                "-",
                scan_target,
            ],
            timeout=600,
        )
        return parse_nmap_xml(result.stdout, target=target)
