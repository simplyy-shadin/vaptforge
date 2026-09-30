from vaptforge.models.finding import Finding
from vaptforge.models.scope import AuthorizedScope
from vaptforge.scanners.base import Scanner
from vaptforge.scanners.registry import coerce_scanner_plugin, discover_scanners


class DemoScanner(Scanner):
    name = "demo"

    def scan(self, target: str, scope: AuthorizedScope) -> list[Finding]:
        scope.require_authorized(target)
        return []


def test_builtin_scanners_are_registered() -> None:
    registry = discover_scanners(include_external=False)
    assert {"http", "tls", "httpx", "nmap", "nuclei", "nikto", "ffuf"} <= set(registry)


def test_scanner_subclass_can_be_loaded_as_plugin() -> None:
    scanner = coerce_scanner_plugin(DemoScanner)
    assert isinstance(scanner, DemoScanner)
    assert scanner.name == "demo"
