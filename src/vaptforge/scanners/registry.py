from __future__ import annotations

import inspect
from importlib.metadata import EntryPoint, entry_points
from typing import Any

from vaptforge.scanners.base import Scanner


class ScannerPluginError(RuntimeError):
    """Raised when a scanner plugin cannot be loaded safely."""


def _builtin_scanners() -> list[Scanner]:
    from vaptforge.scanners.deep_web import DeepWebScanner
    from vaptforge.scanners.ffuf import FfufScanner
    from vaptforge.scanners.http_security import HttpSecurityScanner
    from vaptforge.scanners.httpx_probe import HttpxScanner
    from vaptforge.scanners.nikto import NiktoScanner
    from vaptforge.scanners.nmap import NmapScanner
    from vaptforge.scanners.nuclei import NucleiScanner
    from vaptforge.scanners.tls_security import TlsSecurityScanner

    return [
        HttpSecurityScanner(),
        TlsSecurityScanner(),
        DeepWebScanner(),
        HttpxScanner(),
        NmapScanner(),
        NucleiScanner(),
        NiktoScanner(),
        FfufScanner(),
    ]


def coerce_scanner_plugin(plugin: Any) -> Scanner:
    candidate = plugin
    if inspect.isclass(candidate) or (
        callable(candidate) and not isinstance(candidate, Scanner)
    ):
        candidate = candidate()

    if not isinstance(candidate, Scanner):
        raise ScannerPluginError(
            "Scanner plugins must expose a Scanner instance, Scanner subclass, "
            "or zero-argument factory returning Scanner."
        )
    if not candidate.name.strip():
        raise ScannerPluginError("Scanner plugins must define a non-empty name.")
    return candidate


def _external_entry_points() -> list[EntryPoint]:
    discovered = entry_points()
    if hasattr(discovered, "select"):
        return list(discovered.select(group="vaptforge.scanners"))
    return list(discovered.get("vaptforge.scanners", []))


def discover_scanners(*, include_external: bool = True) -> dict[str, Scanner]:
    registry: dict[str, Scanner] = {}

    for scanner in _builtin_scanners():
        registry[scanner.name] = scanner

    if not include_external:
        return registry

    for entry_point in _external_entry_points():
        try:
            scanner = coerce_scanner_plugin(entry_point.load())
        except Exception as exc:
            raise ScannerPluginError(
                f"Failed to load scanner plugin '{entry_point.name}': {exc}"
            ) from exc

        if scanner.name in registry:
            raise ScannerPluginError(
                f"Scanner plugin '{entry_point.name}' attempted to replace "
                f"registered scanner '{scanner.name}'."
            )
        registry[scanner.name] = scanner

    return registry
