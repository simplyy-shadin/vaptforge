from __future__ import annotations

import json
import re
from collections.abc import Iterable
from importlib import metadata
from pathlib import Path
from typing import Any
from uuid import uuid4

from vaptforge import __version__


def _requirement_name(requirement: str) -> str:
    match = re.match(r"^[A-Za-z0-9_.-]+", requirement.strip())
    return match.group(0) if match else requirement.strip()


def _component(name: str, version: str) -> dict[str, Any]:
    normalized = name.replace("_", "-")
    return {
        "type": "library",
        "name": name,
        "version": version,
        "purl": f"pkg:pypi/{normalized}@{version}",
    }


def project_components(project_name: str = "vaptforge") -> list[tuple[str, str]]:
    requirements = metadata.requires(project_name) or []
    components: dict[str, str] = {}

    for requirement in requirements:
        if "extra ==" in requirement:
            continue
        name = _requirement_name(requirement)
        try:
            version = metadata.version(name)
        except metadata.PackageNotFoundError:
            continue
        components[name.lower()] = version

    return sorted(
        ((name, version) for name, version in components.items()),
        key=lambda item: item[0],
    )


def build_cyclonedx_sbom(
    components: Iterable[tuple[str, str]] | None = None,
) -> dict[str, Any]:
    resolved = list(components) if components is not None else project_components()
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid4()}",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": "vaptforge",
                "version": __version__,
            }
        },
        "components": [_component(name, version) for name, version in resolved],
    }


def write_sbom(path: str | Path) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(build_cyclonedx_sbom(), indent=2),
        encoding="utf-8",
    )
