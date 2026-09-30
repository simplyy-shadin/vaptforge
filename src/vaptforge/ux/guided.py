from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from urllib.parse import urlparse

from vaptforge.models.scope import AuthorizedScope


def discover_scope_files(root: Path = Path("config")) -> list[Path]:
    if not root.exists():
        return []
    return sorted(
        {
            *root.glob("*.json"),
            *root.glob("*.scope.json"),
        }
    )


def _is_network(value: str) -> bool:
    try:
        return "/" in value and ipaddress.ip_network(value, strict=False) is not None
    except ValueError:
        return False


def target_suggestions(scope: AuthorizedScope) -> list[tuple[str, str]]:
    suggestions: list[tuple[str, str]] = []
    seen: set[str] = set()

    def add(target: str, label: str) -> None:
        if target not in seen and scope.is_authorized(target):
            suggestions.append((target, label))
            seen.add(target)

    for entry in scope.targets:
        value = entry.value.strip()
        if "://" in value:
            add(value, entry.description or value)
            continue

        normalized = value.rstrip(".").lower()
        if normalized in {"127.0.0.1", "localhost"}:
            lab_host = "localhost" if normalized == "localhost" else "127.0.0.1"
            add(f"http://{lab_host}:3000", "OWASP Juice Shop local lab")
            add(f"http://{lab_host}:4280", "DVWA local lab")
            add(f"http://{lab_host}", "Local host")
            continue

        if _is_network(value):
            continue

        parsed = urlparse(f"//{value}")
        host = parsed.hostname or value
        add(f"http://{host}", entry.description or f"{host} over HTTP")
        add(f"https://{host}", entry.description or f"{host} over HTTPS")

    return suggestions


def safe_scope_filename(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return f"scope.{slug or 'assessment'}.json"
