from __future__ import annotations

from urllib.parse import urlparse


def host_from_target(target: str) -> str:
    parsed = urlparse(target if "://" in target else f"//{target}")
    return parsed.hostname or target.split(":", maxsplit=1)[0].strip("[]")


def http_url_from_target(target: str) -> str:
    if "://" in target:
        return target
    return f"http://{target}"
