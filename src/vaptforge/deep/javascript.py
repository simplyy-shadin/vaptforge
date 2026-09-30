from __future__ import annotations

import re
from urllib.parse import urljoin, urlsplit, urlunsplit

API_PATH_RE = re.compile(
    r"""(?ix)
    (?:
        https?://[a-z0-9._:-]+
    )?
    /
    (?:api|rest|graphql|api-docs|v[0-9]+)
    (?:
        /[a-z0-9_~!$&()*+,;=:@%{}.-]*
    )*
    (?:
        \?[a-z0-9_~!$&()*+,;=:@%{}./?=-]*
    )?
    """
)

RELATIVE_API_PATH_RE = re.compile(
    r"""(?ix)
    (?<![a-z0-9_])
    (?:api|rest)
    /
    [a-z0-9_~!$&()*+,;=:@%{}.-]+
    (?:
        /[a-z0-9_~!$&()*+,;=:@%{}.-]*
    )*
    (?:
        \?[a-z0-9_~!$&()*+,;=:@%{}./?=-]*
    )?
    """
)


def _clean_candidate(value: str) -> str:
    value = value.replace(r"\/", "/").strip()
    return value.rstrip("'\"),;]")


def _origin(url: str) -> tuple[str, str, int | None]:
    parsed = urlsplit(url)
    return parsed.scheme.lower(), (parsed.hostname or "").lower(), parsed.port


def _normalize(url: str) -> str:
    parsed = urlsplit(url)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))


def extract_javascript_endpoints(
    script_text: str,
    *,
    base_url: str,
    max_endpoints: int = 100,
) -> list[str]:
    """Extract likely API endpoints from static JavaScript without executing it."""
    normalized_script = script_text.replace(r"\/", "/")
    base_origin = _origin(base_url)
    discovered: list[str] = []
    seen: set[str] = set()

    candidates = [
        match.group(0) for match in API_PATH_RE.finditer(normalized_script)
    ]
    candidates.extend(
        match.group(0) for match in RELATIVE_API_PATH_RE.finditer(normalized_script)
    )

    for raw in candidates:
        candidate = _clean_candidate(raw)
        if not candidate:
            continue
        if not candidate.startswith(("http://", "https://", "/")):
            candidate = "/" + candidate
        resolved = _normalize(urljoin(base_url, candidate))
        if _origin(resolved) != base_origin:
            continue
        if resolved in seen:
            continue
        seen.add(resolved)
        discovered.append(resolved)
        if len(discovered) >= max_endpoints:
            break

    return discovered
