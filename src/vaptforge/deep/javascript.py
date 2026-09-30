from __future__ import annotations

import re
from urllib.parse import urljoin, urlsplit, urlunsplit

API_ROOTS = {"api", "rest", "graphql", "api-docs"}

ABSOLUTE_URL_RE = re.compile(
    r"""(?ix)
    https?://
    [a-z0-9._:-]+
    /
    [a-z0-9_~!$&()*+,;=:@%{}./?=-]*
    """
)

ROOT_RELATIVE_API_RE = re.compile(
    r"""(?ix)
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

RELATIVE_API_RE = re.compile(
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
    return value.replace(r"\/", "/").strip().rstrip("'\"),;]")


def _origin(url: str) -> tuple[str, str, int | None]:
    parsed = urlsplit(url)
    return parsed.scheme.lower(), (parsed.hostname or "").lower(), parsed.port


def _normalize(url: str) -> str:
    parsed = urlsplit(url)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))


def _looks_like_api_path(path: str) -> bool:
    first_segment = path.lstrip("/").split("/", maxsplit=1)[0].lower()
    return first_segment in API_ROOTS or (
        len(first_segment) > 1
        and first_segment.startswith("v")
        and first_segment[1:].isdigit()
    )


def extract_javascript_endpoints(
    script_text: str,
    *,
    base_url: str,
    max_endpoints: int = 100,
) -> list[str]:
    """Extract likely same-origin API endpoints from static JavaScript without executing it."""
    normalized_script = script_text.replace(r"\/", "/")
    base_origin = _origin(base_url)
    discovered: list[str] = []
    seen: set[str] = set()

    absolute_matches = list(ABSOLUTE_URL_RE.finditer(normalized_script))
    absolute_spans = [(match.start(), match.end()) for match in absolute_matches]

    candidates: list[str] = []
    for match in absolute_matches:
        value = _clean_candidate(match.group(0))
        if _looks_like_api_path(urlsplit(value).path):
            candidates.append(value)

    for match in ROOT_RELATIVE_API_RE.finditer(normalized_script):
        if any(start <= match.start() < end for start, end in absolute_spans):
            continue
        candidates.append(match.group(0))

    for match in RELATIVE_API_RE.finditer(normalized_script):
        if any(start <= match.start() < end for start, end in absolute_spans):
            continue
        candidates.append(match.group(0))

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
