from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

import httpx

from vaptforge.core.targets import http_url_from_target
from vaptforge.deep.javascript import extract_javascript_endpoints
from vaptforge.models.scope import AuthorizedScope

UNSAFE_GET_MARKERS = (
    "logout",
    "signout",
    "delete",
    "remove",
    "destroy",
    "revoke",
    "unsubscribe",
)


@dataclass(frozen=True)
class DiscoveredParameter:
    endpoint: str
    name: str
    source: str
    value: str = ""


@dataclass(frozen=True)
class DiscoveredForm:
    action: str
    method: str
    parameters: tuple[str, ...]


@dataclass
class CrawlResult:
    pages: list[str] = field(default_factory=list)
    parameters: list[DiscoveredParameter] = field(default_factory=list)
    forms: list[DiscoveredForm] = field(default_factory=list)
    script_sources: list[str] = field(default_factory=list)
    javascript_endpoints: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class _HTMLDiscoveryParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.scripts: list[str] = []
        self.forms: list[tuple[str, str, tuple[str, ...]]] = []
        self._form_action: str | None = None
        self._form_method = "get"
        self._form_parameters: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.lower(): value for key, value in attrs}
        tag = tag.lower()

        if tag == "a" and values.get("href"):
            self.links.append(str(values["href"]))
            return

        if tag == "script" and values.get("src"):
            self.scripts.append(str(values["src"]))
            return

        if tag == "form":
            self._form_action = str(values.get("action") or "")
            self._form_method = str(values.get("method") or "get").lower()
            self._form_parameters = []
            return

        if tag in {"input", "textarea", "select"} and self._form_action is not None:
            name = values.get("name")
            if name:
                self._form_parameters.append(str(name))

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() != "form" or self._form_action is None:
            return
        self.forms.append(
            (
                self._form_action,
                self._form_method,
                tuple(dict.fromkeys(self._form_parameters)),
            )
        )
        self._form_action = None
        self._form_method = "get"
        self._form_parameters = []


def _origin(url: str) -> tuple[str, str, int | None]:
    parsed = urlsplit(url)
    return parsed.scheme.lower(), (parsed.hostname or "").lower(), parsed.port


def _normalize_url(url: str) -> str:
    parsed = urlsplit(url)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))


def _safe_same_origin_url(candidate: str, origin: tuple[str, str, int | None]) -> bool:
    parsed = urlsplit(candidate)
    if parsed.scheme.lower() not in {"http", "https"}:
        return False
    if _origin(candidate) != origin:
        return False
    lowered_path = parsed.path.lower()
    return not any(marker in lowered_path for marker in UNSAFE_GET_MARKERS)


def _query_parameters(url: str, *, source: str = "query") -> list[DiscoveredParameter]:
    parsed = urlsplit(url)
    endpoint = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))
    return [
        DiscoveredParameter(endpoint=endpoint, name=name, source=source, value=value)
        for name, value in parse_qsl(parsed.query, keep_blank_values=True)
        if name
    ]


def _append_parameter(
    result: CrawlResult,
    seen: set[tuple[str, str, str]],
    parameter: DiscoveredParameter,
) -> None:
    key = (parameter.endpoint, parameter.name, parameter.source)
    if key in seen:
        return
    seen.add(key)
    result.parameters.append(parameter)


def crawl_target(
    target: str,
    scope: AuthorizedScope,
    *,
    client: httpx.Client | None = None,
    seed_urls: list[str] | None = None,
    max_pages: int = 40,
    max_depth: int = 2,
    max_scripts: int = 12,
    max_script_bytes: int = 1_000_000,
    max_javascript_endpoints: int = 100,
) -> CrawlResult:
    """Crawl bounded same-origin content and statically inventory JavaScript API routes."""
    scope.require_authorized(target)
    start_url = _normalize_url(http_url_from_target(target))
    start_origin = _origin(start_url)
    result = CrawlResult()
    queue: deque[tuple[str, int]] = deque([(start_url, 0)])
    for seed in seed_urls or []:
        resolved_seed = _normalize_url(urljoin(start_url, seed))
        if not _safe_same_origin_url(resolved_seed, start_origin):
            raise PermissionError(
                f"Crawl seed '{seed}' is outside the target origin or is state-changing"
            )
        scope.require_authorized(resolved_seed)
        queue.append((resolved_seed, 0))

    visited: set[str] = set()
    seen_parameters: set[tuple[str, str, str]] = set()
    seen_forms: set[tuple[str, str, tuple[str, ...]]] = set()
    seen_scripts: set[str] = set()
    seen_javascript_endpoints: set[str] = set()

    owns_client = client is None
    if client is None:
        client = httpx.Client(
            timeout=10.0,
            follow_redirects=False,
            headers={"User-Agent": "VAPTForge/0.9 authorized-deep-assessment"},
        )

    try:
        while queue and len(visited) < max_pages:
            url, depth = queue.popleft()
            url = _normalize_url(url)
            if url in visited or not _safe_same_origin_url(url, start_origin):
                continue

            scope.require_authorized(url)
            visited.add(url)
            result.pages.append(url)

            for parameter in _query_parameters(url):
                _append_parameter(result, seen_parameters, parameter)

            try:
                response = client.get(url)
            except httpx.HTTPError as exc:
                result.errors.append(f"{url}: {type(exc).__name__}")
                continue

            location = response.headers.get("location")
            if 300 <= response.status_code < 400 and location and depth < max_depth:
                redirected = _normalize_url(urljoin(url, location))
                if _safe_same_origin_url(redirected, start_origin):
                    queue.append((redirected, depth + 1))
                continue

            content_type = response.headers.get("content-type", "").lower()
            if "html" not in content_type:
                continue

            parser = _HTMLDiscoveryParser()
            try:
                parser.feed(response.text)
            except (UnicodeError, ValueError):
                result.errors.append(f"{url}: unable to parse HTML")
                continue

            if depth < max_depth:
                for href in parser.links:
                    candidate = _normalize_url(urljoin(url, href))
                    if _safe_same_origin_url(candidate, start_origin):
                        queue.append((candidate, depth + 1))

            for action, method, parameters in parser.forms:
                action_url = _normalize_url(urljoin(url, action or url))
                if not _safe_same_origin_url(action_url, start_origin):
                    continue
                form_key = (action_url, method, parameters)
                if form_key not in seen_forms:
                    seen_forms.add(form_key)
                    result.forms.append(
                        DiscoveredForm(
                            action=action_url,
                            method=method,
                            parameters=parameters,
                        )
                    )
                if method == "get":
                    for name in parameters:
                        _append_parameter(
                            result,
                            seen_parameters,
                            DiscoveredParameter(
                                endpoint=action_url,
                                name=name,
                                source="get-form",
                            ),
                        )

            for script_src in parser.scripts:
                if len(seen_scripts) >= max_scripts:
                    break
                script_url = _normalize_url(urljoin(url, script_src))
                if script_url in seen_scripts:
                    continue
                if not _safe_same_origin_url(script_url, start_origin):
                    continue

                scope.require_authorized(script_url)
                seen_scripts.add(script_url)
                result.script_sources.append(script_url)

                try:
                    script_response = client.get(script_url)
                except httpx.HTTPError as exc:
                    result.errors.append(f"{script_url}: {type(exc).__name__}")
                    continue

                if len(script_response.content) > max_script_bytes:
                    result.errors.append(f"{script_url}: script exceeds analysis size limit")
                    continue

                try:
                    script_text = script_response.text
                except UnicodeError:
                    result.errors.append(f"{script_url}: unable to decode JavaScript")
                    continue

                remaining = max_javascript_endpoints - len(result.javascript_endpoints)
                if remaining <= 0:
                    continue

                endpoints = extract_javascript_endpoints(
                    script_text,
                    base_url=start_url,
                    max_endpoints=remaining,
                )
                for endpoint in endpoints:
                    if endpoint in seen_javascript_endpoints:
                        continue
                    if not _safe_same_origin_url(endpoint, start_origin):
                        continue
                    seen_javascript_endpoints.add(endpoint)
                    result.javascript_endpoints.append(endpoint)
                    for parameter in _query_parameters(endpoint, source="javascript"):
                        _append_parameter(result, seen_parameters, parameter)

    finally:
        if owns_client:
            client.close()

    return result
