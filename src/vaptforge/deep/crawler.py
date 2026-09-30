from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

import httpx

from vaptforge.core.targets import http_url_from_target
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
    errors: list[str] = field(default_factory=list)


class _HTMLDiscoveryParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
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


def _query_parameters(url: str) -> list[DiscoveredParameter]:
    parsed = urlsplit(url)
    endpoint = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))
    return [
        DiscoveredParameter(endpoint=endpoint, name=name, source="query")
        for name, _value in parse_qsl(parsed.query, keep_blank_values=True)
        if name
    ]


def crawl_target(
    target: str,
    scope: AuthorizedScope,
    *,
    client: httpx.Client | None = None,
    max_pages: int = 40,
    max_depth: int = 2,
) -> CrawlResult:
    """Crawl bounded, same-origin GET pages and inventory links, forms, and parameters."""
    scope.require_authorized(target)
    start_url = _normalize_url(http_url_from_target(target))
    start_origin = _origin(start_url)
    result = CrawlResult()
    queue: deque[tuple[str, int]] = deque([(start_url, 0)])
    visited: set[str] = set()
    seen_parameters: set[tuple[str, str, str]] = set()
    seen_forms: set[tuple[str, str, tuple[str, ...]]] = set()

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
                key = (parameter.endpoint, parameter.name, parameter.source)
                if key not in seen_parameters:
                    seen_parameters.add(key)
                    result.parameters.append(parameter)

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
                        key = (action_url, name, "get-form")
                        if key not in seen_parameters:
                            seen_parameters.add(key)
                            result.parameters.append(
                                DiscoveredParameter(
                                    endpoint=action_url,
                                    name=name,
                                    source="get-form",
                                )
                            )
    finally:
        if owns_client:
            client.close()

    return result
