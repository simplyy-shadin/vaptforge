from __future__ import annotations

from collections import defaultdict
from hashlib import sha256
from urllib.parse import urlsplit

import httpx

from vaptforge.core.targets import http_url_from_target
from vaptforge.deep.crawler import CrawlResult, DiscoveredParameter, crawl_target
from vaptforge.deep.session import resolve_session_headers
from vaptforge.models.finding import (
    AssetRef,
    Evidence,
    Finding,
    FindingConfidence,
    FindingStatus,
    Severity,
)
from vaptforge.models.scope import AuthorizedScope
from vaptforge.scanners.base import Scanner

MAX_ACTIVE_PARAMETER_CHECKS = 30
MAX_ANALYZED_BODY_CHARS = 500_000
UNSAFE_PARAMETER_MARKERS = (
    "csrf",
    "token",
    "logout",
    "signout",
    "delete",
    "remove",
    "destroy",
    "revoke",
)

SQL_ERROR_MARKERS = (
    "you have an error in your sql syntax",
    "warning: mysql",
    "mysqli_sql_exception",
    "mariadb",
    "postgresql query failed",
    "pg_query()",
    "sqlite error",
    "sqlite3::sqlexception",
    "unclosed quotation mark after the character string",
    "unterminated quoted string",
    "microsoft ole db provider for sql server",
    "odbc sql server driver",
    "ora-01756",
    "ora-00933",
)


def _asset(target: str) -> AssetRef:
    parsed = urlsplit(target)
    return AssetRef(
        target=target,
        host=parsed.hostname or target,
        port=parsed.port,
        protocol=parsed.scheme or None,
        service="http",
    )


def _body(response: httpx.Response) -> str:
    try:
        return response.text[:MAX_ANALYZED_BODY_CHARS]
    except UnicodeError:
        return ""


def _new_sql_error(baseline: str, mutated: str) -> str | None:
    baseline_lower = baseline.lower()
    mutated_lower = mutated.lower()
    for marker in SQL_ERROR_MARKERS:
        if marker in mutated_lower and marker not in baseline_lower:
            return marker
    return None


def _parameter_location(endpoint: str, parameter: str) -> str:
    return f"{endpoint}?{parameter}=<tested>"


def analyze_reflection(
    *,
    target: str,
    endpoint: str,
    parameter: str,
    baseline: httpx.Response,
    mutated: httpx.Response,
    marker: str,
) -> Finding | None:
    content_type = mutated.headers.get("content-type", "").lower()
    baseline_body = _body(baseline)
    mutated_body = _body(mutated)
    if "html" not in content_type or marker in baseline_body or marker not in mutated_body:
        return None

    return Finding(
        title=f"Potential reflected XSS sink in parameter '{parameter}'",
        severity=Severity.LOW,
        asset=_asset(target),
        source="vaptforge-deep",
        status=FindingStatus.POTENTIAL,
        confidence=FindingConfidence.MEDIUM,
        description=(
            "A benign marker containing HTML-special characters was reflected verbatim in an "
            "HTML response. This is not proof of script execution and requires manual context "
            "validation before it can be classified as XSS."
        ),
        location=_parameter_location(endpoint, parameter),
        cwes=["CWE-79"],
        owasp=["A03:2021 Injection"],
        evidence=[
            Evidence(
                source="vaptforge-deep",
                summary=(
                    f"GET parameter '{parameter}' reflected the exact benign marker in "
                    f"HTTP {mutated.status_code} HTML output"
                ),
            )
        ],
        remediation=(
            "Apply context-appropriate output encoding and avoid inserting untrusted input "
            "directly into HTML, attributes, script, style, or URL contexts."
        ),
        tags=["deep-assessment", "reflection", "xss-candidate"],
        metadata={
            "parameter": parameter,
            "active_check": "benign-reflection-marker",
            "requires_manual_validation": True,
        },
    )


def analyze_sql_error(
    *,
    target: str,
    endpoint: str,
    parameter: str,
    baseline: httpx.Response,
    mutated: httpx.Response,
) -> Finding | None:
    marker = _new_sql_error(_body(baseline), _body(mutated))
    if marker is None:
        return None

    return Finding(
        title=f"Potential SQL injection error behavior in parameter '{parameter}'",
        severity=Severity.MEDIUM,
        asset=_asset(target),
        source="vaptforge-deep",
        status=FindingStatus.POTENTIAL,
        confidence=FindingConfidence.HIGH,
        description=(
            "A single-quote input mutation introduced a database-specific error signature that "
            "was not present in the baseline response. VAPTForge did not attempt data extraction "
            "or exploit the condition."
        ),
        location=_parameter_location(endpoint, parameter),
        cwes=["CWE-89"],
        owasp=["A03:2021 Injection"],
        evidence=[
            Evidence(
                source="vaptforge-deep",
                summary=(
                    f"Database error signature '{marker}' appeared only after a quote mutation; "
                    f"baseline HTTP {baseline.status_code}, mutated HTTP {mutated.status_code}"
                ),
            )
        ],
        remediation=(
            "Use parameterized queries/prepared statements, validate input types, and avoid "
            "constructing SQL statements with untrusted input."
        ),
        tags=["deep-assessment", "sqli-candidate", "differential-analysis"],
        metadata={
            "parameter": parameter,
            "active_check": "single-quote-error-differential",
            "requires_manual_validation": True,
        },
    )


def attack_surface_finding(target: str, crawl: CrawlResult) -> Finding:
    get_forms = sum(form.method == "get" for form in crawl.forms)
    post_forms = sum(form.method == "post" for form in crawl.forms)
    return Finding(
        title="Web attack surface inventory collected",
        severity=Severity.INFO,
        asset=_asset(target),
        source="vaptforge-deep",
        confidence=FindingConfidence.HIGH,
        description=(
            "VAPTForge performed a bounded same-origin crawl and static JavaScript analysis "
            "to inventory reachable pages, forms, API-like routes, and GET parameters before "
            "safe active parameter checks."
        ),
        location=http_url_from_target(target),
        evidence=[
            Evidence(
                source="vaptforge-deep",
                summary=(
                    f"pages={len(crawl.pages)}; parameters={len(crawl.parameters)}; "
                    f"forms={len(crawl.forms)} (GET={get_forms}, POST={post_forms}); "
                    f"scripts={len(crawl.script_sources)}; "
                    f"javascript_endpoints={len(crawl.javascript_endpoints)}; "
                    f"crawl_errors={len(crawl.errors)}"
                ),
            )
        ],
        tags=["deep-assessment", "attack-surface", "reconnaissance"],
        metadata={
            "pages": crawl.pages,
            "parameters": [
                {
                    "endpoint": item.endpoint,
                    "name": item.name,
                    "source": item.source,
                }
                for item in crawl.parameters
            ],
            "forms": [
                {
                    "action": form.action,
                    "method": form.method,
                    "parameters": list(form.parameters),
                }
                for form in crawl.forms
            ],
            "script_sources": crawl.script_sources,
            "javascript_endpoints": crawl.javascript_endpoints,
            "crawl_errors": crawl.errors,
        },
    )


def _parameter_contexts(crawl: CrawlResult) -> list[tuple[DiscoveredParameter, dict[str, str]]]:
    groups: dict[tuple[str, str], dict[str, str]] = defaultdict(dict)
    for item in crawl.parameters:
        groups[(item.endpoint, item.source)][item.name] = item.value

    contexts: list[tuple[DiscoveredParameter, dict[str, str]]] = []
    seen: set[tuple[str, str]] = set()
    for item in crawl.parameters:
        key = (item.endpoint, item.name)
        if key in seen:
            continue
        seen.add(key)
        if any(marker in item.name.lower() for marker in UNSAFE_PARAMETER_MARKERS):
            continue
        if "{" in item.endpoint or "}" in item.endpoint:
            continue
        contexts.append((item, dict(groups[(item.endpoint, item.source)])))
    return contexts


class DeepWebScanner(Scanner):
    name = "deep-web"

    def scan(self, target: str, scope: AuthorizedScope) -> list[Finding]:
        scope.require_authorized(target)
        findings: list[Finding] = []

        request_headers = {
            "User-Agent": "VAPTForge/0.9 authorized-deep-assessment",
            **resolve_session_headers(scope),
        }

        with httpx.Client(
            timeout=10.0,
            follow_redirects=False,
            headers=request_headers,
        ) as client:
            crawl = crawl_target(target, scope, client=client)
            surface = attack_surface_finding(target, crawl)
            surface.metadata["authenticated_session"] = bool(scope.session)
            findings.append(surface)

            contexts = _parameter_contexts(crawl)[:MAX_ACTIVE_PARAMETER_CHECKS]
            for item, baseline_params in contexts:
                scope.require_authorized(item.endpoint)
                try:
                    baseline = client.get(item.endpoint, params=baseline_params)

                    token = sha256(
                        f"{item.endpoint}|{item.name}".encode()
                    ).hexdigest()[:10]
                    reflection_marker = f"VFREFL_{token}_<>\"'&"
                    reflection_params = dict(baseline_params)
                    reflection_params[item.name] = reflection_marker
                    reflected = client.get(item.endpoint, params=reflection_params)
                    reflected_finding = analyze_reflection(
                        target=target,
                        endpoint=item.endpoint,
                        parameter=item.name,
                        baseline=baseline,
                        mutated=reflected,
                        marker=reflection_marker,
                    )
                    if reflected_finding is not None:
                        findings.append(reflected_finding)

                    sql_params = dict(baseline_params)
                    sql_params[item.name] = f"{baseline_params.get(item.name) or '1'}'"
                    sql_mutated = client.get(item.endpoint, params=sql_params)
                    sql_finding = analyze_sql_error(
                        target=target,
                        endpoint=item.endpoint,
                        parameter=item.name,
                        baseline=baseline,
                        mutated=sql_mutated,
                    )
                    if sql_finding is not None:
                        findings.append(sql_finding)
                except httpx.HTTPError:
                    continue

        return findings
