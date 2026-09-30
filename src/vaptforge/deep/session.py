from __future__ import annotations

import os

import httpx

from vaptforge.models.scope import AuthorizedScope


class SessionConfigurationError(RuntimeError):
    """Raised when an authenticated session reference cannot be resolved safely."""


def session_environment_status(scope: AuthorizedScope) -> list[tuple[str, bool]]:
    if scope.session is None:
        return []
    return [
        (name, bool(os.environ.get(name)))
        for name in scope.session.environment_references()
    ]


def resolve_session_headers(scope: AuthorizedScope) -> dict[str, str]:
    """Resolve session headers without persisting secret values in VAPTForge state."""
    if scope.session is None:
        return {}

    missing = [
        name
        for name, available in session_environment_status(scope)
        if not available
    ]
    if missing:
        raise SessionConfigurationError(
            "Missing configured session environment variable(s): "
            + ", ".join(missing)
        )

    headers: dict[str, str] = {}
    if scope.session.cookie_env:
        headers["Cookie"] = os.environ[scope.session.cookie_env]
    if scope.session.authorization_env:
        headers["Authorization"] = os.environ[scope.session.authorization_env]
    for header, env_name in scope.session.headers_env.items():
        headers[header] = os.environ[env_name]
    return headers


def verify_session(client: httpx.Client, scope: AuthorizedScope) -> str:
    """Verify configured auth without exposing secret values."""
    if scope.session is None:
        return "not-configured"

    if scope.session.verify_url is None:
        return "configured-unverified"

    scope.require_authorized(scope.session.verify_url)
    try:
        response = client.get(scope.session.verify_url, follow_redirects=True)
    except httpx.HTTPError as exc:
        raise SessionConfigurationError(
            f"Session verification request failed: {type(exc).__name__}"
        ) from exc

    if response.status_code != scope.session.verify_status:
        raise SessionConfigurationError(
            "Session verification failed: expected HTTP "
            f"{scope.session.verify_status}, received {response.status_code}"
        )

    marker = scope.session.success_contains
    if marker and marker not in response.text:
        raise SessionConfigurationError(
            "Session verification failed: configured success marker was not present"
        )

    return "verified"
