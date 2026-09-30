from __future__ import annotations

import os

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
