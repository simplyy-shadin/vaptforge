from __future__ import annotations

import pytest

from vaptforge.deep.session import (
    SessionConfigurationError,
    resolve_session_headers,
    session_environment_status,
)
from vaptforge.models.scope import AuthorizedScope, ScopeEntry, SessionAuth


def _scope() -> AuthorizedScope:
    return AuthorizedScope(
        assessment_name="Authenticated lab",
        authorization_reference="Owned lab",
        targets=[ScopeEntry(value="127.0.0.1")],
        session=SessionAuth(
            cookie_env="VAPTFORGE_TEST_COOKIE",
            authorization_env="VAPTFORGE_TEST_AUTH",
            headers_env={"X-CSRF-Token": "VAPTFORGE_TEST_CSRF"},
        ),
    )


def test_session_values_are_resolved_from_environment_but_not_serialized(monkeypatch) -> None:
    monkeypatch.setenv("VAPTFORGE_TEST_COOKIE", "session=super-secret-cookie")
    monkeypatch.setenv("VAPTFORGE_TEST_AUTH", "Bearer super-secret-token")
    monkeypatch.setenv("VAPTFORGE_TEST_CSRF", "super-secret-csrf")

    scope = _scope()
    headers = resolve_session_headers(scope)

    assert headers["Cookie"] == "session=super-secret-cookie"
    assert headers["Authorization"] == "Bearer super-secret-token"
    assert headers["X-CSRF-Token"] == "super-secret-csrf"

    serialized = scope.model_dump_json()
    assert "VAPTFORGE_TEST_COOKIE" in serialized
    assert "VAPTFORGE_TEST_AUTH" in serialized
    assert "VAPTFORGE_TEST_CSRF" in serialized
    assert "super-secret-cookie" not in serialized
    assert "super-secret-token" not in serialized
    assert "super-secret-csrf" not in serialized


def test_missing_session_environment_reference_fails_closed(monkeypatch) -> None:
    for name in ("VAPTFORGE_TEST_COOKIE", "VAPTFORGE_TEST_AUTH", "VAPTFORGE_TEST_CSRF"):
        monkeypatch.delenv(name, raising=False)

    scope = _scope()
    status = dict(session_environment_status(scope))

    assert status["VAPTFORGE_TEST_COOKIE"] is False
    with pytest.raises(SessionConfigurationError, match="Missing configured session"):
        resolve_session_headers(scope)


def test_session_header_configuration_blocks_transport_headers() -> None:
    with pytest.raises(ValueError, match="cannot override"):
        SessionAuth(headers_env={"Host": "VAPTFORGE_HOST"})


def test_session_configuration_requires_an_environment_reference() -> None:
    with pytest.raises(ValueError, match="at least one environment variable"):
        SessionAuth()
