from vaptforge.models.scope import AuthorizedScope, ScopeEntry


def make_scope() -> AuthorizedScope:
    return AuthorizedScope(
        assessment_name="Local lab",
        authorization_reference="Owned Docker lab",
        targets=[
            ScopeEntry(value="127.0.0.1"),
            ScopeEntry(value="10.10.10.0/24"),
            ScopeEntry(value="lab.example.test"),
        ],
    )


def test_exact_ip_is_authorized() -> None:
    assert make_scope().is_authorized("127.0.0.1")


def test_url_host_is_authorized() -> None:
    assert make_scope().is_authorized("http://127.0.0.1:3000/login")


def test_cidr_member_is_authorized() -> None:
    assert make_scope().is_authorized("10.10.10.23")


def test_hostname_is_exact_not_wildcard() -> None:
    scope = make_scope()
    assert scope.is_authorized("lab.example.test")
    assert not scope.is_authorized("evil.lab.example.test")


def test_out_of_scope_target_is_rejected() -> None:
    scope = make_scope()
    assert not scope.is_authorized("8.8.8.8")
