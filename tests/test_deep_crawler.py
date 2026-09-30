from __future__ import annotations

import httpx

from vaptforge.deep.crawler import crawl_target
from vaptforge.models.scope import AuthorizedScope, ScopeEntry


def test_crawler_stays_same_origin_and_inventories_get_inputs() -> None:
    requested: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested.append(str(request.url))
        if request.url.path == "/":
            return httpx.Response(
                200,
                headers={"content-type": "text/html"},
                text="""<html><body>
<a href="/search?q=juice">Search</a>
<a href="/logout">Logout</a>
<a href="https://example.org/out">External</a>
<form action="/find" method="get"><input name="q"></form>
<form action="/login" method="post">
  <input name="username"><input name="password">
</form>
</body></html>""",
            )
        return httpx.Response(200, headers={"content-type": "text/html"}, text="<html></html>")

    scope = AuthorizedScope(
        assessment_name="Owned lab",
        authorization_reference="AUTH-1",
        targets=[ScopeEntry(value="127.0.0.1")],
    )
    transport = httpx.MockTransport(handler)

    with httpx.Client(transport=transport, follow_redirects=False) as client:
        result = crawl_target(
            "http://127.0.0.1:3000",
            scope,
            client=client,
            max_pages=10,
            max_depth=2,
        )

    assert "http://127.0.0.1:3000/" in result.pages
    assert "http://127.0.0.1:3000/search?q=juice" in result.pages
    assert all("/logout" not in url for url in requested)
    assert all("example.org" not in url for url in requested)

    discovered = {(item.endpoint, item.name, item.source) for item in result.parameters}
    assert ("http://127.0.0.1:3000/search", "q", "query") in discovered
    assert ("http://127.0.0.1:3000/find", "q", "get-form") in discovered

    forms = {(item.action, item.method, item.parameters) for item in result.forms}
    assert ("http://127.0.0.1:3000/find", "get", ("q",)) in forms
    assert (
        "http://127.0.0.1:3000/login",
        "post",
        ("username", "password"),
    ) in forms



def test_crawler_extracts_same_origin_javascript_attack_surface() -> None:
    requested: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested.append(str(request.url))
        if request.url.path == "/":
            return httpx.Response(
                200,
                headers={"content-type": "text/html"},
                text='<html><script src="/main.js"></script></html>',
            )
        if request.url.path == "/main.js":
            return httpx.Response(
                200,
                headers={"content-type": "application/javascript"},
                text=(
                    'const search="/rest/products/search?q=";'
                    'const users="/api/Users";'
                    'const external="https://example.org/api/private?x=1";'
                ),
            )
        return httpx.Response(404)

    scope = AuthorizedScope(
        assessment_name="Owned lab",
        authorization_reference="AUTH-1",
        targets=[ScopeEntry(value="127.0.0.1")],
    )

    with httpx.Client(
        transport=httpx.MockTransport(handler),
        follow_redirects=False,
    ) as client:
        result = crawl_target(
            "http://127.0.0.1:3000",
            scope,
            client=client,
        )

    assert result.script_sources == ["http://127.0.0.1:3000/main.js"]
    assert "http://127.0.0.1:3000/rest/products/search?q=" in result.javascript_endpoints
    assert "http://127.0.0.1:3000/api/Users" in result.javascript_endpoints
    assert all("example.org" not in endpoint for endpoint in result.javascript_endpoints)
    assert any(
        item.endpoint == "http://127.0.0.1:3000/rest/products/search"
        and item.name == "q"
        and item.source == "javascript"
        for item in result.parameters
    )
    assert all("example.org" not in url for url in requested)



def test_crawler_starts_from_authorized_same_origin_seed() -> None:
    requested: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested.append(str(request.url))
        return httpx.Response(
            200,
            headers={"content-type": "text/html"},
            text="<html></html>",
        )

    scope = AuthorizedScope(
        assessment_name="Owned lab",
        authorization_reference="AUTH-1",
        targets=[ScopeEntry(value="127.0.0.1")],
    )

    with httpx.Client(
        transport=httpx.MockTransport(handler),
        follow_redirects=False,
    ) as client:
        result = crawl_target(
            "http://127.0.0.1:4280",
            scope,
            client=client,
            seed_urls=["/vulnerabilities/sqli/?id=1"],
        )

    assert "http://127.0.0.1:4280/vulnerabilities/sqli/?id=1" in result.pages
    assert any(
        item.endpoint == "http://127.0.0.1:4280/vulnerabilities/sqli/"
        and item.name == "id"
        for item in result.parameters
    )
    assert any("/vulnerabilities/sqli/" in url for url in requested)


def test_crawler_rejects_cross_origin_seed() -> None:
    scope = AuthorizedScope(
        assessment_name="Owned lab",
        authorization_reference="AUTH-1",
        targets=[ScopeEntry(value="127.0.0.1")],
    )

    with httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200))) as client:
        with __import__("pytest").raises(PermissionError, match="outside the target origin"):
            crawl_target(
                "http://127.0.0.1:4280",
                scope,
                client=client,
                seed_urls=["http://127.0.0.1:8000/other"],
            )
