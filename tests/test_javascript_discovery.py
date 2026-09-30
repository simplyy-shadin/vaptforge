from vaptforge.deep.javascript import extract_javascript_endpoints


def test_extracts_same_origin_api_routes_and_query_parameters() -> None:
    script = """
const search = "/rest/products/search?q=";
const users = "api/Users";
const graph = "/graphql?operation=products";
const docs = "/api-docs/swagger.json";
"""
    endpoints = extract_javascript_endpoints(
        script,
        base_url="http://127.0.0.1:3000/",
    )

    assert "http://127.0.0.1:3000/rest/products/search?q=" in endpoints
    assert "http://127.0.0.1:3000/api/Users" in endpoints
    assert "http://127.0.0.1:3000/graphql?operation=products" in endpoints
    assert "http://127.0.0.1:3000/api-docs/swagger.json" in endpoints


def test_external_api_urls_are_not_rewritten_as_local_routes() -> None:
    script = """
const external = "https://example.org/api/private?token=x";
const nested = "https://example.org/site/api/internal";
"""
    endpoints = extract_javascript_endpoints(
        script,
        base_url="http://127.0.0.1:3000/",
    )

    assert endpoints == []


def test_static_extraction_is_bounded() -> None:
    script = "\n".join(f'const x{i} = "/api/item/{i}";' for i in range(20))

    endpoints = extract_javascript_endpoints(
        script,
        base_url="http://127.0.0.1:3000/",
        max_endpoints=5,
    )

    assert len(endpoints) == 5
