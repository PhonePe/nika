from vulnerabilities.idor.detectors import (
    normalize_ownership_functions,
    scope_ownership_to_repo,
)


def test_plain_string_is_global():
    assert normalize_ownership_functions(["checkOwnership"]) == ["checkOwnership"]


def test_dict_resource_only():
    assert normalize_ownership_functions([{"name": "checkUserOwnership", "resource": "userId"}]) == [
        "checkUserOwnership::::userId"
    ]


def test_dict_repository_and_resource():
    out = normalize_ownership_functions(
        [{"name": "checkOrderOwnership", "repository": "orders-svc", "resource": "orderId"}]
    )
    assert out == ["checkOrderOwnership::orders-svc::orderId"]


def test_lists_expand_cross_product():
    out = normalize_ownership_functions(
        [{"name": "m", "repository": ["a", "b"], "resource": ["x", "y"]}]
    )
    assert out == ["m::a::x", "m::a::y", "m::b::x", "m::b::y"]


def test_fully_qualified_name_preserved():
    out = normalize_ownership_functions([{"name": "com.example.security.Utils.validate"}])
    assert out == ["com.example.security.Utils.validate"]


def test_dedupe_preserves_order():
    assert normalize_ownership_functions(["a", "a", "b"]) == ["a", "b"]

def _enc():
    return normalize_ownership_functions([
        "globalCheck",
        {"name": "checkUserOwnership", "repository": "orders-service", "resource": "userId"},
    ])


def test_scope_matches_repo_basename_strips_repo():
    out = scope_ownership_to_repo(_enc(), "/home/u/projects/orders-service")
    assert out == ["globalCheck", "checkUserOwnership::::userId"]


def test_scope_trailing_slash_still_matches():
    out = scope_ownership_to_repo(_enc(), "/home/u/projects/orders-service/")
    assert "checkUserOwnership::::userId" in out


def test_scope_case_insensitive():
    out = scope_ownership_to_repo(_enc(), "/home/u/projects/Orders-Service")
    assert "checkUserOwnership::::userId" in out


def test_scope_drops_non_matching_repo_keeps_global():
    out = scope_ownership_to_repo(_enc(), "/home/u/projects/users-service")
    assert out == ["globalCheck"]


def test_scope_empty_path_keeps_only_global():
    out = scope_ownership_to_repo(_enc(), "")
    assert out == ["globalCheck"]
