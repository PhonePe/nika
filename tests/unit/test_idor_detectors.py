import pytest

from vulnerabilities.idor import detectors as d

@pytest.mark.parametrize("name,expected", [
    ("id", True), ("ID", True), ("userId", True), ("order_id", True),
    ("documentId", True), ("valid", False), ("void", False), ("user", False),
    ("", False),
])
def test_is_generic_identifier(name, expected):
    assert d.is_generic_identifier(name) is expected


def test_path_template_named_identifier():
    assert d.find_idor_identifier("/users/{userId}", "", ["userId"]) == ("userId", "path-template")


def test_path_template_generic_only_with_flag():
    assert d.find_idor_identifier("/things/{id}", "", [], match_generic_id=True) == ("id", "path-template")
    assert d.find_idor_identifier("/things/{id}", "", []) == (None, None)


def test_path_template_generic_does_not_match_lookalike():
    assert d.find_idor_identifier("/x/{valid}", "", [], match_generic_id=True) == (None, None)


def test_query_param_only_when_enabled():
    sig = "public X get(@RequestParam Long resourceId)"
    assert d.find_idor_identifier(None, sig, ["resourceId"], include_query_params=True)[0] == "resourceId"
    assert d.find_idor_identifier(None, sig, ["resourceId"]) == (None, None)


def test_request_body_accessor_match():
    sig = "void f(@RequestBody Dto dto)"
    assert d.find_request_body_identifier(sig, "dto.getAccountId();", ["accountId"]) == ("AccountId", "request-body")


def test_request_body_requires_body_annotation():
    assert d.find_request_body_identifier("void f(Dto dto)", "dto.getAccountId();", ["accountId"]) == (None, None)

def test_explanation_mentions_source_and_no_check():
    text = d.build_idor_explanation([("orderId", "path-template")])
    assert "orderId" in text and "No ownership check" in text


def test_explanation_includes_hint_when_signal_present():
    text = d.build_idor_explanation([("orderId", "path-template")], signal="annotation:@PreAuthorize")
    assert "PreAuthorize" in text and "possible authorization check" in text.lower()

def test_find_ownership_annotation():
    sig = "@PreAuthorize(\"x\") public void f()"
    assert d.find_ownership_annotation(sig, ["PreAuthorize", "PostAuthorize"]) == "PreAuthorize"
    assert d.find_ownership_annotation("public void f()", ["PreAuthorize"]) is None
