from vulnerabilities.idor import detectors as d


def test_extract_path_variables_multiple_and_regex_constraint():
    assert d.extract_path_variables("/a/{x}/b/{y:\\d+}") == ["x", "y"]
    assert d.extract_path_variables("") == []
    assert d.extract_path_variables(None) == []


def test_normalize_strips_case_and_separators():
    assert d.normalize("User_Id") == "userid"
    assert d.normalize("ORDER-ID") == "orderid"
    assert d.normalize(None) == ""


def test_has_request_body_param():
    assert d.has_request_body_param("void f(@RequestBody Dto x)") is True
    assert d.has_request_body_param("void f(Dto x)") is False
    assert d.has_request_body_param(None) is False


def test_header_param_detected_when_query_params_enabled():
    sig = "void f(@RequestHeader Long resourceId)"
    assert d.find_idor_identifier(None, sig, ["resourceId"], include_query_params=True)[0] == "resourceId"
    assert d.find_idor_identifier(None, sig, ["resourceId"]) == (None, None)


def test_bound_name_from_quoted_annotation_value():
    sig = 'String get(@PathVariable("userId") Long uid)'
    assert d.find_idor_identifier(None, sig, ["userId"])[0] == "userId"


def test_join_phrases():
    assert d._join_phrases([]) == ""
    assert d._join_phrases(["a"]) == "a"
    assert d._join_phrases(["a", "b"]) == "a and b"
    assert d._join_phrases(["a", "b", "c"]) == "a, b, and c"


def test_describe_sources_dedupes():
    phrases = d.describe_idor_sources(
        [("orderId", "request-body-model"), ("orderId", "request-body-model")]
    )
    assert phrases == ["a request-body field ('orderId')"]


def test_explanation_request_body_model_phrasing():
    text = d.build_idor_explanation([("orderId", "request-body-model")])
    assert "request-body field" in text and "orderId" in text
