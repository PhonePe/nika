import json

from engines.astrail.translators import _normalize_optional_int, translate_sources
from engines.opengrep.translators import translate_opengrep_results


def test_normalize_optional_int():
    assert _normalize_optional_int("5") == 5
    assert _normalize_optional_int(7) == 7
    assert _normalize_optional_int("") is None
    assert _normalize_optional_int(None) is None
    assert _normalize_optional_int("abc") is None


def test_translate_opengrep_relativizes_path_and_maps_fields():
    raw = {"results": [{
        "check_id": "rules.sqli.java-hibernate",
        "path": "/repo/src/A.java",
        "start": {"line": 12},
        "end": {"line": 14},
        "extra": {"lines": "  em.createQuery(sql)  "},
    }]}
    sinks = translate_opengrep_results(raw, "/repo")
    assert len(sinks) == 1
    s = sinks[0]
    assert s.file_path == "src/A.java"
    assert s.line_number == 12 and s.line_number_end == 14
    assert s.code == "em.createQuery(sql)"
    assert s.rule_id == "rules.sqli.java-hibernate"


def test_translate_opengrep_accepts_string_payload_and_empty_results():
    assert translate_opengrep_results(json.dumps({"results": []}), "/repo") == []


def test_translate_opengrep_leaves_relative_path_untouched():
    raw = {"results": [{"check_id": "r", "path": "src/A.java",
                        "start": {"line": 1}, "end": {"line": 1}, "extra": {}}]}
    assert translate_opengrep_results(raw, "/repo")[0].file_path == "src/A.java"


def test_translate_sources_maps_api_path_metadata():
    raw = [{
        "methodName": "com.x.C.f:void()", "fileName": "C.java", "lineNumber": 3,
        "code": "public void f()", "classAPIPath": "/api", "methodAPIPath": "/x",
    }]
    sources = translate_sources(raw)
    assert len(sources) == 1
    s = sources[0]
    assert s.symbol == "com.x.C.f:void()" and s.file_path == "C.java" and s.line_number == 3
    assert s.metadata["class_api_path"] == "/api" and s.metadata["method_api_path"] == "/x"
