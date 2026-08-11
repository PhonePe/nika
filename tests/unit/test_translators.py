import json

from engines.astrail.translators import (
    _normalize_optional_int,
    translate_batch_reachability,
    translate_sources,
)
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
        "extra": {
            "lines": "  em.createQuery(sql)  ",
            "metadata": {"confidence": "HIGH", "sink_kind": "sql"},
            "metavars": {
                "$SQL": {
                    "abstract_content": "sql",
                    "propagated_value": {"svalue_abstract_content": "name + suffix"},
                }
            },
        },
    }]}
    sinks = translate_opengrep_results(raw, "/repo")
    assert len(sinks) == 1
    s = sinks[0]
    assert s.file_path == "src/A.java"
    assert s.line_number == 12 and s.line_number_end == 14
    assert s.code == "em.createQuery(sql)"
    assert s.rule_id == "rules.sqli.java-hibernate"
    assert s.metadata["rule_id"] == "rules.sqli.java-hibernate"
    assert s.metadata["confidence"] == "HIGH"
    assert s.metadata["sink_kind"] == "sql"
    assert s.metadata["metavars"]["$SQL"]["abstract_content"] == "sql"
    assert s.metadata["metavars"]["$SQL"]["propagated_value"] == "name + suffix"


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


def test_translate_batch_reachability_maps_source_parameter():
    traces = translate_batch_reachability(
        [
            {
                "source": "com.x.Controller.upload:void(java.lang.String)",
                "sourceParam": "filename",
                "sourceKind": "method parameter",
                "fileName": "Service.java",
                "lineNumber": 12,
                "path": [],
            }
        ]
    )

    assert len(traces) == 1
    assert traces[0].source_param == "filename"
    assert traces[0].source_kind == "method parameter"


def test_translate_batch_reachability_ignores_implicit_receiver():
    traces = translate_batch_reachability(
        [
            {
                "source": "com.x.Controller.upload:void(java.lang.String)",
                "sourceParam": "this",
                "sourceKind": "method parameter",
                "fileName": "Service.java",
                "lineNumber": 12,
                "path": [],
            }
        ]
    )

    assert len(traces) == 1
    assert traces[0].source_param is None
    assert traces[0].source_kind is None
