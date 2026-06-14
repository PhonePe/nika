from models.finding import Finding
from reporting.report_models_adapter import _to_legacy_vulnerability


def test_api_path_from_metadata():
    f = Finding(
        vulnerability_id="idor", sink="sig", file_path="C.java", line_number=5,
        metadata={"class_api_path": "/api", "method_api_path": "/users/{id}"},
    )
    v = _to_legacy_vulnerability(f)
    assert v.class_api_path == "/api"
    assert v.method_api_path == "/users/{id}"
    assert v.filename == "C.java" and v.line_number == 5


def test_no_metadata_yields_none_api_path():
    v = _to_legacy_vulnerability(Finding(vulnerability_id="x", sink="s", file_path="C.java", line_number=1))
    assert v.class_api_path is None and v.method_api_path is None


def test_analysis_built_from_review_text():
    f = Finding(vulnerability_id="x", sink="s", status="VULNERABLE", explanation="why", remediation="fix")
    v = _to_legacy_vulnerability(f)
    assert v.analysis is not None
    assert v.analysis.explanation == "why" and v.analysis.remediation == "fix"


def test_no_analysis_when_no_text():
    v = _to_legacy_vulnerability(Finding(vulnerability_id="x", sink="s"))
    assert v.analysis is None


def test_line_number_end_falls_back_to_line_number():
    v = _to_legacy_vulnerability(Finding(vulnerability_id="x", sink="s", line_number=7))
    assert v.line_number_end == 7
