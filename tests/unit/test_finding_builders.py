from types import SimpleNamespace

from models.sink import Sink
from vulnerabilities.base.stages import (
    _finding_from_sink,
    _normalize_path,
    _review_status,
    default_llm_review,
    direct_findings_from_sinks,
    findings_from_sink_review,
)


def _sink(**kw):
    base = dict(rule_id="r", file_path="A.java", line_number=10, line_number_end=10, code="code")
    base.update(kw)
    return Sink(**base)


def test_review_status_precedence():
    assert _review_status({"status": "NEED_MANUAL_REVIEW"}) == "NEED_MANUAL_REVIEW"
    assert _review_status({"vulnerable_status": "VULNERABLE"}) == "VULNERABLE"
    assert _review_status({}) == "VULNERABLE"


def test_normalize_path():
    assert _normalize_path("a/b/../c.java") == "a/c.java"
    assert _normalize_path(None) is None


def test_finding_from_sink_falls_back_to_sink_metadata():
    s = _sink(metadata={"class_api_path": "/api", "method_api_path": "/x"})
    f = _finding_from_sink("idor", s, review={"explanation": "e", "status": "VULNERABLE"})
    assert f.metadata == {"class_api_path": "/api", "method_api_path": "/x"}
    assert f.explanation == "e" and f.status == "VULNERABLE" and f.sink == "code"


def test_finding_from_sink_explicit_metadata_wins():
    s = _sink(metadata={"class_api_path": "/sink"})
    f = _finding_from_sink("idor", s, review={}, metadata={"class_api_path": "/explicit"})
    assert f.metadata == {"class_api_path": "/explicit"}


def test_finding_from_sink_without_metadata_is_empty():
    f = _finding_from_sink("x", _sink(), review={})
    assert f.metadata == {}


def test_default_llm_review_uses_fallbacks():
    vuln = SimpleNamespace(
        fallback_explanation="exp", fallback_remediation="rem", fallback_code_fix="fix"
    )
    review = default_llm_review(vuln)
    assert review["vulnerable_status"] == "VULNERABLE"
    assert review["explanation"] == "exp"
    assert review["remediation"] == "rem"
    assert review["code_fix"] == "fix"


def test_direct_findings_from_sinks():
    sinks = [_sink(code="c1"), _sink(file_path="B.java", code="c2")]
    findings = direct_findings_from_sinks("v", sinks, explanation="e", remediation="r", code_fix="f")
    assert [f.sink for f in findings] == ["c1", "c2"]
    assert findings[1].file_path == "B.java"
    assert all(f.explanation == "e" and f.status == "VULNERABLE" for f in findings)


def test_findings_from_sink_review_pairs_and_carries_metadata():
    sinks = [_sink(metadata={"class_api_path": "/a"})]
    reviews = [{"explanation": "e", "status": "NEED_MANUAL_REVIEW", "remediation": "r", "code_fix": "f"}]
    findings = findings_from_sink_review("v", sinks, reviews)
    assert len(findings) == 1
    assert findings[0].status == "NEED_MANUAL_REVIEW"
    assert findings[0].metadata == {"class_api_path": "/a"}
