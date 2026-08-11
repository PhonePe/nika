from types import SimpleNamespace

from models.finding import Finding
from models.source import Source
from models.trace import Trace, TraceNode
from reporting.report_models_adapter import (
    _to_legacy_vulnerability,
    group_findings_for_legacy_report,
)


def test_api_path_from_metadata():
    f = Finding(
        vulnerability_id="idor", sink="sig", file_path="C.java", line_number=5,
        metadata={"class_api_path": "/api", "method_api_path": "/users/{id}"},
    )
    v = _to_legacy_vulnerability(f)
    assert v.class_api_path == "/api"
    assert v.method_api_path == "/users/{id}"
    assert v.filename == "C.java" and v.line_number == 5
    assert v.metadata == {"class_api_path": "/api", "method_api_path": "/users/{id}"}


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


def _trace_finding(
    sink,
    line_number,
    source_symbol="Controller.upload:void()",
    source_param="filename",
    status="VULNERABLE",
):
    source = Source(
        symbol=source_symbol,
        file_path="Controller.java",
        line_number=10,
        metadata={"class_api_path": "/v1", "method_api_path": "/upload"},
    )
    trace = Trace(
        sink_file_path="Service.java",
        sink_line_number=line_number,
        source_symbol=source_symbol,
        source_param=source_param,
        source=source,
        nodes=[
            TraceNode(
                method_name="upload",
                file_path="Controller.java",
                method_line_number_start=10,
                code="void upload()",
                callee_line_number=12,
            )
        ],
    )
    return Finding(
        vulnerability_id="path_traversal",
        sink=sink,
        file_path="Service.java",
        line_number=line_number,
        status=status,
        explanation=f"review for {sink}",
        trace=trace,
        metadata={
            "class_api_path": "/v1",
            "method_api_path": "/upload",
            "source_param": source_param,
            "rule_id": f"rule-{line_number}",
        },
    )


def test_source_method_grouping_keeps_related_sinks_as_occurrences():
    findings = [
        _trace_finding("new File(name)", 20),
        _trace_finding("new FileInputStream(file)", 30),
        _trace_finding("Files.readAllBytes(path)", 40, source_symbol="Controller.download:void()"),
        _trace_finding("safe sink", 50, status="NOT_VULNERABLE"),
    ]
    vulnerability_metadata = {
        "path_traversal": SimpleNamespace(
            title="Path Traversal",
            description="Path traversal",
            report_grouping="source_method",
        )
    }

    report = group_findings_for_legacy_report(findings, vulnerability_metadata)

    reported_findings = report[0]["result"].findings
    assert len(reported_findings) == 3
    finding_group = reported_findings[0].metadata["finding_group"]
    assert finding_group["strategy"] == "source_method"
    assert finding_group["source_symbol"] == "Controller.upload:void()"
    assert finding_group["occurrence_count"] == 2
    assert finding_group["related_sinks"] == [
        {
            "sink": "new FileInputStream(file)",
            "filename": "Service.java",
            "lineNumber": 30,
            "lineNumberEnd": 30,
            "status": "VULNERABLE",
            "ruleId": "rule-30",
            "explanation": "review for new FileInputStream(file)",
            "callGraph": [
                {
                    "methodname": "upload",
                    "filename": "Controller.java",
                    "calleeLineNumber": 12,
                }
            ],
        }
    ]


def test_findings_are_not_source_grouped_without_opt_in():
    findings = [
        _trace_finding("first sink", 20),
        _trace_finding("second sink", 30),
    ]

    report = group_findings_for_legacy_report(findings)

    assert len(report[0]["result"].findings) == 2


def test_source_method_grouping_keeps_different_parameters_separate():
    findings = [
        _trace_finding("first sink", 20, source_param="filename"),
        _trace_finding("second sink", 30, source_param="templateName"),
    ]
    vulnerability_metadata = {
        "path_traversal": SimpleNamespace(
            title="Path Traversal",
            description="Path traversal",
            report_grouping="source_method",
        )
    }

    report = group_findings_for_legacy_report(findings, vulnerability_metadata)

    assert len(report[0]["result"].findings) == 2
