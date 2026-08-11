import json

import pytest

from reporting.html_renderer import HtmlReportRenderer
from reporting.code_reader import escape_html
from reporting.code_reader import CodeSnippetReader
from reporting.json_writer import JsonReportWriter
from schema.vulnerability_schema import (
    CallGraphNode,
    LLMVulnerabilityOutput,
    Vulnerabilities,
    Vulnerability,
)


@pytest.mark.parametrize("raw,expected", [
    ("<script>", "&lt;script&gt;"),
    ("a & b", "a &amp; b"),
    ('x" onmouseover="y', "x&quot; onmouseover=&quot;y"),
    ("it's", "it&#39;s"),
    (None, ""),
])
def test_escape_html(raw, expected):
    assert escape_html(raw) == expected


def test_amp_escaped_first_no_double_encoding():
    assert escape_html("<") == "&lt;"


def test_attribute_breakout_is_neutralized():
    payload = '"><img src=x onerror=alert(1)>'
    out = escape_html(payload)
    assert '"' not in out and "<" not in out and ">" not in out


def test_html_trace_renders_explicit_sink_for_single_node_trace(tmp_path):
    src = tmp_path / "Controller.java"
    src.write_text(
        "\n".join(
            [
                "class Controller {",
                "  @GetMapping(\"/fetch\")",
                "  String fetch(String url) {",
                "    HttpGet request = new HttpGet(url);",
                "    client.execute(request);",
                "  }",
                "}",
            ]
        ),
        encoding="utf-8",
    )
    vulnerability = Vulnerability(
        sink="client.execute(request);",
        callPath="",
        callGraph=[
            CallGraphNode(
                methodname="fetch",
                filename="Controller.java",
                code="String fetch(String url) { ... }",
                methodLineNumberStart=2,
                methodLineNumberEnd=6,
                calleeLineNumber=None,
                isExternal=False,
            )
        ],
        lineNumber=5,
        lineNumberEnd=5,
        filename="Controller.java",
    )

    html = HtmlReportRenderer(CodeSnippetReader(str(tmp_path)))._trace_code_block(vulnerability)

    assert "Source (Controller.java:2)" in html
    assert "Sink (Controller.java:5)" in html
    assert "client.execute(request);" in html


def test_html_renders_related_sink_occurrences():
    vulnerability = Vulnerability(
        sink="new File(name)",
        callPath="",
        callGraph=[],
        lineNumber=10,
        lineNumberEnd=10,
        filename="Utils.java",
        metadata={
            "finding_group": {
                "occurrence_count": 2,
                "related_sinks": [
                    {
                        "filename": "Service.java",
                        "lineNumber": 20,
                        "sink": "new FileInputStream(file)",
                    }
                ],
            }
        },
    )

    rendered = HtmlReportRenderer._related_sinks_section(vulnerability)

    assert "Related Sink Occurrences (2 total)" in rendered
    assert "Related sink (Service.java:20)" in rendered
    assert "new FileInputStream(file)" in rendered


def _analyzed_vulnerability():
    return Vulnerability(
        sink="execute(input)",
        callPath="",
        callGraph=[],
        lineNumber=10,
        lineNumberEnd=10,
        filename="Service.java",
        analysis=LLMVulnerabilityOutput(
            vulnerable_status="VULNERABLE",
            explanation="Untrusted input reaches the sink.",
            remediation="Validate or safely bind the input.",
        ),
    )


def test_html_report_has_no_code_fix_section(tmp_path):
    renderer = HtmlReportRenderer(CodeSnippetReader(str(tmp_path)))

    rendered = renderer._render_card(
        _analyzed_vulnerability(),
        "Injection",
        "Injection description",
    )

    assert "Untrusted input reaches the sink." in rendered
    assert "Validate or safely bind the input." in rendered
    assert "Code Fix" not in rendered


def test_json_report_has_no_code_fix_field(tmp_path):
    output_path = tmp_path / "report.json"
    report_input = [
        {
            "vulnerability": "injection",
            "VULNERABILITY_TITLE": "Injection",
            "VULNERABILITY_DESCRIPTION": "Injection description",
            "result": Vulnerabilities(findings=[_analyzed_vulnerability()]),
        }
    ]

    JsonReportWriter().generate(report_input, str(output_path))
    report = json.loads(output_path.read_text(encoding="utf-8"))

    finding = report["findings"][0]
    assert finding["explanation"] == "Untrusted input reaches the sink."
    assert finding["remediation"] == "Validate or safely bind the input."
    assert "code_fix" not in finding
