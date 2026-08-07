from types import SimpleNamespace

from models.sink import Sink
from models.source import Source
from models.trace import Trace, TraceNode
from vulnerabilities.base import stages


def _sink(**overrides):
    values = {
        "rule_id": "rules.sql",
        "file_path": "src/Example.java",
        "line_number": 12,
        "code": "statement.executeQuery(sql);",
        "metadata": {"sink_kind": "sql", "confidence": "HIGH"},
    }
    values.update(overrides)
    return Sink(**values)


def _trace(**overrides):
    values = {
        "sink_file_path": "src/Example.java",
        "sink_line_number": 12,
        "source_symbol": "Example.lookup:String(java.lang.String)",
        "nodes": [
            TraceNode(
                method_name="lookup",
                file_path="src/Example.java",
                method_line_number_start=8,
                code="return statement.executeQuery(sql);",
            )
        ],
    }
    values.update(overrides)
    return Trace(**values)


def test_trace_review_deduplicates_exact_evidence_and_preserves_order(monkeypatch):
    first = _trace()
    duplicate = first.model_copy(deep=True)
    distinct = _trace(sink_line_number=20)
    calls = []

    def fake_review(_vulnerability, _context, evidence):
        calls.append(evidence)
        return {"vulnerable_status": "VULNERABLE", "call": len(calls)}

    monkeypatch.setattr(stages, "run_security_agent_review", fake_review)
    state = SimpleNamespace(traces=[first, duplicate, distinct], sinks=[], sources=[])
    vulnerability = SimpleNamespace(vulnerability_id="sql_injection")

    result = stages.review_traces_with_llm(vulnerability, SimpleNamespace(), state)

    assert result is state
    assert len(calls) == 2
    assert [review["call"] for review in state.reviews] == [1, 1, 2]


def test_sink_review_canonicalizes_metadata_order_before_deduplication(monkeypatch):
    first = _sink(metadata={"sink_kind": "sql", "confidence": "HIGH"})
    duplicate = _sink(metadata={"confidence": "HIGH", "sink_kind": "sql"})
    distinct = _sink(metadata={"sink_kind": "sql", "confidence": "LOW"})
    calls = []

    def fake_review(_vulnerability, _context, evidence):
        calls.append(evidence)
        return {"vulnerable_status": "VULNERABLE", "call": len(calls)}

    monkeypatch.setattr(stages, "run_security_agent_review", fake_review)
    state = SimpleNamespace(sinks=[first, duplicate, distinct])
    vulnerability = SimpleNamespace(vulnerability_id="sql_injection")

    result = stages.review_sinks_with_llm(vulnerability, SimpleNamespace(), state)

    assert result is state
    assert len(calls) == 2
    assert [review["call"] for review in state.reviews] == [1, 1, 2]


def test_trace_review_groups_distinct_sinks_by_source_method(monkeypatch):
    source = Source(
        symbol="Controller.upload:void()",
        file_path="src/Controller.java",
        line_number=8,
        code="void upload(String filename) { service.upload(filename); }",
        metadata={"class_api_path": "/v1", "method_api_path": "/upload"},
    )
    first_sink = _sink(line_number=12, code="new File(filename)")
    second_sink = _sink(line_number=30, code="new FileInputStream(file)")
    first = _trace(
        sink_line_number=12,
        source=source,
        source_param="filename",
        source_kind="@FormDataParam",
        sink=first_sink,
    )
    second = _trace(
        sink_line_number=30,
        source=source,
        source_param="filename",
        source_kind="@FormDataParam",
        sink=second_sink,
        nodes=[
            first.nodes[0],
            TraceNode(
                method_name="store",
                file_path="src/Service.java",
                method_line_number_start=25,
                code="void store(File file) { new FileInputStream(file); }",
            ),
        ],
    )
    calls = []

    def fake_review(_vulnerability, _context, evidence, *, human_prompt=None):
        calls.append((evidence, human_prompt))
        return {"vulnerable_status": "VULNERABLE", "call": len(calls)}

    monkeypatch.setattr(stages, "run_security_agent_review", fake_review)
    state = SimpleNamespace(
        traces=[first, second],
        sinks=[first_sink, second_sink],
        sources=[source],
    )
    vulnerability = SimpleNamespace(
        vulnerability_id="path_traversal",
        human_prompt="Analyze path traversal.",
        review_grouping="source_method",
    )

    stages.review_traces_with_llm(vulnerability, SimpleNamespace(), state)

    assert len(calls) == 1
    assert [review["call"] for review in state.reviews] == [1, 1]
    grouped_prompt = calls[0][1]
    assert grouped_prompt is not None
    assert grouped_prompt.count("Shared source evidence:") == 1
    assert "Shared tainted source parameter: @FormDataParam filename" in grouped_prompt
    assert "new File(filename)" in grouped_prompt
    assert "new FileInputStream(file)" in grouped_prompt


def test_trace_review_keeps_different_source_methods_separate(monkeypatch):
    first_source = Source(
        symbol="Controller.upload:void()",
        file_path="src/Controller.java",
        line_number=8,
    )
    second_source = Source(
        symbol="Controller.download:void()",
        file_path="src/Controller.java",
        line_number=20,
    )
    first_sink = _sink(line_number=12)
    second_sink = _sink(line_number=30)
    first = _trace(
        sink_line_number=12,
        source_symbol=first_source.symbol,
        source_param="filename",
        source=first_source,
        sink=first_sink,
    )
    second = _trace(
        sink_line_number=30,
        source_symbol=second_source.symbol,
        source_param="filename",
        source=second_source,
        sink=second_sink,
    )
    calls = []

    def fake_review(_vulnerability, _context, evidence, *, human_prompt=None):
        calls.append((evidence, human_prompt))
        return {"vulnerable_status": "VULNERABLE", "call": len(calls)}

    monkeypatch.setattr(stages, "run_security_agent_review", fake_review)
    state = SimpleNamespace(
        traces=[first, second],
        sinks=[first_sink, second_sink],
        sources=[first_source, second_source],
    )
    vulnerability = SimpleNamespace(
        vulnerability_id="path_traversal",
        human_prompt="Analyze path traversal.",
        review_grouping="source_method",
    )

    stages.review_traces_with_llm(vulnerability, SimpleNamespace(), state)

    assert len(calls) == 2
    assert [review["call"] for review in state.reviews] == [1, 2]
    assert all(human_prompt is None for _, human_prompt in calls)


def test_trace_review_keeps_different_source_parameters_separate(monkeypatch):
    source = Source(
        symbol="Controller.upload:void(java.lang.String,java.lang.String)",
        file_path="src/Controller.java",
        line_number=8,
    )
    first_sink = _sink(line_number=12)
    second_sink = _sink(line_number=30)
    first = _trace(
        sink_line_number=12,
        source_symbol=source.symbol,
        source_param="filename",
        source=source,
        sink=first_sink,
    )
    second = _trace(
        sink_line_number=30,
        source_symbol=source.symbol,
        source_param="templateName",
        source=source,
        sink=second_sink,
    )
    calls = []

    def fake_review(_vulnerability, _context, evidence, *, human_prompt=None):
        calls.append((evidence, human_prompt))
        return {"vulnerable_status": "VULNERABLE", "call": len(calls)}

    monkeypatch.setattr(stages, "run_security_agent_review", fake_review)
    state = SimpleNamespace(
        traces=[first, second],
        sinks=[first_sink, second_sink],
        sources=[source],
    )
    vulnerability = SimpleNamespace(
        vulnerability_id="path_traversal",
        human_prompt="Analyze path traversal.",
        review_grouping="source_method",
    )

    stages.review_traces_with_llm(vulnerability, SimpleNamespace(), state)

    assert len(calls) == 2
    assert [review["call"] for review in state.reviews] == [1, 2]


def test_trace_review_does_not_source_group_without_source_parameter(monkeypatch):
    source = Source(
        symbol="Controller.upload:void()",
        file_path="src/Controller.java",
        line_number=8,
    )
    first_sink = _sink(line_number=12)
    second_sink = _sink(line_number=30)
    first = _trace(sink_line_number=12, source=source, sink=first_sink)
    second = _trace(sink_line_number=30, source=source, sink=second_sink)
    calls = []

    def fake_review(_vulnerability, _context, evidence, *, human_prompt=None):
        calls.append((evidence, human_prompt))
        return {"vulnerable_status": "VULNERABLE", "call": len(calls)}

    monkeypatch.setattr(stages, "run_security_agent_review", fake_review)
    state = SimpleNamespace(
        traces=[first, second],
        sinks=[first_sink, second_sink],
        sources=[source],
    )
    vulnerability = SimpleNamespace(
        vulnerability_id="path_traversal",
        human_prompt="Analyze path traversal.",
        review_grouping="source_method",
    )

    stages.review_traces_with_llm(vulnerability, SimpleNamespace(), state)

    assert len(calls) == 2