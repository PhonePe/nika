import json
from types import SimpleNamespace

import tiktoken
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
from langgraph.graph import END

from agents.security_agent import SecurityAgent


def _test_token_encoding():
    return tiktoken.Encoding(
        name="test",
        pat_str=r"(?s).",
        mergeable_ranks={bytes([value]): value for value in range(256)},
        special_tokens={},
    )


def test_astrail_lookup_tool_returns_structured_error_on_exception():
    class FailingAstrail:
        def get_method_and_file_name(self, code, filename):
            raise RuntimeError("boom")

    agent = SecurityAgent.__new__(SecurityAgent)
    agent.runtime_context = SimpleNamespace(astrail=FailingAstrail())

    lookup_tool = agent._build_astrail_search_method_name_tool()
    result = json.loads(
        lookup_tool.invoke({"code": "call()", "filename": "src/main/java/C.java"})
    )

    assert result["fileName"] == ""
    assert result["methodName"] == ""
    assert result["error"] == "astrail_lookup_failed"
    assert "boom" in result["detail"]


def test_grep_for_code_returns_bounded_compact_source_matches(tmp_path):
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    for index in range(21):
        (source_dir / f"Match{index:02}.java").write_text(
            f"class Match{index:02} {{ void validateInput() {{}} }}\n",
            encoding="utf-8",
        )

    excluded_dir = tmp_path / "target"
    excluded_dir.mkdir()
    (excluded_dir / "Generated.java").write_text(
        "class Generated { void validateInput() {} }\n",
        encoding="utf-8",
    )
    (tmp_path / "notes.txt").write_text("validateInput\n", encoding="utf-8")

    agent = SecurityAgent.__new__(SecurityAgent)
    agent.runtime_context = SimpleNamespace(code_path=str(tmp_path))

    result = json.loads(
        agent._build_grep_for_code_tool().invoke(
            {"code_snippet": "validateInput"}
        )
    )

    assert len(result["matches"]) == 20
    assert result["truncated"] is True
    assert result["matches"][0]["file"] == "src/Match00.java"
    assert all(not match["file"].startswith("target/") for match in result["matches"])


def test_grep_for_code_rejects_empty_search(tmp_path):
    agent = SecurityAgent.__new__(SecurityAgent)
    agent.runtime_context = SimpleNamespace(code_path=str(tmp_path))

    result = json.loads(
        agent._build_grep_for_code_tool().invoke({"code_snippet": ""})
    )

    assert result == {"matches": [], "truncated": False}


def test_message_token_counter_uses_tiktoken_content_length():
    agent = SecurityAgent.__new__(SecurityAgent)
    agent._token_encoding = _test_token_encoding()

    short_count = agent._count_message_tokens([HumanMessage(content="short")])
    long_count = agent._count_message_tokens([HumanMessage(content="word " * 500)])

    assert long_count > short_count + 400


def test_message_token_counter_accepts_tokenizer_special_token_text():
    agent = SecurityAgent.__new__(SecurityAgent)
    agent._token_encoding = _test_token_encoding()

    token_count = agent._count_message_tokens(
        [HumanMessage(content='String marker = "<|endoftext|>";')]
    )

    assert token_count > 0


def test_submitted_assessment_terminates_without_tool_execution():
    agent = SecurityAgent.__new__(SecurityAgent)
    agent._max_iterations = 15
    agent._max_tool_calls = 10
    agent._tool_call_count = 0
    message = AIMessage(
        content="",
        tool_calls=[
            {
                "name": "submit_assessment",
                "args": {
                    "vulnerable_status": "NOT_VULNERABLE",
                    "explanation": "Input is validated before reaching the sink.",
                    "remediation": "No remediation required.",
                    "code_fix": "",
                },
                "id": "assessment-1",
                "type": "tool_call",
            }
        ],
    )

    assessment = agent._find_submitted_assessment([message])

    assert assessment is not None
    assert assessment.vulnerable_status == "NOT_VULNERABLE"
    assert agent._should_continue(
        {"messages": [message], "iteration_count": 1}
    ) == END


def test_invalid_submitted_assessment_routes_to_forced_finalization():
    agent = SecurityAgent.__new__(SecurityAgent)
    agent._max_iterations = 15
    agent._max_tool_calls = 10
    agent._tool_call_count = 0
    message = AIMessage(
        content="",
        tool_calls=[
            {
                "name": "submit_assessment",
                "args": {"vulnerable_status": "VULNERABLE"},
                "id": "assessment-1",
                "type": "tool_call",
            }
        ],
    )

    assert agent._find_submitted_assessment([message]) is None
    assert agent._should_continue(
        {"messages": [message], "iteration_count": 1}
    ) == "finalize"


def test_forced_finalization_drops_unresolved_tool_call():
    class FinalModel:
        invoked_messages = None

        def invoke(self, messages):
            self.invoked_messages = messages
            return AIMessage(content="", tool_calls=[])

    agent = SecurityAgent.__new__(SecurityAgent)
    agent.system_prompt = "Review the finding."
    agent._max_iterations = 15
    agent._max_tool_calls = 10
    agent._token_encoding = _test_token_encoding()
    agent.final_model = FinalModel()
    completed_call_message = AIMessage(
        content="",
        tool_calls=[
            {
                "name": "code_search_tool",
                "args": {"filename": "Example.java", "method_name": "validate"},
                "id": "completed-call",
                "type": "tool_call",
            }
        ],
    )
    completed_tool_message = ToolMessage(
        content="method source",
        tool_call_id="completed-call",
    )
    unresolved_message = AIMessage(
        content="",
        tool_calls=[
            {
                "name": "grep_for_code",
                "args": {"code_snippet": "validate"},
                "id": "unresolved-call",
                "type": "tool_call",
            }
        ],
    )

    agent._finalize_node(
        {
            "messages": [
                HumanMessage(content="Analyze this trace."),
                completed_call_message,
                completed_tool_message,
                unresolved_message,
            ],
            "iteration_count": 2,
        }
    )

    invoked_messages = agent.final_model.invoked_messages
    assert invoked_messages is not None
    assert completed_call_message in invoked_messages
    assert completed_tool_message in invoked_messages
    assert unresolved_message not in invoked_messages
