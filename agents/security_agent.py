import json
import logging
import os
from dataclasses import dataclass
from typing import Annotated, Literal, Optional, Sequence, TypedDict

import httpx
import tiktoken
from langchain.tools import tool
from langchain_core.messages import (
    AIMessage,
    BaseMessage,
    HumanMessage,
    SystemMessage,
    ToolMessage,
    trim_messages,
)
from langchain_openai import ChatOpenAI
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode

from config_provider import ConfigProvider
from schema.vulnerability_schema import LLMVulnerabilityOutput
from utils.java_ast_parser import extract_method_from_file
from utils.token_tracker import TokenCallbackHandler


@dataclass
class SecurityAgentRuntimeContext:
    code_path: str
    source_branch: Optional[str] = None
    target_branch: Optional[str] = None
    astrail: object | None = None


def _get_config():
    return ConfigProvider.get_config()


class AgentState(TypedDict):
    messages: Annotated[Sequence[BaseMessage], add_messages]
    iteration_count: int


class SecurityAgent:
    _ASSESSMENT_TOOL_NAME = "submit_assessment"
    _GREP_MAX_MATCHES = 20
    _GREP_MAX_LINE_CHARS = 300
    _GREP_SOURCE_EXTENSIONS = (".java", ".kt", ".kts")
    _GREP_EXCLUDED_DIRS = {
        ".git",
        ".gradle",
        ".hg",
        ".idea",
        ".svn",
        ".venv",
        "build",
        "dist",
        "node_modules",
        "out",
        "target",
        "venv",
    }

    def __init__(
        self,
        runtime_context: SecurityAgentRuntimeContext,
        system_prompt: str,
        thread_id: Optional[str] = None,
    ):
        self.runtime_context = runtime_context
        self.system_prompt = system_prompt
        self.thread_id = thread_id or f"thread_{id(self)}"
        self._tool_call_count = 0
        self._code_cache: dict[str, str] = {}

        config = _get_config()
        self._llm_config = config.llm_config
        self._max_tool_calls = config.llm_config.max_tool_calls
        self._max_iterations = config.llm_config.max_iterations
        self._http_client = httpx.Client(verify=self._llm_config.verify_tls)
        self._token_encoding = self._create_token_encoding()

        self._search_tools = [
            self._build_code_search_tool(),
            self._build_astrail_search_method_name_tool(),
            self._build_grep_for_code_tool(),
        ]
        self._assessment_tool = self._build_submit_assessment_tool()
        self.tools = [*self._search_tools, self._assessment_tool]
        self.tool_node = ToolNode(self._search_tools)
        base_model = self._create_model()
        self.model = base_model.bind_tools(self.tools)
        self.final_model = base_model.bind_tools(
            [self._assessment_tool],
            tool_choice=self._ASSESSMENT_TOOL_NAME,
        )
        self.graph = self._build_graph()

    def close(self):
        """Release underlying HTTP resources."""
        self._http_client.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def _create_model(self) -> ChatOpenAI:
        return ChatOpenAI(
            model=self._llm_config.model,
            timeout=60,
            base_url=self._llm_config.llm_url,
            api_key=self._llm_config.api_key,
            http_client=self._http_client,
            callbacks=[TokenCallbackHandler()],
        )

    def _create_token_encoding(self):
        model_name = self._llm_config.model.lower().replace("_", "-")
        return self._get_token_encoding(model_name)

    @staticmethod
    def _get_token_encoding(model_name: str):
        try:
            return tiktoken.encoding_for_model(model_name)
        except KeyError:
            return tiktoken.get_encoding("o200k_base")

    def _build_graph(self):
        workflow = StateGraph(AgentState)
        workflow.add_node("agent", self._agent_node)
        workflow.add_node("tools", self._tools_node)
        workflow.add_node("finalize", self._finalize_node)
        workflow.add_edge(START, "agent")
        workflow.add_conditional_edges("agent", self._should_continue)
        workflow.add_edge("tools", "agent")
        workflow.add_edge("finalize", END)
        return workflow.compile(checkpointer=InMemorySaver())

    def _count_message_tokens(self, messages: Sequence[BaseMessage]) -> int:
        token_count = 3
        for message in messages:
            token_count += 4
            token_count += len(self._token_encoding.encode_ordinary(message.type))
            token_count += len(
                self._token_encoding.encode_ordinary(
                    self._stringify_message_content(message.content)
                )
            )

            if isinstance(message, AIMessage) and message.tool_calls:
                serialized_calls = json.dumps(
                    message.tool_calls,
                    ensure_ascii=True,
                    separators=(",", ":"),
                )
                token_count += len(
                    self._token_encoding.encode_ordinary(serialized_calls)
                )
            if isinstance(message, ToolMessage):
                token_count += len(
                    self._token_encoding.encode_ordinary(message.tool_call_id or "")
                )

        return token_count

    def _trim_history(
        self,
        messages: Sequence[BaseMessage],
    ) -> list[BaseMessage]:
        trimmed_messages = trim_messages(
            messages,
            max_tokens=8000,
            strategy="last",
            token_counter=self._count_message_tokens,
            start_on="human",
            end_on=("human", "tool", "ai"),
            include_system=False,
            allow_partial=False,
        )

        first_human = next(
            (message for message in messages if isinstance(message, HumanMessage)),
            None,
        )
        if first_human and first_human not in trimmed_messages:
            return [first_human] + list(trimmed_messages)
        return list(trimmed_messages)

    def _normalize_path(self, filename: str) -> str:
        if os.path.isabs(filename):
            resolved = os.path.realpath(filename)
        else:
            resolved = os.path.realpath(
                os.path.join(self.runtime_context.code_path, filename)
            )
        project_root = os.path.realpath(self.runtime_context.code_path)
        if not resolved.startswith(project_root + os.sep) and resolved != project_root:
            return None
        return resolved

    def _build_code_search_tool(self):
        @tool
        def code_search_tool(filename: str, method_name: str) -> str:
            """
            Returns Java method, constructor, or field source code from the codebase.
            Use this when you need to inspect an implementation or DTO validation annotations.
            Pass the exact symbol name: method name, constructor/class name, or field name
            such as "username". Do not pass "class", "<init>", or "*" when you can name
            the exact method, constructor, or field.
            """
            logging.info("code_search_tool called with filename: %s, method_name: %s", filename, method_name)
            normalized_path = self._normalize_path(filename)
            if normalized_path is None:
                return json.dumps({"error": "Access denied: path outside project"})

            cache_key = f"{normalized_path}::{method_name}"

            if cache_key in self._code_cache:
                logging.info("[CACHE HIT] %s::%s", filename, method_name)
                return self._code_cache[cache_key]

            method_source = extract_method_from_file(
                normalized_path,
                method_name,
                self.runtime_context.code_path,
            )
            result = json.dumps(
                {
                    "filename": filename,
                    "methodName": method_name,
                    "sourceCode": method_source,
                },
                indent=2,
            )
            self._code_cache[cache_key] = result
            return result

        return code_search_tool

    def _build_astrail_search_method_name_tool(self):
        @tool
        def astrail_search_method_name(code: str, filename: str) -> str:
            """
            Returns the method name and filename given a method call snippet.
            Use this to find where a function is defined when you see it being called.
            """
            logging.info("astrail_search_method_name called with code: %s, filename: %s", code, filename)
            astrail = self.runtime_context.astrail
            if astrail is None:
                return '{"fileName": "", "methodName": "", "error": "astrail unavailable"}'

            resolver = getattr(astrail, "get_method_and_file_name", None)
            if callable(resolver):
                try:
                    return resolver(code, filename)
                except Exception as exc:
                    logging.warning(
                        "astrail_search_method_name failed for filename=%s code=%s: %s",
                        filename,
                        code,
                        exc,
                    )
                    return json.dumps(
                        {
                            "fileName": "",
                            "methodName": "",
                            "error": "astrail_lookup_failed",
                            "detail": str(exc),
                        }
                    )

            legacy_resolver = getattr(astrail, "getMethodAndFileName", None)
            if callable(legacy_resolver):
                try:
                    return legacy_resolver(code, filename)
                except Exception as exc:
                    logging.warning(
                        "astrail_search_method_name failed for filename=%s code=%s: %s",
                        filename,
                        code,
                        exc,
                    )
                    return json.dumps(
                        {
                            "fileName": "",
                            "methodName": "",
                            "error": "astrail_lookup_failed",
                            "detail": str(exc),
                        }
                    )

            return (
                '{"fileName": "", "methodName": "", '
                '"error": "astrail method lookup unsupported"}'
            )

        return astrail_search_method_name

    def _build_grep_for_code_tool(self):
        @tool
        def grep_for_code(code_snippet: str) -> str:
            """
            Searches the codebase for an exact code snippet, class name, method name,
            field name, annotation, import statement, or validator call.
            Use this to locate a symbol when you do not know the exact file or method.
            Returns at most 20 compact source matches. If truncated is true, refine
            the query instead of repeating the same broad search.

            TIPS:
            1. Prefer code_search_tool once you know the filename and exact symbol.
            2. For DTO validation, search for the field name or annotation, then fetch
               the exact field with code_search_tool.
            """
            logging.info("grep_for_code called with snippet: %s", code_snippet)
            if not code_snippet:
                return json.dumps(
                    {"matches": [], "truncated": False},
                    separators=(",", ":"),
                )

            matches: list[dict[str, object]] = []
            project_root = os.path.realpath(self.runtime_context.code_path)

            for root, directories, filenames in os.walk(project_root):
                directories[:] = sorted(
                    directory
                    for directory in directories
                    if directory not in self._GREP_EXCLUDED_DIRS
                )
                for filename in sorted(filenames):
                    if not filename.lower().endswith(self._GREP_SOURCE_EXTENSIONS):
                        continue

                    path = os.path.join(root, filename)
                    try:
                        with open(
                            path,
                            "r",
                            encoding="utf-8",
                            errors="replace",
                        ) as source_file:
                            for line_number, line in enumerate(source_file, start=1):
                                if code_snippet not in line:
                                    continue
                                text = line.strip()
                                if len(text) > self._GREP_MAX_LINE_CHARS:
                                    text = text[: self._GREP_MAX_LINE_CHARS] + "..."
                                matches.append(
                                    {
                                        "file": os.path.relpath(path, project_root),
                                        "line": line_number,
                                        "text": text,
                                    }
                                )
                                if len(matches) > self._GREP_MAX_MATCHES:
                                    break
                    except OSError as exc:
                        logging.debug("Skipping unreadable source file %s: %s", path, exc)

                    if len(matches) > self._GREP_MAX_MATCHES:
                        break
                if len(matches) > self._GREP_MAX_MATCHES:
                    break

            truncated = len(matches) > self._GREP_MAX_MATCHES
            return json.dumps(
                {
                    "matches": matches[: self._GREP_MAX_MATCHES],
                    "truncated": truncated,
                },
                ensure_ascii=True,
                separators=(",", ":"),
            )

        return grep_for_code

    def _build_submit_assessment_tool(self):
        @tool(args_schema=LLMVulnerabilityOutput)
        def submit_assessment(
            vulnerable_status: str,
            explanation: str,
            remediation: str,
        ) -> str:
            """
            Submits the final vulnerability assessment and ends the analysis.
            Call this exactly once after reaching a conclusion. Do not combine it
            with search tools in the same response.
            """
            assessment = LLMVulnerabilityOutput(
                vulnerable_status=vulnerable_status,
                explanation=explanation,
                remediation=remediation,
            )
            return assessment.model_dump_json()

        return submit_assessment

    def _agent_node(self, state: AgentState) -> dict:
        messages = state["messages"]
        iteration = state.get("iteration_count", 0)
        trimmed_messages = self._trim_history(messages)

        tool_limit_reached = (
            self._max_tool_calls
            and self._max_tool_calls > 0
            and self._tool_call_count >= self._max_tool_calls
        )
        if tool_limit_reached:
            conclude_msg = SystemMessage(
                content=(
                    self._full_system_prompt
                    + "\n\nTool call limit reached. Submit the final assessment "
                    "from available context now."
                )
            )
            response = self.final_model.invoke(
                [conclude_msg] + list(trimmed_messages)
            )
        else:
            response = self.model.invoke(
                [SystemMessage(content=self._full_system_prompt)]
                + list(trimmed_messages)
            )

        return {
            "messages": [response],
            "iteration_count": iteration + 1,
        }

    def _finalize_node(self, state: AgentState) -> dict:
        messages = state["messages"]
        iteration = state.get("iteration_count", 0)
        conclude_msg = SystemMessage(
            content=(
                self._full_system_prompt
                + "\n\nSubmit the final assessment from the available context now. "
                "Do not request additional tools."
            )
        )
        finalization_history = messages
        if (
            messages
            and isinstance(messages[-1], AIMessage)
            and messages[-1].tool_calls
        ):
            finalization_history = messages[:-1]
        response = self.final_model.invoke(
            [conclude_msg] + self._trim_history(finalization_history)
        )
        return {
            "messages": [response],
            "iteration_count": iteration + 1,
        }

    def _tools_node(self, state: AgentState) -> dict:
        messages = state["messages"]
        last_message = messages[-1]
        if not isinstance(last_message, AIMessage) or not last_message.tool_calls:
            return {"messages": []}

        tool_calls = last_message.tool_calls
        num_calls = len(tool_calls)

        if self._max_tool_calls and self._max_tool_calls > 0 and self._tool_call_count >= self._max_tool_calls:
            denied = [
                ToolMessage(
                    content=(
                        "TOOL LIMIT REACHED. Do not request additional tools. "
                        "Provide final analysis now."
                    ),
                    tool_call_id=tool_call["id"],
                )
                for tool_call in tool_calls
            ]
            return {"messages": denied}

        remaining = (
            self._max_tool_calls - self._tool_call_count
            if (self._max_tool_calls and self._max_tool_calls > 0)
            else num_calls
        )
        if num_calls > remaining:
            allowed_calls = tool_calls[:remaining]
            denied_calls = tool_calls[remaining:]

            modified_last = AIMessage(content=last_message.content, tool_calls=allowed_calls)
            modified_state = {"messages": list(messages[:-1]) + [modified_last]}
            self._tool_call_count += len(allowed_calls)
            result = self.tool_node.invoke(modified_state)

            denied_messages = [
                ToolMessage(
                    content=(
                        "TOOL LIMIT REACHED. This tool call was not executed. "
                        "Finalize with existing context."
                    ),
                    tool_call_id=tool_call["id"],
                )
                for tool_call in denied_calls
            ]

            result_messages = result.get("messages", []) if isinstance(result, dict) else result
            if isinstance(result_messages, dict):
                result_messages = result_messages.get("messages", [])
            return {"messages": list(result_messages) + denied_messages}

        self._tool_call_count += num_calls
        return self.tool_node.invoke(state)

    def _should_continue(
        self,
        state: AgentState,
    ) -> Literal["tools", "finalize", "__end__"]:
        messages = state["messages"]
        iteration = state.get("iteration_count", 0)

        last_message = messages[-1]
        if self._find_submitted_assessment([last_message]) is not None:
            return END

        if self._max_iterations and self._max_iterations > 0 and iteration >= self._max_iterations:
            return "finalize"

        if self._max_tool_calls and self._max_tool_calls > 0 and self._tool_call_count >= self._max_tool_calls:
            return "finalize"

        if not isinstance(last_message, AIMessage) or not last_message.tool_calls:
            return "finalize"
        if any(
            tool_call.get("name") == self._ASSESSMENT_TOOL_NAME
            for tool_call in last_message.tool_calls
        ):
            return "finalize"
        return "tools"

    def run(self, query: str) -> LLMVulnerabilityOutput:
        self._tool_call_count = 0
        self._code_cache = {}

        inputs = {
            "messages": [HumanMessage(content=query)],
            "iteration_count": 0,
        }
        config = {
            "recursion_limit": self._llm_config.recursion_limit,
            "configurable": {"thread_id": self.thread_id},
        }

        try:
            result = self.graph.invoke(inputs, config=config)
            assessment = self._find_submitted_assessment(result["messages"])
            if assessment is not None:
                return assessment
            return LLMVulnerabilityOutput(
                vulnerable_status="NEED_MANUAL_REVIEW",
                explanation=(
                    "Agent ended without submitting a valid structured assessment."
                ),
                remediation="Manual review required.",
            )
        except Exception as exc:
            logging.error("SecurityAgent failed: %s", exc)
            return LLMVulnerabilityOutput(
                vulnerable_status="NEED_MANUAL_REVIEW",
                explanation=f"Analysis failed due to error: {exc}",
                remediation="Manual review required due to analysis error.",
            )

    def _find_submitted_assessment(
        self,
        messages: Sequence[BaseMessage],
    ) -> Optional[LLMVulnerabilityOutput]:
        for message in reversed(messages):
            if not isinstance(message, AIMessage):
                continue
            for tool_call in message.tool_calls:
                if tool_call.get("name") != self._ASSESSMENT_TOOL_NAME:
                    continue
                args = tool_call.get("args", {})
                if isinstance(args, str):
                    try:
                        args = json.loads(args)
                    except json.JSONDecodeError:
                        logging.warning("submit_assessment returned invalid JSON")
                        continue
                try:
                    return LLMVulnerabilityOutput.model_validate(args)
                except Exception as exc:
                    logging.warning(
                        "submit_assessment returned an invalid payload: %s",
                        exc,
                    )
        return None

    @staticmethod
    def _stringify_message_content(content) -> str:
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            normalized_parts: list[str] = []
            for item in content:
                if isinstance(item, str):
                    normalized_parts.append(item)
                elif isinstance(item, dict):
                    normalized_parts.append(json.dumps(item, ensure_ascii=True))
                else:
                    normalized_parts.append(str(item))
            return "\n".join(part for part in normalized_parts if part)
        if content is None:
            return ""
        return str(content)

    @property
    def _full_system_prompt(self) -> str:
        return "\n\n".join(
            [
                self.system_prompt,
                self._core_protocols_prompt(),
                self._tool_usage_prompt(),
            ]
        )

    def _tool_usage_prompt(self) -> str:
        limit_desc = ""
        if self._max_tool_calls and self._max_tool_calls > 0:
            limit_desc += f"- Maximum {self._max_tool_calls} tool calls per analysis\n"
        if self._max_iterations and self._max_iterations > 0:
            limit_desc += f"- Maximum {self._max_iterations} reasoning iterations\n"

        return f"""## AVAILABLE TOOLS

1. code_search_tool(filename, method_name)
2. astrail_search_method_name(code, filename)
3. grep_for_code(code_snippet)
4. submit_assessment(vulnerable_status, explanation, remediation)

## TOOL CALL GUIDANCE
- code_search_tool accepts an exact Java method, constructor, or field name.
- For DTO/request validation, fetch the exact field, e.g. method_name="username".
- For overloaded constructors/methods, include a signature if known, e.g. "User(String,String)".
- Avoid method_name="class", "<init>", or "*" unless broad file context is the only way to proceed.
- When analysis is complete, call submit_assessment exactly once instead of returning
    a plain-text answer. Never combine submit_assessment with a search tool call.

## TOOL USAGE LIMITS
{limit_desc}- Use tools only when needed to resolve uncertainty.
"""

    def _core_protocols_prompt(self) -> str:
        return """## CORE AUDIT PROTOCOLS

1. No assumptions from names alone.
2. Verify sanitization/validation by reading implementation.
3. Trace user input to sink.
4. If uncertain, return NEED_MANUAL_REVIEW.
"""
