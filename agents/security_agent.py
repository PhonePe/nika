import json
import logging
import os
from dataclasses import dataclass
from typing import Annotated, Literal, Optional, Sequence, TypedDict

import httpx
import instructor
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
from openai import OpenAI

from config_provider import ConfigProvider
from schema.vulnerability_schema import LLMVulnerabilityOutput
from utils.common import execute_command
from utils.java_ast_parser import extract_method_from_file
from utils.token_tracker import TokenCallbackHandler, TokenTracker


@dataclass
class SecurityAgentRuntimeContext:
    code_path: str
    source_branch: Optional[str] = None
    target_branch: Optional[str] = None
    astrail: object | None = None


def _get_config():
    return ConfigProvider.get_config()


_SECURITY_AGENT_CHECKPOINTER = InMemorySaver()


class AgentState(TypedDict):
    messages: Annotated[Sequence[BaseMessage], add_messages]
    iteration_count: int


class SecurityAgent:
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
        self._structured_client = self._create_structured_client()

        self.tools = [
            self._build_code_search_tool(),
            self._build_astrail_search_method_name_tool(),
            self._build_grep_for_code_tool(),
        ]
        self.tool_node = ToolNode(self.tools)
        self.model = self._create_model()
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
        ).bind_tools(self.tools)

    def _create_structured_client(self):
        instructor_client = instructor.from_openai(
            OpenAI(
                base_url=self._llm_config.llm_url,
                api_key=self._llm_config.api_key,
                http_client=self._http_client,
                timeout=60,
            ),
            mode=instructor.Mode.TOOLS,
        )

        tracker = TokenTracker.get_instance()

        def _track_usage(response) -> None:
            usage = getattr(response, "usage", None)
            if usage is None:
                return

            tracker.add_usage(
                total_tokens=getattr(usage, "total_tokens", 0) or 0,
                prompt_tokens=getattr(usage, "prompt_tokens", 0) or 0,
                completion_tokens=getattr(usage, "completion_tokens", 0) or 0,
            )

        instructor_client.on("completion:response", _track_usage)
        return instructor_client

    def _build_graph(self):
        workflow = StateGraph(AgentState)
        workflow.add_node("agent", self._agent_node)
        workflow.add_node("tools", self._tools_node)
        workflow.add_edge(START, "agent")
        workflow.add_conditional_edges("agent", self._should_continue)
        workflow.add_edge("tools", "agent")
        return workflow.compile(checkpointer=_SECURITY_AGENT_CHECKPOINTER)

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
            Returns the method source code from the codebase given the filename and method name.
            Use this when you need to inspect a function's implementation.
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
                return resolver(code, filename)

            legacy_resolver = getattr(astrail, "getMethodAndFileName", None)
            if callable(legacy_resolver):
                return legacy_resolver(code, filename)

            return (
                '{"fileName": "", "methodName": "", '
                '"error": "astrail method lookup unsupported"}'
            )

        return astrail_search_method_name

    def _build_grep_for_code_tool(self):
        @tool
        def grep_for_code(code_snippet: str) -> str:
            """
            Searches the codebase for the given code snippet (class name, method name, import statement, etc.).
            Returns matching file names and line numbers ONLY if the code snippet exists in the codebase.
            If no matches are found, returns empty result - this means the code/dependency is NOT used in the project.
            RESTRICTION: This tool must ONLY be used when analyzing "Vulnerable and Outdated Dependencies" or "Cryptographic Failures" to check if vulnerable code is actually used.
            
            TIPS:
            1. Prefer searching for the package name (e.g. 'com.example.lib') to find all usages at once, rather than searching for individual classes or methods one by one.
            2. If you find imports, the library is used. You can then search for specific vulnerable methods if needed.
            """
            logging.info("grep_for_code called with snippet: %s", code_snippet)
            cmd = ["grep", "-rnF", "--", code_snippet, self.runtime_context.code_path]
            result = execute_command(cmd, check=False)
            return result.stdout if result.ok else (result.stderr or "")

        return grep_for_code

    def _agent_node(self, state: AgentState) -> dict:
        messages = state["messages"]
        iteration = state.get("iteration_count", 0)

        if self._max_iterations and self._max_iterations > 0 and iteration >= self._max_iterations:
            return {
                "messages": [
                    AIMessage(
                        content=(
                            "Iteration limit reached. Returning final assessment "
                            "with gathered context."
                        )
                    )
                ],
                "iteration_count": iteration + 1,
            }

        trimmed_messages = trim_messages(
            messages,
            max_tokens=8000,
            strategy="last",
            token_counter=len,
            start_on="human",
            end_on=("human", "tool"),
            include_system=False,
            allow_partial=False,
        )

        first_human = next(
            (message for message in messages if isinstance(message, HumanMessage)),
            None,
        )
        if first_human and first_human not in trimmed_messages:
            trimmed_messages = [first_human] + list(trimmed_messages)

        tool_limit_reached = (
            self._max_tool_calls
            and self._max_tool_calls > 0
            and self._tool_call_count >= self._max_tool_calls
        )
        if tool_limit_reached:
            no_tools_model = ChatOpenAI(
                model=self._llm_config.model,
                timeout=60,
                base_url=self._llm_config.llm_url,
                api_key=self._llm_config.api_key,
                http_client=self._http_client,
                callbacks=[TokenCallbackHandler()],
            )
            conclude_msg = SystemMessage(
                content=(
                    self._full_system_prompt
                    + "\n\nTool call limit reached. Do not request tools. "
                    "Provide final assessment from available context."
                )
            )
            response = no_tools_model.invoke([conclude_msg] + list(trimmed_messages))
        else:
            response = self.model.invoke(
                [SystemMessage(content=self._full_system_prompt)]
                + list(trimmed_messages)
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

    def _should_continue(self, state: AgentState) -> Literal["tools", "__end__"]:
        messages = state["messages"]
        iteration = state.get("iteration_count", 0)

        if self._max_iterations and self._max_iterations > 0 and iteration >= self._max_iterations:
            return END

        if self._max_tool_calls and self._max_tool_calls > 0 and self._tool_call_count >= self._max_tool_calls:
            return END

        last_message = messages[-1]
        if not isinstance(last_message, AIMessage) or not last_message.tool_calls:
            return END
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
            return self._get_structured_output(result["messages"])
        except Exception as exc:
            logging.error("SecurityAgent failed: %s", exc)
            return LLMVulnerabilityOutput(
                vulnerable_status="NEED_MANUAL_REVIEW",
                explanation=f"Analysis failed due to error: {exc}",
                remediation="Manual review required due to analysis error.",
                code_fix="",
            )

    def _get_structured_output(self, messages: Sequence[BaseMessage]) -> LLMVulnerabilityOutput:
        trimmed_messages = trim_messages(
            messages,
            max_tokens=8000,
            strategy="last",
            token_counter=len,
            start_on="human",
            end_on=("human", "tool"),
            include_system=False,
            allow_partial=False,
        )

        extraction_instructions = (
            "Extract FINAL vulnerability assessment from conversation history. "
            "Use tool outputs and final reasoning. If uncertain, return NEED_MANUAL_REVIEW."
        )
        conversation_history = self._format_extraction_history(trimmed_messages)
        final_prompt = [
            {
                "role": "system",
                "content": self._full_system_prompt + "\n\n" + extraction_instructions,
            },
            {
                "role": "user",
                "content": (
                    "Conversation history for final assessment:\n\n"
                    f"{conversation_history}\n\n"
                    "Return only the final structured vulnerability assessment."
                ),
            },
        ]

        try:
            return self._structured_client.chat.completions.create(
                model=self._llm_config.model,
                messages=final_prompt,
                response_model=LLMVulnerabilityOutput,
                max_retries=3,
            )
        except Exception as exc:
            return LLMVulnerabilityOutput(
                vulnerable_status="NEED_MANUAL_REVIEW",
                explanation=f"Failed to generate structured output: {exc}",
                remediation="Manual review required.",
                code_fix="",
            )

    @staticmethod
    def _format_extraction_history(messages: Sequence[BaseMessage]) -> str:
        formatted_messages: list[str] = []

        for message in messages:
            if isinstance(message, SystemMessage):
                role = "System"
            elif isinstance(message, HumanMessage):
                role = "User"
            elif isinstance(message, ToolMessage):
                role = "Tool"
            elif isinstance(message, AIMessage):
                role = "Assistant"
            else:
                role = "Message"

            content = SecurityAgent._stringify_message_content(message.content)
            if isinstance(message, AIMessage) and message.tool_calls:
                tool_call_summaries = [
                    f"{tool_call.get('name', 'tool')}({json.dumps(tool_call.get('args', {}), ensure_ascii=True)})"
                    for tool_call in message.tool_calls
                ]
                content = (
                    f"{content}\nTool Calls: {'; '.join(tool_call_summaries)}"
                    if content
                    else f"Tool Calls: {'; '.join(tool_call_summaries)}"
                )

            formatted_messages.append(f"{role}: {content}" if content else f"{role}:")

        return "\n\n".join(formatted_messages)

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
