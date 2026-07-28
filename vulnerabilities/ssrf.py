import logging

from vulnerabilities.base.base_vulnerability import BaseVulnerability
from vulnerabilities.base.stages import (
    _single_matching_sink_for_trace,
    discover_sources,
    finalize_findings,
    match_rule_sinks,
    review_traces_with_llm,
    run_dataflow,
)
from config_provider import ConfigProvider

_DEFAULT_SSRF_SINK_NAMES = (
    "url",
    "uri",
    "baseUrl",
    "uriString",
    "target",
    "path",
    "replacePath",
    "to",
    "create",
    "newBuilder",
    "newCall",
    "parse",
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "method",
    "exchange",
    "getForObject",
    "getForEntity",
    "postForObject",
    "postForEntity",
    "postForLocation",
    "send",
    "sendAsync",
    "execute",
    "executeMethod",
    "enqueue",
    "invoke",
    "retrieve",
    "openConnection",
    "openStream",
    "getContent",
    "connect",
    "getInputStream",
    "getResponseCode",
    "getResponseMessage",
    "getHeaderField",
    "asString",
    "asJson",
    "asBinary",
    "asObject",
    "subscribe",
    "block",
    "blockOptional",
    "blockFirst",
    "blockLast",
    "blockingFirst",
    "blockingLast",
    "blockingGet",
    "blockingAwait",
    "blockingSubscribe",
    "join",
    "request",
    "head",
    "options",
    "trace",
)

_DEFAULT_RECEIVER_ONLY_SINKS = (
    "openConnection",
    "openStream",
    "getContent",
    "connect",
    "getInputStream",
    "getResponseCode",
    "getResponseMessage",
    "getHeaderField",
    "enqueue",
    "asString",
    "asJson",
    "asBinary",
    "asObject",
    "subscribe",
    "block",
    "blockOptional",
    "blockFirst",
    "blockLast",
    "blockingFirst",
    "blockingLast",
    "blockingGet",
    "blockingAwait",
    "blockingSubscribe",
    "join",
    "request",
    "invoke",
)


def _ssrf_args() -> dict:
    try:
        return ConfigProvider.get_config().vulnerability_args.get("ssrf", {}) or {}
    except Exception:
        return {}


def _configured_values(defaults, *keys) -> tuple[str, ...]:
    values = list(defaults)
    args = _ssrf_args()
    for key in keys:
        configured = args.get(key)
        if isinstance(configured, str):
            configured = [configured]
        for value in configured or []:
            if value and value not in values:
                values.append(str(value))
    return tuple(values)


def _sink_names() -> tuple[str, ...]:
    return _configured_values(_DEFAULT_SSRF_SINK_NAMES, "sink_names", "sinkNames")


def _receiver_only_sinks() -> tuple[str, ...]:
    return _configured_values(
        _DEFAULT_RECEIVER_ONLY_SINKS, "receiver_only_sinks", "receiverOnlySinks"
    )


def _flow_key(source_symbol, file_path, line_number):
    return (source_symbol, file_path, int(line_number or 0))


def _bool_from_engine(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() == "true"
    return None


def _flow_metadata(entry):
    request_controlled = _bool_from_engine(entry.get("requestControlled"))
    metadata = {
        "sink_kind": "ssrf",
        "flow_confidence": entry.get("flowConfidence") or "cpg-destination-flow",
    }
    if request_controlled is not None:
        metadata["request_controlled"] = request_controlled
    if entry.get("sourceParam"):
        metadata["source_param"] = entry.get("sourceParam")
    if entry.get("sourceKind"):
        metadata["source_kind"] = entry.get("sourceKind")
    if entry.get("sinkArgument"):
        metadata["sink_argument"] = entry.get("sinkArgument")
    if entry.get("flowSummary"):
        metadata["flow_summary"] = entry.get("flowSummary")
    elif entry.get("sinkArgument"):
        metadata["flow_summary"] = (
            "Astrail confirmed request input reaches SSRF destination argument "
            f"{entry.get('sinkArgument')}."
        )
    if entry.get("validationEvidence"):
        metadata["validation_evidence"] = entry.get("validationEvidence")
    if entry.get("sinkCode"):
        metadata["sink_code"] = entry.get("sinkCode")
    return metadata


def refine_ssrf_flows(vulnerability, context, state):
    traces = getattr(state, "traces", None) or []
    if not traces:
        return state

    engine = context.engines.get("dataflow_analyzer") if hasattr(context, "engines") else None
    flow_resolver = getattr(engine, "find_ssrf_flows", None)
    if not callable(flow_resolver):
        return state

    try:
        engine_flows = flow_resolver(
            context,
            traces,
            sink_names=_sink_names(),
            receiver_only_sinks=_receiver_only_sinks(),
        )
    except Exception:
        logging.warning(
            "SSRF: destination flow refinement failed; keeping all traces",
            exc_info=True,
        )
        return state

    if not engine_flows:
        return state

    kept = []
    dropped = 0
    for trace in traces:
        entry = engine_flows.get(
            _flow_key(
                getattr(trace, "source_symbol", None),
                getattr(trace, "sink_file_path", None),
                getattr(trace, "sink_line_number", None),
            )
        )
        logging.debug(
            "SSRF: trace %s:%s:%s -> %s:%s, request_controlled=%s",
            getattr(trace, "source_symbol", None),
            getattr(trace, "sink_file_path", None),
            getattr(trace, "sink_line_number", None),
            getattr(trace, "sink", None),
            getattr(trace.sink, "metadata", None) if getattr(trace, "sink", None) else None,
            entry.get("requestControlled") if entry is not None else None,
        )
        if (
            entry is not None
            and _bool_from_engine(entry.get("requestControlled")) is False
        ):
            dropped += 1
            continue

        if entry is not None:
            sink = getattr(trace, "sink", None) or _single_matching_sink_for_trace(
                getattr(state, "sinks", None),
                trace,
            )
            if sink is not None:
                metadata = dict(getattr(sink, "metadata", None) or {})
                metadata.update(_flow_metadata(entry))
                trace = trace.model_copy(
                    update={"sink": sink.model_copy(update={"metadata": metadata})}
                )
        kept.append(trace)

    if dropped:
        logging.info(
            "SSRF: dropped %d trace(s) whose request destination is not attacker-controlled",
            dropped,
        )
    state.traces = kept
    return state


class SsrfVulnerability(BaseVulnerability):
    vulnerability_id = "ssrf"
    title = "Server-Side Request Forgery"
    description = (
        "Server-Side Request Forgery (SSRF) vulnerability allows attackers to "
        "make requests from the server on behalf of the attacker."
    )
    supported_languages = ["java"]
    required_engine_roles = ["sink_finder", "source_finder", "dataflow_analyzer"]
    source_types = ["remote_input"]
    prompt_kind = "trace"
    stages = [
        match_rule_sinks,
        discover_sources,
        run_dataflow,
        refine_ssrf_flows,
        review_traces_with_llm,
        finalize_findings,
    ]
    optional_stages = [review_traces_with_llm]
    review_mode = "optional"
    system_prompt = (
        "Review this trace for SSRF risk. Treat outbound requests influenced by "
        "user input as vulnerable unless the destination is fixed or strongly "
        "allowlisted. If validation might be bypassed or the controls are unclear, "
        "return NEED_MANUAL_REVIEW. When sink evidence says Request controlled: "
        "True, Astrail has already confirmed a CPG flow from remote input into the "
        "request destination; do not spend tools re-proving that flow. Focus tool "
        "lookups on fixed destinations, allowlisting, and validation instead."
    )
    human_prompt = (
        "Analyze this SSRF trace and decide whether attacker-controlled input can "
        "influence the request URL, host, path, or destination without effective "
        "restrictions."
    )
    fallback_explanation = (
        "Trace reached an outbound request sink. Confirm whether untrusted input can "
        "control the destination or internal network access."
    )
    fallback_remediation = (
        "Use fixed destinations or strict allowlists for hosts, schemes, and ports "
        "before making outbound requests."
    )
    fallback_code_fix = (
        "Do not build request destinations directly from user input; map input to "
        "approved endpoints instead."
    )
