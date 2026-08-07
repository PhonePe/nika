import logging
from typing import Optional, Tuple, Dict, Any

from config_provider import ConfigProvider

_DEFAULT_REQUEST_ANNOTATIONS = (
    "RequestParam",
    "PathVariable",
    "RequestHeader",
    "CookieValue",
    "RequestBody",
    "QueryParam",
    "PathParam",
    "HeaderParam",
    "FormParam",
)

_DEFAULT_REQUEST_ACCESSORS = (
    "getParameter",
    "getParameterValues",
    "getHeader",
    "getQueryString",
)


def get_configured_values(
    vulnerability_id: str,
    defaults: Tuple[str, ...],
    *config_keys: str,
) -> Tuple[str, ...]:
    values = list(defaults)
    try:
        args = ConfigProvider.get_config().vulnerability_args.get(vulnerability_id, {}) or {}
    except Exception:
        return tuple(values)

    for key in config_keys:
        configured = args.get(key)
        if isinstance(configured, str):
            configured = [configured]
        for value in configured or []:
            if value and value not in values:
                values.append(str(value))
    return tuple(values)


def get_request_annotations(vulnerability_id: str) -> Tuple[str, ...]:
    """Get configured request source annotations for a vulnerability."""
    return get_configured_values(
        vulnerability_id,
        _DEFAULT_REQUEST_ANNOTATIONS,
        "request_annotations",
        "requestAnnotations",
    )


def get_request_accessors(vulnerability_id: str) -> Tuple[str, ...]:
    """Get configured request accessor methods for a vulnerability."""
    return get_configured_values(
        vulnerability_id,
        _DEFAULT_REQUEST_ACCESSORS,
        "request_accessors",
        "requestAccessors",
    )


def get_sink_names(vulnerability_id: str, default_sinks: Tuple[str, ...]) -> Tuple[str, ...]:
    """Get configured sink method names for a vulnerability."""
    return get_configured_values(
        vulnerability_id,
        default_sinks,
        "sink_names",
        "sinkNames",
    )


def _flow_key(source_symbol: str, file_path: str, line_number: int) -> Tuple:
    """
    Create a flow key for matching engine flows to traces.
    
    Args:
        source_symbol: Source method full name
        file_path: File path
        line_number: Line number
    
    Returns:
        Tuple used as dict key: (source_symbol, file_path, int(line_number))
    """
    return (source_symbol, file_path, int(line_number or 0))


def _bool_from_engine(value: Any) -> Optional[bool]:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() == "true"
    return None


def engine_flow_metadata(vulnerability_id: str, entry: Optional[Dict]) -> Optional[Dict]:
    if not entry:
        return None

    request_controlled = _bool_from_engine(entry.get("requestControlled"))
    metadata = {
        "flow_confidence": entry.get("flowConfidence") or "cpg-data-flow",
    }

    if request_controlled is not None:
        metadata["request_controlled"] = request_controlled

    # Tainted variable information
    if entry.get("taintedVariable"):
        metadata["tainted_variable"] = entry.get("taintedVariable")
    if entry.get("taintedVariableKind"):
        metadata["tainted_variable_kind"] = entry.get("taintedVariableKind")

    # Source information
    if entry.get("sourceParam"):
        metadata["source_param"] = entry.get("sourceParam")
    if entry.get("sourceKind"):
        metadata["source_kind"] = entry.get("sourceKind")

    # Sink information
    if entry.get("sinkArgument"):
        metadata["sink_argument"] = entry.get("sinkArgument")
    if entry.get("sinkCode"):
        metadata["sink_code"] = entry.get("sinkCode")

    # Flow information
    if entry.get("flowSummary"):
        metadata["flow_summary"] = entry.get("flowSummary")

    return metadata


def merge_taint_metadata(primary: Dict, fallback: Optional[Dict]) -> Dict:
    if not fallback:
        return primary

    merged = dict(primary)
    
    # Fill in taint-specific fields from fallback
    for key in (
        "tainted_variable",
        "tainted_variable_kind",
        "source_param",
        "source_kind",
        "sink_argument",
        "flow_summary",
        "flow_confidence",
    ):
        if not merged.get(key) and fallback.get(key):
            merged[key] = fallback[key]

    if (
        fallback.get("request_controlled") is True
        and primary.get("request_controlled") is True
    ):
        merged.setdefault("fallback_flow_summary", fallback.get("flow_summary"))

    return merged


def build_dynamic_explanation(
    vulnerability_id: str,
    trace: Any,
    taint_metadata: Optional[Dict],
    base_explanation: str,
) -> str:
    if not taint_metadata:
        return base_explanation

    parts = [base_explanation + "\n"]

    # Add tainted variable information
    tainted_var = taint_metadata.get("tainted_variable")
    tainted_var_kind = taint_metadata.get("tainted_variable_kind", "")
    if tainted_var:
        parts.append(f"The tainted variable '{tainted_var}' ({tainted_var_kind}) flows into the sink.")

    # Add source information
    source_param = taint_metadata.get("source_param")
    source_kind = taint_metadata.get("source_kind")
    if source_param:
        kind_suffix = f" ({source_kind})" if source_kind else ""
        parts.append(f"Source: {source_param}{kind_suffix}")

    # Add flow information
    flow_summary = taint_metadata.get("flow_summary")
    if flow_summary:
        parts.append(f"Flow: {flow_summary}")

    # Add confidence information
    confidence = taint_metadata.get("flow_confidence")
    if confidence:
        confidence_desc = {
            "cpg-data-flow": "confirmed through code property graph data-flow analysis",
            "accessor-reachability": "confirmed through request accessor reachability",
            "direct": "direct from request source",
            "local-derived": "derived from request source through local assignments",
            "not_request_controlled": "not controlled by request (false positive eliminated)",
        }.get(confidence, confidence)
        parts.append(f"Confidence: {confidence_desc}")

    return "\n".join(parts)


def refine_traces_with_taint_flows(
    vulnerability_id: str,
    context: Any,
    state: Any,
    engine_flows: Optional[Dict],
) -> Any:
    traces = getattr(state, "traces", None) or []
    if not traces or not engine_flows:
        return state

    kept = []
    dropped = 0

    for trace in traces:
        flow_key_val = _flow_key(
            getattr(trace, "source_symbol", None),
            getattr(trace, "sink_file_path", None),
            getattr(trace, "sink_line_number", None),
        )

        entry = engine_flows.get(flow_key_val)
        
        logging.debug(
            "%s: trace %s -> %s:%s, request_controlled=%s, tainted_var=%s",
            vulnerability_id,
            flow_key_val[0],
            flow_key_val[1],
            flow_key_val[2],
            entry.get("requestControlled") if entry else None,
            entry.get("taintedVariable") if entry else None,
        )

        # Filter out false positives
        if entry is not None and entry.get("requestControlled") is False:
            dropped += 1
            logging.debug(
                "%s: dropping non-request-controlled trace at %s:%s",
                vulnerability_id,
                flow_key_val[1],
                flow_key_val[2],
            )
            continue

        # Enrich trace with taint metadata
        if entry is not None:
            sink = getattr(trace, "sink", None)
            if sink is not None:
                metadata = dict(getattr(sink, "metadata", None) or {})
                taint_meta = engine_flow_metadata(vulnerability_id, entry)
                if taint_meta:
                    metadata.update(taint_meta)
                trace = trace.model_copy(
                    update={"sink": sink.model_copy(update={"metadata": metadata})}
                )

        kept.append(trace)

    if dropped > 0:
        logging.info(
            "%s: dropped %d false positive traces based on taint flow analysis",
            vulnerability_id,
            dropped,
        )

    return state.model_copy(update={"traces": kept}) if hasattr(state, "model_copy") else state
