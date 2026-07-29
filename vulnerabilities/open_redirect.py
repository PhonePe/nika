import logging
import os
import re

from config_provider import ConfigProvider
from utils.java_ast_parser import extract_method_from_file
from vulnerabilities.base.base_vulnerability import BaseVulnerability
from vulnerabilities.base.stages import (
    discover_sources,
    finalize_findings,
    match_rule_sinks,
    review_traces_with_llm,
    run_dataflow,
)

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

_DEFAULT_VALIDATION_TERMS = (
    "allow",
    "white",
    "safeRedirect",
    "isSafe",
    "startsWith",
    "UrlUtils",
    "getHost",
    "isAbsolute",
    "URI",
    "URL",
)

_BODY_UNAVAILABLE_PREFIXES = (
    "File not found",
    "Method or Variable",
    "Access denied",
    "Error extracting",
)


def _open_redirect_args() -> dict:
    try:
        return ConfigProvider.get_config().vulnerability_args.get("open_redirect", {}) or {}
    except Exception:
        return {}


def _configured_values(defaults: tuple[str, ...], *keys: str) -> tuple[str, ...]:
    values = list(defaults)
    args = _open_redirect_args()
    for key in keys:
        configured = args.get(key)
        if isinstance(configured, str):
            configured = [configured]
        for value in configured or []:
            if value and value not in values:
                values.append(str(value))
    return tuple(values)


def _request_annotations() -> tuple[str, ...]:
    return _configured_values(
        _DEFAULT_REQUEST_ANNOTATIONS,
        "request_annotations",
        "requestAnnotations",
    )


def _request_accessors() -> tuple[str, ...]:
    return _configured_values(
        _DEFAULT_REQUEST_ACCESSORS,
        "request_accessors",
        "requestAccessors",
    )


def _validation_terms() -> tuple[str, ...]:
    return _configured_values(
        _DEFAULT_VALIDATION_TERMS,
        "validation_terms",
        "validationTerms",
    )


def _normalize_path(path):
    return os.path.normpath(path or "").replace("\\", "/")


def _simple_method_name(symbol: str | None) -> str:
    if not symbol:
        return ""
    head = symbol.split(":", 1)[0]
    return head.rsplit(".", 1)[-1]


def _method_body(context, source) -> str:
    method_name = _simple_method_name(getattr(source, "symbol", None))
    if not method_name or not getattr(source, "file_path", None):
        return ""
    try:
        body = extract_method_from_file(
            source.file_path,
            method_name,
            getattr(context, "path", None),
        )
    except Exception:
        return ""
    if not body or body.startswith(_BODY_UNAVAILABLE_PREFIXES):
        return ""
    return body


def _sink_argument(sink) -> str:
    metadata = getattr(sink, "metadata", None) or {}
    metavars = metadata.get("metavars") if isinstance(metadata, dict) else None
    if isinstance(metavars, dict):
        taint = metavars.get("$TAINT")
        if isinstance(taint, dict) and taint.get("abstract_content"):
            return str(taint.get("abstract_content")).strip()

    code = getattr(sink, "code", "") or ""
    match = re.search(r"\((.*)\)", code)
    if not match:
        return ""
    args = [part.strip() for part in match.group(1).split(",")]
    if "Location" in code or "location" in code:
        return args[-1] if args else ""
    return args[0] if args else ""


def _request_inputs(signature: str, body: str) -> dict[str, str]:
    text = "\n".join(part for part in (signature, body) if part)
    inputs: dict[str, str] = {}
    annotations = "|".join(re.escape(name) for name in _request_annotations())
    annotation_re = re.compile(
        rf"@(?:[\w.]*\.)?(?P<ann>{annotations})\b(?:\([^)]*\))?\s+"
        r"(?:final\s+)?[\w.$<>\[\]?]+(?:\s*,\s*[\w.$<>\[\]?]+)*\s+"
        r"(?P<name>\w+)"
    )
    for match in annotation_re.finditer(text):
        inputs[match.group("name")] = "@" + match.group("ann")

    request_objs = set(
        re.findall(
            r"(?:javax\.servlet\.http\.|jakarta\.servlet\.http\.)?HttpServletRequest\s+(\w+)",
            text,
        )
    )
    if request_objs:
        accessors = "|".join(re.escape(name) for name in _request_accessors())
        req_re = re.compile(
            rf"(?:[\w.$<>\[\]?]+\s+)?(?P<name>\w+)\s*=\s*"
            rf"(?P<obj>{'|'.join(re.escape(obj) for obj in request_objs)})"
            rf"\.(?P<kind>{accessors})\s*\("
        )
        for match in req_re.finditer(body):
            inputs[match.group("name")] = f"{match.group('obj')}.{match.group('kind')}"

    return inputs


def _refs_var(expr: str, name: str) -> bool:
    return bool(re.search(rf"\b{re.escape(name)}\b", expr or ""))


def _assignment_target(statement: str) -> tuple[str, str] | None:
    match = re.search(
        r"(?:^|[;\n]\s*)(?:[\w.$<>\[\]?]+\s+)?(?P<name>\w+)\s*=\s*(?P<expr>[^;]+);",
        statement,
    )
    if not match:
        return None
    return match.group("name"), match.group("expr").strip()


def _body_before_sink(body: str, sink_code: str) -> str:
    if not body or not sink_code:
        return body
    idx = body.find(sink_code.strip())
    return body[:idx] if idx >= 0 else body


def _bool_from_engine(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() == "true"
    return None


def _flow_key(source_symbol, file_path, line_number):
    return (source_symbol, file_path, int(line_number or 0))


def _engine_flow_metadata(entry: dict | None) -> dict | None:
    if not entry:
        return None

    request_controlled = _bool_from_engine(entry.get("requestControlled"))
    metadata = {
        "sink_kind": "redirect",
        "flow_confidence": entry.get("flowConfidence") or "cpg-target-argument",
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
    if entry.get("sinkCode"):
        metadata["sink_code"] = entry.get("sinkCode")
    return metadata


def _merge_flow_metadata(primary: dict, fallback: dict) -> dict:
    merged = dict(primary)
    for key in ("source_param", "source_kind", "sink_argument", "flow_summary"):
        if not merged.get(key) and fallback.get(key):
            merged[key] = fallback[key]
    if fallback.get("validation_evidence"):
        merged["validation_evidence"] = fallback["validation_evidence"]
    if fallback.get("request_controlled") is True and primary.get("request_controlled") is True:
        merged.setdefault("fallback_flow_summary", fallback.get("flow_summary"))
    return merged


def _flow_to_sink(body: str, signature: str, sink_code: str, sink_arg: str) -> dict:
    inputs = _request_inputs(signature, body)
    if not sink_arg:
        return {
            "sink_kind": "redirect",
            "flow_confidence": "unknown",
            "flow_summary": "Redirect sink argument could not be determined.",
        }

    tainted = {name: source for name, source in inputs.items()}
    flows = {name: f"{source} {name}" for name, source in inputs.items()}
    before_sink = _body_before_sink(body, sink_code)

    for statement in re.split(r"(?<=;)", before_sink):
        assignment = _assignment_target(statement)
        if assignment is None:
            continue
        target, expr = assignment
        for source_var, source_flow in list(flows.items()):
            if _refs_var(expr, source_var):
                tainted[target] = tainted[source_var]
                flows[target] = f"{source_flow} -> {target} = {expr}"
                break

    for var, source in tainted.items():
        if _refs_var(sink_arg, var):
            flow = f"{flows[var]} -> {sink_code.strip()}"
            metadata = {
                "sink_kind": "redirect",
                "source_param": var,
                "source_kind": source,
                "sink_argument": sink_arg,
                "flow_summary": flow,
                "flow_confidence": "direct" if var in inputs else "local-derived",
                "request_controlled": True,
            }
            validation = _validation_evidence(before_sink, var)
            if validation:
                metadata["validation_evidence"] = validation
            return metadata

    return {
        "sink_kind": "redirect",
        "sink_argument": sink_arg,
        "flow_summary": (
            f"No request-controlled source was found flowing into redirect target "
            f"{sink_arg!r} in the endpoint method."
        ),
        "flow_confidence": "not_request_controlled",
        "request_controlled": False,
    }


def _validation_evidence(body: str, var: str) -> str:
    if not body or not var:
        return ""
    interesting = []
    validation_terms = _validation_terms()
    for raw_line in body.splitlines():
        line = raw_line.strip()
        if _refs_var(line, var) and any(term in line for term in validation_terms):
            interesting.append(line)
    return " | ".join(interesting[:3])


def _matching_sink(sinks, trace):
    normalized = _normalize_path(getattr(trace, "sink_file_path", ""))
    matches = [
        sink
        for sink in (sinks or [])
        if sink.line_number == trace.sink_line_number
        and (
            _normalize_path(sink.file_path) == normalized
            or normalized.endswith(_normalize_path(sink.file_path))
            or _normalize_path(sink.file_path).endswith(normalized)
        )
    ]
    return matches[0] if len(matches) == 1 else None


def enrich_open_redirect_flows(vulnerability, context, state):
    source_lookup = {
        source.symbol: source
        for source in (getattr(state, "sources", None) or [])
        if getattr(source, "symbol", None)
    }
    engine_flows = {}
    engine = context.engines.get("dataflow_analyzer") if hasattr(context, "engines") else None
    flow_resolver = getattr(engine, "find_open_redirect_flows", None)
    if callable(flow_resolver):
        try:
            engine_flows = flow_resolver(
                context,
                getattr(state, "traces", None) or [],
                source_annotations=_request_annotations(),
                request_accessors=_request_accessors(),
            )
        except Exception:
            logging.warning(
                "Open redirect: CPG target-argument flow enrichment failed; falling back",
                exc_info=True,
            )

    enriched = []
    non_request_controlled = 0

    for trace in getattr(state, "traces", None) or []:
        source = source_lookup.get(getattr(trace, "source_symbol", None))
        sink = _matching_sink(getattr(state, "sinks", None), trace)
        if source is None or sink is None:
            enriched.append(trace)
            continue

        body = _method_body(context, source)
        signature = getattr(source, "code", "") or ""
        sink_arg = _sink_argument(sink)
        fallback_metadata = _flow_to_sink(body, signature, sink.code, sink_arg)
        engine_entry = engine_flows.get(
            _flow_key(trace.source_symbol, trace.sink_file_path, trace.sink_line_number)
        )
        engine_metadata = _engine_flow_metadata(engine_entry)
        flow_metadata = (
            _merge_flow_metadata(engine_metadata, fallback_metadata)
            if engine_metadata is not None
            else fallback_metadata
        )
        metadata = dict(getattr(sink, "metadata", None) or {})
        metadata.update(flow_metadata)
        enriched_sink = sink.model_copy(update={"metadata": metadata})

        if flow_metadata.get("request_controlled") is False:
            non_request_controlled += 1

        enriched.append(
            trace.model_copy(update={"source": source, "sink": enriched_sink})
        )

    state.traces = enriched
    if non_request_controlled:
        logging.info(
            "Open redirect: retained %d trace(s) with non-request-controlled evidence",
            non_request_controlled,
        )
    return state


class OpenRedirectVulnerability(BaseVulnerability):
    vulnerability_id = "open_redirect"
    title = "Open Redirect"
    description = (
        "Open Redirect vulnerability allows attackers to redirect users to an "
        "arbitrary external destination by controlling the target of a redirect "
        "or a Location response header, enabling phishing and credential theft."
    )
    supported_languages = ["java"]
    required_engine_roles = ["sink_finder", "source_finder", "dataflow_analyzer"]
    source_types = ["remote_input"]
    prompt_kind = "trace"
    stages = [
        match_rule_sinks,
        discover_sources,
        run_dataflow,
        enrich_open_redirect_flows,
        review_traces_with_llm,
        finalize_findings,
    ]
    optional_stages = [review_traces_with_llm]
    review_mode = "optional"
    system_prompt = (
        "Review this trace for open redirect risk. Treat a redirect target or "
        "Location header built from user-controlled input as vulnerable unless the "
        "destination is fixed, a relative-only path, or validated against a strict "
        "allowlist of hosts. Note that prefixing input with a constant base URL is "
        "not sufficient if the input can break out of it (e.g. with '//', '\\\\', or "
        "an absolute URL). If the trace evidence already shows a direct request "
        "parameter to redirect/Location flow and no validation evidence, mark it "
        "VULNERABLE even if an optional tool lookup fails. If enrichment evidence "
        "says the redirect target is not request-controlled, treat that as strong "
        "counterevidence but review the surrounding code before deciding. If the "
        "controls are unclear, return NEED_MANUAL_REVIEW."
    )
    human_prompt = (
        "Analyze this open redirect trace and decide whether attacker-controlled "
        "input can influence the redirect destination or Location header without "
        "effective host/scheme validation."
    )
    fallback_explanation = (
        "Trace reached a redirect/Location sink. Confirm whether untrusted input can "
        "control the destination host or scheme."
    )
    fallback_remediation = (
        "Redirect only to relative paths or destinations validated against a strict "
        "allowlist of permitted hosts; reject absolute or protocol-relative URLs."
    )
