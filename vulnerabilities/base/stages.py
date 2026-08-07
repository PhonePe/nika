import logging
import os
import re

from models.evidence import EvidenceBundle
from models.finding import Finding
from vulnerabilities.base.security_agent_reviewer import run_security_agent_review
from vulnerabilities.base.taint_flow_helper import (
    _flow_key as _taint_flow_key,
    build_dynamic_explanation,
    engine_flow_metadata,
    get_request_accessors,
    get_request_annotations,
)

def empty_evidence_bundle() -> EvidenceBundle:
    return EvidenceBundle()

def match_rule_sinks(vulnerability, context, state):
    rules_path = context.language_pack.resolve_rules_path(vulnerability.vulnerability_id)
    sink_engine_role = getattr(vulnerability, "sink_engine_role", "sink_finder")
    logging.info("Finding sinks for vulnerability %s", vulnerability.vulnerability_id)
    state.sinks = context.engines[sink_engine_role].find_sinks(context, rules_path)
    logging.info("Found %d sink(s) for vulnerability %s", len(state.sinks), vulnerability.vulnerability_id)
    return state


def discover_sources(vulnerability, context, state):
    def _discover_sources_for_key():
        source_definitions = context.language_pack.get_source_definitions(
            vulnerability.source_types
        )
        repo_sources = context.engines["source_finder"].find_sources(
            context, source_definitions
        )
        logging.info("Discovered %d sources", len(repo_sources))
        return repo_sources

    get_or_discover_sources = getattr(context, "get_or_discover_sources", None)
    if callable(get_or_discover_sources):
        state.sources = get_or_discover_sources(
            vulnerability.source_types,
            _discover_sources_for_key,
        )
        return state

    cached_sources = None
    if hasattr(context, "get_cached_sources"):
        cached_sources = context.get_cached_sources(vulnerability.source_types)

    if cached_sources is not None:
        state.sources = list(cached_sources)
        return state

    state.sources = _discover_sources_for_key()

    if hasattr(context, "cache_sources"):
        context.cache_sources(vulnerability.source_types, state.sources)

    return state


def run_dataflow(vulnerability, context, state):
    logging.info("Running taint analysis for %s", vulnerability.vulnerability_id)
    sanitizers = getattr(vulnerability, "sanitizers", None) or []
    state.traces = context.engines["dataflow_analyzer"].find_traces(
        context, state.sources, state.sinks, sanitizers=sanitizers
    )
    logging.info("Found %d vulnerabilities for %s", len(state.traces), vulnerability.vulnerability_id)
    return state


def _vulnerability_taint_config(vulnerability):
    source_annotations = list(get_request_annotations(vulnerability.vulnerability_id))
    request_accessors = list(get_request_accessors(vulnerability.vulnerability_id))
    sink_names = list(getattr(vulnerability, "tainted_flow_sink_names", None) or [])
    receiver_only_sinks = list(
        getattr(vulnerability, "tainted_flow_receiver_only_sinks", None) or []
    )
    return source_annotations, request_accessors, sink_names, receiver_only_sinks


def enrich_tainted_variable_flows(vulnerability, context, state):
    traces = getattr(state, "traces", None) or []
    logging.info(
        "%s: tainted-variable flow enrichment stage invoked (%d trace(s))",
        vulnerability.vulnerability_id,
        len(traces),
    )
    if not traces:
        logging.info(
            "%s: tainted-variable flow enrichment skipped (no traces)",
            vulnerability.vulnerability_id,
        )
        return state

    engine = context.engines.get("dataflow_analyzer") if hasattr(context, "engines") else None
    flow_resolver = getattr(engine, "find_tainted_variable_flows", None)
    if not callable(flow_resolver):
        logging.info(
            "%s: tainted-variable flow enrichment skipped (engine %r has no find_tainted_variable_flows)",
            vulnerability.vulnerability_id,
            type(engine).__name__ if engine is not None else None,
        )
        return state

    source_annotations, request_accessors, sink_names, receiver_only_sinks = (
        _vulnerability_taint_config(vulnerability)
    )

    try:
        engine_flows = (
            flow_resolver(
                context,
                traces,
                source_annotations=source_annotations,
                request_accessors=request_accessors,
                sink_names=sink_names,
                receiver_only_sinks=receiver_only_sinks,
            )
            or {}
        )
    except Exception:
        logging.warning(
            "%s: tainted-variable flow enrichment failed; keeping traces unchanged",
            vulnerability.vulnerability_id,
            exc_info=True,
        )
        return state

    if not engine_flows:
        logging.info(
            "%s: tainted-variable flow enrichment ran but engine returned 0 flow entries for %d trace(s)",
            vulnerability.vulnerability_id,
            len(traces),
        )
        return state

    base_explanation = getattr(vulnerability, "fallback_explanation", None) or ""
    source_lookup = _source_lookup(getattr(state, "sources", None))
    sinks = getattr(state, "sinks", None)
    enriched = []
    enriched_count = 0

    for trace in traces:
        entry = engine_flows.get(
            _taint_flow_key(
                getattr(trace, "source_symbol", None),
                getattr(trace, "sink_file_path", None),
                getattr(trace, "sink_line_number", None),
            )
        )
        sink = getattr(trace, "sink", None) or _single_matching_sink_for_trace(sinks, trace)
        if entry is None or sink is None:
            enriched.append(trace)
            continue

        taint_metadata = engine_flow_metadata(vulnerability.vulnerability_id, entry)
        metadata = dict(getattr(sink, "metadata", None) or {})
        if taint_metadata:
            metadata.update(taint_metadata)
            if metadata.get("request_controlled") is not False:
                metadata["tainted_flow_explanation"] = build_dynamic_explanation(
                    vulnerability.vulnerability_id,
                    trace,
                    taint_metadata,
                    base_explanation,
                )

        source = getattr(trace, "source", None) or source_lookup.get(
            getattr(trace, "source_symbol", None)
        )
        enriched.append(
            trace.model_copy(
                update={"sink": sink.model_copy(update={"metadata": metadata}), "source": source}
            )
        )
        if metadata.get("tainted_flow_explanation"):
            enriched_count += 1

    logging.info(
        "%s: tainted-variable flow enrichment matched %d of %d trace(s) (engine returned %d flow entr%s)",
        vulnerability.vulnerability_id,
        enriched_count,
        len(traces),
        len(engine_flows),
        "y" if len(engine_flows) == 1 else "ies",
    )
    state.traces = enriched
    return state


def resolve_dynamic_sinks(vulnerability, context, state):
    candidate_ids = set(getattr(vulnerability, "dynamic_sink_rule_ids", ()) or ())
    sinks = getattr(state, "sinks", None) or []
    engine = context.engines.get("dataflow_analyzer") if hasattr(context, "engines") else None
    if not candidate_ids or not sinks or engine is None or not hasattr(engine, "resolve_constant_args"):
        return state

    def _rule_id(sink):
        return (getattr(sink, "rule_id", None) or "").split(".")[-1]

    candidates = [s for s in sinks if _rule_id(s) in candidate_ids]
    if not candidates:
        return state
    passthrough = [s for s in sinks if _rule_id(s) not in candidate_ids]

    patterns = [re.compile(p) for p in (getattr(vulnerability, "weak_value_patterns", ()) or [])]
    resolved = engine.resolve_constant_args(
        context, [(s.file_path, s.line_number) for s in candidates]
    )

    kept = []
    for sink in candidates:
        values = resolved.get((sink.file_path, sink.line_number), [])
        if values and any(p.search(v) for v in values for p in patterns):
            kept.append(sink)

    logging.info(
        "Resolved %d dynamic sink(s) for %s; kept %d after constant resolution",
        len(candidates), vulnerability.vulnerability_id, len(kept),
    )
    state.sinks = passthrough + kept
    return state


def run_dataflow_without_sinks(vulnerability, context, state):
    state.traces = context.engines["dataflow_analyzer"].find_traces(
        context,
        state.sources,
        [],
    )
    return state


def _source_lookup(sources):
    return {
        source.symbol: source
        for source in (sources or [])
        if getattr(source, "symbol", None)
    }


def _single_matching_sink_for_trace(sinks, trace):
    matches = _matching_sinks_for_trace(sinks or [], trace)
    return matches[0] if len(matches) == 1 else None


def _enrich_trace_for_review(trace, sinks, sources):
    source_lookup = _source_lookup(sources)
    source = getattr(trace, "source", None) or source_lookup.get(
        getattr(trace, "source_symbol", None)
    )
    sink = getattr(trace, "sink", None) or _single_matching_sink_for_trace(sinks, trace)
    return trace.model_copy(update={"source": source, "sink": sink})


def review_traces_with_llm(vulnerability, context, state):
    state.traces = [
        _enrich_trace_for_review(trace, getattr(state, "sinks", None), getattr(state, "sources", None))
        for trace in state.traces
    ]
    state.reviews = [
        run_security_agent_review(vulnerability, context, trace)
        for trace in state.traces
    ]
    return state


def review_sinks_with_llm(vulnerability, context, state):
    state.reviews = [
        run_security_agent_review(vulnerability, context, sink)
        for sink in state.sinks
    ]
    return state


def resolve_llm_reviewer(vulnerability, llm_reviewer=None):
    if llm_reviewer is not None:
        return llm_reviewer

    return lambda system_prompt, human_prompt: default_llm_review(vulnerability)


def default_llm_review(vulnerability):
    return {
        "vulnerable_status": "VULNERABLE",
        "explanation": getattr(vulnerability, "fallback_explanation", None),
        "remediation": getattr(vulnerability, "fallback_remediation", None),
        "code_fix": getattr(vulnerability, "fallback_code_fix", None),
    }


def build_trace_human_prompt(vulnerability, trace):
    opening_instruction = getattr(vulnerability, "human_prompt", None)
    if opening_instruction is None:
        opening_instruction = "Analyze this vulnerability trace."

    prompt_lines = [
        opening_instruction,
        f"Candidate vulnerability: {getattr(vulnerability, 'vulnerability_id', 'unknown')}",
        f"Sink location: {trace.sink_file_path}:{trace.sink_line_number}",
    ]

    source_evidence = _format_source_evidence(getattr(trace, "source", None))
    if source_evidence:
        prompt_lines.extend(["Source evidence:", source_evidence])

    sink_evidence = _format_sink_evidence(getattr(trace, "sink", None), trace)
    if sink_evidence:
        prompt_lines.extend(["Sink evidence:", sink_evidence])

    prompt_lines.append("Trace:")

    for index, node in enumerate(trace.nodes, start=1):
        prompt_lines.append(
            f"{index}. {node.file_path}:{node.method_line_number_start or '?'} {node.method_name}"
        )
        prompt_lines.append(node.code)
        if node.callee_code:
            prompt_lines.append(f"Calls: {node.callee_code}")

    prompt_lines.append(shared_prompt_closing_sentence())
    return "\n".join(prompt_lines)


def shared_prompt_closing_sentence():
    return (
        "Decide whether attacker-controlled input reaches this vulnerability "
        "class's sink unsafely. If the evidence reaches a different sink "
        "category, return NOT_VULNERABLE. If the evidence is insufficient, "
        "return NEED_MANUAL_REVIEW."
    )


def _format_source_evidence(source):
    if source is None:
        return ""

    metadata = getattr(source, "metadata", None) or {}
    path = (metadata.get("class_api_path") or "") + (metadata.get("method_api_path") or "")
    lines = [
        f"Location: {source.file_path}:{source.line_number}",
        f"Symbol: {source.symbol}",
    ]
    if path:
        lines.append(f"API path: {path}")
    if source.code:
        lines.extend(["Code:", source.code])
    return "\n".join(lines)


def _format_sink_evidence(sink, trace):
    if sink is None:
        return f"Location: {trace.sink_file_path}:{trace.sink_line_number}"

    metadata = getattr(sink, "metadata", None) or {}
    lines = [
        f"Location: {sink.file_path}:{sink.line_number}",
        f"Rule ID: {sink.rule_id or metadata.get('rule_id') or 'unknown'}",
    ]
    if metadata.get("sink_kind"):
        lines.append(f"Sink kind: {metadata.get('sink_kind')}")
    if "request_controlled" in metadata:
        lines.append(f"Request controlled: {metadata.get('request_controlled')}")
    if metadata.get("source_param"):
        source_text = metadata.get("source_param")
        if metadata.get("source_kind"):
            source_text = f"{metadata.get('source_kind')} {source_text}"
        lines.append(f"Source parameter: {source_text}")
    if metadata.get("sink_argument"):
        lines.append(f"Sink argument: {metadata.get('sink_argument')}")
    if metadata.get("tainted_variable"):
        lines.append(f"Tainted variable: {metadata.get('tainted_variable')}")
    if metadata.get("flow_summary"):
        lines.append(f"Flow summary: {metadata.get('flow_summary')}")
    if metadata.get("validation_evidence"):
        lines.append(f"Validation evidence: {metadata.get('validation_evidence')}")
    if metadata.get("flow_confidence"):
        lines.append(f"Flow confidence: {metadata.get('flow_confidence')}")
    if metadata.get("confidence"):
        lines.append(f"Rule confidence: {metadata.get('confidence')}")
    if sink.code:
        lines.extend(["Code:", sink.code])

    metavars = metadata.get("metavars")
    if isinstance(metavars, dict) and metavars:
        lines.append("Metavariables:")
        for name, value in sorted(metavars.items()):
            if not isinstance(value, dict):
                continue
            rendered = value.get("abstract_content") or ""
            propagated = value.get("propagated_value")
            if propagated:
                rendered = f"{rendered} (propagated from {propagated})"
            if rendered:
                lines.append(f"- {name}: {rendered}")

    return "\n".join(lines)


def build_sink_human_prompt(vulnerability, sink):
    opening_instruction = getattr(vulnerability, "human_prompt", None)
    if opening_instruction is None:
        opening_instruction = "Analyze this sink."

    return "\n".join(
        [
            opening_instruction,
            f"File: {sink.file_path}:{sink.line_number}",
            sink.code,
            shared_prompt_closing_sentence(),
        ]
    )


def _review_status(review):
    return review.get("status") or review.get("vulnerable_status") or "VULNERABLE"


def _normalize_path(path):
    if not path:
        return path

    return os.path.normpath(path).replace("\\", "/")


def _matching_sinks_for_trace(sinks, trace):
    normalized_trace_path = _normalize_path(trace.sink_file_path)
    exact_matches = [
        sink
        for sink in sinks
        if sink.line_number == trace.sink_line_number
        and _normalize_path(sink.file_path) == normalized_trace_path
    ]
    if exact_matches:
        return exact_matches

    if not normalized_trace_path:
        return []

    return [
        sink
        for sink in sinks
        if sink.line_number == trace.sink_line_number
        and (
            normalized_trace_path.endswith(_normalize_path(sink.file_path))
            or _normalize_path(sink.file_path).endswith(normalized_trace_path)
        )
    ]


def _combine_explanation(review_explanation, taint_explanation):
    review_explanation = (review_explanation or "").strip()
    taint_explanation = (taint_explanation or "").strip()
    if not taint_explanation:
        return review_explanation or None
    if not review_explanation:
        return taint_explanation
    if review_explanation in taint_explanation:
        return taint_explanation
    return f"{review_explanation}\n\n{taint_explanation}"


def _finding_from_sink(vulnerability_id, sink, review=None, trace=None, metadata=None):
    review = review or {}
    sink_metadata = dict(getattr(sink, "metadata", None) or {})
    if getattr(sink, "rule_id", None):
        sink_metadata.setdefault("rule_id", sink.rule_id)
    effective_metadata = metadata or sink_metadata
    explanation = _combine_explanation(
        review.get("explanation"),
        effective_metadata.get("tainted_flow_explanation"),
    )
    return Finding(
        vulnerability_id=vulnerability_id,
        sink=sink.code,
        file_path=sink.file_path,
        line_number=sink.line_number,
        line_number_end=sink.line_number_end or sink.line_number,
        status=_review_status(review),
        explanation=explanation,
        remediation=review.get("remediation"),
        code_fix=review.get("code_fix"),
        trace=trace,
        call_node_count=getattr(trace, "call_node_count", None) if trace is not None else None,
        metadata=effective_metadata,
    )


def _api_path_metadata(trace, source_lookup):
    if not source_lookup or not getattr(trace, "source_symbol", None):
        return {}

    source = source_lookup.get(trace.source_symbol)
    if source is None:
        return {}

    metadata = getattr(source, "metadata", None) or {}
    api_path = {}
    class_api_path = (metadata.get("class_api_path") or "").strip()
    method_api_path = (metadata.get("method_api_path") or "").strip()
    if class_api_path:
        api_path["class_api_path"] = class_api_path
    if method_api_path:
        api_path["method_api_path"] = method_api_path
    return api_path


def _trace_finding_metadata(sink, trace, source_lookup):
    metadata = dict(getattr(sink, "metadata", None) or {})
    trace_sink = getattr(trace, "sink", None)
    if trace_sink is not None:
        metadata.update(getattr(trace_sink, "metadata", None) or {})
    if getattr(sink, "rule_id", None):
        metadata.setdefault("rule_id", sink.rule_id)
    metadata.update(_api_path_metadata(trace, source_lookup))
    return metadata


def findings_from_trace_review(vulnerability_id: str, sinks, traces, reviews, source_lookup=None):
    sink_lookup = {}
    normalized_sink_lookup = {}

    for sink in sinks:
        sink_key = (sink.file_path, sink.line_number)
        sink_lookup.setdefault(sink_key, []).append(sink)

        normalized_key = (_normalize_path(sink.file_path), sink.line_number)
        normalized_sink_lookup.setdefault(normalized_key, []).append(sink)

    findings = []

    for index, trace in enumerate(traces):
        review = reviews[index] if index < len(reviews) else {}
        direct_matches = sink_lookup.get((trace.sink_file_path, trace.sink_line_number), [])
        sink = direct_matches[0] if len(direct_matches) == 1 else None
        if sink is None:
            normalized_matches = normalized_sink_lookup.get(
                (_normalize_path(trace.sink_file_path), trace.sink_line_number)
            ) or []
            if len(normalized_matches) == 1:
                sink = normalized_matches[0]
        if sink is None:
            matches = _matching_sinks_for_trace(sinks, trace)
            if len(matches) == 1:
                sink = matches[0]
        if sink is None:
            continue

        findings.append(
            _finding_from_sink(
                vulnerability_id,
                sink,
                review=review,
                trace=trace,
                metadata=_trace_finding_metadata(sink, trace, source_lookup),
            )
        )

    return findings


def findings_from_sink_review(vulnerability_id: str, sinks, reviews):
    findings = []

    for index, sink in enumerate(sinks):
        review = reviews[index] if index < len(reviews) else {}
        findings.append(_finding_from_sink(vulnerability_id, sink, review=review))

    return findings


def finalize_trace_findings(vulnerability, context, state):
    if not getattr(state, "traces", None):
        return []

    reviews = getattr(state, "reviews", None) or [
        vulnerability.llm_reviewer("", "") for _ in state.traces
    ]
    source_lookup = _source_lookup(getattr(state, "sources", None))
    return findings_from_trace_review(
        vulnerability.vulnerability_id,
        state.sinks,
        state.traces,
        reviews,
        source_lookup=source_lookup,
    )


def finalize_sink_findings(vulnerability, context, state):
    if not getattr(state, "sinks", None):
        return []

    reviews = getattr(state, "reviews", None) or []
    if reviews:
        return findings_from_sink_review(vulnerability.vulnerability_id, state.sinks, reviews)

    review = vulnerability.llm_reviewer("", "")
    return direct_findings_from_sinks(
        vulnerability.vulnerability_id,
        state.sinks,
        explanation=review.get("explanation"),
        remediation=review.get("remediation"),
        code_fix=review.get("code_fix"),
    )


def finalize_findings(vulnerability, context, state):
    """Generic finalize dispatcher — routes to trace or sink finalization based on prompt_kind."""
    if vulnerability.prompt_kind == "trace":
        return finalize_trace_findings(vulnerability, context, state)
    if vulnerability.prompt_kind == "sink":
        return finalize_sink_findings(vulnerability, context, state)
    raise NotImplementedError(
        f"{vulnerability.__class__.__name__} has no prompt_kind set; "
        "override finalize_findings or set prompt_kind."
    )


def _value_from_item(item, value_or_getter, default=None):
    if value_or_getter is None:
        return default

    if callable(value_or_getter):
        return value_or_getter(item)

    return value_or_getter


def direct_static_findings(
    vulnerability_id: str,
    items,
    *,
    status: str = "VULNERABLE",
    sink_text=None,
    file_path=None,
    line_number=None,
    line_number_end=None,
    explanation=None,
    remediation=None,
    code_fix=None,
    metadata=None,
):
    findings = []

    for item in items:
        findings.append(
            Finding(
                vulnerability_id=vulnerability_id,
                sink=_value_from_item(item, sink_text, ""),
                file_path=_value_from_item(item, file_path),
                line_number=_value_from_item(item, line_number),
                line_number_end=_value_from_item(item, line_number_end),
                status=status,
                explanation=_value_from_item(item, explanation),
                remediation=_value_from_item(item, remediation),
                code_fix=_value_from_item(item, code_fix),
                metadata=_value_from_item(item, metadata, {}) or {},
            )
        )

    return findings


def direct_findings_from_sinks(
    vulnerability_id: str,
    sinks,
    *,
    status: str = "VULNERABLE",
    explanation: str | None = None,
    remediation: str | None = None,
    code_fix: str | None = None,
    metadata: dict[str, str] | None = None,
):
    return direct_static_findings(
        vulnerability_id,
        sinks,
        status=status,
        sink_text=lambda sink: sink.code,
        file_path=lambda sink: sink.file_path,
        line_number=lambda sink: sink.line_number,
        line_number_end=lambda sink: sink.line_number_end or sink.line_number,
        explanation=explanation,
        remediation=remediation,
        code_fix=code_fix,
        metadata=metadata,
    )
