from vulnerabilities.base.base_vulnerability import BaseVulnerability
from vulnerabilities.base.stages import (
    discover_sources,
    finalize_findings,
    match_rule_sinks,
    review_traces_with_llm,
    enrich_tainted_variable_flows,
    run_dataflow,
)


class UnsafeReflectionVulnerability(BaseVulnerability):
    vulnerability_id = "unsafe_reflection"
    title = "Unsafe Reflection"
    description = (
        "Unsafe Reflection vulnerability allows attackers to manipulate the "
        "application to instantiate arbitrary classes or invoke arbitrary methods."
    )
    supported_languages = ["java"]
    required_engine_roles = ["sink_finder", "source_finder", "dataflow_analyzer"]
    source_types = ["remote_input"]
    prompt_kind = "trace"
    stages = [
        match_rule_sinks,
        discover_sources,
        run_dataflow,
        enrich_tainted_variable_flows,
        review_traces_with_llm,
        finalize_findings,
    ]
    optional_stages = [review_traces_with_llm]
    review_mode = "optional"
    system_prompt = (
        "Review this trace for unsafe reflection risk. Treat user input that selects "
        "classes, methods, or reflective invocation targets as vulnerable unless the "
        "values are constrained by a strict allowlist. If the validation is not "
        "visible, return NEED_MANUAL_REVIEW."
    )
    human_prompt = (
        "Analyze this unsafe reflection trace and decide whether attacker-controlled "
        "input can influence reflective class selection, method lookup, or "
        "invocation targets without strict restrictions."
    )
    fallback_explanation = (
        "Trace reached a reflection sink. Verify whether untrusted input can control "
        "class loading or reflective invocation targets."
    )
    fallback_remediation = (
        "Map untrusted input to a fixed allowlist of permitted classes or methods "
        "before any reflective operation."
    )
    fallback_code_fix = (
        "Replace reflection driven by user input with an explicit allowlisted "
        "dispatch table."
    )
