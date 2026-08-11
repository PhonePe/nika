from vulnerabilities.base.base_vulnerability import BaseVulnerability
from vulnerabilities.base.stages import (
    discover_sources,
    finalize_findings,
    match_rule_sinks,
    review_traces_with_llm,
    run_dataflow,
)


class TemplateInjectionVulnerability(BaseVulnerability):
    vulnerability_id = "template_injection"
    title = "Template Injection"
    description = (
        "Template Injection vulnerability allows attackers to execute arbitrary code "
        "on the host operating system by injecting malicious input into templates."
    )
    supported_languages = ["java"]
    required_engine_roles = ["sink_finder", "source_finder", "dataflow_analyzer"]
    source_types = ["remote_input"]
    prompt_kind = "trace"
    stages = [
        match_rule_sinks,
        discover_sources,
        run_dataflow,
        review_traces_with_llm,
        finalize_findings,
    ]
    optional_stages = [review_traces_with_llm]
    review_mode = "optional"
    system_prompt = (
        "Review this trace for template injection risk. Treat user input that is "
        "rendered as template source or concatenated into executable templates as "
        "vulnerable. Passing user data as bound template values can be safe. If the "
        "template engine usage is unclear, return NEED_MANUAL_REVIEW."
    )
    human_prompt = (
        "Analyze this template injection trace and decide whether attacker-controlled "
        "input can influence template source or template evaluation rather than being "
        "passed only as data values."
    )
    fallback_explanation = (
        "Trace reached a template rendering sink. Verify whether untrusted input is "
        "treated as template content instead of plain data."
    )
    fallback_remediation = (
        "Keep templates fixed and pass user input only as escaped, non-executable "
        "data values."
    )
