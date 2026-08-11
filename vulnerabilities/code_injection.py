from vulnerabilities.base.base_vulnerability import BaseVulnerability
from vulnerabilities.base.stages import (
    discover_sources,
    finalize_findings,
    match_rule_sinks,
    review_traces_with_llm,
    run_dataflow,
)


class CodeInjectionVulnerability(BaseVulnerability):
    vulnerability_id = "code_injection"
    title = "Code Injection"
    description = (
        "Code Injection vulnerability allows attackers to execute arbitrary code on "
        "the host operating system by injecting malicious input."
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
        "Review this trace for code injection risk. Treat user input that becomes "
        "code, expressions, or executable templates in engines such as MVEL, OGNL, "
        "or SpEL as vulnerable unless the input is strictly constrained to safe "
        "values. If the validation or execution context is unclear, return "
        "NEED_MANUAL_REVIEW."
    )
    human_prompt = (
        "Analyze this code injection trace and decide whether attacker-controlled "
        "input can affect executable code or expression evaluation rather than being "
        "safely isolated as plain data."
    )
    fallback_explanation = (
        "Trace reached a dynamic code or expression execution sink. Verify whether "
        "untrusted input can shape the executed expression."
    )
    fallback_remediation = (
        "Do not evaluate untrusted input as code or expressions unless it is mapped "
        "to a strict allowlist of safe operations."
    )
