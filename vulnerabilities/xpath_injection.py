from vulnerabilities.base.base_vulnerability import BaseVulnerability
from vulnerabilities.base.stages import (
    discover_sources,
    finalize_findings,
    match_rule_sinks,
    review_traces_with_llm,
    run_dataflow,
)


class XpathInjectionVulnerability(BaseVulnerability):
    vulnerability_id = "xpath_injection"
    title = "XPath Injection"
    description = (
        "XPath Injection allows attackers to manipulate XPath queries when "
        "user-controlled input is concatenated into an expression that is compiled "
        "or evaluated against an XML document, enabling authentication bypass or "
        "unauthorized data disclosure."
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
        "Review this trace for XPath injection risk. Treat an XPath expression "
        "compiled or evaluated from user-controlled input as vulnerable unless the "
        "input is bound via variables (e.g. an XPathVariableResolver) or strictly "
        "validated. Building the expression string by concatenating user input is "
        "vulnerable. If the controls are unclear, return NEED_MANUAL_REVIEW."
    )
    human_prompt = (
        "Analyze this XPath injection trace and decide whether attacker-controlled "
        "input can reach an XPath expression that is compiled or evaluated, without "
        "variable binding or validation."
    )
    fallback_explanation = (
        "Trace reached an XPath compile/evaluate sink. Confirm whether user-controlled "
        "input reaches the expression without variable binding."
    )
    fallback_remediation = (
        "Bind user input through XPath variables (XPathVariableResolver) instead of "
        "concatenating it into the expression string."
    )
    fallback_code_fix = (
        "Use parameterized XPath with variable references (e.g. $var) resolved via "
        "an XPathVariableResolver rather than string concatenation."
    )
