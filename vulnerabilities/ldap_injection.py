from vulnerabilities.base.base_vulnerability import BaseVulnerability
from vulnerabilities.base.stages import (
    discover_sources,
    finalize_findings,
    match_rule_sinks,
    review_traces_with_llm,
    run_dataflow,
)


class LdapInjectionVulnerability(BaseVulnerability):
    vulnerability_id = "ldap_injection"
    title = "LDAP Injection"
    description = (
        "LDAP Injection allows attackers to manipulate LDAP search filters or "
        "distinguished names when user-controlled input is concatenated into an LDAP "
        "query, enabling authentication bypass or unauthorized data disclosure."
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
        "Review this trace for LDAP injection risk. Treat LDAP search filters or "
        "distinguished names built from user-controlled input as vulnerable unless "
        "the input is escaped (e.g. via an encoder such as Spring's LdapEncoder or "
        "manual RFC 2254/4515 escaping) or bound through parameterized filter "
        "arguments. If escaping is unclear, return NEED_MANUAL_REVIEW."
    )
    human_prompt = (
        "Analyze this LDAP injection trace and decide whether attacker-controlled "
        "input can reach an LDAP filter or DN without proper escaping or "
        "parameterization."
    )
    fallback_explanation = (
        "Trace reached an LDAP search sink. Confirm whether user-controlled input "
        "reaches the filter or DN without escaping."
    )
    fallback_remediation = (
        "Escape user input used in LDAP filters and DNs (RFC 4515/4514) or use "
        "parameterized filter arguments instead of string concatenation."
    )
    fallback_code_fix = (
        "Encode user input with an LDAP encoder or pass it as a bound filter "
        "argument rather than concatenating it into the filter string."
    )
