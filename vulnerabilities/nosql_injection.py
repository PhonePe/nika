from vulnerabilities.base.base_vulnerability import BaseVulnerability
from vulnerabilities.base.stages import (
    discover_sources,
    finalize_findings,
    match_rule_sinks,
    review_traces_with_llm,
    run_dataflow,
)


class NoSqlInjectionVulnerability(BaseVulnerability):
    vulnerability_id = "nosql_injection"
    title = "NoSQL Injection"
    description = (
        "NoSQL Injection allows attackers to manipulate NoSQL queries when "
        "user-controlled input is parsed into a query document, used in a "
        "JavaScript expression (e.g. MongoDB's $where), or concatenated into a "
        "query string, enabling authentication bypass or unauthorized data access."
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
        "Review this trace for NoSQL injection risk. Treat query documents parsed "
        "from user-controlled JSON strings (e.g. Document.parse, BasicQuery), "
        "$where/JavaScript expressions, or query strings built from user input as "
        "vulnerable. Consider queries built with bound Criteria/field values and "
        "fixed query documents non-vulnerable. If the construction is unclear, "
        "return NEED_MANUAL_REVIEW."
    )
    human_prompt = (
        "Analyze this NoSQL injection trace and decide whether attacker-controlled "
        "input can reach a query document, $where expression, or query string "
        "without safe binding or validation."
    )
    fallback_explanation = (
        "Trace reached a NoSQL query sink. Confirm whether user-controlled input "
        "reaches the query document or $where expression without safe binding."
    )
    fallback_remediation = (
        "Build queries with bound Criteria/field values rather than parsing "
        "user-controlled JSON into query documents, and avoid $where/JavaScript "
        "expressions driven by user input."
    )
    fallback_code_fix = (
        "Use parameterized query builders (e.g. Spring Data Criteria) with bound "
        "values instead of parsing user input into a query document."
    )
