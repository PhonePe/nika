from vulnerabilities.base.base_vulnerability import BaseVulnerability
from vulnerabilities.base.stages import (
    discover_sources,
    finalize_findings,
    match_rule_sinks,
    review_traces_with_llm,
    run_dataflow,
)


class SqlInjectionVulnerability(BaseVulnerability):
    vulnerability_id = "sql_injection"
    title = "SQL Injection"
    description = (
        "SQL Injection vulnerability allows attackers to interfere with the "
        "queries that an application makes to its database."
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
        "Review this trace for SQL injection risk. Treat dynamic SQL built from "
        "user-controlled input as suspicious, but consider parameterized queries "
        "and safe bound parameters non-vulnerable. If the code path is unclear or "
        "uses a custom query builder, return NEED_MANUAL_REVIEW."
    )
    human_prompt = (
        "Analyze this SQL injection trace and decide whether attacker-controlled "
        "input can reach executable SQL without safe parameterization."
    )
    fallback_explanation = (
        "Trace reached the SQL sink. LLM review is not configured, so the finding "
        "is being surfaced for manual triage."
    )
    fallback_remediation = (
        "Verify whether user-controlled input reaches the query without "
        "parameterization."
    )
