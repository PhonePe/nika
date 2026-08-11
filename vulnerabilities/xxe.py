from vulnerabilities.base.base_vulnerability import BaseVulnerability
from vulnerabilities.base.stages import (
    discover_sources,
    finalize_findings,
    match_rule_sinks,
    review_traces_with_llm,
    run_dataflow,
)


class XxeVulnerability(BaseVulnerability):
    vulnerability_id = "xxe"
    title = "XML External Entity Injection"
    description = (
        "XML External Entity Injection (XXE) vulnerability allows attackers to "
        "inject external entities into XML documents."
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
        "Review this trace for XXE risk. Treat XML parsing of untrusted input as "
        "vulnerable when external entities, DTD processing, or unsafe parser "
        "features remain enabled. If parser configuration is not visible, return "
        "NEED_MANUAL_REVIEW."
    )
    human_prompt = (
        "Analyze this XXE trace and decide whether attacker-controlled XML can reach "
        "a parser without clear protections that disable external entities and "
        "related unsafe features."
    )
    fallback_explanation = (
        "Trace reached an XML parsing sink. Verify whether the parser disables "
        "external entity processing for untrusted input."
    )
    fallback_remediation = (
        "Disable external entities, DTD processing, and similar unsafe XML parser "
        "features for untrusted input."
    )
