from vulnerabilities.base.base_vulnerability import BaseVulnerability
from vulnerabilities.base.stages import (
    discover_sources,
    finalize_findings,
    match_rule_sinks,
    review_traces_with_llm,
    run_dataflow,
)


class DeserializationVulnerability(BaseVulnerability):
    vulnerability_id = "deserialization"
    title = "Deserialization"
    description = (
        "Deserialization vulnerability allows attackers to manipulate serialized "
        "objects and potentially execute arbitrary code."
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
        "Review this trace for unsafe deserialization risk. Treat untrusted input "
        "flowing into generic object deserializers, unsafe YAML loaders, XMLDecoder, "
        "or similarly dangerous mechanisms as vulnerable unless a strict class or "
        "type allowlist is enforced. If the filtering controls are unclear, return "
        "NEED_MANUAL_REVIEW."
    )
    human_prompt = (
        "Analyze this deserialization trace and decide whether attacker-controlled "
        "serialized data can reach a dangerous deserializer without strong "
        "restrictions on allowed classes or types."
    )
    fallback_explanation = (
        "Trace reached a deserialization sink. Confirm whether untrusted input is "
        "restricted to safe types before deserialization."
    )
    fallback_remediation = (
        "Use safe deserializers or enforce a strict allowlist of permitted classes "
        "and types for untrusted data."
    )
