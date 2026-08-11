from vulnerabilities.base.base_vulnerability import BaseVulnerability
from vulnerabilities.base.stages import (
    discover_sources,
    finalize_findings,
    match_rule_sinks,
    review_traces_with_llm,
    run_dataflow,
)


class PathTraversalVulnerability(BaseVulnerability):
    vulnerability_id = "path_traversal"
    title = "Path Traversal"
    review_grouping = "source_method"
    report_grouping = "source_method"
    description = (
        "Path Traversal vulnerability allows attackers to access files and "
        "directories outside the intended scope by manipulating file paths."
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
        "Review this trace for path traversal risk. Treat user-controlled path "
        "construction as vulnerable unless the code normalizes or canonicalizes the "
        "path and then enforces a base-directory boundary. Simple string "
        "replacement is not enough. If the validation logic is hidden, return "
        "NEED_MANUAL_REVIEW."
    )
    human_prompt = (
        "Analyze this path traversal trace and decide whether attacker-controlled "
        "input can influence filesystem access without effective canonicalization and "
        "post-normalization boundary checks."
    )
    fallback_explanation = (
        "Trace reached a filesystem sink. Confirm whether untrusted path input is "
        "normalized and constrained to an intended directory."
    )
    fallback_remediation = (
        "Canonicalize the resolved path and verify it remains under an expected base "
        "directory before use."
    )
