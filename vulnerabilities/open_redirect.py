from vulnerabilities.base.base_vulnerability import BaseVulnerability
from vulnerabilities.base.stages import (
    discover_sources,
    finalize_findings,
    match_rule_sinks,
    review_traces_with_llm,
    run_dataflow,
)


class OpenRedirectVulnerability(BaseVulnerability):
    vulnerability_id = "open_redirect"
    title = "Open Redirect"
    description = (
        "Open Redirect vulnerability allows attackers to redirect users to an "
        "arbitrary external destination by controlling the target of a redirect "
        "or a Location response header, enabling phishing and credential theft."
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
        "Review this trace for open redirect risk. Treat a redirect target or "
        "Location header built from user-controlled input as vulnerable unless the "
        "destination is fixed, a relative-only path, or validated against a strict "
        "allowlist of hosts. Note that prefixing input with a constant base URL is "
        "not sufficient if the input can break out of it (e.g. with '//', '\\\\', or "
        "an absolute URL). If the controls are unclear, return NEED_MANUAL_REVIEW."
    )
    human_prompt = (
        "Analyze this open redirect trace and decide whether attacker-controlled "
        "input can influence the redirect destination or Location header without "
        "effective host/scheme validation."
    )
    fallback_explanation = (
        "Trace reached a redirect/Location sink. Confirm whether untrusted input can "
        "control the destination host or scheme."
    )
    fallback_remediation = (
        "Redirect only to relative paths or destinations validated against a strict "
        "allowlist of permitted hosts; reject absolute or protocol-relative URLs."
    )
    fallback_code_fix = (
        "Do not build redirect targets directly from user input; map input to an "
        "approved set of destinations or enforce relative-path-only redirects."
    )
