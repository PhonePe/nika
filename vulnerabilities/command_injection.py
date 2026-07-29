from vulnerabilities.base.base_vulnerability import BaseVulnerability
from vulnerabilities.base.stages import (
    discover_sources,
    finalize_findings,
    match_rule_sinks,
    review_traces_with_llm,
    run_dataflow,
)

class CommandInjectionVulnerability(BaseVulnerability):
    vulnerability_id = "command_injection"
    title = "Command Injection"
    description = (
        "Command Injection vulnerability allows attackers to execute arbitrary "
        "commands on the host operating system by injecting malicious input."
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
        "Review this trace for command injection risk. Treat user input flowing into "
        "shell command strings, shell interpreters, or command selection as "
        "vulnerable. Passing user input as a separate argument can be safe, but not "
        "when the input controls the command itself. If safeguards are unclear, "
        "return NEED_MANUAL_REVIEW."
    )
    human_prompt = (
        "Analyze this command injection trace and decide whether attacker-controlled "
        "input can affect shell syntax, command structure, or command selection "
        "instead of being safely isolated as data."
    )
    fallback_explanation = (
        "Trace reached a command execution sink. Verify whether untrusted input can "
        "change the executed command or invoke a shell."
    )
    fallback_remediation = (
        "Avoid shell invocation and pass fixed commands with separately tokenized "
        "arguments after strict validation."
    )
