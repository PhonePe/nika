from vulnerabilities.base.base_vulnerability import BaseVulnerability
from vulnerabilities.base.stages import (
    finalize_sink_findings,
    match_rule_sinks,
    resolve_dynamic_sinks,
    review_sinks_with_llm,
)


class InsecureCryptoVulnerability(BaseVulnerability):
    vulnerability_id = "cryptographic_failure"
    title = "Cryptographic Failure"
    description = (
        "Cryptographic Failure vulnerability occurs when cryptographic operations "
        "are implemented incorrectly, leading to security weaknesses such as weak "
        "algorithms, insecure random generation, or hardcoded secrets."
    )
    supported_languages = ["java"]
    required_engine_roles = ["sink_finder", "dataflow_analyzer"]
    source_types = []
    prompt_kind = "sink"
    stages = [match_rule_sinks, resolve_dynamic_sinks, finalize_sink_findings]
    dynamic_sink_rule_ids = ["crypto-getinstance-dynamic-algo"]
    weak_value_patterns = [
        r'(?i)"(des|desede|3des|tripledes|rc2|rc4|arcfour|blowfish|idea|rc5)',
        r'(?i)"[^"]*/ecb/',
        r'(?i)"(md2|md4|md5|sha-?0|sha-?1|ripemd|haval)',
    ]
    review_mode = "optional"
    system_prompt = (
        "Review this Java cryptography snippet for insecure crypto usage. Mark "
        "VULNERABLE when weak algorithms, weak modes, weak randomness, hardcoded "
        "secrets, insecure IV handling, or similarly unsafe cryptographic patterns "
        "are present. Mark NOT_VULNERABLE only when the code clearly uses strong "
        "modern cryptographic practices. If context is ambiguous, return "
        "NEED_MANUAL_REVIEW."
    )
    human_prompt = (
        "Analyze this cryptographic sink for insecure usage and decide whether this "
        "snippet uses unsafe cryptography such as weak algorithms, insecure cipher "
        "modes, hardcoded keys, predictable randomness, or unsafe key/IV handling."
    )
    fallback_explanation = (
        "Potential insecure cryptographic usage detected by rule matching. Review "
        "algorithm and key/IV/randomness handling for modern security compliance."
    )
    fallback_remediation = (
        "Use modern cryptographic primitives and safe key, IV, and randomness "
        "handling aligned with current security standards."
    )
    fallback_code_fix = (
        "Replace weak crypto primitives and hardcoded secrets with strong algorithms "
        "and securely generated keys/IVs."
    )
