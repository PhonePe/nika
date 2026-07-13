# Default mapping between a vulnerability id and its OWASP Top 10 (2025) category.
DEFAULT_OWASP_CATEGORY_MAP = {
    "sql_injection": "A05:2025 - Injection",
    "command_injection": "A05:2025 - Injection",
    "code_injection": "A05:2025 - Injection",
    "ldap_injection": "A05:2025 - Injection",
    "xpath_injection": "A05:2025 - Injection",
    "nosql_injection": "A05:2025 - Injection",
    "template_injection": "A05:2025 - Injection",
    "unsafe_reflection": "A05:2025 - Injection",
    "path_traversal": "A01:2025 - Broken Access Control",
    "open_redirect": "A01:2025 - Broken Access Control",
    "idor": "A01:2025 - Broken Access Control",
    "ssrf": "A01:2025 - Broken Access Control",
    "order_scan": "A06:2025 - Insecure Design",
    "xxe": "A02:2025 - Security Misconfiguration",
    "deserialization": "A08:2025 - Software and Data Integrity Failures",
    "cryptographic_failure": "A04:2025 - Cryptographic Failures",
    "sensitive_logging": "A04:2025 - Cryptographic Failures",
}


def resolve_owasp_category_map(overrides=None):
    merged = dict(DEFAULT_OWASP_CATEGORY_MAP)
    if overrides:
        merged.update({key: value for key, value in overrides.items() if value})
    return merged
