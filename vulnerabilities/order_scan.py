from vulnerabilities.base.base_vulnerability import BaseVulnerability
from vulnerabilities.base.stages import direct_findings_from_sinks, match_rule_sinks


DEFAULT_EXPLANATION = (
    "The order of method calls in the provided code snippet does not follow the "
    "expected sequence for this workflow."
)

DEFAULT_REMEDIATION = (
    "Reorder the method chain to follow the expected secure sequence defined by "
    "the order-scan rule."
)

class OrderScanVulnerability(BaseVulnerability):
    vulnerability_id = "order_scan"
    title = "Violation of Order Scan"
    description = (
        "This vulnerability occurs when the order of method calls in a chain does "
        "not follow the expected sequence."
    )
    supported_languages = ["java"]
    required_engine_roles = ["order_finder"]
    sink_engine_role = "order_finder"
    source_types = []
    review_mode = "never"

    def __init__(self, llm_reviewer=None):
        super().__init__(llm_reviewer)
        self.stages = [match_rule_sinks, self.finalize_findings]

    def finalize_findings(self, context, state):
        return direct_findings_from_sinks(
            self.vulnerability_id,
            state.sinks,
            status="VULNERABLE",
            explanation=DEFAULT_EXPLANATION,
            remediation=DEFAULT_REMEDIATION,
        )
