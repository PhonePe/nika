from models.degraded_finding import DegradedFinding
from schema.vulnerability_schema import (
    CallGraphNode,
    LLMVulnerabilityOutput,
    Vulnerabilities,
    Vulnerability,
)


def _to_legacy_vulnerability(finding):
    analysis = None
    if finding.explanation or finding.remediation or finding.code_fix:
        analysis = LLMVulnerabilityOutput(
            vulnerable_status=finding.status,
            explanation=finding.explanation or "",
            remediation=finding.remediation or "",
        )

    call_graph = []
    if finding.trace is not None:
        call_graph = [
            CallGraphNode(
                method_name=node.method_name,
                filename=node.file_path,
                code=node.code,
                method_line_number_start=node.method_line_number_start,
                method_line_number_end=node.method_line_number_end,
                callee_code=node.callee_code,
                callee_line_number=node.callee_line_number,
                is_external=node.is_external,
            )
            for node in finding.trace.nodes
        ]

    metadata = getattr(finding, "metadata", None) or {}

    return Vulnerability(
        sink=finding.sink,
        call_path=" -> ".join(node.code for node in call_graph),
        analysis=analysis,
        call_graph=call_graph,
        line_number=finding.line_number or 0,
        line_number_end=finding.line_number_end or finding.line_number or 0,
        filename=finding.file_path,
        class_api_path=metadata.get("class_api_path") or None,
        method_api_path=metadata.get("method_api_path") or None,
        call_node_count=getattr(finding, "call_node_count", None),
        metadata=metadata,
    )


def _apply_vulnerability_metadata(entries, vulnerability_metadata=None):
    vulnerability_metadata = vulnerability_metadata or {}

    for entry in entries:
        vulnerability_id = entry.get("vulnerability")
        metadata = vulnerability_metadata.get(vulnerability_id)
        entry.setdefault(
            "VULNERABILITY_TITLE",
            getattr(metadata, "title", vulnerability_id),
        )
        entry.setdefault(
            "VULNERABILITY_DESCRIPTION",
            getattr(metadata, "description", ""),
        )

    return entries


def collect_degraded_findings(findings, vulnerability_metadata=None):
    """Build serializable entries for findings that could not complete due to engine failures."""
    vulnerability_metadata = vulnerability_metadata or {}
    degraded = []
    for finding in findings:
        if not isinstance(finding, DegradedFinding):
            continue
        metadata = vulnerability_metadata.get(finding.vulnerability_id)
        degraded.append(
            {
                "vulnerability": finding.vulnerability_id,
                "title": getattr(metadata, "title", finding.vulnerability_id),
                "reason": finding.reason,
            }
        )
    return degraded


def group_findings_for_legacy_report(findings, vulnerability_metadata=None):
    grouped = {}

    for finding in findings:
        if isinstance(finding, DegradedFinding):
            continue
        grouped.setdefault(finding.vulnerability_id, []).append(
            _to_legacy_vulnerability(finding)
        )

    return _apply_vulnerability_metadata(
        [
            {
                "vulnerability": vulnerability_id,
                "result": Vulnerabilities(findings=vulnerabilities),
            }
            for vulnerability_id, vulnerabilities in grouped.items()
        ],
        vulnerability_metadata,
    )
