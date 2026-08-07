from models.degraded_finding import DegradedFinding
from schema.vulnerability_schema import (
    CallGraphNode,
    LLMVulnerabilityOutput,
    Vulnerabilities,
    Vulnerability,
)


def _source_method_group_key(finding):
    trace = getattr(finding, "trace", None)
    source_symbol = getattr(trace, "source_symbol", None)
    if not source_symbol:
        return None

    source = getattr(trace, "source", None)
    metadata = getattr(finding, "metadata", None) or {}
    source_param = metadata.get("source_param") or getattr(
        trace, "source_param", None
    )
    if not source_param:
        return None
    return (
        source_symbol,
        getattr(source, "file_path", None),
        getattr(source, "line_number", None),
        metadata.get("class_api_path"),
        metadata.get("method_api_path"),
        source_param,
        (getattr(finding, "status", None) or "VULNERABLE").strip().upper(),
    )


def _related_sink_occurrence(finding):
    trace = getattr(finding, "trace", None)
    metadata = getattr(finding, "metadata", None) or {}
    call_graph = []
    if trace is not None:
        call_graph = [
            {
                "methodname": node.method_name,
                "filename": node.file_path,
                "calleeLineNumber": node.callee_line_number,
            }
            for node in trace.nodes
        ]

    return {
        "sink": finding.sink,
        "filename": finding.file_path,
        "lineNumber": finding.line_number,
        "lineNumberEnd": finding.line_number_end or finding.line_number,
        "status": finding.status,
        "ruleId": metadata.get("rule_id"),
        "explanation": finding.explanation,
        "callGraph": call_graph,
    }


def _group_findings_by_source_method(findings):
    grouped = []
    group_indexes = {}

    for finding in findings:
        group_key = _source_method_group_key(finding)
        if group_key is None or group_key not in group_indexes:
            group_indexes[group_key] = len(grouped) if group_key is not None else None
            grouped.append(finding.model_copy(deep=True))
            continue

        primary = grouped[group_indexes[group_key]]
        metadata = dict(getattr(primary, "metadata", None) or {})
        finding_group = dict(metadata.get("finding_group") or {})
        related_sinks = list(finding_group.get("related_sinks") or [])
        related_sinks.append(_related_sink_occurrence(finding))
        finding_group.update(
            {
                "strategy": "source_method",
                "source_symbol": group_key[0],
                "occurrence_count": len(related_sinks) + 1,
                "related_sinks": related_sinks,
            }
        )
        metadata["finding_group"] = finding_group
        primary.metadata = metadata

    return grouped


def _to_legacy_vulnerability(finding):
    analysis = None
    if finding.explanation or finding.remediation:
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
    vulnerability_metadata = vulnerability_metadata or {}
    grouped = {}

    for finding in findings:
        if isinstance(finding, DegradedFinding):
            continue
        grouped.setdefault(finding.vulnerability_id, []).append(finding)

    report_groups = {}
    for vulnerability_id, vulnerability_findings in grouped.items():
        metadata = vulnerability_metadata.get(vulnerability_id)
        if getattr(metadata, "report_grouping", None) == "source_method":
            vulnerability_findings = _group_findings_by_source_method(
                vulnerability_findings
            )
        report_groups[vulnerability_id] = [
            _to_legacy_vulnerability(finding)
            for finding in vulnerability_findings
        ]

    return _apply_vulnerability_metadata(
        [
            {
                "vulnerability": vulnerability_id,
                "result": Vulnerabilities(findings=vulnerabilities),
            }
            for vulnerability_id, vulnerabilities in report_groups.items()
        ],
        vulnerability_metadata,
    )
