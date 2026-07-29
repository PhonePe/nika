import json
import logging

from reporting.code_reader import trace_signature
from schema.vulnerability_schema import Vulnerabilities


class JsonReportWriter:
    """Generates JSON reports containing only VULNERABLE or NEED_MANUAL_REVIEW findings."""

    def generate(self, findings: list, output_path: str = "report.json", degraded_findings: list | None = None, owasp_category_map: dict | None = None, debug_metadata: dict | None = None) -> str:
        vulnerable_findings = []
        seen_findings: set = set()
        owasp_category_map = owasp_category_map or {}
        debug_enabled = debug_metadata is not None
        total_call_nodes = 0

        for entry in findings:
            vuln_name = entry.get("VULNERABILITY_TITLE", entry.get("vulnerability", "Unknown"))
            vuln_description = entry.get("VULNERABILITY_DESCRIPTION", "")
            results = entry.get("result")
            vulns = results if isinstance(results, Vulnerabilities) else None
            if not vulns or not vulns.findings:
                continue

            for v in vulns.findings:
                if getattr(v, "type", "") in ("dependency", "cbom"):
                    continue

                if v.analysis is not None:
                    status = getattr(v.analysis, "vulnerable_status", "NEED_MANUAL_REVIEW")
                else:
                    status = "VULNERABLE"

                if status.strip().upper() not in ("VULNERABLE", "NEED_MANUAL_REVIEW"):
                    continue

                dedup_key = (
                    vuln_name,
                    getattr(v, "filename", "") or "",
                    getattr(v, "line_number", 0),
                    getattr(v, "sink", ""),
                    trace_signature(v),
                )
                if dedup_key in seen_findings:
                    continue
                seen_findings.add(dedup_key)

                finding_data = {
                    "vulnerability": vuln_name,
                    "description": vuln_description,
                    "owaspCategory": owasp_category_map.get(vuln_name, ""),
                    "status": status,
                    "sink": v.sink,
                    "filename": v.filename,
                    "lineNumber": v.line_number,
                    "lineNumberEnd": v.line_number_end,
                }

                api_path = {}
                if getattr(v, "class_api_path", None):
                    api_path["classPath"] = v.class_api_path
                if getattr(v, "method_api_path", None):
                    api_path["methodPath"] = v.method_api_path
                if api_path:
                    finding_data["apiPath"] = api_path

                metadata = getattr(v, "metadata", None) or {}
                if metadata:
                    finding_data["metadata"] = metadata

                if v.analysis:
                    finding_data["explanation"] = v.analysis.explanation
                    finding_data["remediation"] = v.analysis.remediation

                if v.call_graph:
                    finding_data["callGraph"] = [
                        {
                            "methodname": node.method_name,
                            "filename": node.filename,
                            "methodLineNumberStart": node.method_line_number_start,
                            "methodLineNumberEnd": node.method_line_number_end,
                            "calleeLineNumber": node.callee_line_number,
                            "isExternal": node.is_external,
                        }
                        for node in v.call_graph
                    ]

                if debug_enabled:
                    call_node_count = v.call_node_count
                    if call_node_count is None:
                        call_node_count = len(v.call_graph or [])
                    total_call_nodes += call_node_count

                    total_trace_loc = 0
                    for node_data, node in zip(finding_data.get("callGraph", []), v.call_graph or []):
                        start = node.method_line_number_start
                        end = node.method_line_number_end
                        loc = (end - start + 1) if (start and end and end >= start) else None
                        if loc is not None:
                            total_trace_loc += loc
                        node_data["debug"] = {
                            "linesOfCode": loc,
                        }

                    finding_data["debug"] = {
                        "callNodesBetweenSourceAndSink": call_node_count,
                        "totalTraceLinesOfCode": total_trace_loc,
                    }

                vulnerable_findings.append(finding_data)

        degraded_findings = degraded_findings or []

        report = {
            "reportType": "SAST",
            "totalVulnerableFindings": len(vulnerable_findings),
            "owaspCategoryMap": owasp_category_map,
            "findings": vulnerable_findings,
            "degradedFindings": degraded_findings,
        }

        if debug_enabled:
            report["debug"] = {
                **debug_metadata,
                "totalReportedFindings": len(vulnerable_findings),
                "totalDegradedFindings": len(degraded_findings),
                "totalCallNodes": total_call_nodes,
            }

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

        logging.info(
            "JSON report generated at %s with %d vulnerable findings and %d degraded findings",
            output_path,
            len(vulnerable_findings),
            len(degraded_findings),
        )
        return output_path
