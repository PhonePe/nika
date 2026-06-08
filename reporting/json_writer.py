import json
import logging

from reporting.code_reader import trace_signature
from schema.vulnerability_schema import Vulnerabilities


class JsonReportWriter:
    """Generates JSON reports containing only VULNERABLE or NEED_MANUAL_REVIEW findings."""

    def generate(self, findings: list, output_path: str = "report.json") -> str:
        vulnerable_findings = []
        seen_findings: set = set()

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

                if status.strip().upper() not in ("VULNERABLE", "NEED_MANUAL_REVIEW", "ENGINE_FAILURE"):
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

                if v.analysis:
                    finding_data["explanation"] = v.analysis.explanation
                    finding_data["remediation"] = v.analysis.remediation
                    finding_data["code_fix"] = v.analysis.code_fix

                if v.call_graph:
                    finding_data["callGraph"] = [
                        {
                            "methodname": node.method_name,
                            "filename": node.filename,
                            "calleeLineNumber": node.callee_line_number,
                            "isExternal": node.is_external,
                        }
                        for node in v.call_graph
                    ]

                vulnerable_findings.append(finding_data)

        report = {
            "reportType": "SAST",
            "totalVulnerableFindings": len(vulnerable_findings),
            "findings": vulnerable_findings,
        }

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

        logging.info("JSON report generated at %s with %d vulnerable findings", output_path, len(vulnerable_findings))
        return output_path
