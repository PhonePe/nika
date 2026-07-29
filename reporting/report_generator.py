import logging
import os

from reporting.code_reader import CodeSnippetReader
from reporting.html_renderer import HtmlReportRenderer
from reporting.json_writer import JsonReportWriter
from schema.vulnerability_schema import Vulnerabilities


class ReportGenerator:
    def __init__(self, findings, state, scan_type=None, degraded_findings=None, owasp_category_map=None, debug_metadata=None, **kwargs):
        legacy_scan_type = kwargs.pop("scanType", None)
        if kwargs:
            unexpected = ", ".join(sorted(kwargs.keys()))
            raise TypeError(f"Unexpected keyword arguments: {unexpected}")
        self.findings = findings
        self.state = state
        self.scan_type = scan_type if scan_type is not None else legacy_scan_type
        self.degraded_findings = degraded_findings or []
        self.owasp_category_map = owasp_category_map or {}
        self.debug_metadata = debug_metadata

        self._code_reader = CodeSnippetReader(state.code_path)
        self._html_renderer = HtmlReportRenderer(self._code_reader)
        self._json_writer = JsonReportWriter()

    def generate_report(self, output_path="report.html"):
        self._log_findings_summary()

        html_report = self._html_renderer.render(self.findings, self.state)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_report)

        json_output_path = os.path.splitext(output_path)[0] + ".json"
        self._json_writer.generate(self.findings, json_output_path, self.degraded_findings, self.owasp_category_map, self.debug_metadata)

        return "Report generated successfully."

    def generate_json_report(self, output_path: str = "report.json") -> str:
        return self._json_writer.generate(self.findings, output_path, self.degraded_findings, self.owasp_category_map, self.debug_metadata)

    def generate_html_report(self) -> str:
        return self._html_renderer.render(self.findings, self.state)

    def _log_findings_summary(self):
        for finding in self.findings:
            logging.info("=== Finding ===")
            vuln_name = finding.get("VULNERABILITY_TITLE", finding.get("vulnerability", "Unknown"))
            logging.info(vuln_name)

            results = finding.get("result")
            if not isinstance(results, Vulnerabilities) or not results.findings:
                continue

            for result in results.findings:
                logging.info("Sink: %s", result.sink)
                if result.analysis:
                    logging.info("Analysis: %s", result.analysis.explanation)
                    logging.info("Vulnerability Status: %s", result.analysis.vulnerable_status)
        logging.info("=== End Finding ===")

