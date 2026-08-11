import logging
from time import perf_counter

from config_provider import ConfigProvider
from reporting.report_generator import ReportGenerator
from reporting.report_models_adapter import (
    collect_degraded_findings,
    group_findings_for_legacy_report,
)
from reporting.owasp import resolve_owasp_category_map

from runtime.registry import Registry, build_default_registry
from runtime.scan_runner import ScanRunner
from utils.common import count_lines_of_code
from utils.token_tracker import TokenTracker


_LANGUAGE_SOURCE_EXTENSIONS = {
    "java": [".java"],
}


class LegacyReportStateAdapter:
    def __init__(self, request, total_sources_found: int = 0, total_time_taken: str | None = None):
        self.code_path = request.path
        self.source_branch = getattr(request, "source_branch", None)
        self.target_branch = getattr(request, "target_branch", None)
        self.total_sources_found = total_sources_found
        self.total_time_taken = total_time_taken


class RuntimeValidator:
    def __init__(self, registry):
        self.registry = registry

    def validate(self, request):
        if request.language not in self.registry.languages:
            raise ValueError(f"Unknown language: {request.language}")

        for role, engine_name in request.engine_selection.items():
            if role not in self.registry.engines:
                raise ValueError(f"Unknown engine role: {role}")
            if engine_name not in self.registry.engines[role]:
                raise ValueError(
                    f"Unknown engine '{engine_name}' for role: {role}"
                )

        for vulnerability_name in request.enabled_vulnerabilities:
            if vulnerability_name not in self.registry.vulnerabilities:
                raise ValueError(f"Unknown vulnerability: {vulnerability_name}")

            vulnerability = self.registry.create_vulnerability(vulnerability_name)
            for role in vulnerability.required_engine_roles:
                if role not in request.engine_selection:
                    raise ValueError(
                        f"Missing engine selection for role: {role}"
                    )
                if role not in self.registry.engines:
                    raise ValueError(f"Unknown engine role: {role}")
                engine_name = request.engine_selection[role]
                if engine_name not in self.registry.engines[role]:
                    raise ValueError(
                        f"Unknown engine '{engine_name}' for role: {role}"
                    )


class NikaApplicationRuntime:
    def __init__(self, registry: Registry | None = None, config=None):
        self.registry = registry if registry is not None else build_default_registry()
        self.config = config
        self.validator = RuntimeValidator(self.registry)
        self.scan_runner = ScanRunner(self.registry)

    def _get_config(self):
        if self.config is None:
            self.config = ConfigProvider.get_config()
        return self.config

    def _build_engine_selection(self):
        return {
            "sink_finder": "opengrep",
            "source_finder": "astrail",
            "dataflow_analyzer": "astrail",
            "order_finder": "order_analyzer",
        }

    def _build_enabled_vulnerabilities(self):
        configured_vulnerabilities = self._get_config().vulnerability_config
        registered_vulnerabilities = self.registry.vulnerabilities
        return [
            vulnerability_name
            for vulnerability_name in configured_vulnerabilities
            if vulnerability_name in registered_vulnerabilities
        ]

    def _is_llm_review_enabled(self):
        return self._get_config().llm_review_enabled

    def _format_duration(self, elapsed_seconds):
        minutes, seconds = divmod(elapsed_seconds, 60)
        hours, minutes = divmod(int(minutes), 60)
        if hours:
            return f"{hours}h {minutes}m {seconds:.2f}s"
        if minutes:
            return f"{minutes}m {seconds:.2f}s"
        return f"{elapsed_seconds:.2f}s"

    def _format_scan_summary_table(self, rows):
        metric_width = max(len("Metric"), *(len(metric) for metric, _ in rows))
        value_width = max(len("Value"), *(len(value) for _, value in rows))
        border = f"+-{'-' * metric_width}-+-{'-' * value_width}-+"
        lines = [
            "",
            "SCAN SUMMARY",
            border,
            f"| {'Metric'.ljust(metric_width)} | {'Value'.ljust(value_width)} |",
            border,
        ]
        for metric, value in rows:
            lines.append(f"| {metric.ljust(metric_width)} | {value.ljust(value_width)} |")
        lines.append(border)
        return lines

    def _log_scan_summary(self, request, findings, elapsed_seconds):
        run_stats = self.scan_runner.last_run_stats
        token_snapshot = TokenTracker.get_instance().snapshot()
        llm_enabled = getattr(request, "review_llm_enabled", False)

        total_sources = run_stats.total_sources if run_stats is not None else 0
        total_findings = run_stats.total_findings if run_stats is not None else len(findings)
        false_positive_value = (
            str(run_stats.total_false_positives)
            if llm_enabled and run_stats is not None
            else ("0" if llm_enabled else "N/A")
        )
        total_tokens_value = str(token_snapshot["total_tokens"]) if llm_enabled else "N/A"
        cached_tokens_value = (
            str(token_snapshot["cached_prompt_tokens"])
            if llm_enabled
            else "N/A"
        )
        total_cost_value = f"${token_snapshot['total_cost']:.4f}" if llm_enabled else "N/A"

        rows = [
            ("Total Sources Found", str(total_sources)),
            ("Total Findings", str(total_findings)),
            ("Total False Positives", false_positive_value),
            ("Total Time Taken", self._format_duration(elapsed_seconds)),
            ("Total Tokens Used", total_tokens_value),
            ("Cached Prompt Tokens", cached_tokens_value),
            ("Total Cost", total_cost_value),
        ]

        for line in self._format_scan_summary_table(rows):
            logging.info(line)

    def run(self, request):
        token_tracker = TokenTracker.get_instance()
        token_tracker.reset()
        started_at = perf_counter()

        if not request.enabled_vulnerabilities:
            request.enabled_vulnerabilities = self._build_enabled_vulnerabilities()
        if not request.engine_selection:
            request.engine_selection = self._build_engine_selection()

        request.review_llm_enabled = self._is_llm_review_enabled()

        self.validator.validate(request)
        findings = self.scan_runner.run(request)
        elapsed_seconds = perf_counter() - started_at
        vulnerability_metadata = {
            vulnerability_name: self.registry.create_vulnerability(vulnerability_name)
            for vulnerability_name in request.enabled_vulnerabilities
        }
        report_input = group_findings_for_legacy_report(
            findings, vulnerability_metadata
        )
        degraded_findings = collect_degraded_findings(findings, vulnerability_metadata)
        owasp_by_id = resolve_owasp_category_map(
            ConfigProvider.get_config().owasp_category_map
        )
        owasp_category_map = {
            getattr(metadata, "title", vulnerability_name): owasp_by_id.get(
                vulnerability_name, ""
            )
            for vulnerability_name, metadata in vulnerability_metadata.items()
        }
        run_stats = self.scan_runner.last_run_stats
        report_state = LegacyReportStateAdapter(
            request,
            total_sources_found=run_stats.total_sources if run_stats is not None else 0,
            total_time_taken=self._format_duration(elapsed_seconds),
        )
        debug_metadata = None
        if getattr(request, "debug", False):
            extensions = _LANGUAGE_SOURCE_EXTENSIONS.get(request.language, [])
            loc_stats = count_lines_of_code(request.path, extensions)
            debug_metadata = {
                "scanPath": request.path,
                "language": request.language,
                "totalTimeSeconds": round(elapsed_seconds, 2),
                "totalSourcesFound": run_stats.total_sources if run_stats is not None else 0,
                "enabledVulnerabilities": list(request.enabled_vulnerabilities),
                **loc_stats,
            }
        ReportGenerator(
            report_input,
            report_state,
            scan_type="FullScan",
            degraded_findings=degraded_findings,
            owasp_category_map=owasp_category_map,
            debug_metadata=debug_metadata,
        ).generate_report(
            output_path=request.output
        )
        self._log_scan_summary(request, findings, elapsed_seconds)
        return findings
