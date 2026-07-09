import logging
import sys
from types import SimpleNamespace

from config_provider import ConfigProvider
from engines.astrail.query_runner import AstrailQueryRunner, _scala_literal
from engines.astrail.server import get_astrail_server
from engines.astrail.translators import (
    translate_batch_reachability,
    translate_sources,
)


class AstrailEngine:
    requires_exclusive_run = True

    def __init__(self, repo_path: str):
        self.repo_path = repo_path
        self.query_runner = None

    def _get_query_runner(self):
        if self.query_runner is None:
            self.query_runner = AstrailQueryRunner(self.repo_path)
        return self.query_runner

    def prepare(self):
        query_runner = self._get_query_runner()
        if query_runner.generate_cpg() != "ok":
            raise RuntimeError("Astrail CPG generation failed")

        astrail_server = get_astrail_server()
        astrail_server.set_cpg_path(query_runner.cpg_file_path)
        port = ConfigProvider.get_config().tools.get("astrail", {}).get("port", 9001)
        try:
            astrail_server.start(port=port)
        except RuntimeError as e:
            logging.error("Failed to start Astrail server: Please ensure port is free and Astrail is properly installed. Error details: %s", str(e))
            sys.exit(1)
        logging.info("Loading CPG into Astrail from %s", query_runner.cpg_file_path)
        import_result = query_runner.execute_query_once(
            f"importCpg({_scala_literal(query_runner.cpg_file_path)})"
        )
        if import_result.get("success") is False:
            raise RuntimeError(
                f"Astrail importCpg failed: {import_result.get('error', 'unknown error')}"
            )
        logging.info("Astrail CPG import successful")

    def cleanup(self):
        logging.info("Stopping Astrail server")
        get_astrail_server().stop()

    def find_sources(self, context, source_definitions: dict[str, list[str]]):
        raw_sources = self._get_query_runner().find_sources(source_definitions)
        return translate_sources(raw_sources)

    def find_traces(self, context, sources, sinks, sanitizers=None):
        if not sources or not sinks:
            return translate_batch_reachability([])

        pairs = (
            (
                SimpleNamespace(methodName=source.symbol),
                {"lineNumber": sink.line_number, "file": sink.file_path},
            )
            for sink in sinks
            for source in sources
        )

        config = ConfigProvider.get_config()
        if getattr(config, "aggressive_scan", False):
            batch_result = self._get_query_runner().run_aggressive_reachability(
                pairs, sanitizers=sanitizers
            )
        else:
            exclude_source_args = getattr(config, "exclude_source_args", None)
            exclude_arg_annotations = (
                list(exclude_source_args.annotations) if exclude_source_args else []
            )
            exclude_arg_types = (
                list(exclude_source_args.types) if exclude_source_args else []
            )
            batch_result = self._get_query_runner().run_batch_reachability(
                pairs,
                sanitizers=sanitizers,
                exclude_arg_annotations=exclude_arg_annotations,
                exclude_arg_types=exclude_arg_types,
            )

        return translate_batch_reachability(batch_result)

    def resolve_constant_args(self, context, locations):
        raw = self._get_query_runner().run_const_arg_resolution(locations)
        resolved = {}
        for entry in raw or []:
            resolved[(entry.get("file"), entry.get("line"))] = list(entry.get("values") or [])
        return resolved

    def find_ownership_protected(
        self,
        endpoint_symbols,
        principal_markers,
        principal_types,
        principal_annotations,
        identifier_names,
        explicit_functions,
        require_identifier_param: bool = True,
        require_comparison: bool = True,
        match_generic_id: bool = True,
        endpoint_identifiers: dict | None = None,
        ownership_annotations=None,
    ):
        raw = self._get_query_runner().run_ownership_reachability(
            endpoint_symbols,
            principal_markers,
            principal_types,
            principal_annotations,
            identifier_names,
            explicit_functions,
            require_identifier_param=require_identifier_param,
            require_comparison=require_comparison,
            match_generic_id=match_generic_id,
            endpoint_identifiers=endpoint_identifiers,
            ownership_annotations=ownership_annotations,
        )
        protected = {}
        for entry in raw or []:
            endpoint = entry.get("endpoint")
            if endpoint:
                protected[endpoint] = entry
        return protected

    def find_request_body_identifiers(
        self,
        endpoint_symbols,
        identifier_names,
        body_annotations,
        match_generic_id: bool = True,
    ):
        raw = self._get_query_runner().run_request_body_identifiers(
            endpoint_symbols,
            identifier_names,
            body_annotations,
            match_generic_id=match_generic_id,
        )
        results = {}
        for entry in raw or []:
            endpoint = entry.get("endpoint")
            if endpoint:
                results[endpoint] = entry
        return results

    def find_ssrf_flows(
        self,
        context,
        traces,
        sink_names=None,
        receiver_only_sinks=None,
    ):
        pairs = (
            (
                SimpleNamespace(methodName=trace.source_symbol),
                {"lineNumber": trace.sink_line_number, "file": trace.sink_file_path},
            )
            for trace in (traces or [])
            if getattr(trace, "source_symbol", None)
            and getattr(trace, "sink_line_number", None)
            and getattr(trace, "sink_file_path", None)
        )
        raw = self._get_query_runner().run_ssrf_flow_analysis(
            pairs,
            sink_names=sink_names,
            receiver_only_sinks=receiver_only_sinks,
        )
        results = {}
        for entry in raw or []:
            key = (
                entry.get("source"),
                entry.get("fileName"),
                int(entry.get("lineNumber") or 0),
            )
            results[key] = entry
        return results

    def find_open_redirect_flows(
        self,
        context,
        traces,
        source_annotations=None,
        request_accessors=None,
    ):
        pairs = (
            (
                SimpleNamespace(methodName=trace.source_symbol),
                {"lineNumber": trace.sink_line_number, "file": trace.sink_file_path},
            )
            for trace in (traces or [])
            if getattr(trace, "source_symbol", None)
            and getattr(trace, "sink_line_number", None)
            and getattr(trace, "sink_file_path", None)
        )
        raw = self._get_query_runner().run_open_redirect_flow_analysis(
            pairs,
            source_annotations=source_annotations,
            request_accessors=request_accessors,
        )
        results = {}
        for entry in raw or []:
            key = (
                entry.get("source"),
                entry.get("fileName"),
                int(entry.get("lineNumber") or 0),
            )
            results[key] = entry
        return results

    def get_method_and_file_name(self, code: str, filename: str):
        return self._get_query_runner().get_method_and_file_name(code, filename)
