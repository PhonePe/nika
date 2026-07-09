import json
import logging
import os
import tempfile
import itertools
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from engines.astrail.errors import AstrailEngineError
from engines.astrail.server import get_astrail_server
from utils.common import execute_command


def _get_config():
    from config_provider import ConfigProvider

    return ConfigProvider.get_config()


def _scala_literal(value: str) -> str:
    escaped = (
        str(value)
        .replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
    )
    return f'"{escaped}"'


class AstrailQueryRunner:
    def __init__(self, repo_path: str):
        self.repo_path = repo_path
        self._project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        self._cpg_file_path = ""

    def _get_astrail_config(self) -> dict:
        config = _get_config()
        return (config.tools or {}).get("astrail", {})

    def _query_file_path(self, name: str) -> str:
        return os.path.join(self._project_root, "queries", name)

    @staticmethod
    def _write_params_file(params: dict) -> str:
        import base64
        fd, path = tempfile.mkstemp(suffix=".params")
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            first = True
            for key, value in params.items():
                if isinstance(value, bool):
                    values = ["true" if value else "false"]
                elif isinstance(value, (str, bytes)):
                    values = [value]
                elif hasattr(value, "__iter__"):
                    values = value
                else:
                    values = [value]
                for item in values:
                    if item is None:
                        continue
                    encoded = base64.b64encode(str(item).encode("utf-8")).decode("ascii")
                    handle.write(("" if first else "\n") + f"{key}\t{encoded}")
                    first = False
        return path

    def _execute_query_sync(self, query: str, timeout: int = 300):
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        http = requests.Session()
        http.trust_env = False
        http.mount("http://", adapter)

        astrail_server = get_astrail_server()
        url = astrail_server.get_query_sync_url()

        try:
            response = http.post(
                url, json={"query": query}, timeout=timeout, auth=astrail_server.get_auth()
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.ConnectionError:
            return {
                "success": False,
                "error": f"Could not connect to Astrail server at {url}. Is it running?",
            }
        except requests.exceptions.Timeout:
            return {"success": False, "error": f"Query timed out after {timeout} seconds."}
        except Exception as exc:
            return {"success": False, "error": str(exc)}
        finally:
            http.close()

    def _execute_query_to_json(self, query: str):
        init_query = """import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Paths, StandardOpenOption}
import org.json4s._
import org.json4s.native.JsonMethods._
import org.json4s.native.Serialization
import org.json4s.native.Serialization.writePretty
import org.json4s.JsonDSL._
def save_as_json(reports: Any, path: String): Unit = {
    implicit val formats: Formats = Serialization.formats(NoTypeHints)
    val materialized = reports match {
        case iter: Iterator[_] => iter.toList
        case stream: Stream[_] => stream.toList
        case other => other
    }
    Files.write(
        Paths.get(path),
        writePretty(materialized).getBytes(StandardCharsets.UTF_8),
        StandardOpenOption.CREATE,
        StandardOpenOption.TRUNCATE_EXISTING
    )
}"""

        output_file = None
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp:
                output_file = tmp.name

            output_file_scala = output_file.replace("\\", "\\\\")
            script = (
                init_query
                + "\n"
                + query
                + "\n"
                + f'save_as_json(execute_once, "{output_file_scala}")'
            )

            result = self._execute_query_sync(script)
            if result.get("success") is False:
                raise AstrailEngineError(
                    f"Astrail query failed: {result.get('error', 'unknown')}"
                )

            if not output_file or not os.path.exists(output_file):
                raise AstrailEngineError(
                    "Output file not found after Astrail execution."
                )

            with open(output_file, "r", encoding="utf-8") as handle:
                data = handle.read()

            if not data:
                result = self._execute_query_sync(script)
                if result.get("success") is False:
                    raise AstrailEngineError(
                        f"Astrail query retry failed: {result.get('error', 'unknown')}"
                    )
                with open(output_file, "r", encoding="utf-8") as handle:
                    data = handle.read()

            if not data:
                raise AstrailEngineError(
                    "Astrail execution produced empty output file after retry."
                )

            return json.loads(data)
        except AstrailEngineError:
            raise
        except json.JSONDecodeError as exc:
            raise AstrailEngineError(f"Invalid JSON produced by Astrail: {exc}") from exc
        except Exception as exc:
            raise AstrailEngineError(f"Unexpected error executing Astrail query: {exc}") from exc
        finally:
            if output_file and os.path.exists(output_file):
                try:
                    os.remove(output_file)
                except OSError:
                    pass

    def _execute_scala_query(self, query_file_path: str, call: str):
        if not os.path.exists(query_file_path):
            raise AstrailEngineError(f"Query file not found: {query_file_path}")

        try:
            with open(query_file_path, "r", encoding="utf-8") as handle:
                query_content = handle.read()
        except OSError as exc:
            raise AstrailEngineError(
                f"Failed to read query file {query_file_path}: {exc}"
            ) from exc

        wrapped_query = query_content + f"""
def execute_once = {{
    {call}
}}
"""
        return self._execute_query_to_json(wrapped_query)

    def get_method_and_file_name(self, code: str, filename: str):
        params_tmp = self._write_params_file({"code": code, "filename": filename})
        try:
            params_escaped = params_tmp.replace("\\", "\\\\")
            try:
                result = self._execute_scala_query(
                    self._query_file_path("getFilenameFromMethodCode.scala"),
                    f'getMethodandFileName("{params_escaped}")',
                )
            except AstrailEngineError as exc:
                logging.warning(
                    "Astrail method lookup failed for filename=%s code=%s: %s",
                    filename,
                    code,
                    exc,
                )
                return json.dumps(
                    {
                        "fileName": "",
                        "methodName": "",
                        "error": "astrail_lookup_failed",
                        "detail": str(exc),
                    }
                )
        finally:
            if os.path.exists(params_tmp):
                try:
                    os.remove(params_tmp)
                except OSError:
                    pass
        if result is None:
            return '{"fileName": "", "methodName": ""}'
        if isinstance(result, str):
            return result
        if isinstance(result, dict):
            return json.dumps(result)
        if isinstance(result, list) and result:
            first = result[0]
            if isinstance(first, dict):
                return json.dumps(first)
            if isinstance(first, str):
                return first
        return '{"fileName": "", "methodName": ""}'

    def generate_cpg(self):
        logging.info("Starting CPG generation with Astrail for repo at %s. This may take a while...", self.repo_path)
        output_dir = os.path.join(self._project_root, "output")
        os.makedirs(output_dir, exist_ok=True)

        output_cpg_path = os.path.join(
            output_dir, f"{os.path.splitext(os.path.basename(self.repo_path))[0]}.cpg"
        )

        astrail_config = self._get_astrail_config()
        tool_name = astrail_config.get("javasrc2cpg")
        if not tool_name:
            raise RuntimeError("config.tools.astrail.javasrc2cpg is not set")
        cmd = [
            tool_name,
            self.repo_path,
            "--output",
            output_cpg_path,
            "--delombok-mode",
            "no-delombok",
            "--exclude",
            "lib/**",
        ]

        for jar_path in astrail_config.get("inference_jar_paths", []) or []:
            if jar_path:
                cmd.extend(["--inference-jar-paths", str(jar_path)])

        command_result = execute_command(cmd)
        logging.info("CPG generation duration: %s seconds", command_result.duration_sec)
        if not command_result.ok or not os.path.exists(output_cpg_path):
            self._cpg_file_path = ""
            return "error"

        self._cpg_file_path = output_cpg_path
        return "ok"

    def find_sources(self, source_definitions: dict[str, list[str]] | None = None):
        if source_definitions is None:
            source_definitions = {"default": list(_get_config().sources.annotations)}
        else:
            source_definitions["default"] = list(_get_config().sources.annotations)

        annotations = []
        servlet_methods = []
        for tokens in source_definitions.values():
            for token in tokens:
                if not token:
                    continue
                if token.startswith("@"):
                    name = token[1:]
                    if name not in annotations:
                        annotations.append(name)
                elif token not in servlet_methods:
                    servlet_methods.append(token)

        annotations_list_str = ", ".join(
            _scala_literal(annotation) for annotation in annotations
        )
        servlet_list_str = ", ".join(
            _scala_literal(name) for name in servlet_methods
        )
        source_method_fqns = list(_get_config().sources.source_methods or [])
        source_method_list_str = ", ".join(
            _scala_literal(name) for name in source_method_fqns if name
        )
        result = self._execute_scala_query(
            self._query_file_path("getApiPath.scala"),
            "getAPIData("
            f"Set({annotations_list_str}), "
            f"Set({servlet_list_str}), "
            f"Set({source_method_list_str}))",
        )

        if isinstance(result, str):
            try:
                return json.loads(result)
            except json.JSONDecodeError as exc:
                raise AstrailEngineError(
                    "Astrail source query returned invalid JSON string payload"
                ) from exc
        return result

    @staticmethod
    def _encode_pairs(pairs):
        for source, sink in pairs:
            yield f"{source.methodName}\t{sink.get('lineNumber', '')}\t{sink.get('file', '')}"

    @staticmethod
    def _seq_literal(values) -> str:
        return "Seq(" + ", ".join(_scala_literal(v) for v in (values or []) if v) + ")"

    def run_batch_reachability(self, pairs, sanitizers=None, exclude_arg_annotations=None, exclude_arg_types=None):
        CHUNK_SIZE = self._get_astrail_config().get("chunk_size", 100_000)
        iterator_pairs = iter(pairs)
        chunks = list(itertools.islice(iterator_pairs, CHUNK_SIZE))
        if not chunks:
            return []
        results = []
        processed_pairs = 0
        try:
            while chunks:
                processed_pairs += len(chunks)
                logging.info("Processing batch reachability chunk with %d pairs processed so far", processed_pairs)
                chunk_results = self.run_batch_reachability_chunk(
                    chunks,
                    sanitizers,
                    exclude_arg_annotations=exclude_arg_annotations,
                    exclude_arg_types=exclude_arg_types,
                )
                results.extend(chunk_results)
                chunks = list(itertools.islice(iterator_pairs, CHUNK_SIZE))
        except Exception as exc:
            raise AstrailEngineError(f"Error in batch reachability: {exc}") from exc
        return results 

    def run_batch_reachability_chunk(self, pairs, sanitizers=None, exclude_arg_annotations=None, exclude_arg_types=None):
        params_tmp = self._write_params_file({"pair": self._encode_pairs(pairs)})
        if os.path.getsize(params_tmp) == 0:
            os.remove(params_tmp)
            return []

        ping_result = self._execute_query_sync("1")
        if ping_result.get("success") is False:
            os.remove(params_tmp)
            raise AstrailEngineError(
                "Astrail server is not reachable for batch reachability."
            )

        query_file = self._query_file_path("batchReachabilityCheck.scala")
        if not os.path.exists(query_file):
            os.remove(params_tmp)
            raise AstrailEngineError(f"Batch query file not found: {query_file}")

        output_tmp = None
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as handle:
                output_tmp = handle.name

            with open(query_file, "r", encoding="utf-8") as handle:
                query_content = handle.read()

            params_escaped = params_tmp.replace("\\", "\\\\")
            output_escaped = output_tmp.replace("\\", "\\\\")
            sanitizer_seq = self._seq_literal(sanitizers)
            exclude_anno_seq = self._seq_literal(exclude_arg_annotations)
            exclude_type_seq = self._seq_literal(exclude_arg_types)
            script = query_content + (
                f'\nfindPathsBatch("{params_escaped}", "{output_escaped}", '
                f'{sanitizer_seq}, {exclude_anno_seq}, {exclude_type_seq})'
            )
            result = self._execute_query_sync(script, timeout=3600)

            if result.get("success") is False:
                raise AstrailEngineError(
                    f"Batch reachability query failed: {result.get('error', 'unknown')}"
                )

            if output_tmp and os.path.exists(output_tmp):
                with open(output_tmp, "r", encoding="utf-8") as handle:
                    data = handle.read()
                if data:
                    return json.loads(data)
            return []
        except AstrailEngineError:
            raise
        except Exception as exc:
            raise AstrailEngineError(f"Error in batch reachability: {exc}") from exc
        finally:
            for tmp in [params_tmp, output_tmp]:
                if tmp and os.path.exists(tmp):
                    try:
                        os.remove(tmp)
                    except OSError:
                        pass

    def run_aggressive_reachability(self, pairs, sanitizers=None):
        params_tmp = self._write_params_file({"pair": self._encode_pairs(pairs)})
        if os.path.getsize(params_tmp) == 0:
            os.remove(params_tmp)
            return []

        ping_result = self._execute_query_sync("1")
        if ping_result.get("success") is False:
            os.remove(params_tmp)
            raise AstrailEngineError(
                "Astrail server is not reachable for aggressive reachability."
            )

        query_file = self._query_file_path("aggressiveReachabilityCheck.scala")
        if not os.path.exists(query_file):
            os.remove(params_tmp)
            raise AstrailEngineError(f"Aggressive query file not found: {query_file}")

        output_tmp = None
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as handle:
                output_tmp = handle.name

            with open(query_file, "r", encoding="utf-8") as handle:
                query_content = handle.read()

            params_escaped = params_tmp.replace("\\", "\\\\")
            output_escaped = output_tmp.replace("\\", "\\\\")
            sanitizer_seq = self._seq_literal(sanitizers)
            script = query_content + (
                f'\nfindAggressivePathsBatch("{params_escaped}", "{output_escaped}", {sanitizer_seq})'
            )
            result = self._execute_query_sync(script, timeout=3600)

            if result.get("success") is False:
                raise AstrailEngineError(
                    f"Aggressive reachability query failed: {result.get('error', 'unknown')}"
                )

            if output_tmp and os.path.exists(output_tmp):
                with open(output_tmp, "r", encoding="utf-8") as handle:
                    data = handle.read()
                if data:
                    return json.loads(data)

            return []
        except AstrailEngineError:
            raise
        except Exception as exc:
            raise AstrailEngineError(f"Error in aggressive reachability: {exc}") from exc
        finally:
            for tmp in [params_tmp, output_tmp]:
                if tmp and os.path.exists(tmp):
                    try:
                        os.remove(tmp)
                    except OSError:
                        pass

    def run_const_arg_resolution(self, locations):
        if not locations:
            return []

        ping_result = self._execute_query_sync("1")
        if ping_result.get("success") is False:
            raise AstrailEngineError(
                "Astrail server is not reachable for constant-argument resolution."
            )

        query_file = self._query_file_path("resolveConstArg.scala")
        if not os.path.exists(query_file):
            raise AstrailEngineError(f"Resolver query file not found: {query_file}")

        params_tmp = self._write_params_file(
            {"location": [f"{file_path}\t{line_number}" for file_path, line_number in locations]}
        )
        output_tmp = None
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as handle:
                output_tmp = handle.name

            with open(query_file, "r", encoding="utf-8") as handle:
                query_content = handle.read()

            params_escaped = params_tmp.replace("\\", "\\\\")
            output_escaped = output_tmp.replace("\\", "\\\\")
            script = query_content + (
                f'\nresolveBatch("{params_escaped}", "{output_escaped}")'
            )
            result = self._execute_query_sync(script, timeout=1800)
            if result.get("success") is False:
                raise AstrailEngineError(
                    f"Constant-argument resolution failed: {result.get('error', 'unknown')}"
                )

            if output_tmp and os.path.exists(output_tmp):
                with open(output_tmp, "r", encoding="utf-8") as handle:
                    data = handle.read()
                if data:
                    return json.loads(data)
            return []
        except AstrailEngineError:
            raise
        except Exception as exc:
            raise AstrailEngineError(f"Error in constant-argument resolution: {exc}") from exc
        finally:
            for tmp in [params_tmp, output_tmp]:
                if tmp and os.path.exists(tmp):
                    try:
                        os.remove(tmp)
                    except OSError:
                        pass

    def run_ownership_reachability(
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
        if not endpoint_symbols:
            return []

        endpoint_identifiers = endpoint_identifiers or {}

        ping_result = self._execute_query_sync("1")
        if ping_result.get("success") is False:
            raise AstrailEngineError(
                "Astrail server is not reachable for ownership reachability."
            )

        query_file = self._query_file_path("ownershipReachability.scala")
        if not os.path.exists(query_file):
            raise AstrailEngineError(f"Ownership query file not found: {query_file}")

        endpoint_lines = [
            f"{symbol}\t{','.join(endpoint_identifiers.get(symbol, []) or [])}"
            for symbol in endpoint_symbols
            if symbol
        ]
        params_tmp = self._write_params_file(
            {
                "principalMarker": principal_markers,
                "principalType": principal_types,
                "principalAnnotation": principal_annotations,
                "identifier": identifier_names,
                "explicitFunction": explicit_functions,
                "requireIdentifierParam": require_identifier_param,
                "requireComparison": require_comparison,
                "matchGenericId": match_generic_id,
                "ownershipAnnotation": ownership_annotations or [],
                "endpoint": endpoint_lines,
            }
        )

        output_tmp = None
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as handle:
                output_tmp = handle.name

            with open(query_file, "r", encoding="utf-8") as handle:
                query_content = handle.read()

            params_escaped = params_tmp.replace("\\", "\\\\")
            output_escaped = output_tmp.replace("\\", "\\\\")
            script = query_content + (
                f'\nfindOwnershipReachable("{params_escaped}", "{output_escaped}")'
            )
            result = self._execute_query_sync(script, timeout=1800)

            if result.get("success") is False:
                raise AstrailEngineError(
                    f"Ownership reachability query failed: {result.get('error', 'unknown')}"
                )

            if output_tmp and os.path.exists(output_tmp):
                with open(output_tmp, "r", encoding="utf-8") as handle:
                    data = handle.read()
                if data:
                    return json.loads(data)
            return []
        except AstrailEngineError:
            raise
        except Exception as exc:
            raise AstrailEngineError(f"Error in ownership reachability: {exc}") from exc
        finally:
            for tmp in [params_tmp, output_tmp]:
                if tmp and os.path.exists(tmp):
                    try:
                        os.remove(tmp)
                    except OSError:
                        pass

    def run_request_body_identifiers(
        self,
        endpoint_symbols,
        identifier_names,
        body_annotations,
        match_generic_id: bool = True,
    ):
        if not endpoint_symbols:
            return []

        ping_result = self._execute_query_sync("1")
        if ping_result.get("success") is False:
            raise AstrailEngineError(
                "Astrail server is not reachable for request-body identifier analysis."
            )

        query_file = self._query_file_path("requestBodyIdentifiers.scala")
        if not os.path.exists(query_file):
            raise AstrailEngineError(f"Request-body query file not found: {query_file}")

        params_tmp = self._write_params_file(
            {
                "identifier": identifier_names,
                "bodyAnnotation": body_annotations,
                "matchGenericId": match_generic_id,
                "endpoint": [symbol for symbol in endpoint_symbols if symbol],
            }
        )

        output_tmp = None
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as handle:
                output_tmp = handle.name

            with open(query_file, "r", encoding="utf-8") as handle:
                query_content = handle.read()

            params_escaped = params_tmp.replace("\\", "\\\\")
            output_escaped = output_tmp.replace("\\", "\\\\")
            script = query_content + (
                f'\nfindRequestBodyIdentifiers("{params_escaped}", "{output_escaped}")'
            )
            result = self._execute_query_sync(script, timeout=1800)

            if result.get("success") is False:
                raise AstrailEngineError(
                    f"Request-body identifier query failed: {result.get('error', 'unknown')}"
                )

            if output_tmp and os.path.exists(output_tmp):
                with open(output_tmp, "r", encoding="utf-8") as handle:
                    data = handle.read()
                if data:
                    return json.loads(data)
            return []
        except AstrailEngineError:
            raise
        except Exception as exc:
            raise AstrailEngineError(
                f"Error in request-body identifier analysis: {exc}"
            ) from exc
        finally:
            for tmp in [params_tmp, output_tmp]:
                if tmp and os.path.exists(tmp):
                    try:
                        os.remove(tmp)
                    except OSError:
                        pass

    def run_ssrf_flow_analysis(
        self,
        pairs,
        sink_names=None,
        receiver_only_sinks=None,
    ):
        pair_values = list(self._encode_pairs(pairs))
        if not pair_values:
            return []

        ping_result = self._execute_query_sync("1")
        if ping_result.get("success") is False:
            raise AstrailEngineError(
                "Astrail server is not reachable for SSRF flow analysis."
            )

        query_file = self._query_file_path("ssrfFlow.scala")
        if not os.path.exists(query_file):
            raise AstrailEngineError(f"SSRF flow query file not found: {query_file}")

        params_tmp = self._write_params_file(
            {
                "pair": pair_values,
                "sinkName": sink_names or [],
                "receiverOnlySink": receiver_only_sinks or [],
            }
        )
        output_tmp = None
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as handle:
                output_tmp = handle.name

            with open(query_file, "r", encoding="utf-8") as handle:
                query_content = handle.read()

            params_escaped = params_tmp.replace("\\", "\\\\")
            output_escaped = output_tmp.replace("\\", "\\\\")
            script = query_content + (
                f'\nfindSsrfFlows("{params_escaped}", "{output_escaped}")'
            )
            result = self._execute_query_sync(script, timeout=1800)

            if result.get("success") is False:
                raise AstrailEngineError(
                    f"SSRF flow query failed: {result.get('error', 'unknown')}"
                )

            if output_tmp and os.path.exists(output_tmp):
                with open(output_tmp, "r", encoding="utf-8") as handle:
                    data = handle.read()
                if data:
                    return json.loads(data)
            return []
        except AstrailEngineError:
            raise
        except Exception as exc:
            raise AstrailEngineError(
                f"Error in SSRF flow analysis: {exc}"
            ) from exc
        finally:
            for tmp in [params_tmp, output_tmp]:
                if tmp and os.path.exists(tmp):
                    try:
                        os.remove(tmp)
                    except OSError:
                        pass

    def run_open_redirect_flow_analysis(
        self,
        pairs,
        source_annotations=None,
        request_accessors=None,
    ):
        pair_values = list(self._encode_pairs(pairs))
        if not pair_values:
            return []

        ping_result = self._execute_query_sync("1")
        if ping_result.get("success") is False:
            raise AstrailEngineError(
                "Astrail server is not reachable for open-redirect flow analysis."
            )

        query_file = self._query_file_path("openRedirectFlow.scala")
        if not os.path.exists(query_file):
            raise AstrailEngineError(f"Open-redirect flow query file not found: {query_file}")

        params_tmp = self._write_params_file(
            {
                "pair": pair_values,
                "sourceAnnotation": source_annotations or [],
                "requestAccessor": request_accessors or [],
            }
        )
        output_tmp = None
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as handle:
                output_tmp = handle.name

            with open(query_file, "r", encoding="utf-8") as handle:
                query_content = handle.read()

            params_escaped = params_tmp.replace("\\", "\\\\")
            output_escaped = output_tmp.replace("\\", "\\\\")
            script = query_content + (
                f'\nfindOpenRedirectFlows("{params_escaped}", "{output_escaped}")'
            )
            result = self._execute_query_sync(script, timeout=1800)

            if result.get("success") is False:
                raise AstrailEngineError(
                    f"Open-redirect flow query failed: {result.get('error', 'unknown')}"
                )

            if output_tmp and os.path.exists(output_tmp):
                with open(output_tmp, "r", encoding="utf-8") as handle:
                    data = handle.read()
                if data:
                    return json.loads(data)
            return []
        except AstrailEngineError:
            raise
        except Exception as exc:
            raise AstrailEngineError(
                f"Error in open-redirect flow analysis: {exc}"
            ) from exc
        finally:
            for tmp in [params_tmp, output_tmp]:
                if tmp and os.path.exists(tmp):
                    try:
                        os.remove(tmp)
                    except OSError:
                        pass

    def _execute_astrail_script(
        self,
        script_name: str,
        params: dict[str, str],
        timeout: int = 600,
    ):
        astrail_config = self._get_astrail_config()
        astrail_path = astrail_config.get("astrailpath")
        if not astrail_path:
            raise RuntimeError("config.tools.astrail.astrailpath is not set")

        script_path = self._query_file_path(script_name)
        if not os.path.exists(script_path):
            raise FileNotFoundError(f"Astrail script not found: {script_path}")

        cmd = [astrail_path, "--script", script_path]
        for key, value in params.items():
            cmd.extend(["--param", f"{key}={value}"])

        result = execute_command(cmd, cwd=self._project_root, timeout=timeout)
        if not result.ok:
            logging.error(
                "Astrail script failed: %s %s",
                script_name,
                result.stderr or result.stdout,
            )
            return False
        return True

    def execute_query_once(self, query: str):
        return self._execute_query_sync(query)

    @property
    def cpg_file_path(self) -> str:
        return self._cpg_file_path
