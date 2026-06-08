from models.source import Source
from models.trace import Trace, TraceNode


def _normalize_optional_int(value):
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def translate_sources(raw: list[dict]) -> list[Source]:
    sources = []

    for entry in raw:
        sources.append(
            Source(
                symbol=entry.get("methodName", ""),
                file_path=entry.get("fileName", ""),
                line_number=entry.get("lineNumber"),
                code=entry.get("code"),
                metadata={
                    "class_api_path": entry.get("classAPIPath") or "",
                    "method_api_path": entry.get("methodAPIPath") or "",
                },
            )
        )

    return sources


def _extract_source_symbol(entry: dict) -> str | None:
    source = entry.get("source")
    if isinstance(source, str) and source:
        return source
    return None

def translate_batch_reachability(raw: list[dict]) -> list[Trace]:
    traces = []

    for entry in raw:
        nodes = []
        for node in entry.get("path", []):
            is_external = node.get("isExternal", False)
            if isinstance(is_external, str):
                is_external = is_external.lower() == "true"

            nodes.append(
                TraceNode(
                    method_name=node.get("methodname", ""),
                    file_path=node.get("filename", ""),
                    code=node.get("code", ""),
                    callee_code=node.get("calleeCode"),
                    callee_line_number=_normalize_optional_int(
                        node.get("calleeLineNumber")
                    ),
                    is_external=bool(is_external),
                    method_line_number_start=_normalize_optional_int(
                        node.get("methodLineNumberStart")
                    ),
                    method_line_number_end=_normalize_optional_int(
                        node.get("methodLineNumberEnd")
                    ),
                )
            )

        traces.append(
            Trace(
                sink_file_path=entry.get("fileName", ""),
                sink_line_number=int(entry.get("lineNumber") or 0),
                nodes=nodes,
                source_symbol=_extract_source_symbol(entry),
            )
        )

    return traces
