import json
import os

from models.sink import Sink


_SINK_METAVARIABLE_PRIORITY = (
    "$TAINT",
    "$SQL",
    "$CMD",
    "$FILTER",
    "$PATH",
    "$URL",
    "$INPUT",
    "$ARG",
    "$PARAM",
    "$EXPR",
    "$TEMPLATE",
)


def _position(value: dict | None) -> dict:
    value = value or {}
    return {
        key: value.get(key)
        for key in ("line", "col", "offset")
        if value.get(key) is not None
    }


def _metavar_metadata(extra: dict) -> dict:
    normalized = {}
    for name, value in (extra.get("metavars") or {}).items():
        if not isinstance(value, dict):
            continue
        entry = {}
        if value.get("abstract_content") is not None:
            entry["abstract_content"] = value.get("abstract_content")
        start = _position(value.get("start"))
        end = _position(value.get("end"))
        if start:
            entry["start"] = start
        if end:
            entry["end"] = end
        propagated = value.get("propagated_value")
        if isinstance(propagated, dict):
            entry["propagated_value"] = propagated.get("svalue_abstract_content")
        if entry:
            normalized[name] = entry
    return normalized


def _sink_operand(metavars: dict, configured_name: str | None = None) -> dict | None:
    names = ([configured_name] if configured_name else []) + list(
        _SINK_METAVARIABLE_PRIORITY
    )
    for name in names:
        value = metavars.get(name)
        if not isinstance(value, dict) or not value.get("abstract_content"):
            continue
        return {
            "metavariable": name,
            "code": value["abstract_content"],
            "start": value.get("start") or {},
            "end": value.get("end") or {},
        }
    return None


def _result_metadata(result: dict, extra: dict, start: dict, end: dict) -> dict:
    metadata = dict(extra.get("metadata") or {})
    if result.get("check_id"):
        metadata["rule_id"] = result.get("check_id")
    metadata["match_start"] = _position(start)
    metadata["match_end"] = _position(end)
    metavars = _metavar_metadata(extra)
    if metavars:
        metadata["metavars"] = metavars
        operand = _sink_operand(metavars, metadata.get("sink_metavariable"))
        if operand:
            metadata["sink_operand"] = operand
    return metadata


def translate_opengrep_results(raw, repo_path: str) -> list[Sink]:
    payload = json.loads(raw) if isinstance(raw, str) else raw
    sinks = []
    seen = set()

    for result in payload.get("results", []):
        path = result.get("path", "")
        if os.path.isabs(path):
            path = os.path.relpath(path, repo_path)

        start = result.get("start", {}) or {}
        end = result.get("end", {}) or {}
        extra = result.get("extra", {}) or {}

        line_number = start.get("line", 0)
        metadata = _result_metadata(result, extra, start, end)
        metadata["sink_id"] = "|".join(
            str(value or "")
            for value in (
                result.get("check_id"),
                path,
                start.get("line"),
                start.get("col"),
                end.get("line"),
                end.get("col"),
            )
        )
        operand = metadata.get("sink_operand") or {}
        key = (
            path,
            result.get("check_id"),
            start.get("line"),
            start.get("col"),
            end.get("line"),
            end.get("col"),
            operand.get("metavariable"),
            operand.get("code"),
        )
        if key in seen:
            continue
        seen.add(key)

        sinks.append(
            Sink(
                rule_id=result.get("check_id"),
                file_path=path,
                line_number=line_number,
                line_number_end=end.get("line"),
                code=(extra.get("lines") or "").strip(),
                metadata=metadata,
            )
        )

    return sinks
