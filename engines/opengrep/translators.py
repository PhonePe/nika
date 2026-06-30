import json
import os

from models.sink import Sink


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
        key = (path, line_number)
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
            )
        )

    return sinks
