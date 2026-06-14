import re
import os

_PATH_VAR_RE = re.compile(r"\{\s*([A-Za-z_$][\w$]*)\s*(?::[^}]*)?\}")

_PATH_PARAM_ANNOTATIONS = ("PathVariable", "PathParam")
_QUERY_PARAM_ANNOTATIONS = ("RequestParam", "QueryParam", "RequestHeader", "HeaderParam")
_REQUEST_BODY_ANNOTATIONS = ("RequestBody",)

_ACCESSOR_RE = re.compile(r"\b(?:get|is)([A-Z][\w$]*)\s*\(\s*\)")

# A bare `id` or a camelCase/snake_case `*Id` suffix
_GENERIC_ID_RE = re.compile(r"^(?:id|ID)$|[A-Za-z0-9]Id$|_id$")

OWNERSHIP_REPO_DELIM = "::"


def normalize(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (name or "").lower())


def is_generic_identifier(name: str) -> bool:
    if not name:
        return False
    return bool(_GENERIC_ID_RE.search(name))


def _matches(
    name: str,
    normalized_identifiers: set[str],
    *,
    match_generic: bool = False,
) -> bool:
    candidate = normalize(name)
    if not candidate:
        return False
    if any(
        candidate == identifier or candidate.endswith(identifier)
        for identifier in normalized_identifiers
        if identifier
    ):
        return True
    return bool(match_generic and is_generic_identifier(name))


def extract_path_variables(path: str) -> list[str]:
    if not path:
        return []
    return _PATH_VAR_RE.findall(path)


def _bound_names_from_code(code: str, annotation_names: tuple[str, ...]) -> list[str]:
    if not code:
        return []

    pattern = re.compile(
        r"@(?:" + "|".join(annotation_names) + r")\b\s*(\([^)]*\))?\s*([^,)]*)"
    )
    names: list[str] = []
    for match in pattern.finditer(code):
        paren, remainder = match.group(1) or "", match.group(2) or ""
        quoted = re.search(r'"([^"]+)"', paren)
        if quoted:
            names.append(quoted.group(1))
        words = re.findall(r"[A-Za-z_$][\w$]*", remainder)
        if words:
            names.append(words[-1])
    return names


def find_idor_identifier(
    path: str | None,
    code: str | None,
    identifiers: list[str],
    *,
    include_query_params: bool = False,
    scan_code: bool = True,
    match_generic_id: bool = False,
) -> tuple[str | None, str | None]:
    normalized_identifiers = {normalize(identifier) for identifier in identifiers if identifier}
    if not normalized_identifiers and not match_generic_id:
        return None, None

    for variable in extract_path_variables(path):
        if _matches(variable, normalized_identifiers, match_generic=match_generic_id):
            return variable, "path-template"

    if scan_code:
        annotation_names = _PATH_PARAM_ANNOTATIONS
        if include_query_params:
            annotation_names = annotation_names + _QUERY_PARAM_ANNOTATIONS
        for name in _bound_names_from_code(code, annotation_names):
            if _matches(name, normalized_identifiers, match_generic=match_generic_id):
                return name, "path-parameter"

    return None, None


def has_request_body_param(
    signature: str | None,
    body_annotations: tuple[str, ...] = _REQUEST_BODY_ANNOTATIONS,
) -> bool:
    if not signature:
        return False
    return any(
        re.search(r"@" + re.escape(annotation) + r"\b", signature)
        for annotation in body_annotations
    )


def find_request_body_identifier(
    signature: str | None,
    body_code: str | None,
    identifiers: list[str],
    *,
    body_annotations: tuple[str, ...] = _REQUEST_BODY_ANNOTATIONS,
    match_generic_id: bool = False,
) -> tuple[str | None, str | None]:
    if not has_request_body_param(signature, body_annotations):
        return None, None

    normalized_identifiers = {normalize(identifier) for identifier in identifiers if identifier}
    if (not normalized_identifiers and not match_generic_id) or not body_code:
        return None, None

    for field in _ACCESSOR_RE.findall(body_code):
        if _matches(field, normalized_identifiers, match_generic=match_generic_id):
            return field, "request-body"
    return None, None


_SOURCE_PHRASES = {
    "path-template": "the URL path ('{name}')",
    "path-parameter": "a request parameter ('{name}')",
    "request-body": "a request-body accessor ('{name}()')",
    "request-body-model": "a request-body field ('{name}')",
}


def _join_phrases(phrases: list[str]) -> str:
    if not phrases:
        return ""
    if len(phrases) == 1:
        return phrases[0]
    if len(phrases) == 2:
        return f"{phrases[0]} and {phrases[1]}"
    return ", ".join(phrases[:-1]) + f", and {phrases[-1]}"


def describe_idor_sources(matches) -> list[str]:
    phrases: list[str] = []
    seen: set[tuple[str, str]] = set()
    for name, how in matches or []:
        if (name, how) in seen:
            continue
        seen.add((name, how))
        phrases.append(_SOURCE_PHRASES.get(how, "'{name}'").format(name=name))
    return phrases


def build_idor_explanation(matches, signal: str | None = None) -> str:
    phrases = describe_idor_sources(matches)
    source = _join_phrases(phrases) if phrases else "a caller-supplied identifier"
    text = (
        f"This endpoint reads a direct object identifier from {source} and uses it to "
        f"reference a resource."
    )
    if signal:
        text += (
            f" A possible authorization check was detected ({signal}), but it was not "
            f"confirmed to bind this identifier to the authenticated principal; verify it "
            f"authorizes access to this object rather than only checking a role."
        )
    else:
        text += (
            " No ownership check tying the identifier to the authenticated principal was "
            "found, so a caller can likely reach another user's object by changing the value."
        )
    return text


def normalize_ownership_functions(raw) -> list[str]:
    delimiter = OWNERSHIP_REPO_DELIM

    def as_list(value):
        if isinstance(value, str):
            value = [value]
        return [str(item).strip() for item in (value or []) if str(item).strip()]

    encoded: list[str] = []
    for entry in raw or []:
        if isinstance(entry, str):
            name = entry.strip()
            if name:
                encoded.append(name)
            continue
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("name") or entry.get("function") or "").strip()
        if not name:
            continue
        repositories = as_list(
            entry.get("repository") or entry.get("repositories") or entry.get("repo")
        ) or [""]
        resources = as_list(
            entry.get("resource")
            or entry.get("resources")
            or entry.get("identifier")
            or entry.get("identifiers")
        )
        for repository in repositories:
            if resources:
                encoded.extend(
                    f"{name}{delimiter}{repository}{delimiter}{resource}"
                    for resource in resources
                )
            elif repository:
                encoded.append(f"{name}{delimiter}{repository}")
            else:
                encoded.append(name)

    seen: set[str] = set()
    deduped: list[str] = []
    for item in encoded:
        if item not in seen:
            seen.add(item)
            deduped.append(item)
    return deduped


def scope_ownership_to_repo(encoded, repo_path: str | None) -> list[str]:
    delimiter = OWNERSHIP_REPO_DELIM
    repo_name = os.path.basename(os.path.normpath((repo_path or "").lower()))
    out: list[str] = []
    for entry in encoded or []:
        parts = entry.split(delimiter)
        name = parts[0]
        repository = parts[1] if len(parts) >= 2 else ""
        resource = parts[2] if len(parts) >= 3 else ""
        if repository and repository.lower() != repo_name:
            continue
        out.append(f"{name}{delimiter}{delimiter}{resource}" if resource else name)
    return out


def find_ownership_annotation(
    signature: str | None,
    annotations: list[str] | None,
) -> str | None:
    if not signature:
        return None
    for annotation in annotations or []:
        if annotation and re.search(r"@" + re.escape(annotation) + r"\b", signature):
            return annotation
    return None
