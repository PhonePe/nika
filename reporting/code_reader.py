import os


def escape_html(text: str) -> str:
    return (
        (text or "")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def trace_signature(v) -> str:
    """Fingerprint of a finding's call graph for deduplication."""
    if not getattr(v, "call_graph", None):
        return ""
    return "|".join(
        f"{node.filename}:{node.callee_line_number}"
        for node in v.call_graph
    )


class CodeSnippetReader:
    """Reads source file segments and renders code snippets for reports."""

    def __init__(self, code_path: str):
        self.code_path = code_path

    def read_segment(self, filename: str, line_no: int, context: int = 2):
        """Read a segment of a file around a specific line number (1-based).

        Returns (before, target, after, start_line) where before/after are
        strings of surrounding lines and start_line is the 1-based first line.
        """
        try:
            if os.path.isabs(filename):
                full_path = filename
            else:
                full_path = os.path.join(self.code_path, filename)

            if not os.path.exists(full_path):
                return "", f"File not found: {filename}", "", line_no

            with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()

            total_lines = len(lines)
            target_idx = line_no - 1

            start_idx = max(0, target_idx - context)
            end_idx = min(total_lines, target_idx + context + 1)

            before = lines[start_idx:target_idx]
            target = lines[target_idx] if 0 <= target_idx < total_lines else ""
            after = lines[target_idx + 1 : end_idx]

            return "".join(before), target, "".join(after), start_idx + 1

        except Exception as e:
            return "", f"Error reading file: {str(e)}", "", line_no

    def render_snippet(self, before: str, target: str, after: str, start_line: int) -> str:
        html_lines = []
        current_line = start_line

        for line in before.splitlines():
            ln_html = f'<span class="ln">{current_line}</span>'
            code_span = f'<span class="code">{escape_html(line)}</span>'
            html_lines.append(f"{ln_html} {code_span}")
            current_line += 1

        if target:
            ln_html = f'<span class="ln">{current_line}</span>'
            code_span = f'<span class="code matched">{escape_html(target)}</span>'
            html_lines.append(f"{ln_html} {code_span}")
            current_line += 1

        for line in after.splitlines():
            ln_html = f'<span class="ln">{current_line}</span>'
            code_span = f'<span class="code">{escape_html(line)}</span>'
            html_lines.append(f"{ln_html} {code_span}")
            current_line += 1

        joined = "\n".join(html_lines)
        return f'<pre class="code-block">{joined}</pre>'

    def render_with_line_numbers(self, code: str) -> str:
        lines = (code or "").splitlines() or [""]
        numbered = "\n".join(
            f'<span class="ln">{i + 1:>4}</span> <span class="code">{escape_html(line)}</span>'
            for i, line in enumerate(lines)
        )
        return f'<pre class="code-block">{numbered}</pre>'

    def render_file_lines(self, lines_with_numbers: list[tuple[int, str]]) -> str:
        if not lines_with_numbers:
            return self.render_with_line_numbers("")
        numbered = "\n".join(
            f'<span class="ln">{ln:>4}</span> <span class="code">{escape_html(text)}</span>'
            for ln, text in lines_with_numbers
        )
        return f'<pre class="code-block">{numbered}</pre>'
