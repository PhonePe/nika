from typing import Dict, List, Tuple

from config_provider import ConfigProvider
from reporting.code_reader import CodeSnippetReader, escape_html, trace_signature
from schema.vulnerability_schema import Vulnerabilities, Vulnerability
from utils.token_tracker import TokenTracker


class HtmlReportRenderer:
    """Renders an HTML vulnerability report with dark-themed cards."""

    def __init__(self, code_reader: CodeSnippetReader):
        self._reader = code_reader

    def render(self, findings: list, state) -> str:
        cards, vulnerability_counts, finding_count = self._build_cards(findings)

        tracker = TokenTracker.get_instance()
        summary_html = self._summary_bar(finding_count, tracker, state)
        counts_html = self._vulnerability_counts_table(vulnerability_counts)
        styles = self._page_styles()
        header = self._page_header(state)

        return f"""<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Nika SAST Report</title>
    {styles}
</head>
<body>
    <div class="container">
        {header}
        {summary_html}
        {counts_html}
        {''.join(cards)}
        <footer>Nika.</footer>
    </div>
</body>
</html>"""

    # ------------------------------------------------------------------
    # Card construction
    # ------------------------------------------------------------------

    @staticmethod
    def _status_priority(vulnerability: Vulnerability) -> int:
        status = getattr(getattr(vulnerability, "analysis", None), "vulnerable_status", None)
        normalized = (status or "VULNERABLE").strip().upper()
        if normalized == "VULNERABLE":
            return 1
        if normalized == "NEED_MANUAL_REVIEW":
            return 2
        if normalized == "NOT_VULNERABLE":
            return 3
        return 2

    def _build_cards(self, findings: list) -> Tuple[List[str], Dict[str, int], int]:
        cards: List[str] = []
        sortable_cards: List[Tuple[int, str]] = []
        seen_findings: set = set()
        vulnerability_counts: Dict[str, int] = {}

        if not findings:
            cards.append('<div class="card"><p>No vulnerabilities found.</p></div>')
            return cards, vulnerability_counts, 0

        for entry in findings:
            vuln_name = entry.get("VULNERABILITY_TITLE", entry.get("vulnerability", "Unknown"))
            vuln_description = entry.get("VULNERABILITY_DESCRIPTION", "")
            results = entry.get("result")
            vulns = results if isinstance(results, Vulnerabilities) else None
            if not vulns or not vulns.findings:
                continue

            for v in vulns.findings:
                if getattr(v, "type") in ("dependency", "cbom"):
                    continue

                dedup_key = (
                    entry.get("vulnerability", ""),
                    getattr(v, "filename", "") or "",
                    getattr(v, "line_number", 0),
                    getattr(v, "sink", ""),
                    trace_signature(v),
                )
                if dedup_key in seen_findings:
                    continue
                seen_findings.add(dedup_key)

                vulnerability_counts[vuln_name] = vulnerability_counts.get(vuln_name, 0) + 1
                sortable_cards.append(
                    (self._status_priority(v), self._render_card(v, vuln_name, vuln_description))
                )

        if sortable_cards:
            cards.extend(card for _, card in sorted(sortable_cards, key=lambda item: item[0]))
            return cards, vulnerability_counts, len(sortable_cards)

        cards.append('<div class="card"><p>No vulnerabilities found.</p></div>')

        return cards, vulnerability_counts, 0

    def _render_card(self, v: Vulnerability, vuln_name: str, vuln_description: str) -> str:
        has_llm = v.analysis is not None

        if has_llm:
            status = getattr(v.analysis, "vulnerable_status", "NEED_MANUAL_REVIEW")
            explanation = getattr(v.analysis, "explanation", "No explanation provided")
            remediation = getattr(v.analysis, "remediation", "No remediation provided")
            code_fix = getattr(v.analysis, "code_fix", None)
        else:
            status = "VULNERABLE"
            explanation = ""
            remediation = ""
            code_fix = None

        taint_flow_section = self._trace_code_block(v)
        description_html = escape_html(vuln_description) if vuln_description else "Placeholder description for the vulnerability."

        code_fix_section = ""
        if code_fix:
            code_fix_section = f"""
            <div class="section-title">Code Fix</div>
            <div class="explanation">{escape_html(code_fix)}</div>
            """

        llm_sections = ""
        if has_llm:
            llm_sections = f"""
            <div class="section-title">Explanation</div>
            <div class="explanation">{escape_html(explanation)}</div>
            <div class="section-title">Remediation</div>
            <div class="explanation">{escape_html(remediation)}</div>
            {code_fix_section}
            """

        return f"""
        <div class="card">
            <h1>{escape_html(vuln_name)}</h1>
            <div class="meta">
                <span class="badge status {self._status_class(status)}">Status: {escape_html(status)}</span>
            </div>
            <div class="section-title">Description</div>
            <div class="explanation">{description_html}</div>
            {taint_flow_section}
            {llm_sections}
        </div>
        """

    # ------------------------------------------------------------------
    # Trace / code block rendering
    # ------------------------------------------------------------------

    def _trace_code_block(self, v: Vulnerability) -> str:
        flow_segments = []
        rendered_locations = set()
        # evidence = self._evidence_summary(v)
        # if evidence:
        #     flow_segments.append(evidence)

        if v.call_graph and len(v.call_graph) > 0:
            for i, node in enumerate(v.call_graph):
                if i == 0 and len(v.call_graph) == 1:
                    section_title = "Source"
                    line_no = node.callee_line_number
                    if not line_no or line_no < 1:
                        line_no = node.method_line_number_start if node.method_line_number_start and node.method_line_number_start > 0 else 1
                elif i == 0:
                    section_title = "Source"
                    line_no = node.callee_line_number
                    if not line_no or line_no < 1:
                        line_no = node.method_line_number_start if node.method_line_number_start and node.method_line_number_start > 0 else 1
                elif i == len(v.call_graph) - 1:
                    section_title = "Sink"
                    line_no = v.line_number
                else:
                    section_title = "Intermediate Call"
                    line_no = node.callee_line_number
                    if not line_no or line_no < 1:
                        line_no = node.method_line_number_start if node.method_line_number_start and node.method_line_number_start > 0 else 1

                before, target, after, start_line = self._reader.read_segment(node.filename, line_no)
                rendered = self._reader.render_snippet(before, target, after, int(start_line))
                flow_segments.append(
                    f'<div class="flow-step-title">{section_title} ({escape_html(node.filename)}:{line_no})</div>{rendered}'
                )
                rendered_locations.add((node.filename, line_no))

            sink_location = (v.filename, v.line_number)
            if v.filename and v.line_number and sink_location not in rendered_locations:
                before, target, after, start_line = self._reader.read_segment(v.filename, v.line_number)
                rendered = self._reader.render_snippet(before, target, after, int(start_line))
                flow_segments.append(
                    f'<div class="flow-step-title">Sink ({escape_html(v.filename)}:{v.line_number})</div>{rendered}'
                )
        elif v.filename:
            line_no = v.line_number
            before, target, after, start_line = self._reader.read_segment(v.filename, line_no)
            rendered = self._reader.render_snippet(before, target, after, int(start_line))
            flow_segments.append(
                f'<div class="flow-step-title">Sink ({escape_html(v.filename)}:{line_no})</div>{rendered}'
            )

        else:
            flow_segments.append(
                f'<div class="flow-step-title">Sink Code</div><pre class="code-block">{escape_html(v.sink)}</pre>'
            )

        return (
            '<div class="taint-flow-box">'
            '<div class="section-title">Taint Flow</div>'
            + ''.join(flow_segments)
            + '</div>'
        )

    @staticmethod
    def _evidence_summary(v: Vulnerability) -> str:
        metadata = getattr(v, "metadata", None) or {}
        rows = []
        for label, key in (
            ("Flow", "flow_summary"),
            ("Source", "source_param"),
            ("Sink argument", "sink_argument"),
            ("Validation", "validation_evidence"),
        ):
            value = metadata.get(key)
            if value:
                rows.append(
                    f'<div><strong>{escape_html(label)}:</strong> {escape_html(str(value))}</div>'
                )
        if not rows:
            return ""
        return '<div class="explanation">' + ''.join(rows) + '</div>'

    # ------------------------------------------------------------------
    # Page structure helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _status_class(status: str) -> str:
        s = (status or "").strip().lower()
        if "engine_failure" in s:
            return "need-manual-review"
        if "not" in s:
            return "not-vulnerable"
        if "vulnerable" in s:
            return "vulnerable"
        return "need-manual-review"

    @staticmethod
    def _summary_bar(finding_count: int, tracker, state) -> str:
        model_name = escape_html(ConfigProvider.get_config().llm_config.model)
        total_sources_found = getattr(state, "total_sources_found", 0)
        total_time_taken = escape_html(getattr(state, "total_time_taken", "N/A") or "N/A")
        return f"""
        <section class="summary-section">
            <div class="summary-head">
                <div>
                    <div class="summary-section-title">Scan Summary</div>
                </div>
            </div>
            <div class="summary-bar">
                <div class="stat">
                    <div class="num danger">{finding_count}</div>
                    <div class="label">Code Findings</div>
                </div>
                <div class="stat">
                    <div class="num accent">{total_sources_found}</div>
                    <div class="label">Total Sources Found</div>
                </div>
                <div class="stat">
                    <div class="num accent time-num">{total_time_taken}</div>
                    <div class="label">Total Time Taken</div>
                </div>
                <div class="stat">
                    <div class="num accent">{tracker.total_tokens}</div>
                    <div class="label">Total Tokens</div>
                </div>
                <div class="stat">
                    <div class="num accent">{tracker.prompt_tokens}</div>
                    <div class="label">Prompt Tokens</div>
                </div>
                <div class="stat">
                    <div class="num accent">{tracker.completion_tokens}</div>
                    <div class="label">Completion Tokens</div>
                </div>
                <div class="stat metric-stat">
                    <div class="num accent">${tracker.total_cost:.4f}</div>
                    <div class="label">Estimated Cost</div>
                </div>
                <div class="stat model-stat">
                    <div class="model-name">{model_name}</div>
                    <div class="model-label">Model</div>
                </div>
            </div>
        </section>
        """

    @staticmethod
    def _vulnerability_counts_table(vulnerability_counts: Dict[str, int]) -> str:
        if not vulnerability_counts:
            return ""

        rows = "".join(
            f"""
                <tr>
                    <td>{escape_html(vulnerability_name)}</td>
                    <td>{count}</td>
                </tr>
            """
            for vulnerability_name, count in sorted(
                vulnerability_counts.items(), key=lambda item: (-item[1], item[0].lower())
            )
        )

        return f"""
        <section class="counts-section">
            <div class="summary-head counts-head">
                <div>
                    <div class="summary-section-title">Vulnerability Counts</div>
                </div>
            </div>
            <div class="counts-table-wrap">
                <table class="counts-table">
                    <thead>
                        <tr>
                            <th>Vulnerability</th>
                            <th>Count</th>
                        </tr>
                    </thead>
                    <tbody>
                        {rows}
                    </tbody>
                </table>
            </div>
        </section>
        """

    @staticmethod
    def _page_header(state) -> str:
        branch_signal = ""
        if getattr(state, "source_branch", None) and getattr(state, "target_branch", None):
            branch_signal = (
                f'<span class="signal-pill">'
                f'{escape_html(state.source_branch)} &rarr; {escape_html(state.target_branch)}'
                f'</span>'
            )
        return f"""
        <header class="page-header">
            <div class="header-top">
                <div class="header-status">Static Analysis</div>
            </div>
            <h1>Nika SAST Report</h1>
            <p class="subtitle">This report summarizes detected vulnerabilities. Explanations are provided by the LLM analysis.</p>
            <div class="signal-strip">
                {branch_signal}
            </div>
        </header>
        """

    @staticmethod
    def _page_styles() -> str:
        return """
        <style>
            @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=Space+Grotesk:wght@400;500;700&display=swap');

            :root {
                --bg: #04070b;
                --bg-deep: #010203;
                --panel: rgba(7, 15, 22, 0.88);
                --panel-strong: rgba(10, 20, 28, 0.94);
                --panel-alt: rgba(5, 12, 18, 0.96);
                --text: #eafff6;
                --text-soft: #d4fff1;
                --muted: #8baea4;
                --border: rgba(92, 255, 196, 0.16);
                --border-strong: rgba(55, 231, 255, 0.35);
                --danger: #ff5d87;
                --safe: #67ff9c;
                --warn: #ffd166;
                --accent: #37e7ff;
                --accent-2: #8cffb5;
                --glow: rgba(55, 231, 255, 0.18);
                --shadow: 0 26px 80px rgba(0, 0, 0, 0.42);
            }

            * { box-sizing: border-box; }

            html, body {
                margin: 0;
                padding: 0;
                min-height: 100%;
                background: var(--bg-deep);
                color: var(--text);
                font-family: 'Space Grotesk', 'Segoe UI', sans-serif;
            }

            body {
                background:
                    radial-gradient(circle at 10% 10%, rgba(55, 231, 255, 0.14), transparent 28%),
                    radial-gradient(circle at 88% 14%, rgba(140, 255, 181, 0.11), transparent 24%),
                    linear-gradient(180deg, #06090f 0%, #020406 100%);
                position: relative;
                overflow-x: hidden;
            }

            body::before {
                content: "";
                position: fixed;
                inset: 0;
                background:
                    linear-gradient(rgba(255, 255, 255, 0.03) 1px, transparent 1px),
                    linear-gradient(90deg, rgba(255, 255, 255, 0.03) 1px, transparent 1px);
                background-size: 34px 34px;
                opacity: 0.24;
                mask-image: linear-gradient(180deg, rgba(255, 255, 255, 0.82), transparent 88%);
                pointer-events: none;
            }

            body::after {
                content: "";
                position: fixed;
                inset: 0;
                background: linear-gradient(transparent 0%, rgba(103, 255, 156, 0.025) 50%, transparent 100%);
                background-size: 100% 8px;
                opacity: 0.26;
                mix-blend-mode: screen;
                pointer-events: none;
            }

            ::selection {
                background: rgba(55, 231, 255, 0.28);
                color: #ffffff;
            }

            .container {
                max-width: 1120px;
                margin: 40px auto;
                padding: 0 20px 48px;
                position: relative;
                counter-reset: findings;
            }

            .page-header {
                margin-bottom: 24px;
                padding: 28px 30px 26px;
                border: 1px solid var(--border);
                border-radius: 26px;
                background: linear-gradient(145deg, rgba(7, 11, 18, 0.96), rgba(10, 22, 30, 0.84));
                box-shadow: var(--shadow);
                overflow: hidden;
                position: relative;
                backdrop-filter: blur(14px);
            }

            .page-header::before {
                content: "";
                position: absolute;
                inset: 0 auto auto 0;
                width: 100%;
                height: 2px;
                background: linear-gradient(90deg, transparent, var(--accent), var(--accent-2), transparent);
            }

            .page-header::after {
                content: "";
                position: absolute;
                top: -120px;
                right: -70px;
                width: 270px;
                height: 270px;
                background: radial-gradient(circle, rgba(55, 231, 255, 0.2), transparent 70%);
                pointer-events: none;
            }

            .header-top {
                display: flex;
                justify-content: space-between;
                gap: 12px;
                flex-wrap: wrap;
                margin-bottom: 18px;
                position: relative;
                z-index: 1;
            }

            .eyebrow,
            .header-status,
            .signal-pill,
            .summary-eyebrow,
            .badge,
            .section-title,
            footer {
                font-family: 'IBM Plex Mono', 'SFMono-Regular', monospace;
            }

            .eyebrow,
            .header-status {
                display: inline-flex;
                align-items: center;
                gap: 10px;
                padding: 8px 12px;
                border-radius: 999px;
                border: 1px solid rgba(55, 231, 255, 0.18);
                background: rgba(4, 12, 18, 0.65);
                color: var(--text-soft);
                font-size: 12px;
                letter-spacing: 0.14em;
                text-transform: uppercase;
                backdrop-filter: blur(10px);
            }

            .eyebrow::before {
                content: "";
                width: 10px;
                height: 10px;
                border-radius: 50%;
                background: var(--accent-2);
                box-shadow: 0 0 18px rgba(140, 255, 181, 0.7);
                animation: pulse-signal 2.6s ease-in-out infinite;
            }

            .page-header h1 {
                margin: 0 0 12px;
                font-size: clamp(2.4rem, 5vw, 4.2rem);
                line-height: 0.96;
                letter-spacing: -0.04em;
                color: #f7fffc;
                max-width: 11ch;
                position: relative;
                z-index: 1;
                text-shadow: 0 0 24px rgba(55, 231, 255, 0.18);
            }

            .page-header .subtitle {
                margin: 0;
                max-width: 760px;
                color: var(--muted);
                font-size: 1rem;
                line-height: 1.7;
                position: relative;
                z-index: 1;
            }

            .signal-strip {
                display: flex;
                flex-wrap: wrap;
                gap: 10px;
                margin-top: 18px;
                position: relative;
                z-index: 1;
            }

            .signal-pill {
                padding: 9px 12px;
                border-radius: 999px;
                border: 1px solid rgba(140, 255, 181, 0.16);
                background: rgba(6, 14, 21, 0.78);
                color: var(--text-soft);
                font-size: 11px;
                letter-spacing: 0.12em;
                text-transform: uppercase;
            }

            .summary-section {
                background: linear-gradient(150deg, rgba(7, 14, 21, 0.95), rgba(7, 17, 26, 0.85));
                border: 1px solid var(--border);
                border-radius: 24px;
                padding: 22px;
                margin-bottom: 24px;
                box-shadow: var(--shadow);
                position: relative;
                overflow: hidden;
                backdrop-filter: blur(12px);
            }

            .counts-section {
                background: linear-gradient(150deg, rgba(7, 14, 21, 0.95), rgba(7, 17, 26, 0.85));
                border: 1px solid var(--border);
                border-radius: 24px;
                padding: 22px;
                margin-bottom: 24px;
                box-shadow: var(--shadow);
                position: relative;
                overflow: hidden;
                backdrop-filter: blur(12px);
            }

            .summary-section::before {
                content: "";
                position: absolute;
                inset: auto -5% -30% auto;
                width: 320px;
                height: 320px;
                background: radial-gradient(circle, rgba(140, 255, 181, 0.08), transparent 70%);
                pointer-events: none;
            }

            .counts-section::before {
                content: "";
                position: absolute;
                inset: auto auto -35% -6%;
                width: 280px;
                height: 280px;
                background: radial-gradient(circle, rgba(55, 231, 255, 0.08), transparent 72%);
                pointer-events: none;
            }

            .summary-head {
                display: flex;
                justify-content: space-between;
                gap: 16px;
                align-items: flex-end;
                flex-wrap: wrap;
                margin-bottom: 18px;
                position: relative;
                z-index: 1;
            }

            .summary-eyebrow {
                display: inline-block;
                color: var(--accent);
                font-size: 11px;
                letter-spacing: 0.14em;
                text-transform: uppercase;
                margin-bottom: 8px;
            }

            .summary-section-title {
                font-size: 1.65rem;
                font-weight: 700;
                color: #f8fffd;
                margin: 0;
                letter-spacing: -0.03em;
            }

            .summary-copy {
                margin: 0;
                max-width: 380px;
                color: var(--muted);
                line-height: 1.6;
                font-size: 0.95rem;
            }

            .counts-head {
                margin-bottom: 16px;
            }

            .counts-table-wrap {
                position: relative;
                z-index: 1;
                border: 1px solid rgba(55, 231, 255, 0.14);
                border-radius: 18px;
                overflow: hidden;
                background: linear-gradient(180deg, rgba(8, 14, 22, 0.96), rgba(5, 11, 17, 0.92));
                box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.04), 0 10px 26px rgba(0, 0, 0, 0.25);
            }

            .counts-table {
                width: 100%;
                border-collapse: collapse;
            }

            .counts-table th,
            .counts-table td {
                padding: 14px 18px;
                text-align: left;
            }

            .counts-table th {
                color: var(--text-soft);
                font-family: 'IBM Plex Mono', 'SFMono-Regular', monospace;
                font-size: 11px;
                font-weight: 600;
                letter-spacing: 0.14em;
                text-transform: uppercase;
                background: rgba(4, 12, 18, 0.78);
                border-bottom: 1px solid rgba(55, 231, 255, 0.14);
            }

            .counts-table td {
                color: var(--text);
                border-bottom: 1px solid rgba(55, 231, 255, 0.08);
            }

            .counts-table tbody tr:last-child td {
                border-bottom: none;
            }

            .counts-table tbody tr:nth-child(even) td {
                background: rgba(255, 255, 255, 0.015);
            }

            .counts-table td:last-child,
            .counts-table th:last-child {
                width: 120px;
                text-align: right;
                color: var(--accent-2);
                font-weight: 600;
            }

            .summary-bar {
                display: grid;
                grid-template-columns: repeat(4, minmax(0, 1fr));
                gap: 16px;
                margin: 0;
                position: relative;
                z-index: 1;
            }

            .summary-bar .stat {
                position: relative;
                min-height: 126px;
                padding: 18px;
                border-radius: 18px;
                border: 1px solid rgba(55, 231, 255, 0.12);
                background: linear-gradient(180deg, rgba(8, 14, 22, 0.96), rgba(5, 11, 17, 0.92));
                box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.04), 0 10px 26px rgba(0, 0, 0, 0.25);
                overflow: hidden;
                display: flex;
                flex-direction: column;
                justify-content: space-between;
                gap: 8px;
                transition: transform 180ms ease, border-color 180ms ease, box-shadow 180ms ease;
            }

            .summary-bar .stat::before {
                content: "";
                position: absolute;
                inset: 0 auto auto 0;
                width: 100%;
                height: 1px;
                background: linear-gradient(90deg, var(--accent), transparent 70%);
            }

            .summary-bar .stat:hover,
            .card:hover {
                transform: translateY(-3px);
                border-color: rgba(140, 255, 181, 0.28);
                box-shadow: 0 24px 44px rgba(0, 0, 0, 0.3);
            }

            .summary-bar .stat .num {
                font-size: 2rem;
                font-weight: 700;
                line-height: 1.05;
                margin: 0;
                letter-spacing: -0.04em;
                word-break: break-word;
            }

            .summary-bar .stat .num.accent { color: var(--accent); }
            .summary-bar .stat .num.danger { color: var(--danger); }
            .summary-bar .stat .num.time-num { font-size: 1.55rem; }

            .summary-bar .stat .label,
            .summary-bar .stat.model-stat .model-label {
                font-size: 11px;
                color: var(--muted);
                margin: 0;
                letter-spacing: 0.12em;
                text-transform: uppercase;
            }

            .summary-bar .stat .detail {
                font-size: 0.92rem;
                color: var(--muted);
                word-break: break-word;
                overflow-wrap: anywhere;
            }

            .summary-bar .stat.model-stat .model-name {
                font-size: 1rem;
                font-weight: 600;
                color: var(--accent-2);
                line-height: 1.5;
                word-break: break-word;
                overflow-wrap: anywhere;
            }

            .card {
                background: linear-gradient(165deg, rgba(7, 14, 20, 0.94), rgba(7, 10, 15, 0.9));
                border: 1px solid var(--border);
                border-radius: 22px;
                padding: 22px;
                margin-bottom: 22px;
                box-shadow: var(--shadow);
                overflow: hidden;
                position: relative;
                backdrop-filter: blur(10px);
                transition: transform 180ms ease, border-color 180ms ease, box-shadow 180ms ease;
                counter-increment: findings;
            }

            .card::before {
                content: "";
                position: absolute;
                inset: 0 auto 0 0;
                width: 3px;
                background: linear-gradient(180deg, var(--danger), var(--accent));
            }

            .card::after {
                content: "";
                position: absolute;
                top: 12px;
                right: -20px;
                width: 180px;
                height: 180px;
                background: radial-gradient(circle, rgba(55, 231, 255, 0.08), transparent 70%);
                pointer-events: none;
            }

            .card h1 {
                margin: 0;
                font-size: clamp(1.45rem, 3.2vw, 2rem);
                color: #f8fffd;
                letter-spacing: -0.03em;
                overflow-wrap: anywhere;
                position: relative;
                z-index: 1;
            }

            .card h1::before {
                content: "F-" counter(findings, decimal-leading-zero);
                display: block;
                margin-bottom: 10px;
                color: var(--accent);
                font-family: 'IBM Plex Mono', 'SFMono-Regular', monospace;
                font-size: 11px;
                letter-spacing: 0.16em;
                text-transform: uppercase;
            }

            .meta {
                display: flex;
                gap: 12px;
                flex-wrap: wrap;
                margin: 14px 0 18px;
                position: relative;
                z-index: 1;
            }

            .badge {
                display: inline-flex;
                align-items: center;
                gap: 8px;
                padding: 7px 12px;
                border-radius: 999px;
                font-size: 11px;
                border: 1px solid var(--border);
                background: rgba(4, 12, 18, 0.78);
                color: var(--text);
                letter-spacing: 0.12em;
                text-transform: uppercase;
            }

            .badge::before {
                content: "";
                width: 8px;
                height: 8px;
                border-radius: 50%;
                background: currentColor;
                box-shadow: 0 0 14px currentColor;
                opacity: 0.9;
            }

            .badge.status.vulnerable {
                color: var(--danger);
                border-color: rgba(255, 93, 135, 0.4);
                background: rgba(56, 8, 22, 0.42);
            }

            .badge.status.not-vulnerable {
                color: var(--safe);
                border-color: rgba(103, 255, 156, 0.38);
                background: rgba(5, 30, 15, 0.42);
            }

            .badge.status.need-manual-review {
                color: var(--warn);
                border-color: rgba(255, 209, 102, 0.38);
                background: rgba(53, 35, 7, 0.42);
            }

            .section-title {
                display: inline-flex;
                align-items: center;
                gap: 10px;
                margin: 18px 0 10px;
                font-size: 12px;
                font-weight: 600;
                color: var(--text-soft);
                text-transform: uppercase;
                letter-spacing: 0.16em;
            }

            .section-title::before {
                content: "//";
                color: var(--accent-2);
            }

            .taint-flow-box {
                margin-top: 22px;
                padding: 18px;
                border: 1px solid rgba(55, 231, 255, 0.26);
                border-radius: 18px;
                background: linear-gradient(180deg, rgba(5, 12, 18, 0.98), rgba(7, 15, 24, 0.94));
                overflow: hidden;
                box-shadow: inset 0 0 0 1px rgba(55, 231, 255, 0.05);
            }

            .flow-step-title {
                display: flex;
                align-items: center;
                gap: 10px;
                margin: 22px 0 0;
                padding: 11px 16px;
                border: 1px solid rgba(55, 231, 255, 0.18);
                border-bottom: none;
                border-radius: 14px 14px 0 0;
                background:
                    linear-gradient(180deg, rgba(11, 22, 30, 0.96), rgba(7, 16, 23, 0.96)),
                    linear-gradient(90deg, rgba(55, 231, 255, 0.05), transparent 60%);
                color: var(--text-soft);
                font-family: 'IBM Plex Mono', 'SFMono-Regular', monospace;
                font-size: 12px;
                font-weight: 500;
                line-height: 1.45;
                letter-spacing: 0.01em;
                text-transform: none;
                word-break: break-word;
                overflow-wrap: anywhere;
                box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.04);
            }

            .flow-step-title::before {
                content: "";
                flex-shrink: 0;
                width: 8px;
                height: 8px;
                border-radius: 50%;
                background: var(--accent);
                box-shadow: 0 0 14px rgba(55, 231, 255, 0.65), 0 0 0 3px rgba(55, 231, 255, 0.08);
            }

            .flow-step-title::after {
                content: "";
                flex-shrink: 0;
                margin-left: auto;
                width: 14px;
                height: 14px;
                border-radius: 4px;
                background:
                    linear-gradient(135deg, rgba(140, 255, 181, 0.3), rgba(55, 231, 255, 0.18)),
                    repeating-linear-gradient(90deg, transparent 0 2px, rgba(140, 255, 181, 0.4) 2px 3px);
                opacity: 0.7;
            }

            .explanation {
                background: linear-gradient(180deg, rgba(9, 16, 24, 0.92), rgba(5, 11, 17, 0.94));
                border: 1px solid rgba(92, 255, 196, 0.12);
                border-radius: 14px;
                padding: 14px 16px;
                white-space: pre-wrap;
                font-family: 'IBM Plex Mono', 'SFMono-Regular', monospace;
                font-size: 13px;
                line-height: 1.65;
                color: #dcfff3;
                overflow-wrap: anywhere;
                box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.04);
            }

            .code-block {
                margin: 0 0 6px;
                background: linear-gradient(180deg, #050e14 0%, #030a10 100%);
                border: 1px solid rgba(55, 231, 255, 0.16);
                border-radius: 14px;
                padding: 12px 0;
                overflow-x: auto;
                overflow-y: hidden;
                font-family: 'IBM Plex Mono', 'JetBrains Mono', 'SFMono-Regular', monospace;
                font-size: 12.75px;
                line-height: 1.9;
                max-width: 100%;
                box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.04), 0 12px 28px rgba(0, 0, 0, 0.28);
                tab-size: 4;
            }

            .flow-step-title + .code-block {
                margin-top: 0;
                border-top-left-radius: 0;
                border-top-right-radius: 0;
                border-top-color: rgba(55, 231, 255, 0.1);
            }

            .code-block::-webkit-scrollbar {
                height: 8px;
            }

            .code-block::-webkit-scrollbar-track {
                background: transparent;
            }

            .code-block::-webkit-scrollbar-thumb {
                background: linear-gradient(90deg, rgba(55, 231, 255, 0.28), rgba(140, 255, 181, 0.28));
                border-radius: 999px;
            }

            .code-block::-webkit-scrollbar-thumb:hover {
                background: linear-gradient(90deg, rgba(55, 231, 255, 0.5), rgba(140, 255, 181, 0.5));
            }

            .code-block .ln {
                display: inline-block;
                width: 56px;
                padding: 0 14px 0 8px;
                margin-right: 0;
                text-align: right;
                color: rgba(139, 174, 164, 0.45);
                user-select: none;
                font-variant-numeric: tabular-nums;
                border-right: 1px solid rgba(55, 231, 255, 0.08);
            }

            .code-block .code {
                display: inline-block;
                vertical-align: top;
                width: calc(100% - 70px);
                padding: 0 18px;
                color: #e2fff5;
                white-space: pre-wrap;
                transition: background 160ms ease;
            }

            .code-block .code:hover {
                background: rgba(55, 231, 255, 0.04);
            }

            .code-block .code.matched {
                position: relative;
                color: #ffe6ee;
                background: linear-gradient(90deg, rgba(255, 93, 135, 0.22) 0%, rgba(255, 93, 135, 0.06) 60%, transparent 100%);
                box-shadow: inset 3px 0 0 var(--danger), inset 0 0 0 1px rgba(255, 93, 135, 0.18);
            }

            .code-block .code.matched:hover {
                background: linear-gradient(90deg, rgba(255, 93, 135, 0.28) 0%, rgba(255, 93, 135, 0.08) 60%, transparent 100%);
            }

            .code-block .code.muted {
                color: rgba(139, 174, 164, 0.55);
                font-style: italic;
            }

            footer {
                margin-top: 28px;
                padding: 18px 20px;
                border: 1px solid var(--border);
                border-radius: 18px;
                background: linear-gradient(180deg, rgba(6, 12, 18, 0.95), rgba(4, 9, 13, 0.92));
                color: var(--muted);
                font-size: 11px;
                letter-spacing: 0.14em;
                text-transform: uppercase;
                box-shadow: var(--shadow);
            }

            footer::before {
                content: "Generated by";
                display: block;
                margin-bottom: 8px;
                color: var(--accent-2);
            }

            @keyframes pulse-signal {
                0%, 100% { opacity: 0.65; transform: scale(1); }
                50% { opacity: 1; transform: scale(1.22); }
            }

            @media (max-width: 1100px) {
                .summary-bar { grid-template-columns: repeat(3, minmax(0, 1fr)); }
            }

            @media (max-width: 860px) {
                .container { margin-top: 24px; padding: 0 16px 34px; }
                .page-header,
                .summary-section,
                .card { padding: 18px; border-radius: 20px; }
                .summary-bar { grid-template-columns: repeat(2, minmax(0, 1fr)); }
            }

            @media (max-width: 560px) {
                .page-header h1 { max-width: none; }
                .summary-bar { grid-template-columns: 1fr; }
                .header-top { flex-direction: column; align-items: flex-start; }
                .summary-head { align-items: flex-start; }
                .counts-table th,
                .counts-table td { padding: 12px 14px; }
                .flow-step-title { padding: 10px 12px; font-size: 11.5px; }
                .code-block { font-size: 12px; line-height: 1.85; }
                .code-block .ln { width: 44px; padding: 0 10px 0 6px; }
                .code-block .code { width: calc(100% - 58px); padding: 0 14px; }
            }
        </style>
        """
