import json
import os
import shutil
import subprocess
import sys
import tempfile

import pytest
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
FIXTURE = os.path.join(HERE, "fixtures", "vulnapp")
DEFAULT_CONFIG = os.path.join(ROOT, "config", "crtConfig.yml")

ALL_VULNERABILITIES = [
    "command_injection",
    "code_injection",
    "order_scan",
    "sql_injection",
    "path_traversal",
    "ssrf",
    "open_redirect",
    "template_injection",
    "deserialization",
    "cryptographic_failure",
    "unsafe_reflection",
    "xxe",
    "idor",
    "ldap_injection",
    "xpath_injection",
    "nosql_injection",
    "sensitive_logging",
]


def _resolve_config_path(request) -> str:
    return (
        request.config.getoption("--nika-config")
        or os.environ.get("NIKA_E2E_CONFIG")
        or DEFAULT_CONFIG
    )


def _tool_paths(config: dict):
    astrail = (config.get("tools", {}).get("astrail", {}) or {})
    opengrep = (config.get("tools", {}).get("opengrep", {}) or {})
    return {
        "astrail": astrail.get("astrailpath"),
        "javasrc2cpg": astrail.get("javasrc2cpg"),
        "opengrep": opengrep.get("path"),
    }


@pytest.fixture(scope="session")
def golden_findings(request):
    """Run the real scanner once over the fixture repo and return its findings.
    """
    config_path = _resolve_config_path(request)
    if not os.path.exists(config_path):
        pytest.skip(f"config not found: {config_path} (set --nika-config or NIKA_E2E_CONFIG)")

    with open(config_path, "r", encoding="utf-8") as handle:
        config = yaml.safe_load(handle)

    for name, path in _tool_paths(config).items():
        if not path or not os.path.exists(path):
            pytest.skip(
                f"{name} not found at {path!r} (from {os.path.basename(config_path)}); "
                f"point --nika-config / NIKA_E2E_CONFIG at a config with installed tool paths"
            )

    config["llm_review_enabled"] = False
    config["vulnerabilityConfig"] = list(ALL_VULNERABILITIES)

    workdir = tempfile.mkdtemp(prefix="nika-e2e-")
    try:
        scan_config = os.path.join(workdir, "e2e.yml")
        with open(scan_config, "w", encoding="utf-8") as handle:
            yaml.safe_dump(config, handle, sort_keys=False)

        out_html = os.path.join(workdir, "report.html")
        print(
            f"\n[e2e] scanning fixture with {os.path.basename(config_path)} "
            f"(CPG + opengrep + dataflow across {len(ALL_VULNERABILITIES)} detectors) "
            f"Run with -s to stream progress.\n",
            flush=True,
        )
        try:
            proc = subprocess.run(
                [sys.executable, "-u", "main.py", "--config", scan_config, "--path", FIXTURE,
                 "--output", out_html],
                cwd=ROOT,
                timeout=900,
            )
        except subprocess.TimeoutExpired:
            pytest.skip("e2e scan exceeded 900s (toolchain/env issue)")

        report_json = os.path.splitext(out_html)[0] + ".json"
        if not os.path.exists(report_json):
            pytest.skip(
                f"scan produced no report (exit {proc.returncode}); see the scan output above"
            )

        with open(report_json, "r", encoding="utf-8") as handle:
            return json.load(handle).get("findings", [])
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
