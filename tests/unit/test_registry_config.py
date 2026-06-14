import os

import pytest
import yaml

from runtime.registry import build_default_registry

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
CONFIGS = [
    os.path.join(ROOT, "config", "crtConfig.yml")
]


@pytest.fixture(scope="module")
def registry():
    return build_default_registry()


def _config_vuln_names(path):
    with open(path, "r", encoding="utf-8") as handle:
        cfg = yaml.safe_load(handle) or {}
    return cfg.get("vulnerabilityConfig") or []


@pytest.mark.parametrize("config_path", [p for p in CONFIGS if os.path.exists(p)])
def test_every_configured_vuln_is_registered(config_path, registry):
    names = _config_vuln_names(config_path)
    unknown = sorted({n for n in names if n not in registry.vulnerabilities})
    assert not unknown, (
        f"{os.path.basename(config_path)} enables unregistered detector(s) {unknown}; "
        f"they are silently skipped. Registered: {sorted(registry.vulnerabilities)}"
    )


def test_sink_based_detectors_have_rules(registry):
    missing = []
    for name, cls in registry.vulnerabilities.items():
        roles = getattr(cls, "required_engine_roles", []) or []
        if "sink_finder" not in roles:
            continue
        rules_dir = os.path.join(ROOT, "rules", name, "java")
        has_rules = os.path.isdir(rules_dir) and any(
            f.endswith((".yml", ".yaml"))
            for _root, _dirs, files in os.walk(rules_dir)
            for f in files
        )
        if not has_rules:
            missing.append(name)
    assert not missing, f"sink-based detectors with no Java rules: {missing}"


def test_registry_has_no_empty_names(registry):
    assert all(registry.vulnerabilities), "registry contains an empty vulnerability name"
