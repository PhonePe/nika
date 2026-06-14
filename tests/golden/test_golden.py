import os

import pytest
import yaml

pytestmark = pytest.mark.e2e

HERE = os.path.dirname(os.path.abspath(__file__))

with open(os.path.join(HERE, "expected.yaml"), "r", encoding="utf-8") as handle:
    EXPECTED = yaml.safe_load(handle)

POSITIVE = EXPECTED.get("positive", {})
NEGATIVE = EXPECTED.get("negative", {})


def _findings_in(findings, fixture_file):
    return [f for f in findings if (f.get("filename") or "").endswith(fixture_file)]


@pytest.mark.parametrize("category", sorted(POSITIVE))
def test_vulnerability_detected(golden_findings, category):
    spec = POSITIVE[category]
    matches = _findings_in(golden_findings, spec["fixture"])
    if not matches and spec.get("xfail"):
        pytest.xfail(spec["xfail"])
    reported = sorted({(f.get("vulnerability"), f.get("filename")) for f in golden_findings})
    assert matches, (
        f"{category}: expected a finding in {spec['fixture']}, got none.\nAll findings: {reported}"
    )


@pytest.mark.parametrize("category", sorted(NEGATIVE))
def test_safe_code_not_flagged(golden_findings, category):
    spec = NEGATIVE[category]
    matches = _findings_in(golden_findings, spec["fixture"])
    assert not matches, (
        f"{category}: safe fixture {spec['fixture']} was flagged (false positive): "
        f"{[f.get('vulnerability') for f in matches]}"
    )
