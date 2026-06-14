import os

from engines.order.scanner import OrderAnalyzer

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
RULES = os.path.join(ROOT, "rules", "order_scan", "java")
EXAMPLE = os.path.join(
    ROOT, "tests", "golden", "fixtures", "vulnapp",
    "src", "main", "java", "com", "example", "vulnapp", "Example.java",
)


def _analyze():
    return OrderAnalyzer(RULES).analyze(EXAMPLE)


def test_order_scan_reports_violations_on_fixture():
    findings = _analyze()
    assert findings, "order_scan engine reported no violations on the Example.java fixture"
    assert all(f["file"].endswith("Example.java") for f in findings)


def test_call_sequence_flags_missing_call():
    messages = " ".join(f["code"] for f in _analyze())
    assert "call2" in messages and "Missing required call" in messages


def test_chain_order_flags_out_of_order_arg():
    messages = " ".join(f["code"] for f in _analyze())
    assert "Expected call to router1" in messages
