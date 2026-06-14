import pytest

from reporting.code_reader import escape_html


@pytest.mark.parametrize("raw,expected", [
    ("<script>", "&lt;script&gt;"),
    ("a & b", "a &amp; b"),
    ('x" onmouseover="y', "x&quot; onmouseover=&quot;y"),
    ("it's", "it&#39;s"),
    (None, ""),
])
def test_escape_html(raw, expected):
    assert escape_html(raw) == expected


def test_amp_escaped_first_no_double_encoding():
    assert escape_html("<") == "&lt;"


def test_attribute_breakout_is_neutralized():
    payload = '"><img src=x onerror=alert(1)>'
    out = escape_html(payload)
    assert '"' not in out and "<" not in out and ">" not in out
