import base64
import os

from engines.astrail.query_runner import AstrailQueryRunner, _scala_literal


def test_scala_literal_escapes_quotes_and_backslashes():
    out = _scala_literal('a"b\\c')
    assert out == '"a\\"b\\\\c"'


def test_scala_literal_neutralizes_breakout():
    payload = '"); System.exit(0); importCpg("x'
    literal = _scala_literal(payload)
    assert literal.count('"') == 2 + payload.count('"')
    assert literal.startswith('"') and literal.endswith('"')


def test_scala_literal_escapes_newlines():
    assert _scala_literal("a\nb\rc") == '"a\\nb\\rc"'


def _decode_params(path):
    groups = {}
    with open(path) as handle:
        for line in handle.read().splitlines():
            if not line.strip():
                continue
            key, b64 = line.split("\t", 1)
            groups.setdefault(key, []).append(base64.b64decode(b64).decode("utf-8"))
    return groups


def test_params_file_roundtrip_handles_hostile_values():
    params = {
        "identifier": ["userId", 'order"Id', "a\\b", "with\nnewline"],
        "matchGenericId": True,
        "requireComparison": False,
        "endpoint": ["com.x.Foo.bar:int(int)\tuserId,orderId"],
        "empty": [],
    }
    path = AstrailQueryRunner._write_params_file(params)
    try:
        groups = _decode_params(path)
    finally:
        os.remove(path)

    assert groups["identifier"] == ["userId", 'order"Id', "a\\b", "with\nnewline"]
    assert groups["matchGenericId"] == ["true"]
    assert groups["requireComparison"] == ["false"]
    assert "empty" not in groups
    fullname, ids = groups["endpoint"][0].split("\t", 1)
    assert fullname == "com.x.Foo.bar:int(int)" and ids == "userId,orderId"
