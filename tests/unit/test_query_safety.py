import base64
import os
from types import SimpleNamespace

from engines.astrail import query_runner as query_runner_mod
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


def test_precise_pair_encoding_carries_operand_rule_and_source_indexes():
    source = SimpleNamespace(
        methodName="com.x.Foo.endpoint:void(java.lang.String)",
        taintParameterIndexes=[1, 3],
    )
    sink = {
        "file": "src/Foo.java",
        "lineNumber": 42,
        "ruleId": "rules.sql.sink",
        "sinkId": "rules.sql.sink|src/Foo.java|42|9|42|31",
        "matchStart": {"line": 42, "col": 9},
        "matchEnd": {"line": 42, "col": 31},
        "operand": {
            "code": "name + suffix\twith-tab",
            "start": {"line": 42, "col": 22},
            "end": {"line": 42, "col": 30},
        },
    }

    encoded = next(AstrailQueryRunner._encode_pairs([(source, sink)]))
    parts = encoded.split("\t")

    assert parts[:7] == [
        source.methodName, "42", "src/Foo.java", "42", "9", "42", "31"
    ]
    assert base64.b64decode(parts[7]).decode() == "name + suffix\twith-tab"
    assert base64.b64decode(parts[12]).decode() == "rules.sql.sink"
    assert parts[13] == "1,3"
    assert base64.b64decode(parts[14]).decode() == sink["sinkId"]


def test_batch_query_uses_exact_file_and_operand_selection():
    query_path = os.path.join(
        os.path.dirname(__file__), "..", "..", "queries", "batchReachabilityCheck.scala"
    )
    with open(query_path, encoding="utf-8") as handle:
        query = handle.read()

    assert "sameFile(f.name, fileName)" in query
    assert 'val regexFileName = s".*$fileName"' not in query
    assert "positionMatchedArguments" in query
    assert "pair.sourceParameterIndexes" in query
    assert "inferredEndPosition" in query
    assert "c.lineNumberEnd" not in query
    assert "arg.lineNumberEnd" not in query


def test_batch_query_recognizes_dominating_same_operand_sanitizers():
    query_path = os.path.join(
        os.path.dirname(__file__), "..", "..", "queries", "batchReachabilityCheck.scala"
    )
    with open(query_path, encoding="utf-8") as handle:
        query = handle.read()

    assert "def hasDominatingSanitizer" in query
    assert "sinkCall.dominatedBy.l" in query
    assert "sinkArgumentCodes.contains(argument.code.trim)" in query
    assert "cand, sinkArgCand, pair.operandCode" in query


def test_source_query_limits_servlet_taint_to_request_carriers():
    query_path = os.path.join(
        os.path.dirname(__file__), "..", "..", "queries", "getApiPath.scala"
    )
    with open(query_path, encoding="utf-8") as handle:
        query = handle.read()

    assert 'parameterType.endsWith("HttpServletRequest")' in query
    assert "if (requestCarriers.nonEmpty)" in query
    assert '"taintParameterIndexes"' in query


def test_generate_cpg_passes_dedicated_java_opts(monkeypatch, tmp_path):
    repo_path = tmp_path / "service"
    repo_path.mkdir()
    runner = AstrailQueryRunner(str(repo_path))
    runner._project_root = str(tmp_path)
    monkeypatch.setattr(
        runner,
        "_get_astrail_config",
        lambda: {
            "javasrc2cpg": "/tools/javasrc2cpg",
            "cpg_opts": "-Xms2g -Xmx16g",
        },
    )
    captured = {}

    def fake_execute(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        output_path = command[command.index("--output") + 1]
        open(output_path, "w", encoding="utf-8").close()
        return SimpleNamespace(duration_sec=0.1, ok=True)

    monkeypatch.setattr(query_runner_mod, "execute_command", fake_execute)

    assert runner.generate_cpg() == "ok"
    assert captured["kwargs"]["env"] == {"JAVA_OPTS": "-Xms2g -Xmx16g"}
    assert captured["kwargs"]["check"] is True


def test_generate_cpg_preserves_environment_without_cpg_opts(monkeypatch, tmp_path):
    repo_path = tmp_path / "service"
    repo_path.mkdir()
    runner = AstrailQueryRunner(str(repo_path))
    runner._project_root = str(tmp_path)
    monkeypatch.setattr(
        runner,
        "_get_astrail_config",
        lambda: {"javasrc2cpg": "/tools/javasrc2cpg"},
    )
    captured = {}

    def fake_execute(command, **kwargs):
        captured["kwargs"] = kwargs
        output_path = command[command.index("--output") + 1]
        open(output_path, "w", encoding="utf-8").close()
        return SimpleNamespace(duration_sec=0.1, ok=True)

    monkeypatch.setattr(query_runner_mod, "execute_command", fake_execute)

    assert runner.generate_cpg() == "ok"
    assert captured["kwargs"]["env"] is None
