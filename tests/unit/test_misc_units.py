from schema.config_schema import LLMConfig
from utils.java_ast_parser import find_method_signature_line
from vulnerabilities.sensitive_logging.detectors import is_sensitive_log_snippet


_LOG_PII = """
class C {
  void f(String password, String name) {
    log.info("password=" + password);
  }
}
"""

_LOG_SAFE = """
class C {
  void f(String name) {
    log.info("hello " + name);
  }
}
"""

_NO_LOG = """
class C {
  void f(String password) {
    String x = "password=" + password;
  }
}
"""


def test_sensitive_log_flags_pii():
    assert is_sensitive_log_snippet(_LOG_PII, ["password", "secret"]) is True


def test_sensitive_log_ignores_non_pii():
    assert is_sensitive_log_snippet(_LOG_SAFE, ["password"]) is False


def test_sensitive_log_ignores_non_log_statements():
    assert is_sensitive_log_snippet(_NO_LOG, ["password"]) is False


def test_sensitive_log_empty_inputs():
    assert is_sensitive_log_snippet("", ["password"]) is False
    assert is_sensitive_log_snippet(_LOG_PII, []) is False

def test_signature_line_skips_annotations(tmp_path):
    src = tmp_path / "C.java"
    src.write_text(
        "class C {\n"
        "  @GetMapping(\"/x\")\n"
        "  @PreAuthorize(\"y\")\n"
        "  public String get(Long id) { return null; }\n"
        "}\n"
    )
    assert find_method_signature_line(str(src), "get") == 4


def test_signature_line_missing_method_returns_none(tmp_path):
    src = tmp_path / "C.java"
    src.write_text("class C { void a() {} }\n")
    assert find_method_signature_line(str(src), "nope") is None
