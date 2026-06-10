from engines.astrail.adapter import AstrailEngine
from engines.order.adapter import OrderSinkFinder
from engines.opengrep.adapter import OpenGrepSinkFinder
from languages.java.pack import JavaLanguagePack
from vulnerabilities.code_injection import CodeInjectionVulnerability
from vulnerabilities.command_injection import CommandInjectionVulnerability
from vulnerabilities.deserialization import DeserializationVulnerability
from vulnerabilities.idor.vulnerability import IdorVulnerability
from vulnerabilities.insecure_crypto import InsecureCryptoVulnerability
from vulnerabilities.open_redirect import OpenRedirectVulnerability
from vulnerabilities.order_scan import OrderScanVulnerability
from vulnerabilities.path_traversal import PathTraversalVulnerability
from vulnerabilities.sensitive_logging.vulnerability import SensitiveLoggingVulnerability
from vulnerabilities.ssrf import SsrfVulnerability
from vulnerabilities.sql_injection import SqlInjectionVulnerability
from vulnerabilities.template_injection import TemplateInjectionVulnerability
from vulnerabilities.unsafe_reflection import UnsafeReflectionVulnerability
from vulnerabilities.xpath_injection import XpathInjectionVulnerability
from vulnerabilities.xxe import XxeVulnerability
from vulnerabilities.ldap_injection import LdapInjectionVulnerability
from vulnerabilities.nosql_injection import NoSqlInjectionVulnerability

class _EngineEntry:
    __slots__ = ("factory", "requires_path")

    def __init__(self, factory, requires_path=False):
        self.factory = factory
        self.requires_path = requires_path


class Registry:
    def __init__(self):
        self.languages = {}
        self.engines = {}
        self.vulnerabilities = {}

    def register_language(self, name, factory):
        self.languages[name] = factory

    def register_engine(self, role, name, factory, *, requires_path=False):
        if role not in self.engines:
            self.engines[role] = {}
        self.engines[role][name] = _EngineEntry(factory, requires_path=requires_path)

    def register_vulnerability(self, name, factory):
        self.vulnerabilities[name] = factory

    def create_language(self, name):
        return self.languages[name]()

    def create_engine(self, role, name, request):
        entry = self.engines[role][name]
        if entry.requires_path:
            return entry.factory(request.path)
        return entry.factory()

    def create_vulnerability(self, name):
        return self.vulnerabilities[name]()


def build_default_registry():
    registry = Registry()
    registry.register_language("java", JavaLanguagePack)
    registry.register_engine("sink_finder", "opengrep", OpenGrepSinkFinder)
    registry.register_engine("source_finder", "astrail", AstrailEngine, requires_path=True)
    registry.register_engine("dataflow_analyzer", "astrail", AstrailEngine, requires_path=True)
    registry.register_engine("order_finder", "order_analyzer", OrderSinkFinder)
    registry.register_vulnerability("sensitive_logging", SensitiveLoggingVulnerability)
    registry.register_vulnerability("sql_injection", SqlInjectionVulnerability)
    registry.register_vulnerability("ssrf", SsrfVulnerability)
    registry.register_vulnerability("open_redirect", OpenRedirectVulnerability)
    registry.register_vulnerability("ldap_injection", LdapInjectionVulnerability)
    registry.register_vulnerability("nosql_injection", NoSqlInjectionVulnerability)
    registry.register_vulnerability("xpath_injection", XpathInjectionVulnerability)
    registry.register_vulnerability("xxe", XxeVulnerability)
    registry.register_vulnerability("path_traversal", PathTraversalVulnerability)
    registry.register_vulnerability("command_injection", CommandInjectionVulnerability)
    registry.register_vulnerability("code_injection", CodeInjectionVulnerability)
    registry.register_vulnerability("template_injection", TemplateInjectionVulnerability)
    registry.register_vulnerability("deserialization", DeserializationVulnerability)
    registry.register_vulnerability("unsafe_reflection", UnsafeReflectionVulnerability)
    registry.register_vulnerability("cryptographic_failure", InsecureCryptoVulnerability)
    registry.register_vulnerability("order_scan", OrderScanVulnerability)
    registry.register_vulnerability("idor", IdorVulnerability)
    return registry
