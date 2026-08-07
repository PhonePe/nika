from types import SimpleNamespace

from models.sink import Sink
from models.trace import Trace
from vulnerabilities.base.stages import build_trace_human_prompt
from vulnerabilities.ssrf import SsrfVulnerability, _flow_key, refine_ssrf_flows


class _SsrfEngine:
    def __init__(self, flows):
        self.flows = flows

    def find_ssrf_flows(self, *args, **kwargs):
        return self.flows


def _state_for_engine_flow(request_controlled=True):
    source_symbol = "com.example.Controller.fetch:void(java.lang.String)"
    sink = Sink(
        rule_id="java-ssrf-url-sink",
        file_path="src/Client.java",
        line_number=20,
        code="client.url(request.getPath());",
    )
    trace = Trace(
        sink_file_path="src/Client.java",
        sink_line_number=20,
        source_symbol=source_symbol,
    )
    key = _flow_key(source_symbol, sink.file_path, sink.line_number)
    state = SimpleNamespace(sinks=[sink], traces=[trace])
    context = SimpleNamespace(
        engines={
            "dataflow_analyzer": _SsrfEngine(
                {
                    key: {
                        "requestControlled": request_controlled,
                        "sinkArgument": "request.getPath()",
                        "sinkCode": "client.url(request.getPath())",
                    }
                }
            )
        }
    )
    return context, state


def test_refine_ssrf_flows_attaches_engine_evidence_to_sinkless_trace():
    context, state = _state_for_engine_flow()

    refine_ssrf_flows(None, context, state)

    assert len(state.traces) == 1
    metadata = state.traces[0].sink.metadata
    assert metadata["request_controlled"] is True
    assert metadata["sink_argument"] == "request.getPath()"
    assert metadata["flow_confidence"] == "cpg-destination-flow"
    assert "Astrail confirmed" in metadata["flow_summary"]

    prompt = build_trace_human_prompt(SsrfVulnerability(), state.traces[0])
    assert "Request controlled: True" in prompt
    assert "Flow confidence: cpg-destination-flow" in prompt


def test_refine_ssrf_flows_drops_engine_negative_trace():
    context, state = _state_for_engine_flow(request_controlled=False)

    refine_ssrf_flows(None, context, state)

    assert state.traces == []