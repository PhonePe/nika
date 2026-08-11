from pydantic import BaseModel, Field

from .sink import Sink
from .source import Source


class TraceNode(BaseModel):
    method_name: str
    file_path: str
    method_line_number_start: int | None = None
    method_line_number_end: int | None = None
    code: str
    callee_code: str | None = None
    callee_line_number: int | None = None
    is_external: bool = False


class Trace(BaseModel):
    sink_file_path: str
    sink_line_number: int
    nodes: list[TraceNode] = Field(default_factory=list)
    source_symbol: str | None = None
    source_param: str | None = None
    source_kind: str | None = None
    source: Source | None = None
    sink: Sink | None = None
    call_node_count: int | None = None
