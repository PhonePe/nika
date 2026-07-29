from typing import Any

from pydantic import BaseModel, Field

from .trace import Trace


class Finding(BaseModel):
    vulnerability_id: str
    sink: str
    file_path: str | None = None
    line_number: int | None = None
    line_number_end: int | None = None
    status: str = "VULNERABLE"
    explanation: str | None = None
    remediation: str | None = None
    trace: Trace | None = None
    call_node_count: int | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
