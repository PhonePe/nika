from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class LLMConfig(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    api_key: str = Field(alias="API_KEY")
    llm_url: str = Field(alias="LLM_URL")
    model: str = Field(alias="MODEL")
    max_tool_calls: int = Field(default=20, alias="MAX_TOOL_CALLS")
    max_iterations: int = Field(default=15, alias="MAX_ITERATIONS")
    recursion_limit: int = Field(default=100, alias="RECURSION_LIMIT")
    prompt_cost_per_million: float = Field(
        default=5.0,
        alias="PROMPT_COST_PER_MILLION",
    )
    completion_cost_per_million: float = Field(
        default=15.0,
        alias="COMPLETION_COST_PER_MILLION",
    )
    verify_tls: bool = Field(default=True, alias="VERIFY_TLS")

class SourceConfig(BaseModel):
    annotations: List[str]
    source_methods: List[str] = []

class SourceArgExclusionConfig(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    annotations: List[str] = []
    types: List[str] = []

class ConfigSchema(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    llm_config: LLMConfig = Field(alias="LLMConfig")
    sources: SourceConfig
    max_threads: int = 4
    vulnerability_config: List[str] = Field(alias="vulnerabilityConfig")
    vulnerability_args: Dict[str, Dict[str, Any]] = Field(
        default_factory=dict,
        alias="vulnerabilityArgs",
    )
    llm_review_enabled: bool = Field(default=True, alias="llmReviewEnabled")
    aggressive_scan: bool = Field(default=False, alias="aggressiveScan")
    exclude_source_args: SourceArgExclusionConfig = Field(
        default_factory=SourceArgExclusionConfig,
        alias="excludeSourceArgs",
    )
    tools: Dict[str, Dict[str, Any]] = {}
