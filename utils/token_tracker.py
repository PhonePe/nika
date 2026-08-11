import logging
import threading
from langchain_core.callbacks import BaseCallbackHandler
from langchain_core.outputs import LLMResult
from typing import Any
from config_provider import ConfigProvider


class TokenUsageSnapshot(dict):
    pass

class TokenTracker:
    _instance = None
    _lock = threading.Lock()
    
    def __init__(self):
        self.total_tokens = 0
        self.prompt_tokens = 0
        self.cached_prompt_tokens = 0
        self.completion_tokens = 0
        self.successful_requests = 0
        self._counter_lock = threading.Lock()
        config = ConfigProvider.get_config()
        self.prompt_cost_per_m = config.llm_config.prompt_cost_per_million
        cached_prompt_cost = config.llm_config.cached_token_cost_per_million
        self.cached_prompt_cost_per_m = (
            self.prompt_cost_per_m
            if cached_prompt_cost is None
            else cached_prompt_cost
        )
        self.completion_cost_per_m = config.llm_config.completion_cost_per_million

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    def add_usage(
        self,
        total_tokens=0,
        prompt_tokens=0,
        completion_tokens=0,
        cached_prompt_tokens=0,
    ):
        cached_prompt_tokens = max(0, min(cached_prompt_tokens, prompt_tokens))
        with self._counter_lock:
            self.total_tokens += total_tokens
            self.prompt_tokens += prompt_tokens
            self.cached_prompt_tokens += cached_prompt_tokens
            self.completion_tokens += completion_tokens
            self.successful_requests += 1

    def reset(self):
        with self._counter_lock:
            self.total_tokens = 0
            self.prompt_tokens = 0
            self.cached_prompt_tokens = 0
            self.completion_tokens = 0
            self.successful_requests = 0

    def snapshot(self) -> TokenUsageSnapshot:
        with self._counter_lock:
            return TokenUsageSnapshot(
                total_tokens=self.total_tokens,
                prompt_tokens=self.prompt_tokens,
                cached_prompt_tokens=self.cached_prompt_tokens,
                completion_tokens=self.completion_tokens,
                successful_requests=self.successful_requests,
                total_cost=self.total_cost,
            )

    @property
    def total_cost(self) -> float:
        uncached_prompt_tokens = self.prompt_tokens - self.cached_prompt_tokens
        return (
            uncached_prompt_tokens * self.prompt_cost_per_m / 1_000_000
            + self.cached_prompt_tokens * self.cached_prompt_cost_per_m / 1_000_000
            + self.completion_tokens * self.completion_cost_per_m / 1_000_000
        )

    def print_summary(self):
        logging.info("\n")
        logging.info("LLM TOKEN USAGE SUMMARY")
        logging.info("="*50)
        logging.info("Total LLM Calls:     %d", self.successful_requests)
        logging.info("Total Tokens:        %d", self.total_tokens)
        logging.info("Prompt Tokens:       %d", self.prompt_tokens)
        logging.info("Cached Prompt Tokens: %d", self.cached_prompt_tokens)
        logging.info("Completion Tokens:   %d", self.completion_tokens)
        logging.info("Estimated Cost:      $%.4f", self.total_cost)
        logging.info("\n")

class TokenCallbackHandler(BaseCallbackHandler):
    def __init__(self):
        self.tracker = TokenTracker.get_instance()
    
    def on_llm_end(self, response: LLMResult, **kwargs: Any) -> None:
        # Check standard OpenAI response format in llm_output
        if response.llm_output and 'token_usage' in response.llm_output:
            usage = response.llm_output['token_usage']
            total = usage.get('total_tokens', 0)
            prompt = usage.get('prompt_tokens', usage.get('input_tokens', 0))
            completion = usage.get(
                'completion_tokens',
                usage.get('output_tokens', 0),
            )
            prompt_details = usage.get('prompt_tokens_details') or {}
            input_details = usage.get('input_token_details') or {}
            cached_prompt_tokens = (
                prompt_details.get('cached_tokens', 0)
                or input_details.get('cache_read', 0)
                or usage.get('cached_tokens', 0)
            )
            self.tracker.add_usage(
                total,
                prompt,
                completion,
                cached_prompt_tokens,
            )
