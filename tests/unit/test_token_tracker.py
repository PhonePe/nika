import threading
from types import SimpleNamespace

import pytest

from utils.token_tracker import TokenCallbackHandler, TokenTracker


def _tracker():
    tracker = TokenTracker.__new__(TokenTracker)
    tracker.total_tokens = 0
    tracker.prompt_tokens = 0
    tracker.cached_prompt_tokens = 0
    tracker.completion_tokens = 0
    tracker.successful_requests = 0
    tracker.prompt_cost_per_m = 5.0
    tracker.cached_prompt_cost_per_m = 1.0
    tracker.completion_cost_per_m = 15.0
    tracker.__dict__["_counter_lock"] = threading.Lock()
    return tracker


def test_cached_prompt_tokens_use_cached_rate_without_double_charging():
    tracker = _tracker()

    tracker.add_usage(
        total_tokens=1_100_000,
        prompt_tokens=1_000_000,
        completion_tokens=100_000,
        cached_prompt_tokens=400_000,
    )

    assert tracker.total_cost == pytest.approx(4.9)
    assert tracker.snapshot()["cached_prompt_tokens"] == 400_000


def test_callback_reads_openai_cached_prompt_token_details():
    tracker = _tracker()
    callback = TokenCallbackHandler.__new__(TokenCallbackHandler)
    callback.tracker = tracker
    response = SimpleNamespace(
        llm_output={
            "token_usage": {
                "total_tokens": 150,
                "prompt_tokens": 100,
                "completion_tokens": 50,
                "prompt_tokens_details": {"cached_tokens": 40},
            }
        }
    )

    callback.on_llm_end(response)

    assert tracker.prompt_tokens == 100
    assert tracker.cached_prompt_tokens == 40
    assert tracker.completion_tokens == 50


def test_callback_reads_langchain_cache_read_details():
    tracker = _tracker()
    callback = TokenCallbackHandler.__new__(TokenCallbackHandler)
    callback.tracker = tracker
    response = SimpleNamespace(
        llm_output={
            "token_usage": {
                "total_tokens": 150,
                "input_tokens": 100,
                "output_tokens": 50,
                "input_token_details": {"cache_read": 25},
            }
        }
    )

    callback.on_llm_end(response)

    assert tracker.prompt_tokens == 100
    assert tracker.cached_prompt_tokens == 25
    assert tracker.completion_tokens == 50


def test_reset_clears_cached_prompt_tokens():
    tracker = _tracker()
    tracker.add_usage(100, 80, 20, 30)

    tracker.reset()

    assert tracker.snapshot()["cached_prompt_tokens"] == 0