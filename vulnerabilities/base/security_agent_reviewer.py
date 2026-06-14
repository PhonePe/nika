from __future__ import annotations
from typing import Any

from schema.vulnerability_schema import LLMVulnerabilityOutput


def _fallback_review(vulnerability, reason: str) -> dict[str, Any]:
    return {
        "vulnerable_status": "NEED_MANUAL_REVIEW",
        "explanation": reason,
        "remediation": getattr(vulnerability, "fallback_remediation", None),
        "code_fix": getattr(vulnerability, "fallback_code_fix", None),
    }


def _normalize_review(output, vulnerability) -> dict[str, Any]:
    if isinstance(output, LLMVulnerabilityOutput):
        review = output.model_dump()
    elif isinstance(output, dict):
        review = output
    else:
        return _fallback_review(
            vulnerability,
            "SecurityAgent returned an unsupported review payload type.",
        )

    return {
        "vulnerable_status": review.get("vulnerable_status")
        or review.get("status")
        or "NEED_MANUAL_REVIEW",
        "explanation": review.get("explanation"),
        "remediation": review.get("remediation"),
        "code_fix": review.get("code_fix"),
    }


def run_security_agent_review(
    vulnerability,
    context,
    evidence,
    *,
    agent_factory=None,
):
    from agents.security_agent import SecurityAgent, SecurityAgentRuntimeContext

    if agent_factory is None:
        agent_factory = SecurityAgent

    system_prompt = vulnerability.build_system_prompt(evidence)
    human_prompt = vulnerability.build_human_prompt(evidence)

    astrail_engine = context.engines.get("dataflow_analyzer") or context.engines.get(
        "source_finder"
    )
    if astrail_engine is None:
        return _fallback_review(
            vulnerability,
            "SecurityAgent review skipped because no Astrail engine is available in runtime context.",
        )

    has_resolver = callable(getattr(astrail_engine, "get_method_and_file_name", None))
    has_legacy_resolver = callable(getattr(astrail_engine, "getMethodAndFileName", None))
    if not has_resolver and not has_legacy_resolver:
        return _fallback_review(
            vulnerability,
            "SecurityAgent review skipped because Astrail engine does not expose method lookup support.",
        )

    runtime_context = SecurityAgentRuntimeContext(
        code_path=context.path,
        source_branch=getattr(context, "source_branch", None),
        target_branch=getattr(context, "target_branch", None),
        astrail=astrail_engine,
    )

    try:
        thread_id = str(vulnerability.vulnerability_id)
        with agent_factory(
            runtime_context=runtime_context,
            system_prompt=system_prompt,
            thread_id=thread_id,
        ) as agent:
            review = agent.run(query=human_prompt)
    except Exception as exc:
        return _fallback_review(
            vulnerability,
            f"SecurityAgent review failed and requires manual triage: {exc}",
        )

    return _normalize_review(review, vulnerability)
