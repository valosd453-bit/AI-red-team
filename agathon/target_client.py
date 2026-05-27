"""
Target HTTP client — UI scan key ONLY (Operation: Key Isolation).

Brain/strategy uses GROQ_API_KEY / OPENROUTER_API_KEY via clients/llm_client.py.
All outbound target strikes MUST use the api_key from the scan request payload.
"""

from __future__ import annotations

import logging
import os
from typing import Optional
from urllib.parse import urlparse

from forgeguard_bridge import OpenAICompatibleClient

log = logging.getLogger(__name__)

AUTH_FAILURE_MESSAGE = (
    "Authentication Error: Target rejected the provided API Key."
)

# Engine env keys — never use for target Authorization
_ENGINE_KEY_ENVS = (
    "GROQ_API_KEY",
    "OPENROUTER_API_KEY",
    "DEEPSEEK_API_KEY",
    "OPENAI_API_KEY",
)


def resolve_target_provider(target_url: str, explicit: str = "") -> str:
    """Infer provider from URL host when not supplied by the runner."""
    if explicit and explicit.strip():
        return explicit.strip().lower()
    host = (urlparse(target_url).hostname or "").lower()
    if "groq.com" in host:
        return "groq"
    if "openai.com" in host or "api.openai" in host:
        return "openai"
    if "anthropic.com" in host:
        return "anthropic"
    if "together.xyz" in host or "fireworks.ai" in host:
        return "openai_compat"
    return "openai_compat"


def _engine_env_keys() -> set[str]:
    keys: set[str] = set()
    for name in _ENGINE_KEY_ENVS:
        val = (os.environ.get(name) or "").strip()
        if val:
            keys.add(val)
    return keys


def assert_target_key_isolation(
    api_key: str,
    *,
    target_url: str,
    target_provider: str = "",
) -> None:
    """
    Reject when the scan key is an engine credential sent to the wrong host.
    Prevents Railway GROQ_API_KEY leaking into OpenAI target calls.
    """
    key = (api_key or "").strip()
    if not key:
        raise ValueError("Target API key is empty — provide the key from the scan form.")

    provider = resolve_target_provider(target_url, target_provider)
    host = (urlparse(target_url).hostname or "").lower()
    engine_keys = _engine_env_keys()

    if key in engine_keys:
        if provider == "groq" or "groq.com" in host:
            return
        raise ValueError(
            "Target API key matches an engine credential (GROQ/OpenRouter) but "
            f"target URL is not Groq ({host or target_url}). "
            "Use the API key for the target endpoint you entered in the scan form."
        )

    if provider == "openai" and key.startswith("gsk_"):
        raise ValueError(
            "Groq API key (gsk_…) cannot be used against OpenAI endpoints. "
            "Paste your OpenAI sk-… key in the scan form."
        )

    if provider == "groq" and key.startswith("sk-") and not key.startswith("gsk_"):
        log.warning(
            "[target] OpenAI-style sk- key used against Groq host — may 401"
        )


def build_target_authorization(api_key: str, target_provider: str = "") -> str:
    """Bearer header for target chat/completions — UI key only."""
    key = (api_key or "").strip()
    provider = (target_provider or "").lower()
    if provider in ("openai", "openai_compat", "groq", "anthropic", ""):
        return f"Bearer {key}"
    return f"Bearer {key}"


def build_target_client(
    *,
    base_url: str,
    api_key: str,
    model: str,
    target_provider: str = "",
    timeout: float = 30.0,
    max_tokens: int = 512,
) -> OpenAICompatibleClient:
    """Factory for kinetic weapon HTTP — validates isolation before firing."""
    provider = resolve_target_provider(base_url, target_provider)
    assert_target_key_isolation(
        api_key, target_url=base_url, target_provider=provider
    )
    client = OpenAICompatibleClient(
        base_url=base_url,
        api_key=api_key.strip(),
        model=model,
        timeout=timeout,
        max_tokens=max_tokens,
    )
    client.target_provider = provider  # type: ignore[attr-defined]
    return client


def is_auth_failure_response(response: str, http_status: int = 0) -> bool:
    if http_status == 401:
        return True
    text = (response or "").lower()
    return "[http-401]" in text or "invalid api key" in text or "incorrect api key" in text
