"""
Target HTTP client — UI scan key ONLY (Operation: Key Isolation).

Brain/strategy uses GROQ_API_KEY / OPENROUTER_API_KEY via clients/llm_client.py.
All outbound target strikes MUST use the api_key from the scan request payload.
"""

from __future__ import annotations

import logging
import os
from urllib.parse import urlparse

from forgeguard_bridge import OpenAICompatibleClient

log = logging.getLogger(__name__)

AUTH_FAILURE_MESSAGE = (
    "Authentication Error: Target rejected the provided API Key."
)

HANDSHAKE_ABORT_MESSAGE = "CRITICAL: Key-Provider Mismatch. Strike Aborted."

# Engine env keys — never use for target Authorization
_ENGINE_KEY_ENVS = (
    "GROQ_API_KEY",
    "OPENROUTER_API_KEY",
    "DEEPSEEK_API_KEY",
    "OPENAI_API_KEY",
)


class ProviderHandshakeError(ValueError):
    """Raised when scan-form api_key prefix does not match target URL host."""


def _url_host(target_url: str) -> str:
    return (urlparse(target_url).hostname or "").lower()


def provider_from_url_host(target_url: str) -> str | None:
    """Return canonical provider when URL host is unambiguous, else None."""
    host = _url_host(target_url)
    url_lower = (target_url or "").lower()
    if "groq.com" in host or "groq.com" in url_lower:
        return "groq"
    if "openai.com" in host or "api.openai" in host or "openai.com" in url_lower:
        return "openai"
    if "anthropic.com" in host or "anthropic.com" in url_lower:
        return "anthropic"
    return None


def resolve_target_provider(target_url: str, explicit: str = "") -> str:
    """Infer provider — URL host wins over explicit when host is unambiguous."""
    from_url = provider_from_url_host(target_url)
    if from_url:
        return from_url
    if explicit and explicit.strip():
        return explicit.strip().lower()
    host = _url_host(target_url)
    if "together.xyz" in host or "fireworks.ai" in host:
        return "openai_compat"
    return "openai_compat"


def assert_provider_handshake(api_key: str, target_url: str) -> None:
    """
    Strict URL-first key prefix validation (ignores misleading target_provider).
    """
    key = (api_key or "").strip()
    host = _url_host(target_url)
    url_lower = (target_url or "").lower()

    if "openai.com" in host or "openai.com" in url_lower or "api.openai" in url_lower:
        if not key.startswith("sk-"):
            log.critical(HANDSHAKE_ABORT_MESSAGE)
            raise ProviderHandshakeError(HANDSHAKE_ABORT_MESSAGE)

    if "groq.com" in host or "groq.com" in url_lower:
        if not key.startswith("gsk_"):
            log.critical(HANDSHAKE_ABORT_MESSAGE)
            raise ProviderHandshakeError(HANDSHAKE_ABORT_MESSAGE)


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
    host = _url_host(target_url)
    engine_keys = _engine_env_keys()

    if key in engine_keys:
        if provider == "groq" or "groq.com" in host:
            return
        raise ValueError(
            "Target API key matches an engine credential (GROQ/OpenRouter) but "
            f"target URL is not Groq ({host or target_url}). "
            "Use the API key for the target endpoint you entered in the scan form."
        )

    if key.startswith("gsk_") and provider != "groq" and "groq.com" not in host:
        raise ValueError(
            "Groq API key (gsk_…) cannot be used against non-Groq target endpoints. "
            "When targeting OpenAI, paste your OpenAI sk-… key from the scan form. "
            "GROQ_API_KEY is reserved for the Agathon brain only."
        )

    if provider == "openai" and key.startswith("gsk_"):
        raise ValueError(
            "Groq API key (gsk_…) cannot be used against OpenAI endpoints. "
            "Paste your OpenAI sk-… key in the scan form."
        )

    if (provider == "groq" or "groq.com" in host) and key.startswith("sk-") and not key.startswith("gsk_"):
        raise ValueError(
            "OpenAI API key (sk-…) cannot be used against Groq endpoints. "
            "Paste your Groq gsk_… key in the scan form."
        )


def _require_user_scan_key(api_key: str) -> str:
    """
    Scan-form key only — never substitute GROQ_API_KEY or other engine secrets.
    """
    key = (api_key or "").strip()
    if not key:
        raise ValueError("Target API key is empty — provide the key from the scan form.")
    for env_name in _ENGINE_KEY_ENVS:
        env_val = (os.environ.get(env_name) or "").strip()
        if env_val and key == env_val:
            log.debug(
                "[target] scan key matches engine env %s — isolation check follows",
                env_name,
            )
            break
    return key


def build_target_authorization(api_key: str, target_provider: str = "") -> str:
    """Bearer header for target chat/completions — UI key only."""
    key = _require_user_scan_key(api_key)
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
    scan_key = _require_user_scan_key(api_key)
    assert_provider_handshake(scan_key, base_url)
    provider = resolve_target_provider(base_url, target_provider)
    assert_target_key_isolation(
        scan_key, target_url=base_url, target_provider=provider
    )
    client = OpenAICompatibleClient(
        base_url=base_url,
        api_key=scan_key,
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
