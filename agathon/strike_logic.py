"""
Strike logic — target HTTP uses the scan-form API key only (Key Isolation).

Re-exports the canonical target client factory. Brain/strategy keys live in
clients/llm_client.py (GROQ_API_KEY / OPENROUTER_API_KEY).
"""

from .target_client import (
    AUTH_FAILURE_MESSAGE,
    assert_target_key_isolation,
    build_target_authorization,
    build_target_client,
    is_auth_failure_response,
    resolve_target_provider,
)

__all__ = [
    "AUTH_FAILURE_MESSAGE",
    "assert_target_key_isolation",
    "build_target_authorization",
    "build_target_client",
    "is_auth_failure_response",
    "resolve_target_provider",
]
