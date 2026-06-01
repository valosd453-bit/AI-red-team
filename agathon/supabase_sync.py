"""
Supabase scan_logs insert path with kinetic vocabulary normalization.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Dict, Optional

log = logging.getLogger(__name__)

ALLOWED_LOG_TYPES = frozenset({"info", "thought", "strike", "breach", "finance"})

LEGACY_LOG_TYPE_MAP: Dict[str, str] = {
    "info": "info",
    "audit": "info",
    "error": "info",
    "progress": "info",
    "report": "info",
    "cost_event": "finance",
    "brain_decision": "thought",
    "attempt": "strike",
    "finding": "breach",
    "tool_run": "strike",
    "tool_authored": "thought",
    # kinetic vocabulary passes through
    "thought": "thought",
    "strike": "strike",
    "breach": "breach",
    "finance": "finance",
}


def stringify_payload_numerics(value: Any) -> Any:
    """
    Cast numeric values in log/finding payloads to strings for Supabase JSON safety.

    Scores and CVSS fields are stored as ``str(score)`` per Stronghold contract.
    """
    if isinstance(value, dict):
        return {k: stringify_payload_numerics(v) for k, v in value.items()}
    if isinstance(value, list):
        return [stringify_payload_numerics(item) for item in value]
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        if isinstance(value, float) and value != value:
            return "nan"
        return str(value)
    return value


_DASH_REPLACEMENTS = (
    ("\u2014", "-"),  # em dash
    ("\u2013", "-"),  # en dash
    ("\u2012", "-"),  # figure dash
    ("\u2212", "-"),  # minus sign
)
_SMART_QUOTE_REPLACEMENTS = (
    ("\u2018", "'"),
    ("\u2019", "'"),
    ("\u201c", '"'),
    ("\u201d", '"'),
)


def sanitize_text_for_transport(text: str) -> str:
    """
    Normalize Unicode punctuation that breaks ASCII-only transports.

    Replaces em/en dashes with ASCII hyphen; ensures valid UTF-8 bytes.
    """
    if not text:
        return text
    for old, new in _DASH_REPLACEMENTS + _SMART_QUOTE_REPLACEMENTS:
        text = text.replace(old, new)
    return text.encode("utf-8", errors="replace").decode("utf-8")


def sanitize_payload_strings(value: Any) -> Any:
    """Recursively sanitize every string in a dict/list tree."""
    if isinstance(value, str):
        return sanitize_text_for_transport(value)
    if isinstance(value, dict):
        return {k: sanitize_payload_strings(v) for k, v in value.items()}
    if isinstance(value, list):
        return [sanitize_payload_strings(item) for item in value]
    return value


def prepare_outbound_payload(value: Any) -> Any:
    """Numeric stringify + UTF-8 transport safety for Supabase / WebSocket egress."""
    return sanitize_payload_strings(stringify_payload_numerics(value))


def normalize_log_type(raw: str) -> str:
    """Map legacy orchestrator types to production scan_logs CHECK vocabulary."""
    key = (raw or "info").strip().lower()
    mapped = LEGACY_LOG_TYPE_MAP.get(key, "info")
    if mapped not in ALLOWED_LOG_TYPES:
        return "info"
    return mapped


class SupabaseSync:
    """Single insert path for scan_logs with type normalization."""

    def __init__(self, admin_factory: Callable[[], Any]) -> None:
        self._admin_factory = admin_factory

    def insert_scan_log(self, row: Dict[str, Any]) -> None:
        payload = dict(row)
        payload["type"] = normalize_log_type(str(payload.get("type", "info")))
        if payload.get("attack_name") is not None:
            payload["attack_name"] = sanitize_text_for_transport(
                str(payload["attack_name"])
            )
        if payload.get("severity") is not None:
            payload["severity"] = sanitize_text_for_transport(str(payload["severity"]))
        if "payload" in payload and payload["payload"] is not None:
            payload["payload"] = prepare_outbound_payload(payload["payload"])
        try:
            admin = self._admin_factory()
            admin.table("scan_logs").insert(payload).execute()
        except Exception as exc:  # noqa: BLE001
            log.error(
                "scan_logs insert failed scan_id=%s type=%s: %s",
                payload.get("scan_id"),
                payload.get("type"),
                exc,
            )
            raise
