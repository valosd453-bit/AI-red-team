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
