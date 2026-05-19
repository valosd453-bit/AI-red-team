"""
db.py — Supabase client + leads table helpers
──────────────────────────────────────────────────────────────────────────────
All DB interactions go through this module. Uses the service role key so it
bypasses RLS — run server-side only, never expose this client to a browser.
"""

from __future__ import annotations

import logging
from typing import Any, Optional
from supabase import create_client, Client
from config import SUPABASE_URL, SUPABASE_SERVICE_KEY

logger = logging.getLogger("war-machine.db")

# ─── Singleton client ─────────────────────────────────────────────────────────

_client: Optional[Client] = None

def get_client() -> Client:
    global _client
    if _client is None:
        _client = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)
    return _client


# ─── Lead helpers ─────────────────────────────────────────────────────────────

def upsert_lead(lead: dict[str, Any]) -> dict[str, Any]:
    """
    Insert a lead or update it if the website_url already exists.
    Returns the full row including the auto-generated id + click_token.
    """
    sb = get_client()
    result = (
        sb.table("leads")
        .upsert(lead, on_conflict="website_url")
        .execute()
    )
    if result.data:
        return result.data[0]
    raise RuntimeError(f"upsert_lead failed: {result}")


def get_unsent_leads(limit: int = 50) -> list[dict[str, Any]]:
    """Return leads that haven't been emailed yet and have a valid email."""
    sb = get_client()
    result = (
        sb.table("leads")
        .select("*")
        .eq("status", "new")
        .not_.is_("email", "null")
        .limit(limit)
        .execute()
    )
    return result.data or []


def mark_emailed(lead_id: str, scare_hook: str) -> None:
    """Mark a lead as emailed and store the scare hook used."""
    sb = get_client()
    sb.table("leads").update({
        "status":     "emailed",
        "scare_hook": scare_hook,
        "emailed_at": "now()",
    }).eq("id", lead_id).execute()


def mark_clicked(click_token: str) -> Optional[dict[str, Any]]:
    """
    Called by the tracking API route when a lead clicks the link.
    Returns the updated lead row.
    """
    sb = get_client()
    result = (
        sb.table("leads")
        .update({"status": "clicked", "clicked_at": "now()"})
        .eq("click_token", click_token)
        .execute()
    )
    return result.data[0] if result.data else None


def mark_responded(lead_id: str) -> None:
    """Mark a lead as responded (manually triggered)."""
    sb = get_client()
    sb.table("leads").update({"status": "responded"}).eq("id", lead_id).execute()


def get_pipeline_stats() -> dict[str, int]:
    """Return counts for each status — used by the Shadow Fleet dashboard."""
    sb    = get_client()
    rows  = sb.table("leads").select("status").execute().data or []
    stats: dict[str, int] = {}
    for row in rows:
        s = row.get("status", "unknown")
        stats[s] = stats.get(s, 0) + 1
    return stats
