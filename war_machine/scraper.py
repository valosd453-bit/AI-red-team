"""
War Machine — Product Hunt AI category scraper (last 24h).
Writes leads to Supabase war_machine_leads (falls back to public.leads).
"""

from __future__ import annotations

import logging
import os
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

log = logging.getLogger("war_machine.scraper")

PH_GRAPHQL = "https://api.producthunt.com/v2/api/graphql"
PH_TOPIC_SLUG = "artificial-intelligence"

WAR_MACHINE_LEADS_TABLE = os.environ.get("WAR_MACHINE_LEADS_TABLE", "war_machine_leads")
WAR_MACHINE_LEADS_WRITE_TABLE = os.environ.get("WAR_MACHINE_LEADS_WRITE_TABLE", "leads")

PH_QUERY = """
query RecentAiPosts($postedAfter: DateTime!, $first: Int!) {
  posts(
    topic: "%s"
    order: NEWEST
    first: $first
    postedAfter: $postedAfter
  ) {
    edges {
      node {
        name
        tagline
        url
        website
        createdAt
        makers {
          name
        }
      }
    }
  }
}
""" % PH_TOPIC_SLUG


def _write_table() -> str:
    """Physical table for upserts — war_machine_leads is a read-only view in Supabase."""
    return WAR_MACHINE_LEADS_WRITE_TABLE


def _parse_iso_ts(raw: str) -> Optional[datetime]:
    if not raw:
        return None
    try:
        if raw.endswith("Z"):
            return datetime.fromisoformat(raw.replace("Z", "+00:00"))
        return datetime.fromisoformat(raw)
    except ValueError:
        return None


def _domain_from_url(url: str) -> str:
    try:
        host = urlparse(url).netloc.lower()
        return host[4:] if host.startswith("www.") else host
    except Exception:  # noqa: BLE001
        return ""


def _fetch_via_product_hunt_api(hours: int = 24) -> List[Dict[str, Any]]:
    token = os.environ.get("PRODUCT_HUNT_API_TOKEN", "").strip()
    if not token:
        return []

    import httpx

    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    payload = {
        "query": PH_QUERY,
        "variables": {
            "postedAfter": cutoff.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "first": 50,
        },
    }
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    with httpx.Client(timeout=45.0) as client:
        resp = client.post(PH_GRAPHQL, json=payload, headers=headers)
        resp.raise_for_status()
        data = resp.json()

    edges = data.get("data", {}).get("posts", {}).get("edges", [])
    leads: List[Dict[str, Any]] = []
    for edge in edges:
        node = edge.get("node") or {}
        created = _parse_iso_ts(str(node.get("createdAt") or ""))
        if created and created < cutoff:
            continue
        website = str(node.get("website") or node.get("url") or "").strip()
        makers = node.get("makers") or []
        founder = makers[0].get("name") if makers else None
        leads.append(
            {
                "company_name": str(node.get("name") or "Unknown AI Product"),
                "website_url": website or None,
                "founder_name": founder,
                "description": str(node.get("tagline") or "")[:2000],
                "source": "producthunt",
                "rank": "Lieutenant",
                "status": "new",
            }
        )
    return leads


def _fetch_via_public_feed(hours: int = 24) -> List[Dict[str, Any]]:
    import httpx

    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    url = "https://www.producthunt.com/feed"
    headers = {"User-Agent": "ForgeGuard-WarMachine/1.0 (+https://forgeguard.ai)"}

    with httpx.Client(timeout=30.0, follow_redirects=True) as client:
        resp = client.get(url, headers=headers)
        resp.raise_for_status()
        body = resp.text

    leads: List[Dict[str, Any]] = []
    for block in re.findall(r"<item>([\s\S]*?)</item>", body):
        title_m = re.search(r"<title>(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?</title>", block)
        link_m = re.search(r"<link>(.*?)</link>", block)
        desc_m = re.search(
            r"<description>(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?</description>", block, re.S
        )
        pub_m = re.search(r"<pubDate>(.*?)</pubDate>", block)
        if not title_m:
            continue
        title = re.sub(r"<[^>]+>", "", title_m.group(1)).strip()
        if not re.search(
            r"\b(AI|LLM|GPT|agent|model|ML)\b",
            title + (desc_m.group(1) if desc_m else ""),
            re.I,
        ):
            continue
        if pub_m:
            try:
                from email.utils import parsedate_to_datetime

                published = parsedate_to_datetime(pub_m.group(1).strip())
                if published.tzinfo is None:
                    published = published.replace(tzinfo=timezone.utc)
                if published < cutoff:
                    continue
            except (TypeError, ValueError):
                pass
        link = link_m.group(1).strip() if link_m else ""
        desc = re.sub(r"<[^>]+>", "", desc_m.group(1)).strip() if desc_m else ""
        leads.append(
            {
                "company_name": title[:200],
                "website_url": link or None,
                "founder_name": None,
                "description": desc[:2000],
                "source": "producthunt",
                "rank": "Recruit",
                "status": "new",
            }
        )
    return leads[:40]


def scrape_product_hunt_ai(
    *,
    hours: int = 24,
    supabase_admin: Any = None,
) -> Dict[str, Any]:
    """Scrape Product Hunt AI category and upsert into war_machine_leads."""
    started = time.time()
    leads = _fetch_via_product_hunt_api(hours=hours)
    source_mode = "product_hunt_api"
    if not leads:
        leads = _fetch_via_public_feed(hours=hours)
        source_mode = "product_hunt_rss"

    inserted = 0
    updated = 0
    errors: List[str] = []
    table_name = _write_table()

    if supabase_admin is not None:
        for lead in leads:
            website = lead.get("website_url")
            if not website:
                domain = _domain_from_url(str(lead.get("company_name", "")))
                website = f"https://{domain}" if domain else None
                lead["website_url"] = website
            if not website:
                errors.append(f"skip:{lead.get('company_name')}:no_url")
                continue
            try:
                existing = (
                    supabase_admin.table(table_name)
                    .select("id")
                    .eq("website_url", website)
                    .maybe_single()
                    .execute()
                )
                if existing.data:
                    supabase_admin.table(table_name).update(
                        {
                            "description": lead.get("description"),
                            "founder_name": lead.get("founder_name"),
                            "source": "producthunt",
                        }
                    ).eq("id", existing.data["id"]).execute()
                    updated += 1
                else:
                    supabase_admin.table(table_name).insert(lead).execute()
                    inserted += 1
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{lead.get('company_name')}:{exc}")
                log.warning("[war-machine] lead upsert failed: %s", exc)

        try:
            supabase_admin.table("war_machine_stats").upsert(
                {
                    "id": "producthunt_ai",
                    "total_scraped": len(leads),
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                },
                on_conflict="id",
            ).execute()
        except Exception as exc:  # noqa: BLE001
            log.debug("[war-machine] war_machine_stats upsert skipped: %s", exc)

    elapsed = round(time.time() - started, 2)
    return {
        "ok": True,
        "source_mode": source_mode,
        "hours": hours,
        "table": table_name,
        "leads_found": len(leads),
        "inserted": inserted,
        "updated": updated,
        "errors": errors[:10],
        "elapsed_s": elapsed,
        "sample": leads[:5],
    }
