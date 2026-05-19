"""
agathon/recon.py
────────────────────────────────────────────────────────────────────────────
Recon Intelligence Module
=========================
Performs OSINT reconnaissance on a target domain/IP using:
  - DNS enumeration (A, MX, NS, TXT, CNAME records)
  - HTTP banner grabbing (title, server header, tech stack hints)
  - Basic port scanning (common web ports)
  - Subdomain enumeration (wordlist-based)
  - Link/path enumeration via BeautifulSoup HTML parsing

Results are persisted to the `recon_targets` Supabase table and emitted
as a `surface_map` JSON structure for the frontend tree graph.

The run_recon() coroutine is called by the orchestrator as a BackgroundTask.

Env vars:
  SUPABASE_URL              Supabase project URL
  SUPABASE_SERVICE_ROLE_KEY Service role key
  PLAYWRIGHT_HEADLESS       "true" (default) or "false"
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import socket
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import httpx

log = logging.getLogger("agathon.recon")

# ── Optional DNS library ──────────────────────────────────────────────────────
try:
    import dns.resolver
    HAS_DNSPY = True
except ImportError:
    HAS_DNSPY = False
    log.warning("dnspython not installed — DNS enumeration will use socket fallback")

# ── BeautifulSoup ────────────────────────────────────────────────────────────
try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False
    log.warning("beautifulsoup4 not installed — HTML parsing disabled")

# ── Playwright (optional, for JS-heavy targets) ───────────────────────────────
try:
    from playwright.async_api import async_playwright
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False
    log.warning("playwright not installed — falling back to httpx for page fetch")


# ── Common ports to check ────────────────────────────────────────────────────
COMMON_PORTS = [21, 22, 25, 53, 80, 443, 3000, 3306, 5432, 6379, 8080, 8443, 8888, 9200, 27017]

# ── Common subdomains to bruteforce ─────────────────────────────────────────
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "api", "dev", "staging", "admin", "blog",
    "app", "static", "cdn", "docs", "support", "m", "mobile",
    "login", "auth", "dashboard", "portal", "beta",
]


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _normalize_target(target: str) -> tuple[str, str]:
    """Return (hostname, base_url) for a given target string."""
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"
    parsed = urlparse(target)
    hostname = parsed.hostname or target
    base_url = f"{parsed.scheme}://{hostname}"
    return hostname, base_url


async def _check_port(hostname: str, port: int, timeout: float = 1.5) -> bool:
    """Async TCP connect check. Returns True if port is open."""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(hostname, port), timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False


async def _dns_records(hostname: str) -> Dict[str, List[str]]:
    """Query common DNS record types. Returns dict of type → [values]."""
    records: Dict[str, List[str]] = {}

    if HAS_DNSPY:
        for rtype in ("A", "MX", "NS", "TXT", "CNAME"):
            try:
                answers = dns.resolver.resolve(hostname, rtype, lifetime=5)
                records[rtype] = [str(r) for r in answers]
            except Exception:
                pass
    else:
        # Fallback: just A record via socket
        try:
            infos = socket.getaddrinfo(hostname, None)
            records["A"] = list({info[4][0] for info in infos})
        except Exception:
            pass

    return records


async def _http_banner(base_url: str, timeout: float = 10.0) -> Dict[str, Any]:
    """Grab HTTP headers and page title."""
    result: Dict[str, Any] = {"url": base_url, "reachable": False}
    try:
        async with httpx.AsyncClient(
            timeout=timeout, follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (ForgeGuard Recon/1.0)"},
        ) as client:
            resp = await client.get(base_url)
            result["status_code"] = resp.status_code
            result["reachable"] = True
            result["server"] = resp.headers.get("server", "")
            result["x_powered_by"] = resp.headers.get("x-powered-by", "")
            result["content_type"] = resp.headers.get("content-type", "")
            result["redirect_url"] = str(resp.url) if str(resp.url) != base_url else None

            if HAS_BS4 and "html" in result.get("content_type", ""):
                soup = BeautifulSoup(resp.text, "html.parser")
                title_tag = soup.find("title")
                result["title"] = title_tag.get_text(strip=True)[:200] if title_tag else ""
                # Extract meta generator
                gen = soup.find("meta", attrs={"name": "generator"})
                result["generator"] = gen.get("content", "")[:100] if gen else ""
                # Count links
                result["link_count"] = len(soup.find_all("a", href=True))
    except Exception as e:
        result["error"] = str(e)[:200]

    return result


async def _playwright_fetch(url: str) -> Dict[str, Any]:
    """Fetch a JS-rendered page with Playwright for richer enumeration."""
    if not HAS_PLAYWRIGHT:
        return {}
    result: Dict[str, Any] = {}
    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage"],
            )
            page = await browser.new_page()
            await page.goto(url, timeout=20000, wait_until="networkidle")
            result["title"] = await page.title()
            result["links"] = await page.eval_on_selector_all(
                "a[href]", "els => els.slice(0,50).map(e => e.href)"
            )
            await browser.close()
    except Exception as e:
        result["playwright_error"] = str(e)[:200]
    return result


async def _subdomain_bruteforce(hostname: str) -> List[str]:
    """Check common subdomains via DNS."""
    found: List[str] = []
    # Strip leading www if present
    base = hostname.lstrip("www.") if hostname.startswith("www.") else hostname

    async def check(sub: str) -> Optional[str]:
        candidate = f"{sub}.{base}"
        try:
            if HAS_DNSPY:
                dns.resolver.resolve(candidate, "A", lifetime=3)
            else:
                socket.getaddrinfo(candidate, None)
            return candidate
        except Exception:
            return None

    tasks = [check(sub) for sub in COMMON_SUBDOMAINS]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, str):
            found.append(r)
    return found


# ─────────────────────────────────────────────────────────────────────────────
# Surface map builder
# ─────────────────────────────────────────────────────────────────────────────

def _build_surface_map(
    hostname: str,
    dns_records: Dict[str, List[str]],
    banner: Dict[str, Any],
    open_ports: List[int],
    subdomains: List[str],
) -> Dict[str, Any]:
    """Build the tree-graph JSON for the frontend."""
    nodes = []

    # DNS node
    dns_children = []
    for rtype, vals in dns_records.items():
        for val in vals[:3]:  # cap at 3 per type
            node_id = f"dns_{rtype}_{val[:20].replace(' ', '_')}"
            nodes.append({
                "id": node_id,
                "label": f"{rtype}: {val[:40]}",
                "type": "record",
                "children": [],
            })
            dns_children.append(node_id)
    nodes.append({"id": "dns", "label": "DNS Records", "type": "dns", "children": dns_children})

    # HTTP node
    http_children = []
    if banner.get("reachable"):
        if banner.get("title"):
            nodes.append({"id": "http_title", "label": f"Title: {banner['title'][:40]}", "type": "record", "children": []})
            http_children.append("http_title")
        if banner.get("server"):
            nodes.append({"id": "http_server", "label": f"Server: {banner['server'][:40]}", "type": "record", "children": []})
            http_children.append("http_server")
        if banner.get("status_code"):
            nodes.append({"id": "http_status", "label": f"HTTP {banner['status_code']}", "type": "record", "children": []})
            http_children.append("http_status")
    nodes.append({"id": "http", "label": "HTTP Banner", "type": "http", "children": http_children})

    # Ports node
    port_children = []
    for port in open_ports:
        nid = f"port_{port}"
        label = {80: "HTTP :80", 443: "HTTPS :443", 22: "SSH :22", 21: "FTP :21",
                 3306: "MySQL :3306", 5432: "Postgres :5432", 6379: "Redis :6379",
                 8080: "Alt-HTTP :8080", 9200: "Elastic :9200"}.get(port, f"TCP :{port}")
        nodes.append({"id": nid, "label": label, "type": "port", "children": []})
        port_children.append(nid)
    nodes.append({"id": "ports", "label": f"Open Ports ({len(open_ports)})", "type": "ports", "children": port_children})

    # Subdomains node
    sub_children = []
    for sub in subdomains[:8]:
        nid = f"sub_{sub.replace('.', '_')}"
        nodes.append({"id": nid, "label": sub, "type": "subdomain", "children": []})
        sub_children.append(nid)
    if subdomains:
        nodes.append({"id": "subdomains", "label": f"Subdomains ({len(subdomains)})", "type": "subdomains", "children": sub_children})

    # Root children
    root_children = ["dns", "http", "ports"]
    if subdomains:
        root_children.append("subdomains")

    return {
        "root": hostname,
        "nodes": nodes,
        "root_children": root_children,
        "meta": {
            "dns_records": len(dns_records),
            "open_ports": open_ports,
            "subdomains_found": len(subdomains),
            "http_reachable": banner.get("reachable", False),
        },
    }


# ─────────────────────────────────────────────────────────────────────────────
# Main entrypoint — called as BackgroundTask from orchestrator
# ─────────────────────────────────────────────────────────────────────────────

async def run_recon(
    recon_id: str,
    target: str,
    depth: int,
    supabase_admin: Any,
) -> None:
    """
    Background recon task. Updates the recon_targets row with results.

    Args:
        recon_id:       UUID of the recon_targets row
        target:         Domain, IP, or URL to scan
        depth:          Scan depth (1=fast, 2=normal, 3=deep)
        supabase_admin: Admin Supabase client (bypasses RLS)
    """
    log.info(f"[recon:{recon_id[:8]}] Starting recon on {target!r} depth={depth}")

    # Mark as running
    supabase_admin.table("recon_targets").update({
        "status": "running",
        "started_at": datetime.now(timezone.utc).isoformat(),
    }).eq("id", recon_id).execute()

    try:
        hostname, base_url = _normalize_target(target)

        # Phase 1: DNS + HTTP (always)
        dns_task = _dns_records(hostname)
        banner_task = _http_banner(base_url)
        dns_records, banner = await asyncio.gather(dns_task, banner_task)

        # Phase 2: Port scan (depth >= 1)
        ports_to_check = COMMON_PORTS if depth >= 2 else [80, 443, 22, 8080]
        port_tasks = [_check_port(hostname, p) for p in ports_to_check]
        port_results = await asyncio.gather(*port_tasks, return_exceptions=True)
        open_ports = [
            ports_to_check[i]
            for i, r in enumerate(port_results)
            if r is True
        ]

        # Phase 3: Subdomain bruteforce (depth >= 2)
        subdomains: List[str] = []
        if depth >= 2:
            subdomains = await _subdomain_bruteforce(hostname)

        # Phase 4: Playwright deep fetch (depth >= 3)
        if depth >= 3 and HAS_PLAYWRIGHT:
            playwright_data = await _playwright_fetch(base_url)
            if playwright_data.get("links"):
                banner["links"] = playwright_data["links"]

        surface_map = _build_surface_map(hostname, dns_records, banner, open_ports, subdomains)

        # Persist results
        supabase_admin.table("recon_targets").update({
            "status": "done",
            "surface_map": surface_map,
            "completed_at": datetime.now(timezone.utc).isoformat(),
        }).eq("id", recon_id).execute()

        log.info(
            f"[recon:{recon_id[:8]}] Done — "
            f"{len(dns_records)} DNS types, {len(open_ports)} open ports, "
            f"{len(subdomains)} subdomains"
        )

    except Exception as exc:
        log.exception(f"[recon:{recon_id[:8]}] Failed: {exc}")
        supabase_admin.table("recon_targets").update({
            "status": "failed",
            "error_msg": str(exc)[:500],
            "completed_at": datetime.now(timezone.utc).isoformat(),
        }).eq("id", recon_id).execute()
