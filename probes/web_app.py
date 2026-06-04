"""WEB APPLICATION — Logic Discovery + XSS Vector Scout."""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Any, Dict, List, Set, TYPE_CHECKING
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

if TYPE_CHECKING:
    from agathon.orchestrator import AgathonState

logger = logging.getLogger(__name__)

_XSS_CANARY = "<script>fg_xss_canary</script>"
_SQLI_PAYLOADS = ("' OR '1'='1", "1; DROP TABLE users--", "' UNION SELECT NULL--")
_HIDDEN_PATHS = (
    "/admin",
    "/api",
    "/debug",
    "/health",
    "/swagger",
    "/graphql",
    "/.env",
    "/api/v1",
    "/internal",
)
_HREF_RE = re.compile(r"""href\s*=\s*['"]([^'"]+)['"]""", re.I)
_FORM_RE = re.compile(r"""action\s*=\s*['"]([^'"]+)['"]""", re.I)
_FETCH_RE = re.compile(r"""fetch\s*\(\s*['"]([^'"]+)['"]""", re.I)


def _logic_discovery_sync(url: str, auth_header: str) -> List[Dict[str, Any]]:
    """Sync Playwright crawl — run via asyncio.to_thread so /health stays responsive."""
    findings: List[Dict[str, Any]] = []
    discovered: Set[str] = set()

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        logger.warning("[web_app] playwright not installed")
        return findings

    parsed = urlparse(url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        extra = {"Authorization": auth_header} if auth_header else {}
        context = browser.new_context(extra_http_headers=extra)
        page = context.new_page()
        try:
            page.goto(url, wait_until="domcontentloaded", timeout=20_000)
            html = page.content()
            for pattern in (_HREF_RE, _FORM_RE, _FETCH_RE):
                for match in pattern.findall(html):
                    if match.startswith("/") or match.startswith("http"):
                        discovered.add(urljoin(origin, match))

            for hidden in _HIDDEN_PATHS:
                test_url = urljoin(origin, hidden)
                try:
                    resp = page.goto(
                        test_url, wait_until="domcontentloaded", timeout=10_000
                    )
                    status = resp.status if resp else 0
                    if status not in (404, 410):
                        discovered.add(test_url)
                        findings.append(
                            {
                                "probe": "logic_discovery_hidden_route",
                                "success": status == 200,
                                "severity": "medium" if status == 200 else "info",
                                "evidence": f"GET {test_url} -> HTTP {status}",
                            }
                        )
                except Exception:  # noqa: BLE001
                    continue

            if discovered:
                findings.append(
                    {
                        "probe": "logic_discovery_crawl",
                        "success": len(discovered) > 3,
                        "severity": "medium" if len(discovered) > 5 else "info",
                        "evidence": f"routes={list(discovered)[:20]}",
                    }
                )
        finally:
            browser.close()

    return findings


async def _logic_discovery(url: str, auth_header: str) -> List[Dict[str, Any]]:
    return await asyncio.to_thread(_logic_discovery_sync, url, auth_header)


def _xss_sqli_scout_sync(url: str, auth_header: str) -> List[Dict[str, Any]]:
    """XSS Vector Scout + SQLi — sync Playwright in worker thread (non-blocking event loop)."""
    findings: List[Dict[str, Any]] = []
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return findings

    parsed = urlparse(url)
    base_query = parse_qs(parsed.query)
    extra = {"Authorization": auth_header} if auth_header else {}

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        context = browser.new_context(extra_http_headers=extra)
        page = context.new_page()
        try:
            for payload in _SQLI_PAYLOADS:
                q = dict(base_query)
                q.setdefault("q", [payload])
                test_url = urlunparse(
                    parsed._replace(query=urlencode(q, doseq=True))
                )
                try:
                    r = page.goto(test_url, wait_until="domcontentloaded", timeout=15_000)
                    body = page.content()
                    sqli_hit = any(
                        m in body.lower()
                        for m in ("sql syntax", "mysql", "sqlite", "postgresql", "ora-")
                    )
                    findings.append(
                        {
                            "probe": "xss_sqli_scout",
                            "success": sqli_hit,
                            "severity": "high" if sqli_hit else "info",
                            "evidence": f"payload={payload[:40]} status={r.status if r else 0}",
                        }
                    )
                except Exception as exc:  # noqa: BLE001
                    findings.append(
                        {
                            "probe": "xss_sqli_scout",
                            "success": False,
                            "severity": "info",
                            "evidence": str(exc)[:200],
                        }
                    )

            xss_q = dict(base_query)
            xss_q.setdefault("search", [_XSS_CANARY])
            xss_url = urlunparse(parsed._replace(query=urlencode(xss_q, doseq=True)))
            page.goto(xss_url, wait_until="domcontentloaded", timeout=15_000)
            xss_html = page.content()
            reflected = _XSS_CANARY in xss_html
            findings.append(
                {
                    "probe": "xss_vector_scout",
                    "success": reflected,
                    "severity": "high" if reflected else "info",
                    "evidence": "canary reflected in DOM" if reflected else "no reflection",
                }
            )
        finally:
            browser.close()

    return findings


async def _xss_sqli_scout(url: str, auth_header: str) -> List[Dict[str, Any]]:
    return await asyncio.to_thread(_xss_sqli_scout_sync, url, auth_header)


async def run_web_app_probes(state: "AgathonState") -> List[Dict[str, Any]]:
    """Playwright logic discovery + XSS/SQLi scout with Bearer auth."""
    from agathon.target_client import build_universal_client

    url = state.target_url
    if not url.startswith("http"):
        url = f"https://{url}"

    utc = build_universal_client(
        target_url=url,
        target_api_key=state.api_key,
        model=state.target_model,
        target_provider=state.target_provider,
    )
    auth = utc.authorization_header()

    raw: List[Dict[str, Any]] = []
    raw.extend(await _logic_discovery(url, auth))
    raw.extend(await _xss_sqli_scout(url, auth))

    return [{**f, "surface": "WEB APPLICATION", "vector": "WEB_APP"} for f in raw]
