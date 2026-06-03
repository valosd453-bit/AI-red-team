"""WEB_APP surface — Playwright XSS / SQLi scout skeleton."""

from __future__ import annotations

import logging
from typing import Any, Dict, List, TYPE_CHECKING
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

if TYPE_CHECKING:
    from agathon.orchestrator import AgathonState

logger = logging.getLogger(__name__)

_XSS_CANARY = '<script>fg_xss_canary</script>'
_SQLI_PAYLOADS = ("' OR '1'='1", "1; DROP TABLE users--", "' UNION SELECT NULL--")


async def _playwright_scout(url: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        logger.warning("[web_app] playwright not installed")
        return findings

    parsed = urlparse(url)
    base_query = parse_qs(parsed.query)

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        context = await browser.new_context()
        page = await context.new_page()

        try:
            resp = await page.goto(url, wait_until="domcontentloaded", timeout=20_000)
            status = resp.status if resp else 0
            html = await page.content()
            findings.append(
                {
                    "probe": "baseline_fetch",
                    "success": status >= 500,
                    "severity": "medium" if status >= 500 else "info",
                    "evidence": f"HTTP {status}, body_len={len(html)}",
                }
            )

            for payload in _SQLI_PAYLOADS:
                q = dict(base_query)
                q.setdefault("q", [payload])
                test_url = urlunparse(
                    parsed._replace(query=urlencode(q, doseq=True))
                )
                try:
                    r = await page.goto(test_url, wait_until="domcontentloaded", timeout=15_000)
                    body = await page.content()
                    sqli_hit = any(
                        m in body.lower()
                        for m in ("sql syntax", "mysql", "sqlite", "postgresql", "ora-")
                    )
                    findings.append(
                        {
                            "probe": "sqli_param_fuzz",
                            "success": sqli_hit,
                            "severity": "high" if sqli_hit else "info",
                            "evidence": f"payload={payload[:40]} status={r.status if r else 0}",
                        }
                    )
                except Exception as exc:  # noqa: BLE001
                    findings.append(
                        {
                            "probe": "sqli_param_fuzz",
                            "success": False,
                            "severity": "info",
                            "evidence": str(exc)[:200],
                        }
                    )

            xss_q = dict(base_query)
            xss_q.setdefault("search", [_XSS_CANARY])
            xss_url = urlunparse(parsed._replace(query=urlencode(xss_q, doseq=True)))
            try:
                await page.goto(xss_url, wait_until="domcontentloaded", timeout=15_000)
                xss_html = await page.content()
                reflected = _XSS_CANARY in xss_html
                findings.append(
                    {
                        "probe": "xss_reflection_scout",
                        "success": reflected,
                        "severity": "high" if reflected else "info",
                        "evidence": "canary reflected in DOM" if reflected else "no reflection",
                    }
                )
            except Exception as exc:  # noqa: BLE001
                findings.append(
                    {
                        "probe": "xss_reflection_scout",
                        "success": False,
                        "severity": "info",
                        "evidence": str(exc)[:200],
                    }
                )
        finally:
            await browser.close()

    return findings


async def run_web_app_probes(state: "AgathonState") -> List[Dict[str, Any]]:
    """Playwright XSS/SQLi scout against the scan target URL."""
    url = state.target_url
    if not url.startswith("http"):
        url = f"https://{url}"
    raw = await _playwright_scout(url)
    return [{**f, "surface": "WEB_APP"} for f in raw]
