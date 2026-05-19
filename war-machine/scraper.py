"""
scraper.py — Lead Scraper
──────────────────────────────────────────────────────────────────────────────
Targets:
  1. Y Combinator Startup Directory  (ycombinator.com/companies)
  2. Product Hunt Today's Top Posts  (producthunt.com)

Each scraper extracts:
  company_name, website_url, founder_name, description, batch (YC only)

Results are upserted into Supabase → leads table.

Usage:
  python scraper.py --source yc --max 50
  python scraper.py --source producthunt --max 30
  python scraper.py --source all
"""

from __future__ import annotations

import asyncio
import argparse
import logging
import time
import re
from typing import Optional

from playwright.async_api import async_playwright, Page, Browser
from db import upsert_lead, get_client
from config import MAX_LEADS_PER_RUN, HEADLESS, SCRAPE_DELAY_SECONDS

logger = logging.getLogger("war-machine.scraper")
logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(levelname)s  %(message)s")


# ─── Helpers ──────────────────────────────────────────────────────────────────

def clean(text: Optional[str]) -> str:
    if not text:
        return ""
    return re.sub(r"\s+", " ", text.strip())


def infer_rank(description: str, batch: str = "") -> str:
    """
    Rough rank inference from description keywords.
    Admirable = Series A+, Lieutenant = Seed, Recruit = unknown/pre-seed.
    """
    desc = description.lower()
    if any(k in desc for k in ["series a", "series b", "series c", "ipo", "$10m", "$20m", "$50m"]):
        return "Admiral"
    if any(k in desc for k in ["seed", "pre-series", "$1m", "$2m", "$3m", "$5m", "launched"]):
        return "Lieutenant"
    return "Recruit"


# ─── YC Scraper ───────────────────────────────────────────────────────────────

async def scrape_yc(page: Page, max_leads: int) -> list[dict]:
    """
    Scrapes the YC company directory.
    Uses their public directory at https://www.ycombinator.com/companies
    Filters to AI / ML / Security companies.
    """
    logger.info("🔍 Navigating to YC company directory…")
    leads: list[dict] = []

    await page.goto(
        "https://www.ycombinator.com/companies?query=ai+security",
        wait_until="networkidle",
        timeout=60_000,
    )

    # YC directory is React-rendered; scroll to load more
    prev_count = 0
    for _ in range(20):
        cards = await page.query_selector_all("a._company_86jzd_338")
        if len(cards) >= max_leads:
            break
        if len(cards) == prev_count:
            break
        prev_count = len(cards)
        await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
        await asyncio.sleep(SCRAPE_DELAY_SECONDS)

    cards = await page.query_selector_all("a._company_86jzd_338")
    logger.info(f"Found {len(cards)} YC company cards")

    for card in cards[:max_leads]:
        try:
            name_el   = await card.query_selector("._coName_86jzd_453")
            desc_el   = await card.query_selector("._coDescription_86jzd_478")
            href      = await card.get_attribute("href") or ""

            company_name = clean(await name_el.inner_text() if name_el else "")
            description  = clean(await desc_el.inner_text() if desc_el else "")
            yc_url       = f"https://www.ycombinator.com{href}" if href.startswith("/") else href

            if not company_name:
                continue

            # Visit company page for website + founder
            website_url  = ""
            founder_name = ""
            batch        = ""

            if href:
                try:
                    await page.goto(yc_url, wait_until="domcontentloaded", timeout=30_000)
                    await asyncio.sleep(0.8)

                    # Website link
                    link_el = await page.query_selector('a[rel~="nofollow"][target="_blank"]')
                    if link_el:
                        website_url = clean(await link_el.get_attribute("href") or "")

                    # Founders
                    founder_els = await page.query_selector_all(".founder-name, [class*='founder'] h3")
                    if founder_els:
                        names = [clean(await el.inner_text()) for el in founder_els[:2]]
                        founder_name = ", ".join(n for n in names if n)

                    # Batch (e.g. W24, S23)
                    batch_el = await page.query_selector("[class*='batch']")
                    if batch_el:
                        batch = clean(await batch_el.inner_text())

                except Exception as e:
                    logger.debug(f"Company page visit failed for {company_name}: {e}")

            lead = {
                "company_name": company_name,
                "website_url":  website_url or yc_url,
                "founder_name": founder_name,
                "description":  description,
                "source":       "yc",
                "batch":        batch,
                "rank":         infer_rank(description, batch),
                "status":       "new",
            }
            leads.append(lead)
            logger.info(f"  ✓ {company_name} [{batch}]")

            # Go back to list
            await page.goto(
                "https://www.ycombinator.com/companies?query=ai+security",
                wait_until="domcontentloaded",
                timeout=30_000,
            )
            await asyncio.sleep(SCRAPE_DELAY_SECONDS)

        except Exception as e:
            logger.warning(f"  ✗ Card parse error: {e}")
            continue

    return leads


# ─── Product Hunt Scraper ─────────────────────────────────────────────────────

async def scrape_producthunt(page: Page, max_leads: int) -> list[dict]:
    """
    Scrapes Product Hunt's today's top posts filtered to AI tools.
    """
    logger.info("🔍 Navigating to Product Hunt AI category…")
    leads: list[dict] = []

    await page.goto(
        "https://www.producthunt.com/topics/artificial-intelligence",
        wait_until="networkidle",
        timeout=60_000,
    )

    # Scroll to load more posts
    for _ in range(5):
        await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
        await asyncio.sleep(SCRAPE_DELAY_SECONDS)

    post_links = await page.query_selector_all('a[href^="/posts/"]')
    seen_hrefs: set[str] = set()
    unique_links = []
    for lnk in post_links:
        href = await lnk.get_attribute("href") or ""
        if href and href not in seen_hrefs and len(href) > 7:
            seen_hrefs.add(href)
            unique_links.append(lnk)

    logger.info(f"Found {len(unique_links)} PH posts")

    for link in unique_links[:max_leads]:
        try:
            href     = await link.get_attribute("href") or ""
            post_url = f"https://www.producthunt.com{href}"

            await page.goto(post_url, wait_until="domcontentloaded", timeout=30_000)
            await asyncio.sleep(0.8)

            # Title
            title_el = await page.query_selector("h1")
            title    = clean(await title_el.inner_text() if title_el else "")

            # Tagline / description
            tagline_el = await page.query_selector('[data-test="product-tagline"], .tagline')
            description = clean(await tagline_el.inner_text() if tagline_el else "")
            if not description:
                # Fallback: og:description meta
                meta_el = await page.query_selector('meta[name="description"]')
                description = clean(await meta_el.get_attribute("content") if meta_el else "")

            # External URL
            visit_el    = await page.query_selector('a[data-test="visit-product-button"], a[rel~="nofollow"][href^="http"]')
            website_url = clean(await visit_el.get_attribute("href") if visit_el else "") or post_url

            # Maker name
            maker_el    = await page.query_selector('[class*="maker"] a, [data-test="maker-name"]')
            founder_name = clean(await maker_el.inner_text() if maker_el else "")

            if not title:
                continue

            lead = {
                "company_name": title,
                "website_url":  website_url,
                "founder_name": founder_name,
                "description":  description,
                "source":       "producthunt",
                "batch":        "",
                "rank":         infer_rank(description),
                "status":       "new",
            }
            leads.append(lead)
            logger.info(f"  ✓ {title}")

        except Exception as e:
            logger.warning(f"  ✗ PH post error: {e}")
            continue

    return leads


# ─── Email hunter (best-effort) ───────────────────────────────────────────────

def guess_email(company_name: str, website_url: str) -> str:
    """
    Generate a best-guess cold email address from the website domain.
    Pattern: founder@domain.com or hello@domain.com
    (In production, replace this with Hunter.io API or Apollo.io lookup)
    """
    if not website_url:
        return ""
    domain = re.sub(r"^https?://(www\.)?", "", website_url).split("/")[0].lower()
    if not domain or "." not in domain:
        return ""
    return f"founder@{domain}"


# ─── Main runner ──────────────────────────────────────────────────────────────

async def run_scraper(source: str = "all", max_leads: int = MAX_LEADS_PER_RUN) -> int:
    total = 0
    async with async_playwright() as pw:
        browser: Browser = await pw.chromium.launch(
            headless=HEADLESS,
            args=["--no-sandbox", "--disable-dev-shm-usage"],
        )
        ctx  = await browser.new_context(
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
            viewport={"width": 1440, "height": 900},
        )
        page = await ctx.new_page()

        scrapers = []
        if source in ("yc", "all"):
            scrapers.append(("yc", scrape_yc(page, max_leads)))
        if source in ("producthunt", "ph", "all"):
            scrapers.append(("producthunt", scrape_producthunt(page, max_leads)))

        for name, coro in scrapers:
            logger.info(f"\n{'='*60}\n  Running {name.upper()} scraper\n{'='*60}")
            try:
                leads = await coro
                for lead in leads:
                    lead["email"] = guess_email(lead["company_name"], lead["website_url"])
                    try:
                        row = upsert_lead(lead)
                        logger.info(f"  DB ✓ {lead['company_name']} → id={row.get('id','?')[:8]}…")
                        total += 1
                    except Exception as e:
                        logger.error(f"  DB ✗ {lead['company_name']}: {e}")
            except Exception as e:
                logger.error(f"Scraper {name} failed: {e}")

        await browser.close()

    logger.info(f"\n✅  Scraped + saved {total} leads total.")
    return total


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ForgeGuard War Machine — Lead Scraper")
    parser.add_argument("--source", default="all", choices=["yc", "producthunt", "ph", "all"])
    parser.add_argument("--max",    type=int, default=MAX_LEADS_PER_RUN)
    args = parser.parse_args()
    asyncio.run(run_scraper(source=args.source, max_leads=args.max))
