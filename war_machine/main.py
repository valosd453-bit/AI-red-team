"""
War Machine microservice — Marine Swarm lead scraper.
Separate from Agathon; writes to war_machine_leads only.
"""

from __future__ import annotations

import asyncio
import os
from typing import Any, Dict

import uvicorn
from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from war_machine.scraper import scrape_product_hunt_ai

app = FastAPI(title="ForgeGuard War Machine", version="1.0.0")


def _require_internal_secret(
    x_internal_scan_token: str | None = Header(default=None, alias="x-internal-scan-token"),
    authorization: str | None = Header(default=None),
) -> str:
    expected = (
        os.environ.get("INTERNAL_SCAN_TOKEN")
        or os.environ.get("AGATHON_INTERNAL_SECRET")
        or ""
    ).strip()
    if not expected:
        raise HTTPException(status_code=503, detail="INTERNAL_SCAN_TOKEN not configured")
    token = (x_internal_scan_token or "").strip()
    if not token and authorization:
        auth = authorization.strip()
        if auth.lower().startswith("bearer "):
            token = auth[7:].strip()
    if token != expected:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return token


def _get_supabase_admin():
    from supabase import create_client

    url = os.environ.get("SUPABASE_URL", "").strip()
    key = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "").strip()
    if not url or not key:
        raise HTTPException(status_code=503, detail="Supabase admin not configured")
    return create_client(url, key)


class ScrapeRequest(BaseModel):
    hours: int = Field(default=24, ge=1, le=168)
    source: str = Field(default="producthunt_ai")


@app.get("/health")
async def health() -> Dict[str, str]:
    return {"status": "ok", "service": "war-machine"}


@app.post("/scrape", status_code=202)
async def scrape(
    payload: ScrapeRequest,
    background_tasks: BackgroundTasks,
    _auth: str = Depends(_require_internal_secret),
) -> JSONResponse:
    admin = _get_supabase_admin()

    def _run() -> Dict[str, Any]:
        return scrape_product_hunt_ai(hours=payload.hours, supabase_admin=admin)

    background_tasks.add_task(_run)
    return JSONResponse(
        {
            "ok": True,
            "status": "started",
            "source": payload.source,
            "hours": payload.hours,
            "message": "Marine Swarm scraper dispatched — Product Hunt AI category",
        },
        status_code=202,
    )


@app.post("/scrape/sync")
async def scrape_sync(
    payload: ScrapeRequest,
    _auth: str = Depends(_require_internal_secret),
) -> JSONResponse:
    admin = _get_supabase_admin()
    result = await asyncio.to_thread(
        scrape_product_hunt_ai, hours=payload.hours, supabase_admin=admin
    )
    return JSONResponse(result, status_code=200)


if __name__ == "__main__":
    port = int(os.environ.get("WAR_MACHINE_PORT", os.environ.get("PORT", 7871)))
    uvicorn.run(
        "war_machine_service:app",
        host="0.0.0.0",
        port=port,
        proxy_headers=True,
        forwarded_allow_ips="*",
    )
