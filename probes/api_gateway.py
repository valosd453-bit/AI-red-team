"""API_GATEWAY surface — sequential IDOR / BOLA fuzzer skeleton."""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, TYPE_CHECKING
from urllib.parse import urljoin, urlparse

import httpx

if TYPE_CHECKING:
    from agathon.orchestrator import AgathonState

logger = logging.getLogger(__name__)

_ID_PATTERNS = (
    re.compile(r"/(?:users|user|orders|order|accounts|account|resources|resource)/(\d+)", re.I),
    re.compile(r"/(?:api/)?(?:v\d+/)?(?:users|orders|items)/(\d+)", re.I),
    re.compile(r"[?&](?:id|user_id|order_id)=(\d+)", re.I),
)


def _extract_seed_id(url: str) -> int | None:
    for pat in _ID_PATTERNS:
        m = pat.search(url)
        if m:
            try:
                return int(m.group(1))
            except (TypeError, ValueError):
                continue
    return None


def _build_id_url(base: str, seed: int, test_id: int) -> str:
    return re.sub(str(seed), str(test_id), base, count=1)


async def run_api_gateway_probes(state: "AgathonState") -> List[Dict[str, Any]]:
    """Sequential ID fuzzer — probe adjacent resource IDs for BOLA/IDOR."""
    findings: List[Dict[str, Any]] = []
    url = state.target_url
    if not url.startswith("http"):
        url = f"https://{url}"

    seed = _extract_seed_id(url)
    headers: Dict[str, str] = {}
    if state.api_key:
        headers["Authorization"] = f"Bearer {state.api_key.strip()}"

    async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
        if seed is None:
            parsed = urlparse(url)
            base_path = parsed.path.rstrip("/") or "/api/v1/users"
            seed = 1
            candidates = [
                urljoin(url, f"{base_path}/{seed + delta}")
                for delta in range(-3, 4)
                if seed + delta > 0
            ]
        else:
            candidates = [
                _build_id_url(url, seed, seed + delta)
                for delta in range(-5, 6)
                if seed + delta > 0 and seed + delta != seed
            ]

        baseline_status: int | None = None
        for probe_url in candidates[:12]:
            try:
                resp = await client.get(probe_url, headers=headers)
                if baseline_status is None:
                    baseline_status = resp.status_code
                idor_hit = resp.status_code == 200 and len(resp.text) > 20
                if idor_hit and probe_url != url:
                    findings.append(
                        {
                            "surface": "API_GATEWAY",
                            "probe": "idor_sequential_fuzz",
                            "success": True,
                            "severity": "high",
                            "evidence": f"GET {probe_url} -> {resp.status_code}, len={len(resp.text)}",
                        }
                    )
                else:
                    findings.append(
                        {
                            "surface": "API_GATEWAY",
                            "probe": "idor_sequential_fuzz",
                            "success": False,
                            "severity": "info",
                            "evidence": f"GET {probe_url} -> {resp.status_code}",
                        }
                    )
            except Exception as exc:  # noqa: BLE001
                findings.append(
                    {
                        "surface": "API_GATEWAY",
                        "probe": "idor_sequential_fuzz",
                        "success": False,
                        "severity": "info",
                        "evidence": str(exc)[:200],
                    }
                )

    return findings
