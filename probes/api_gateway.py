"""API GATEWAY — BOLA/IDOR sequential ID fuzzer."""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, TYPE_CHECKING
from urllib.parse import urljoin, urlparse

if TYPE_CHECKING:
    from agathon.orchestrator import AgathonState

logger = logging.getLogger(__name__)

_ID_PATTERNS = (
    re.compile(r"/(?:api/)?(?:user|users)/(\d+)", re.I),
    re.compile(r"/(?:orders|order|accounts|account|resources|resource)/(\d+)", re.I),
    re.compile(r"/(?:v\d+/)?(?:users|items|accounts)/(\d+)", re.I),
    re.compile(r"[?&](?:id|user_id|order_id)=(\d+)", re.I),
    re.compile(
        r"/(?:api/)?(?:user|users|profile|profiles)/"
        r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
        re.I,
    ),
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
    """Sequential ID fuzzer — BOLA/IDOR sweep via UniversalTargetClient."""
    from agathon.target_client import build_universal_client

    findings: List[Dict[str, Any]] = []
    url = state.target_url
    if not url.startswith("http"):
        url = f"https://{url}"

    utc = build_universal_client(
        target_url=url,
        target_api_key=state.api_key,
        model=state.target_model,
        target_provider=state.target_provider,
    )

    seed = _extract_seed_id(url)
    if seed is None:
        parsed = urlparse(url)
        base_path = parsed.path.rstrip("/") or "/api/user"
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

    baseline_body = ""
    exfiltration_hits = 0
    for probe_url in candidates[:12]:
        try:
            resp = await utc.request_async("GET", probe_url)
            body_snippet = (resp.text or "")[:300]
            tested_id: str | int | None = None
            for pat in _ID_PATTERNS:
                m = pat.search(probe_url)
                if m:
                    raw_id = m.group(1)
                    try:
                        tested_id = int(raw_id)
                    except (TypeError, ValueError):
                        tested_id = raw_id
                    break
            idor_hit = (
                resp.status_code == 200
                and len(resp.text or "") > 20
                and probe_url.rstrip("/") != url.rstrip("/")
            )
            if idor_hit and baseline_body and body_snippet != baseline_body:
                exfiltration_hits += 1
            evidence = {
                "baseline_id": seed,
                "tested_id": tested_id,
                "url": probe_url,
                "status": resp.status_code,
                "body_snippet": body_snippet,
            }
            if idor_hit:
                findings.append(
                    {
                        "surface": "API GATEWAY",
                        "vector": "API_GATEWAY",
                        "probe": "bola_idor_sweep",
                        "success": True,
                        "severity": "high",
                        "category": "idor",
                        "evidence": str(evidence),
                    }
                )
            else:
                if not baseline_body and resp.status_code == 200:
                    baseline_body = body_snippet
                findings.append(
                    {
                        "surface": "API GATEWAY",
                        "vector": "API_GATEWAY",
                        "probe": "bola_idor_sweep",
                        "success": False,
                        "severity": "info",
                        "category": "idor",
                        "evidence": str(evidence),
                    }
                )
        except Exception as exc:  # noqa: BLE001
            findings.append(
                {
                    "surface": "API GATEWAY",
                    "vector": "API_GATEWAY",
                    "probe": "bola_idor_sweep",
                    "success": False,
                    "severity": "info",
                    "category": "idor",
                    "evidence": str(exc)[:200],
                }
            )

    if exfiltration_hits >= 2:
        findings.append(
            {
                "surface": "API GATEWAY",
                "vector": "API_GATEWAY",
                "probe": "bola_hidden_user_exfiltration",
                "success": True,
                "severity": "critical",
                "category": "idor",
                "evidence": f"cross_user_responses={exfiltration_hits}",
            }
        )

    return findings
