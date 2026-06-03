"""AI_MODEL / LLM ENDPOINT — Garak + PyRIT prompt hijacking and jailbreak strikes."""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, TYPE_CHECKING

from agathon.garak_catalog import get_kinetic_battery_strikes
from agathon.target_client import build_universal_client

if TYPE_CHECKING:
    from agathon.orchestrator import AgathonState

logger = logging.getLogger(__name__)

_PRIORITY = frozenset({"prompt_injection", "jailbreak", "pii_leak"})


def _run_ai_model_probes_sync(state: "AgathonState") -> List[Dict[str, Any]]:
    """Sync Garak/PyRIT probe loop — run via asyncio.to_thread from async callers."""
    findings: List[Dict[str, Any]] = []
    utc = build_universal_client(
        target_url=state.target_url,
        target_api_key=state.api_key,
        model=state.target_model,
        target_provider=state.target_provider,
    )
    llm_client = utc._llm()

    try:
        from probes.garak import run_garak_probe
        from probes.pyrit_adapter import PYRIT_SCENARIOS, run_pyrit_probe
    except ImportError:
        logger.warning("[ai_model] probe imports unavailable")
        return findings

    strikes = [
        s for s in get_kinetic_battery_strikes() if s[1] in _PRIORITY
    ][:8]
    if not strikes:
        strikes = get_kinetic_battery_strikes()[:6]

    for registry_name, category in strikes:
        try:
            parts = registry_name.split(".")
            if len(parts) >= 3:
                result = run_garak_probe(
                    llm_client,
                    state.target_model,
                    probe_module=parts[1],
                    probe_class=parts[2],
                    category=category,
                    registry_name=registry_name,
                )
            else:
                result = run_garak_probe(
                    llm_client,
                    state.target_model,
                    probe_module=category.replace("_", ""),
                    probe_class="InjectMarkup",
                    category=category,
                    registry_name=registry_name,
                )
            findings.append(
                {
                    "surface": "LLM ENDPOINT",
                    "vector": "AI_MODEL",
                    "probe": registry_name,
                    "category": category,
                    "success": bool(getattr(result, "success", False)),
                    "severity": getattr(result, "severity", "info"),
                    "evidence": (getattr(result, "response", "") or "")[:500],
                }
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug("[ai_model] garak probe %s skipped: %s", registry_name, exc)

    for spec in PYRIT_SCENARIOS[:2]:
        try:
            result = run_pyrit_probe(
                llm_client,
                registry_name=spec["name"],
                category=spec["category"],
            )
            findings.append(
                {
                    "surface": "LLM ENDPOINT",
                    "vector": "AI_MODEL",
                    "probe": spec["name"],
                    "category": spec["category"],
                    "success": bool(getattr(result, "success", False)),
                    "severity": getattr(result, "severity", "info"),
                    "evidence": (getattr(result, "response", "") or "")[:500],
                }
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug("[ai_model] pyrit %s skipped: %s", spec["name"], exc)

    return findings


async def run_ai_model_probes(state: "AgathonState") -> List[Dict[str, Any]]:
    """Run Garak/PyRIT probes without blocking the orchestrator event loop."""
    return await asyncio.to_thread(_run_ai_model_probes_sync, state)
