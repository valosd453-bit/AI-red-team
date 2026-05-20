"""
ForgeGuard AI — Cost Protector
═══════════════════════════════════════════════════════════════════════════
Estimates OpenRouter token cost before sending a prompt. If the projected
cost exceeds $0.10, the prompt is automatically routed through a free model
(Google Gemma / NVIDIA Nemotron) for lossless compression before the final
inference call.

Pricing data sourced from OpenRouter as of May 2026.
═══════════════════════════════════════════════════════════════════════════
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Tuple

import aiohttp

logger = logging.getLogger("forgeguard.cost-protector")

# ═══════════════════════════════════════════════════════════════════════════
# OpenRouter Pricing Table — May 2026 (USD per 1M tokens)
# ═══════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class ModelPricing:
    """Token pricing for a single model on OpenRouter."""
    model_id: str
    input_price_per_million: float     # USD
    output_price_per_million: float    # USD
    cached_input_price_per_million: float = 0.0
    tier: str = "paid"                 # "paid" | "free"


# ── Pricing catalogue (subset of OpenRouter models) ──

OPENROUTER_PRICES: Dict[str, ModelPricing] = {
    # ── OpenAI ──
    "openai/gpt-5":                     ModelPricing("openai/gpt-5", 1.25, 10.00),
    "openai/gpt-4o":                    ModelPricing("openai/gpt-4o", 2.50, 10.00),
    "openai/gpt-4o-mini":              ModelPricing("openai/gpt-4o-mini", 0.15, 0.60),
    "openai/o1":                        ModelPricing("openai/o1", 15.00