"""
Dynamic Garak probe catalogue for ForgeGuard Agathon.

Introspects the installed ``garak`` package and registers hundreds of probe
classes into the bridge REGISTRY. Execution is batched per probe to respect
scan budgets (see ``MAX_PROBES_PER_STRIKE`` in ``garak_runner``).
"""

from __future__ import annotations

import importlib
import inspect
import logging
import pkgutil
import re
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Build-time floor (Docker/nixpacks) — Garak cold-starts without full runtime env
COLD_START_MIN_PROBES = 100
# Runtime goal — warn below this when API keys are present; never crash startup
RUNTIME_TARGET_PROBES = 350

_RUNTIME_KEY_VARS = (
    "GROQ_API_KEY",
    "OPENROUTER_API_KEY",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
)

# Curated families for mandatory kinetic battery (before Brain loop)
KINETIC_BATTERY_FAMILIES: Tuple[str, ...] = (
    "prompt_injection",
    "jailbreak",
    "pii_leak",
    "hallucination",
    "dan",
    "leak",
    "promptinject",
    "misleading",
)

# Map garak probe submodule names → execution category / curated fallback
_MODULE_TO_CATEGORY: Dict[str, str] = {
    "promptinject": "prompt_injection",
    "prompt_injection": "prompt_injection",
    "dan": "jailbreak",
    "jailbreak": "jailbreak",
    "leak": "pii_leak",
    "pii_leak": "pii_leak",
    "misleading": "hallucination",
    "hallucination": "hallucination",
    "packagehallucination": "hallucination",
    "malwaregen": "jailbreak",
    "atkgen": "prompt_injection",
    "encoding": "prompt_injection",
    "glitch": "prompt_injection",
    "goodside": "prompt_injection",
    "grandma": "jailbreak",
    "donotanswer": "jailbreak",
    "tap": "prompt_injection",
    "continuation": "jailbreak",
    "lmrc": "jailbreak",
    "realtoxicityprompts": "jailbreak",
    "knownbads": "jailbreak",
    "topic": "prompt_injection",
    "suffix": "prompt_injection",
    "xss": "prompt_injection",
    "visual_jailbreak": "jailbreak",
    "base64": "prompt_injection",
    "ansiescape": "prompt_injection",
    "figstep": "jailbreak",
    "latentinjection": "prompt_injection",
}

_CANONICAL_CATEGORIES = frozenset(
    {"prompt_injection", "jailbreak", "pii_leak", "hallucination"}
)


def canonical_garak_family(category: str) -> str:
    """Map any Garak category to one of four tier-filterable families."""
    cat = category.replace("-", "_").lower()
    if cat not in _CANONICAL_CATEGORIES:
        cat = _MODULE_TO_CATEGORY.get(cat, cat)
    if cat not in _CANONICAL_CATEGORIES:
        if "leak" in cat or "pii" in cat:
            cat = "pii_leak"
        elif "jail" in cat or "dan" in cat:
            cat = "jailbreak"
        elif "halluc" in cat or "mislead" in cat:
            cat = "hallucination"
        else:
            cat = "prompt_injection"
    return f"garak_{cat}"


@dataclass(frozen=True)
class GarakProbeSpec:
    """One discoverable Garak probe class."""

    registry_name: str
    module_name: str
    class_name: str
    category: str
    family: str
    level: str


def _level_for_module(module_name: str) -> str:
    """Assign catalogue tier from probe family name."""
    hardish = {"dan", "malwaregen", "atkgen", "jailbreak", "leak", "packagehallucination"}
    if module_name in hardish:
        return "medium"
    return "easy"


def _category_for_module(module_name: str) -> str:
    """Map garak submodule to curated fallback category."""
    key = module_name.lower().replace("-", "_")
    return _MODULE_TO_CATEGORY.get(key, key)


def _is_probe_class(obj: Any, module_name: str) -> bool:
    """Return True if ``obj`` looks like a Garak Probe class."""
    if not inspect.isclass(obj):
        return False
    name = getattr(obj, "__name__", "")
    if not name or name.startswith("_"):
        return False
    if name in ("Probe", "TreeSearchProbe"):
        return False
    mod = getattr(obj, "__module__", "") or ""
    if f"garak.probes.{module_name}" not in mod and module_name not in mod:
        return False
    try:
        from garak.probes.base import Probe  # type: ignore

        return issubclass(obj, Probe) and obj is not Probe
    except Exception:  # noqa: BLE001
        # Fallback: Garak probes are conventionally PascalCase in probe modules
        return bool(re.match(r"^[A-Z][A-Za-z0-9_]+$", name))


def discover_garak_probes() -> List[GarakProbeSpec]:
    """
    Walk ``garak.probes`` and collect concrete Probe subclasses.

    Returns an empty list when garak is not installed; callers fall back to
    the four legacy garak.* catalogue entries.
    """
    specs: List[GarakProbeSpec] = []
    try:
        import garak.probes as probes_root  # type: ignore
    except ImportError:
        logger.warning("[garak_catalog] garak not installed — using legacy 4 probes")
        return specs

    for modinfo in pkgutil.iter_modules(probes_root.__path__, probes_root.__name__ + "."):
        short_name = modinfo.name.split(".")[-1]
        if short_name.startswith("_"):
            continue
        try:
            mod = importlib.import_module(modinfo.name)
        except Exception as exc:  # noqa: BLE001
            log_fn = logger.info if len(specs) < RUNTIME_TARGET_PROBES else logger.debug
            log_fn("[garak_catalog] skip module %s: %s", modinfo.name, exc)
            continue

        category = _category_for_module(short_name)
        family = canonical_garak_family(category)
        level = _level_for_module(short_name)

        for _attr, obj in inspect.getmembers(mod, inspect.isclass):
            if not _is_probe_class(obj, short_name):
                continue
            class_name = obj.__name__
            registry_name = f"garak.{short_name}.{class_name}"
            specs.append(
                GarakProbeSpec(
                    registry_name=registry_name,
                    module_name=short_name,
                    class_name=class_name,
                    category=category,
                    family=family,
                    level=level,
                )
            )

    # Stable ordering for reproducible catalogues
    specs.sort(key=lambda s: s.registry_name)
    logger.info("[garak_catalog] discovered %d Garak probe classes", len(specs))
    return specs


def probe_count(*, log: bool = True) -> int:
    """Return number of discoverable Garak probe specs (for health checks)."""
    specs = discover_garak_probes()
    n = len(specs)
    if log:
        msg = f"[registry] Cold-start probes detected: {n}"
        print(msg, flush=True)
        logger.info(msg)
    return n


def _runtime_keys_present() -> bool:
    import os

    return any(os.environ.get(k, "").strip() for k in _RUNTIME_KEY_VARS)


def warm_runtime_garak_registry() -> int:
    """
    Re-discover Garak probes after the bunker env is live and extend REGISTRY.

    Idempotent — existing registry names are skipped by the bridge reload helper.
    """
    import os

    n = probe_count(log=True)
    keys_present = _runtime_keys_present()

    if keys_present:
        present = [k for k in _RUNTIME_KEY_VARS if os.environ.get(k, "").strip()]
        logger.info("[registry] Runtime API keys detected: %s", ", ".join(present))
    else:
        logger.info(
            "[registry] No runtime LLM keys set — using cold-start Garak catalogue (%d)",
            n,
        )

    from forgeguard_bridge import REGISTRY, reload_garak_heavy_registry

    added, registry_size = reload_garak_heavy_registry()
    n = probe_count(log=False)
    msg = (
        f"[registry] Runtime arsenal: {registry_size} entries, "
        f"garak_classes={n} (target {RUNTIME_TARGET_PROBES}+)"
    )
    print(msg, flush=True)
    logger.info(msg)
    if added:
        logger.info("[registry] Garak reload added %d new probe entries", added)

    if keys_present and n < RUNTIME_TARGET_PROBES:
        logger.warning(
            "[registry] Runtime Garak count %d below target %d — "
            "some probe modules may still be unavailable",
            n,
            RUNTIME_TARGET_PROBES,
        )

    return n


def get_kinetic_battery_strikes() -> List[Tuple[str, str]]:
    """
    Return (registry_name, category) pairs for the mandatory pre-Brain battery.

    Picks representatives for jailbreak, prompt_injection, and pii_leak first,
    then fills up to 24 strikes from discovered specs.
    """
    specs = discover_garak_probes()
    battery: List[Tuple[str, str]] = []
    seen_categories: set[str] = set()
    priority = ("prompt_injection", "jailbreak", "pii_leak", "hallucination")

    legacy = [
        ("garak.prompt_injection", "prompt_injection"),
        ("garak.jailbreak", "jailbreak"),
        ("garak.pii_leak", "pii_leak"),
        ("garak.hallucination", "hallucination"),
    ]
    for name, cat in legacy:
        battery.append((name, cat))
        seen_categories.add(cat)

    for cat in priority:
        for spec in specs:
            if spec.category != cat:
                continue
            if (spec.registry_name, cat) not in battery:
                battery.append((spec.registry_name, cat))
                seen_categories.add(cat)
                break

    for spec in specs:
        if len(battery) >= 24:
            break
        mod_key = spec.module_name.lower()
        cat = spec.category
        if mod_key in KINETIC_BATTERY_FAMILIES or cat in priority:
            if (spec.registry_name, cat) not in battery:
                battery.append((spec.registry_name, cat))
                seen_categories.add(cat)

    return battery[:24]


def make_registry_entry(
    spec: GarakProbeSpec,
    runner_fn: Callable[..., Any],
) -> Dict[str, Any]:
    """Build one forgeguard_bridge REGISTRY dict for a Garak probe."""

    def _fn(client: Any, model: str, _spec: GarakProbeSpec = spec) -> Any:
        return runner_fn(
            client,
            model,
            probe_module=_spec.module_name,
            probe_class=_spec.class_name,
            category=_spec.category,
            registry_name=_spec.registry_name,
        )

    return {
        "name": spec.registry_name,
        "family": spec.family,
        "level": spec.level,
        "fn": _fn,
    }


def resolve_category_from_registry_name(registry_name: str) -> str:
    """
    Map ``garak.module.Class`` or ``garak.category`` to execution category.

    Used by kinetic strike and ``run_attack`` when the Brain passes a full
    Garak probe name.
    """
    parts = registry_name.split(".")
    if len(parts) >= 3 and parts[0] == "garak":
        return _category_for_module(parts[1])
    if len(parts) == 2 and parts[0] == "garak":
        return _category_for_module(parts[1])
    return registry_name


def build_garak_registry_entries(
    runner_fn: Callable[..., Any],
) -> List[Dict[str, Any]]:
    """
    Produce bridge REGISTRY entries for all discovered Garak probes.

    Args:
        runner_fn: ``run_garak_probe`` from ``garak_runner`` module.
    """
    return [make_registry_entry(spec, runner_fn) for spec in discover_garak_probes()]
