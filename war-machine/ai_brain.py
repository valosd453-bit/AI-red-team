"""
ai_brain.py — OpenRouter Scare Hook Generator
──────────────────────────────────────────────────────────────────────────────
Sends a startup description to Llama-3 via OpenRouter.
Returns a 2-sentence "Scare Hook" identifying a specific AI security risk
and positioning ForgeGuard AI as the solution.

Also generates a dynamic, personalized email subject line.
"""

from __future__ import annotations

import logging
import re
import time
from typing import Optional

import httpx
from config import (
    OPENROUTER_API_KEY,
    OPENROUTER_MODEL,
    OPENROUTER_BASE_URL,
)

logger = logging.getLogger("war-machine.ai_brain")

# ─── System prompt ────────────────────────────────────────────────────────────

SCARE_HOOK_SYSTEM = """\
You are an elite AI Red Teamer working for ForgeGuard AI — the most advanced \
AI security platform on the market.

Your job: analyze a startup's description and identify ONE high-impact AI \
security vulnerability they are almost certainly exposing RIGHT NOW.

Choose from vulnerabilities like:
- Prompt Injection (LLM hijacking via user input)
- Economic Denial of Sustainability / EDoS (token exhaustion attacks)
- Data Leakage via LLM context windows (training data extraction)
- Agent Privilege Escalation (autonomous agents exceeding their scope)
- Indirect Prompt Injection (malicious data poisoning external sources)
- Model Inversion (reconstructing private training data)
- Jailbreak-as-a-Service (weaponized jailbreaks against their AI product)

Output format — respond with ONLY a JSON object, nothing else:
{
  "vulnerability": "<short vulnerability name>",
  "scare_hook": "<2 sentences: sentence 1 names the threat specifically for their product. Sentence 2 says ForgeGuard AI can stop it — keep it urgent but not cheesy>",
  "subject_line": "<cold email subject line under 60 chars — punchy, specific, NOT clickbait>"
}

Rules:
- Be technically specific. Name the exact attack vector.
- Reference THEIR product type in the hook (not generic AI talk).
- Never mention competitor tools.
- Sound like a red-team report, not a sales pitch.
- subject_line should create urgency without being cringe.
"""

# ─── OpenRouter call ──────────────────────────────────────────────────────────

def generate_scare_hook(
    company_name: str,
    description:  str,
    retries:      int = 3,
    backoff:      float = 2.0,
) -> dict[str, str]:
    """
    Calls OpenRouter with the startup description.
    Returns dict with keys: vulnerability, scare_hook, subject_line.
    Falls back to safe defaults on total failure.
    """
    if not description.strip():
        description = f"{company_name} — AI-powered startup (no description available)"

    prompt = (
        f"Startup: {company_name}\n"
        f"Description: {description}\n\n"
        "Identify their highest-priority AI security vulnerability and generate the scare hook JSON."
    )

    headers = {
        "Authorization":  f"Bearer {OPENROUTER_API_KEY}",
        "Content-Type":   "application/json",
        "HTTP-Referer":   "https://forgeguard.ai",
        "X-Title":        "ForgeGuard War Machine",
    }

    payload = {
        "model":    OPENROUTER_MODEL,
        "messages": [
            {"role": "system",  "content": SCARE_HOOK_SYSTEM},
            {"role": "user",    "content": prompt},
        ],
        "temperature": 0.7,
        "max_tokens":  300,
    }

    last_err: Optional[Exception] = None
    for attempt in range(retries):
        try:
            resp = httpx.post(
                OPENROUTER_BASE_URL,
                headers=headers,
                json=payload,
                timeout=30.0,
            )
            resp.raise_for_status()
            content = resp.json()["choices"][0]["message"]["content"].strip()
            return _parse_json_response(content, company_name)

        except Exception as e:
            last_err = e
            wait = backoff ** attempt
            logger.warning(f"OpenRouter attempt {attempt+1} failed: {e}. Retrying in {wait}s…")
            time.sleep(wait)

    logger.error(f"All OpenRouter attempts failed for {company_name}: {last_err}")
    return _fallback_hook(company_name)


def _parse_json_response(raw: str, company_name: str) -> dict[str, str]:
    """Extract JSON from the model response (handles markdown code fences)."""
    # Strip markdown code fences if present
    raw = re.sub(r"```(?:json)?", "", raw).strip("` \n")

    try:
        import json
        data = json.loads(raw)
        return {
            "vulnerability": str(data.get("vulnerability", "Prompt Injection")),
            "scare_hook":    str(data.get("scare_hook", _fallback_hook(company_name)["scare_hook"])),
            "subject_line":  str(data.get("subject_line", f"Your AI might be wide open — {company_name}")),
        }
    except Exception as e:
        logger.warning(f"JSON parse failed ({e}), extracting manually from: {raw[:200]}")
        # Best-effort regex extraction
        scare = re.search(r'"scare_hook"\s*:\s*"([^"]+)"', raw)
        subj  = re.search(r'"subject_line"\s*:\s*"([^"]+)"', raw)
        vuln  = re.search(r'"vulnerability"\s*:\s*"([^"]+)"', raw)
        return {
            "vulnerability": vuln.group(1) if vuln else "Prompt Injection",
            "scare_hook":    scare.group(1) if scare else _fallback_hook(company_name)["scare_hook"],
            "subject_line":  subj.group(1) if subj else f"Critical AI vulnerability found — {company_name}",
        }


def _fallback_hook(company_name: str) -> dict[str, str]:
    """Used when OpenRouter fails entirely."""
    return {
        "vulnerability": "Prompt Injection",
        "scare_hook": (
            f"{company_name}'s AI surface is exposed to prompt injection attacks "
            f"that can hijack your model's behavior in production. "
            f"ForgeGuard AI's automated red-teaming can map and seal this attack vector "
            f"before a threat actor finds it first."
        ),
        "subject_line": f"Your AI product has an open attack surface, {company_name}",
    }


# ─── Batch processor ─────────────────────────────────────────────────────────

def process_leads_batch(leads: list[dict]) -> list[dict]:
    """
    Enrich a list of lead dicts with scare_hook + subject_line.
    Modifies in place and returns.
    """
    for i, lead in enumerate(leads):
        logger.info(f"[{i+1}/{len(leads)}] Generating scare hook for {lead['company_name']}…")
        hook = generate_scare_hook(
            company_name=lead.get("company_name", ""),
            description=lead.get("description", ""),
        )
        lead["scare_hook"]    = hook["scare_hook"]
        lead["subject_line"]  = hook["subject_line"]
        lead["vulnerability"] = hook["vulnerability"]
        time.sleep(0.5)  # gentle rate limit on free tier
    return leads


if __name__ == "__main__":
    # Quick smoke test
    import json
    logging.basicConfig(level=logging.INFO)
    result = generate_scare_hook(
        company_name="Synthwave AI",
        description="We build an AI copilot for enterprise sales teams that reads emails, CRM data, and Slack to auto-generate deal summaries.",
    )
    print(json.dumps(result, indent=2))
