# Agathon Engine (AI-red-team)

An AI red-teaming framework and FastAPI orchestrator for adversarial testing and security assessment of large language models. Powers ForgeGuard scan execution (kinetic strikes, Garak probes, Groq Brain).

**Deploy target:** [Railway](https://railway.app) via **Railpack** (`runtime.txt`, `mise.toml`, `railway.toml`). Legacy `nixpacks.toml` is kept for reference if you switch builders in the dashboard.

| Item | Value |
|------|--------|
| Entry | `uvicorn main:app` → [`agathon/orchestrator.py`](agathon/orchestrator.py) |
| Port | `$PORT` (injected by Railway) |
| Build | Railpack + mise (`python-3.11` in `runtime.txt`; `python.github_attestations = false` in `mise.toml`) |

### Required environment variables

| Variable | Purpose |
|----------|---------|
| `SUPABASE_URL` | Postgres / Realtime |
| `SUPABASE_SERVICE_ROLE_KEY` | Engine writes `scan_logs` |
| `INTERNAL_SCAN_TOKEN` or `AGATHON_INTERNAL_SECRET` | Bearer auth from ForgeGuard |
| `GROQ_API_KEY` | Brain loop only |
| `OPENROUTER_API_KEY` | Scout / Assassin / Judge |

Optional: `DEEPSEEK_API_KEY`, `AGATHON_DOCKER_IMAGE`, `AGATHON_LOG_LEVEL`.

Optional webhook callback (engine → ForgeGuard):

- `AGATHON_WEBHOOK_CALLBACK_URL` = `https://www.forgeguard-ai.com/api/v1/webhooks/agathon`
- `AGATHON_WEBHOOK_SECRET` = same as ForgeGuard `AGATHON_WEBHOOK_SECRET` or `INTERNAL_SCAN_TOKEN`

### Health endpoints

- `GET /health` — survival liveness (no auth), returns `{"status":"healthy","engine":"Agathon-Sovereign"}`
- `GET /healthz` — same survival payload (platform probes)

Scan and identity routes still require `Authorization: Bearer <INTERNAL_SCAN_TOKEN>`.

**Canonical repository:** [github.com/valosd453-bit/AI-red-team](https://github.com/valosd453-bit/AI-red-team)

ForgeGuard Vercel must set `PYTHON_ENGINE_URL` / `AGATHON_ORCHESTRATOR_URL` to your Railway engine URL. The Next.js UI is **not** included in this image.

### Local smoke test

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
playwright install chromium
uvicorn main:app --host 0.0.0.0 --port 7860
curl http://localhost:7860/healthz
```

## Project Structure

```
AI-red-team/
├── agathon/              # FastAPI orchestrator + kinetic strike
│   ├── orchestrator.py   # Production app (Railway)
│   ├── kinetic_strike.py
│   └── reporter.py
├── attacks/              # Attack implementations + Garak
├── clients/              # LLM router (OpenRouter / Groq)
├── main.py               # Uvicorn entry (exports `app`)
├── cli.py                # CLI red-team runner
├── nixpacks.toml         # Railway Nixpacks build
├── requirements.txt      # Unified deps (Playwright, Garak, FastAPI)
├── run_redteam.py
└── config.py
```

## Setup (local development)

### Prerequisites

- Python 3.11+
- Virtual environment (recommended)

### Installation

```bash
git clone https://github.com/valosd453-bit/AI-red-team.git
cd AI-red-team
python -m venv .venv
source .venv/bin/activate   # or .venv\Scripts\activate on Windows
pip install -r requirements.txt
playwright install chromium
```

### Run the orchestrator (API)

```bash
uvicorn main:app --host 0.0.0.0 --port 7860
# or
python -m agathon.orchestrator
```

### Run the CLI assessment

```bash
python cli.py --model openai/gpt-oss-20b -m <model> ...
```

### Other runners

```bash
python run_redteam.py
python comprehensive_test.py
```
