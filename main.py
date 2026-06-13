"""
Railway entrypoint — single source for Agathon engine boot.

`uvicorn main:app` loads `app` from agathon.orchestrator (see railway.toml).
"""
import os

import uvicorn
from agathon.orchestrator import app

__all__ = ["app"]

print("[SOVEREIGN] Agathon Engine Active. All pathways isolated.", flush=True)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "7860"))
    print(f"--- AGATHON BATTLE ENGINE BOOTING ON 0.0.0.0:{port} ---", flush=True)
    uvicorn.run(
        "agathon.orchestrator:app",
        host="0.0.0.0",
        port=port,
        proxy_headers=True,
        forwarded_allow_ips="*",
    )
