import os

import uvicorn
from agathon.orchestrator import app

print("[SOVEREIGN] Agathon Engine Active. All pathways isolated.", flush=True)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 7860))
    print(f"--- AGATHON BATTLE ENGINE BOOTING ON SOVEREIGN PORT {port} ---")
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=port,
        proxy_headers=True,
        forwarded_allow_ips="*",
    )
