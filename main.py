import os

import uvicorn
from agathon.orchestrator import app


def _boot_garak_hot_reload() -> None:
    """Re-awaken full Garak arsenal on every process start (Railway live env)."""
    try:
        from agathon.garak_catalog import hot_reload_garak_catalog

        n = hot_reload_garak_catalog()
        print(f"[registry] Process boot hot_reload_garak_catalog: {n} probes", flush=True)
    except Exception as exc:  # noqa: BLE001
        print(f"[registry] Process boot hot reload skipped: {exc}", flush=True)


_boot_garak_hot_reload()

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
