import os
import uvicorn
from agathon.orchestrator import app


def _boot_garak_arsenal() -> None:
    try:
        from agathon.garak_catalog import warm_runtime_garak_registry

        warm_runtime_garak_registry()
    except Exception as exc:  # noqa: BLE001
        print(f"[registry] Runtime warmup skipped: {exc}", flush=True)


_boot_garak_arsenal()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 7860))
    print(f'--- AGATHON BATTLE ENGINE BOOTING ON SOVEREIGN PORT {port} ---')
    uvicorn.run(
        'main:app',
        host='0.0.0.0',
        port=port,
        proxy_headers=True,
        forwarded_allow_ips='*',
    )
