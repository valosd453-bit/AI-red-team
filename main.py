import uvicorn
from agathon.orchestrator import app

if __name__ == '__main__':
    # Force port to 7860 to match Railway settings
    port = 7860
    print(f'--- AGATHON BATTLE ENGINE BOOTING ON SOVEREIGN PORT {port} ---')
    uvicorn.run('main:app', host='0.0.0.0', port=port, proxy_headers=True, forwarded_allow_ips='*')
