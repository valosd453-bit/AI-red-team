"""War Machine microservice entrypoint — run: uvicorn war_machine_service:app"""

from war_machine.main import app  # noqa: F401
