"""Hugging Face / Docker entry — exposes FastAPI app for ``uvicorn main:app``."""

from api.app import app

__all__ = ["app"]

if __name__ == "__main__":
    import os

    import uvicorn

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 7860)),
    )
