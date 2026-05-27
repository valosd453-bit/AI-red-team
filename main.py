"""Hugging Face / Docker entry — exposes FastAPI app for `uvicorn main:app`."""

from agathon.orchestrator import app

__all__ = ["app"]
