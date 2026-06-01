"""Hugging Face / Docker entry — exposes FastAPI app for ``uvicorn main:app``."""

from api.app import app

__all__ = ["app"]
