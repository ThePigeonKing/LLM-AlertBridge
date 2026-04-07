import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from backend.app.config import settings

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
TEMPLATES_DIR = PROJECT_ROOT / "frontend" / "templates"
STATIC_DIR = PROJECT_ROOT / "frontend" / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    )
    logger.info("LLM-AlertBridge starting up")
    yield
    logger.info("LLM-AlertBridge shutting down")


def create_app() -> FastAPI:
    from backend.app.api.router import api_router

    app = FastAPI(
        title="LLM-AlertBridge",
        description="SOC/SIEM alert analysis with a local LLM",
        version="0.1.0",
        lifespan=lifespan,
    )

    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    app.include_router(api_router)

    return app


app = create_app()
