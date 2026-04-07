from fastapi import APIRouter

from backend.app.api.alerts import router as alerts_router
from backend.app.api.analysis import router as analysis_router
from backend.app.api.health import router as health_router
from backend.app.api.views import router as views_router

api_router = APIRouter()
api_router.include_router(health_router)
api_router.include_router(alerts_router)
api_router.include_router(analysis_router)
api_router.include_router(views_router)
