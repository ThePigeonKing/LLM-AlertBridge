import uuid

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.db.session import get_session
from backend.app.services import alert_service
from backend.app.templates import templates

router = APIRouter(tags=["views"])


@router.get("/", response_class=RedirectResponse)
async def index():
    return RedirectResponse(url="/alerts", status_code=302)


@router.get("/alerts", response_class=HTMLResponse)
async def alerts_page(
    request: Request,
    page: int = 1,
    session: AsyncSession = Depends(get_session),
):
    alerts, total = await alert_service.list_alerts(session, page=page, size=20)
    total_pages = max(1, (total + 19) // 20)
    return templates.TemplateResponse(
        request=request,
        name="alerts.html",
        context={
            "alerts": alerts,
            "page": page,
            "total": total,
            "total_pages": total_pages,
        },
    )


@router.get("/alerts/{alert_id}", response_class=HTMLResponse)
async def alert_detail_page(
    request: Request,
    alert_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
):
    alert = await alert_service.get_alert(session, alert_id)
    if alert is None:
        return templates.TemplateResponse(
            request=request,
            name="404.html",
            context={"message": "Alert not found"},
            status_code=404,
        )
    latest_analysis = None
    if alert.analyses:
        latest_analysis = max(alert.analyses, key=lambda a: a.created_at)
    return templates.TemplateResponse(
        request=request,
        name="alert_detail.html",
        context={
            "alert": alert,
            "analysis": latest_analysis,
        },
    )
