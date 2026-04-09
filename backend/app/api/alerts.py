import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.db.session import get_session
from backend.app.models.alert import AlertStatus
from backend.app.schemas.alert import AlertBrief, AlertList, AlertRead
from backend.app.schemas.analysis import AnalysisRead
from backend.app.schemas.enrichment import EnrichmentRead
from backend.app.services import alert_service, analysis_service, enrichment_service
from backend.app.services.analysis_service import AnalysisMode
from backend.app.templates import templates

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


@router.get("", response_model=AlertList)
async def list_alerts(
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    status: AlertStatus | None = None,
    session: AsyncSession = Depends(get_session),
):
    alerts, total = await alert_service.list_alerts(
        session, page=page, size=size, status_filter=status
    )
    return AlertList(
        items=[AlertBrief.model_validate(a) for a in alerts],
        total=total,
        page=page,
        size=size,
    )


@router.get("/{alert_id}", response_model=AlertRead)
async def get_alert(
    alert_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
):
    alert = await alert_service.get_alert(session, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return AlertRead.model_validate(alert)


@router.get("/{alert_id}/analysis", response_model=AnalysisRead | None)
async def get_alert_analysis(
    alert_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
):
    alert = await alert_service.get_alert(session, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    if not alert.analyses:
        return None
    latest = max(alert.analyses, key=lambda a: a.created_at)
    return AnalysisRead.model_validate(latest)


@router.post("/sync")
async def sync_alerts(
    request: Request,
    limit: int = Query(50, ge=1, le=200),
    session: AsyncSession = Depends(get_session),
):
    try:
        new_alerts = await alert_service.ingest_from_wazuh(session, limit=limit)
        count = len(new_alerts)
    except Exception as e:
        if request.headers.get("HX-Request") == "true":
            from fastapi.responses import HTMLResponse
            return HTMLResponse(
                f'<div class="text-red-400 text-sm p-2">Sync failed: {e}</div>'
            )
        raise HTTPException(status_code=502, detail=str(e)) from e

    if request.headers.get("HX-Request") == "true":
        from fastapi.responses import HTMLResponse

        if count > 0:
            msg = f"Synced {count} new alert{'s' if count != 1 else ''}."
            return HTMLResponse(
                f'<div class="text-green-400 text-sm p-2">{msg} '
                '<a href="/alerts" class="underline">Refresh</a></div>'
            )
        return HTMLResponse(
            '<div class="text-soc-muted text-sm p-2">No new alerts found.</div>'
        )
    return {"status": "ok", "new_alerts": count}


@router.post("/{alert_id}/enrich")
async def enrich_alert(
    alert_id: uuid.UUID,
    request: Request,
    session: AsyncSession = Depends(get_session),
):
    is_htmx = request.headers.get("HX-Request") == "true"
    try:
        enrichment = await enrichment_service.enrich_alert(session, alert_id)
        if is_htmx:
            return templates.TemplateResponse(
                request=request,
                name="partials/enrichment_result.html",
                context={"enrichment": enrichment},
            )
        return EnrichmentRead.model_validate(enrichment)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
    except Exception as e:
        if is_htmx:
            from fastapi.responses import HTMLResponse
            return HTMLResponse(
                f'<div class="text-red-400 text-sm p-2">Enrichment failed: {e}</div>'
            )
        raise HTTPException(status_code=502, detail=str(e)) from e


@router.post("/{alert_id}/analyze")
async def analyze_alert(
    alert_id: uuid.UUID,
    request: Request,
    mode: str = Query("llm_enriched", pattern="^(baseline|llm|llm_enriched)$"),
    session: AsyncSession = Depends(get_session),
):
    is_htmx = request.headers.get("HX-Request") == "true"
    analysis_mode = AnalysisMode(mode)
    try:
        analysis = await analysis_service.analyze_alert(session, alert_id, mode=analysis_mode)
        if is_htmx:
            return templates.TemplateResponse(
                request=request,
                name="partials/analysis_result.html",
                context={"analysis": analysis},
            )
        return AnalysisRead.model_validate(analysis)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
    except RuntimeError as e:
        raise HTTPException(status_code=502, detail=str(e)) from e
