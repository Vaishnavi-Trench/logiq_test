"""VirusTotal routes package."""

from typing import Optional, Any
from fastapi import APIRouter, Path, Body
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import json
from pltfrm import Logger2 as Logger
from app.services.intelligence.spycloud.tools import get_alert_context
from app.services.general.iputils import tools as iptools


class AlertRequest(BaseModel):
    task: Optional[str] = None
    alert: Any
    aid: str


# Create router without prefix (prefix is added by parent router)
router = APIRouter(tags=["spycloud"])


@router.post("/get_alert_context/{intcid}")
async def get_alert_context_route(
    intcid: str = Path(..., description="Customer ID"),
    request: AlertRequest = Body(..., description="Alert request body"),
):
    """
    Get alert context from Spycloud for a specific alert

    Args:
        intcid: Customer ID
        request: Request body containing alert information

    Returns:
        Alert context for the provided alert
    """
    alert = request.alert
    aid = request.aid
    task = request.task or "Get alert context"
    Logger.info(
        f"api: /intelligence/spycloud/get_alert_context/{intcid}: Retrieving alert context for alert {aid}"
    )

    if isinstance(alert, str):
        try:
            alert = json.loads(alert)  # Attempt to parse string as JSON
        except json.JSONDecodeError:
            Logger.error("Failed to decode alert from string.")
            return JSONResponse(
                status_code=400,
                content={"error": "alert_decode_error", "message": "Failed to decode alert from string."},
            )
    
    alert_context = get_alert_context(intcid, task, alert, aid)
    if not alert_context:
        Logger.error(f"Failed to retrieve alert context for alert {aid}")
        return JSONResponse(
            status_code=500,
            content={"error": "alert_context_retrieval_error", "message": "Failed to retrieve alert context."},
        )
    Logger.info(f"Retrieved alert context for alert {aid}: {alert_context}")
    return alert_context
    
