"""IPInfo routes package."""

from typing import Optional
from fastapi.responses import JSONResponse
from fastapi import APIRouter, Path, Body
from pydantic import BaseModel
from pltfrm import Logger2 as Logger
from app.services.orbit.tablename import handler


class FeedbackFormRequest(BaseModel):
    type: str
    vendor: str
    alertName: str
    tid: str
    questionId: str
    stepId: str
    selectedTableName: str


class ProcessFeedbackRequest(BaseModel):
    type: str
    vendor: str
    alertName: str
    tid: str
    noteId: str


# Create router without prefix (prefix is added by parent router)
router = APIRouter(tags=["ipinfo"])


@router.post("/feedback-form/{intcid}")
async def feedbackform_route(
    intcid: str = Path(..., description="Customer ID"),
    request: FeedbackFormRequest = Body(
        ..., description="" "feedback form request body"
    ),
):
    """
    Get geolocation information for an IP address

    Args:
        intcid: Customer ID
        request: Request body containing IP address

    Returns:
        Geolocation information for the provided IP address
    """
    Logger.info(
        f"api: /orbit/tablename/get_feedbackform/{intcid}: Retrieving feedbackform"
    )
    success, response = handler.get_feedbackform(
        intcid,
        request.type,
        request.vendor,
        request.alertName,
        request.tid,
        request.questionId,
        request.stepId,
        request.selectedTableName,
    )
    if not success:
        Logger.error(f"Failed to retrieve feedback form: {response}")
        return JSONResponse(
            status_code=500, content={"error": "Failed to retrieve feedback form"}
        )

    return response


@router.post("/process-feedback/{intcid}")
async def process_feedbackform(
    intcid: str = Path(..., description="Customer ID"),
    request: ProcessFeedbackRequest = Body(
        ..., description="" "feedback form request body"
    ),
):
    """
    Get geolocation information for an IP address

    Args:
        intcid: Customer ID
        request: Request body containing IP address

    Returns:
        Geolocation information for the provided IP address
    """
    Logger.info(
        f"api: /orbit/tablename/get_feedbackform/{intcid}: Retrieving feedbackform"
    )
    success, response = handler.process_feedbackform(
        intcid,
        request.type,
        request.vendor,
        request.alertName,
        request.tid,
        request.noteId,
    )
    if not success:
        Logger.error(f"Failed to retrieve feedback form: {response}")
        return JSONResponse(
            status_code=500, content={"error": "Failed to retrieve feedback form"}
        )

    return response
