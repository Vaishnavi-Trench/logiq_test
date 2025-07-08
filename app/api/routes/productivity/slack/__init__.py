from fastapi.responses import JSONResponse
from fastapi import APIRouter, Path, Body
from pydantic import BaseModel
from typing import Any, Optional
from pltfrm import Logger2 as Logger
from app.services.productivity.slack.tools import send_notification
from fastapi.encoders import jsonable_encoder
import json



class SlackRequest(BaseModel):
    task: Optional[str] = None
    message: str

router = APIRouter(tags=["slack"])

@router.post("/send_notification/{intcid}", response_model=dict)
async def send_notification_route(
    intcid: str,
    request: SlackRequest
):
    message = request.message
    if not message:
        Logger.error("Message is required to send to Slack.")
        return JSONResponse(
            status_code=400,
            content={"error": "Message is required to send to Slack."}
        )
    
    Logger.info(f"Sending message to Slack for integration {intcid}")
    
    # Call the service function to send the message
    result = await send_notification(
        intcid=intcid,
        message=message
    )
    
    return result