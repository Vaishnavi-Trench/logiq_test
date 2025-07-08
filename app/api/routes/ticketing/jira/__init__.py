from fastapi.responses import JSONResponse
from fastapi import APIRouter, Path, Body
from pydantic import BaseModel
from typing import Any, Optional
from pltfrm import Logger2 as Logger
from app.services.ticketing.jira.tools import raise_ticket
from fastapi.encoders import jsonable_encoder
import json





router = APIRouter(tags=["jira"])


class JiraRequest(BaseModel):
    task: Optional[str] = None
    summary: str
    description: str
    issuetype: Optional[str] = "Task"
    
@router.post("/raise_ticket/{intcid}", response_model=dict)
async def raise_ticket_route(
    intcid: str,
    request: JiraRequest
):
    summary = request.summary
    description = request.description
    issuetype = request.issuetype
    
    if not summary or not description:
        Logger.error("Summary and description are required to raise a ticket.")
        return JSONResponse(
            status_code=400,
            content={"error": "Summary and description are required to raise a ticket."}
        )
    
    Logger.info(f"Raising ticket in Jira for integration {intcid}")
    
    # Call the service function to raise the ticket
    result = await raise_ticket(
        intcid=intcid,
        summary=summary,
        description=description,
        issuetype=issuetype
    )
    
    return result