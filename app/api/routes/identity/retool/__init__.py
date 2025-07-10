"""VirusTotal routes package."""

from typing import Optional, Any
from fastapi import APIRouter, Path, Body
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import json
from pltfrm import Logger2 as Logger
from app.services.identity.retool.tools import check_user_existence
from app.services.general.iputils import tools as iptools


class UserExistenceRequest(BaseModel):
    """Request model for checking user existence."""
    email: str

# Create router without prefix (prefix is added by parent router)
router = APIRouter(tags=["retool"])

@router.post("/check_user_existence/{intcid}", response_model=dict)
async def check_user_existence_route(
    intcid: str = Path(..., description="Integration ID for tracking"),
    request: UserExistenceRequest = Body(..., description="User existence request data")
) -> JSONResponse:
    """
    Check if a user exists by their email using pycurl and regex.
    
    Args:
        intcid (str): Integration ID for tracking.
        request (UserExistenceRequest): Request data containing email, domain, and login URL.
    
    Returns:
        JSONResponse: Response indicating whether the user exists or not.
    """
    Logger.info(f"Checking existence of user: {request.email} in integration {intcid}")
    response = check_user_existence(intcid, request.email)
    
    if response["status"]:
        Logger.info(f"User '{request.email}' exists.")
    else:
        Logger.info(f"User '{request.email}' does not exist. Reason: {response['description']}")
    
    return JSONResponse(content=response)

