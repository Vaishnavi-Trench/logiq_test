# filepath: /Users/harish/trench/logiq/app/api/routes/general/userutils/__init__.py
"""UserUtils routes package."""

from fastapi.responses import JSONResponse
from fastapi import APIRouter, Path, Body
from pydantic import BaseModel
from typing import Any
from pltfrm import Logger2 as Logger
from app.services.general.userutils import tools
from fastapi.encoders import jsonable_encoder
import json


class UserRequest(BaseModel):
    user_identifier: str


class UserListResponse(BaseModel):
    result: bool
    description: str


# Create router without prefix (prefix is added by parent router)
router = APIRouter(tags=["userutils"])


@router.post("/is_whitelist_user/{intcid}", response_model=UserListResponse)
async def is_whitelist_user_route(
    intcid: str = Path(..., description="Customer ID"),
    request: UserRequest = Body(..., description="User identifier request body"),
):
    user_identifier = request.user_identifier
    Logger.info(f"api: /general/userutils/is_whitelist_user/{intcid}: {user_identifier}")
    try:
        result = tools.is_whitelist_user(user_identifier, intcid)
        filtered_result = {k: v for k, v in result.items() if k in ("result", "description")}
        return filtered_result
    except Exception as e:
        Logger.error(f"Error checking whitelist user: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed in checking whitelist user: {str(e)}"},
        )


@router.post("/is_blocklist_user/{intcid}", response_model=UserListResponse)
async def is_blocklist_user_route(
    intcid: str = Path(..., description="Customer ID"),
    request: UserRequest = Body(..., description="User identifier request body"),
):
    user_identifier = request.user_identifier
    Logger.info(f"api: /general/userutils/is_blocklist_user/{intcid}: {user_identifier}")
    try:
        result = tools.is_blocklist_user(user_identifier, intcid)
        filtered_result = {k: v for k, v in result.items() if k in ("result", "description")}
        return filtered_result
    except Exception as e:
        Logger.error(f"Error checking blocklist user: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed in checking blocklist user: {str(e)}"},
        )