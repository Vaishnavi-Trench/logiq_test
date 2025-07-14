# filepath: /Users/harish/trench/logiq/app/api/routes/general/urlutils/__init__.py
"""URLUtils routes package."""

from fastapi.responses import JSONResponse
from fastapi import APIRouter, Path, Body
from pydantic import BaseModel
from typing import Any
from pltfrm import Logger2 as Logger
from app.services.general.urlutils import tools
from fastapi.encoders import jsonable_encoder
import json


class UrlRequest(BaseModel):
    url: str


class UrlListResponse(BaseModel):
    result: bool
    description: str


# Create router without prefix (prefix is added by parent router)
router = APIRouter(tags=["urlutils"])


@router.post("/is_whitelist_url/{intcid}", response_model=UrlListResponse)
async def is_whitelist_url_route(
    intcid: str = Path(..., description="Customer ID"),
    request: UrlRequest = Body(..., description="URL request body"),
):
    url = request.url
    Logger.info(f"api: /general/urlutils/is_whitelist_url/{intcid}: {url}")
    try:
        result = tools.is_whitelist_url(url, intcid)
        filtered_result = {k: v for k, v in result.items() if k in ("result", "description")}
        return filtered_result
    except Exception as e:
        Logger.error(f"Error checking whitelist URL: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed in checking whitelist URL: {str(e)}"},
        )


@router.post("/is_blocklist_url/{intcid}", response_model=UrlListResponse)
async def is_blocklist_url_route(
    intcid: str = Path(..., description="Customer ID"),
    request: UrlRequest = Body(..., description="URL request body"),
):
    url = request.url
    Logger.info(f"api: /general/urlutils/is_blocklist_url/{intcid}: {url}")
    try:
        result = tools.is_blocklist_url(url, intcid)
        filtered_result = {k: v for k, v in result.items() if k in ("result", "description")}
        return filtered_result
    except Exception as e:
        Logger.error(f"Error checking blocklist URL: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed in checking blocklist URL: {str(e)}"},
        )