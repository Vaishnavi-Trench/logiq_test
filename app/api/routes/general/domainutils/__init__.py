"""DomainUtils routes package."""

from fastapi.responses import JSONResponse
from fastapi import APIRouter, Path, Body
from pydantic import BaseModel
from typing import Any
from pltfrm import Logger2 as Logger
from app.services.general.domainutils import tools
from fastapi.encoders import jsonable_encoder
import json


class DomainRequest(BaseModel):
    domain: str


class DomainListResponse(BaseModel):
    result: bool
    description: str


# Create router without prefix (prefix is added by parent router)
router = APIRouter(tags=["domainutils"])


@router.post("/is_whitelist_domain/{intcid}", response_model=DomainListResponse)
async def is_whitelist_domain_route(
    intcid: str = Path(..., description="Customer ID"),
    request: DomainRequest = Body(..., description="Domain request body"),
):
    domain = request.domain
    Logger.info(f"api: /general/domainutils/is_whitelist_domain/{intcid}: {domain}")
    try:
        result = tools.is_whitelist_domain(domain, intcid)
        filtered_result = {k: v for k, v in result.items() if k in ("result", "description")}
        return filtered_result
    except Exception as e:
        Logger.error(f"Error checking whitelist domain: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed in checking whitelist domain: {str(e)}"},
        )


@router.post("/is_blocklist_domain/{intcid}", response_model=DomainListResponse)
async def is_blocklist_domain_route(
    intcid: str = Path(..., description="Customer ID"),
    request: DomainRequest = Body(..., description="Domain request body"),
):
    domain = request.domain
    Logger.info(f"api: /general/domainutils/is_blocklist_domain/{intcid}: {domain}")
    try:
        result = tools.is_blocklist_domain(domain, intcid)
        filtered_result = {k: v for k, v in result.items() if k in ("result", "description")}
        return filtered_result
    except Exception as e:
        Logger.error(f"Error checking blocklist domain: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed in checking blocklist domain: {str(e)}"},
        )