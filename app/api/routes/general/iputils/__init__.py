"""IPInfo routes package."""

from fastapi.responses import JSONResponse
from fastapi import APIRouter, Path, Body
from pydantic import BaseModel
from typing import Any
from pltfrm import Logger2 as Logger
from app.services.general.iputils import tools
from fastapi.encoders import jsonable_encoder
import json


class IpTypeRequest(BaseModel):
    ip_address: str


class IpListResponse(BaseModel):
    result: bool
    description: str


# Create router without prefix (prefix is added by parent router)
router = APIRouter(tags=["iputils"])


@router.post("/get_ip_address_type/{intcid}")
async def get_ip_address_type_route(
    intcid: str = Path(..., description="Customer ID"),
    request: IpTypeRequest = Body(..., description="IP address request body"),
):
    ip_address = request.ip_address
    Logger.info(f"api: /general/iputils/get_ip_address_type/{intcid}: {ip_address}")
    try:
        result = tools.get_ip_type(ip_address)
        return result
    except Exception as e:
        Logger.error(f"Error retrieving IP type: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed to retrieve IP type: {str(e)}"},
        )


@router.post("/is_whitelist_ip/{intcid}", response_model=IpListResponse)
async def is_whitelist_ip_route(
    intcid: str = Path(..., description="Customer ID"),
    request: IpTypeRequest = Body(..., description="IP address request body"),
):
    ip_address = request.ip_address
    Logger.info(f"api: /general/iputils/is_whitelist_ip/{intcid}: {ip_address}")
    try:
        result = tools.is_whitelist_ip(ip_address, intcid)
        filtered_result = {k: v for k, v in result.items() if k in ("result", "description")}
        return filtered_result
    except Exception as e:
        Logger.error(f"Error checking whitelist ip: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed in checking whitelist ip: {str(e)}"},
        )


@router.post("/is_blocklist_ip/{intcid}", response_model=IpListResponse)
async def is_blocklist_ip_route(
    intcid: str = Path(..., description="Customer ID"),
    request: IpTypeRequest = Body(..., description="IP address request body"),
):
    ip_address = request.ip_address
    Logger.info(f"api: /general/iputils/is_blocklist_ip/{intcid}: {ip_address}")
    try:
        result = tools.is_blocklist_ip(ip_address, intcid)
        filtered_result = {k: v for k, v in result.items() if k in ("result", "description")}
        return filtered_result
    except Exception as e:
        Logger.error(f"Error checking blocklist ip: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed in checking blocklist ip: {str(e)}"},
        )

