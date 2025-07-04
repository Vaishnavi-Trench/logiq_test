from fastapi.responses import JSONResponse
from fastapi import APIRouter, Path, Body
from pydantic import BaseModel
from typing import Any
from pltfrm import Logger2 as Logger
from app.services.endpoint.crowdstrike.tools import contain_host, lift_containment
from fastapi.encoders import jsonable_encoder
import json



class HostRequest(BaseModel):
    host: str
    


router = APIRouter(tags=["crowdstrike"])


@router.post("/contain_host/{intcid}")
async def contain_host_route(
    intcid: str, 
    host_request: HostRequest = Body(..., description="Host containment request body")
    ):
    """
    Contain a host by its ID.
    """
    host = host_request.host
    if not host:
        Logger.error("Host containment request must include a host ID.")
        return JSONResponse(
            status_code=400,
            content={"error": "Host containment request must include a host ID."}
        )
    Logger.info(f"Controlling host containment for {host} in integration {intcid}")
    result = await contain_host(intcid, host)
    return result

@router.post("/lift_containment/{intcid}")
async def lift_containment_route(
    intcid: str, 
    host_request: HostRequest = Body(..., description="Host lift containment request body")
    ):
    """
    Lift containment for a host by its ID.
    """
    host = host_request.host
    if not host:
        Logger.error("Host lift containment request must include a host ID.")
        return JSONResponse(
            status_code=400,
            content={"error": "Host lift containment request must include a host ID."}
        )
    Logger.info(f"Lifting containment for host {host} in integration {intcid}")
    result = await lift_containment(intcid, host)
    return result