"""IPInfo routes package."""

from typing import Optional
from fastapi.responses import JSONResponse
from fastapi import APIRouter, Path, Body
from pydantic import BaseModel
from pltfrm import Logger2 as Logger
from app.services.intelligence.ipinfo.tools import get_ip_geolocation
from app.services.general.iputils import tools as iptools


class IPAddressRequest(BaseModel):
    task: Optional[str] = None
    ip_address: str


# Create router without prefix (prefix is added by parent router)
router = APIRouter(tags=["ipinfo"])


@router.post("/get_ip_geolocation/{intcid}")
async def ip_geolocation_route(
    intcid: str = Path(..., description="Customer ID"),
    request: IPAddressRequest = Body(..., description="IP address request body"),
):
    """
    Get geolocation information for an IP address

    Args:
        intcid: Customer ID
        request: Request body containing IP address

    Returns:
        Geolocation information for the provided IP address
    """
    ip_address = request.ip_address
    Logger.info(
        f"api: /intelligence/ipinfo/get_ip_geolocation/{intcid}: Retrieving geolocation for IP {ip_address}"
    )

    result = {
        "ip_address": ip_address,
    }
    summary = iptools.get_ip_type(ip_address)
    if not summary["valid"]:
        result["status"] = (
            "error: invalid ip address not applicable for geolocation check"
        )
        result["description"] = summary["description"]
        return summary

    if summary["type"] == "loopback":
        result["status"] = (
            "error: loopback ip address not applicable for geolocation check"
        )
        result["description"] = (
            "Loopback IP address is not valid for geolocation check, skipped geolocation check"
        )
        return result

    if summary["type"] == "private":
        result["status"] = (
            "error: private ip address not applicable for geolocation check"
        )
        result["description"] = (
            "Private IP address is not valid for geolocation check, skipped geolocation check"
        )
        return result

    if summary["type"] == "link_local":
        result["status"] = (
            "error: link local ip address not applicable for geolocation check"
        )
        result["description"] = (
            "Link local IP address is not valid for geolocation check, skipped geolocation check"
        )
        return result

    try:
        result = get_ip_geolocation(intcid, ip_address)
        return result
    except Exception as e:
        Logger.error(f"Error retrieving IP geolocation: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed to retrieve IP geolocation: {str(e)}"},
        )
