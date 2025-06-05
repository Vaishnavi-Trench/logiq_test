"""Abuse routes package."""

from typing import Optional
from fastapi import APIRouter, Path, Body
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from pltfrm import Logger2 as Logger
from app.services.intelligence.abuseipdb.tools import get_ip_reputation_report
from app.services.general.iputils import tools as iptools


class IPAddressRequest(BaseModel):
    task: Optional[str] = None
    ip_address: str


# Create router without prefix (prefix is added by parent router)
router = APIRouter(tags=["abuseipdb"])


@router.post("/get_ip_reputation_report/{intcid}")
async def ip_reputation_route(
    intcid: str = Path(..., description="Customer ID"),
    request: IPAddressRequest = Body(..., description="IP address request body"),
):
    """
    Get reputation report from VirusTotal for an IP address

    Args:
        intcid: Customer ID
        request: Request body containing IP address

    Returns:
        Reputation report for the provided IP address
    """
    ip_address = request.ip_address
    Logger.info(
        f"api: /intelligence/abuse/get_ip_reputation_report/{intcid}: Retrieving reputation for IP {ip_address}"
    )

    result = {
        "ip_address": ip_address,
    }
    summary = iptools.get_ip_type(ip_address)
    if not summary["valid"]:
        result["status"] = (
            "error: invalid ip address not applicable for reputation check"
        )
        result["description"] = summary["description"]
        return summary

    if summary["type"] == "loopback":
        result["status"] = "error: loopback ip address"
        result["description"] = (
            "Loopback IP address is not valid for reputation check, skipped reputation check"
        )
        return result

    if summary["type"] == "private":
        result["status"] = (
            "error: private ip address not applicable for reputation check"
        )
        result["description"] = (
            "Private IP address is not valid for reputation check, skipped reputation check"
        )
        return result

    if summary["type"] == "link_local":
        result["status"] = (
            "error: link local ip address not applicable for reputation check"
        )
        result["description"] = (
            "Link local IP address is not valid for reputation check, skipped reputation check"
        )
        return result

    try:
        result = get_ip_reputation_report(intcid, ip_address)
        return result
    except Exception as e:
        Logger.error(f"Error retrieving IP reputation: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed to retrieve IP reputation: {str(e)}"},
        )
