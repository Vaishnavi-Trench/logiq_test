"""VirusTotal routes package."""

from typing import Optional
from fastapi import APIRouter, Path, Body
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, ValidationError
from pltfrm import Logger2 as Logger
from app.services.intelligence.virustotal.tools import get_ip_reputation_report, get_hash_reputation_report, get_url_reputation_report, get_domain_reputation_report
from app.services.general.iputils import tools as iptools


class IPAddressRequest(BaseModel):
    task: Optional[str] = None
    ip_address: str
    aid : str = Field(default=None, description="The alert ID.")
    tid : str = Field(default=None, description="The task ID.")
    question_id: str = Field(default=None, description="The question ID.")
    triage_question: str = Field(default=None, description="The triage question.")

class FileHashRequest(BaseModel):
    task: Optional[str] = None
    hash: str
    aid : str = Field(default=None, description="The alert ID.")
    tid : str = Field(default=None, description="The task ID.")
    question_id: str = Field(default=None, description="The question ID.")
    triage_question: str = Field(default=None, description="The triage question.")

class URLRequest(BaseModel):
    task: Optional[str] = None
    url: str
    aid : str = Field(default=None, description="The alert ID.")
    tid : str = Field(default=None, description="The task ID.")
    question_id: str = Field(default=None, description="The question ID.")
    triage_question: str = Field(default=None, description="The triage question.")

class DomainRequest(BaseModel):
    task: Optional[str] = None
    domain: str
    aid : str = Field(default=None, description="The alert ID.")
    tid : str = Field(default=None, description="The task ID.")
    question_id: str = Field(default=None, description="The question ID.")
    triage_question: str = Field(default=None, description="The triage question.")

# Create router without prefix (prefix is added by parent router)
router = APIRouter(tags=["virustotal"])


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
    tid = request.tid
    aid = request.aid
    question_id = request.question_id
    triage_question = request.triage_question
    Logger.info(
        f"api: /intelligence/virustotal/get_ip_reputation_report/{intcid}: Retrieving reputation for IP {ip_address}"
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
        result = get_ip_reputation_report(intcid, ip_address, tid, aid, question_id, triage_question)
        return result
    except Exception as e:
        Logger.error(f"Error retrieving IP reputation: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed to retrieve IP reputation: {str(e)}"},
        )

@router.post("/get_hash_reputation_report/{intcid}")
async def hash_reputation_route(
    intcid: str = Path(..., description="Customer ID"),
    request: FileHashRequest = Body(..., description="File hash request body"),
):
    """
    Get reputation report from VirusTotal for a file hash

    Args:
        intcid: Customer ID
        request: Request body containing file hash

    Returns:
        Reputation report for the provided file hash
    """
    hash= request.hash
    aid = request.aid
    tid = request.tid
    question_id = request.question_id
    triage_question = request.triage_question
    Logger.info(
        f"api: /intelligence/virustotal/get_hash_reputation_report/{intcid}: Retrieving reputation for file hash {hash}"
    )

    result = {
        "hash": hash,
    }

    try:
        # Assuming a function get_hash_reputation_report exists to fetch the report
        result = get_hash_reputation_report(intcid, hash, aid, tid, question_id, triage_question)
        return result
    except Exception as e:
        Logger.error(f"Error retrieving file hash reputation: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed to retrieve file hash reputation: {str(e)}"},
        )
        
@router.post("/get_url_reputation_report/{intcid}")
async def url_reputation_route(
    intcid: str = Path(..., description="Customer ID"),
    request: URLRequest = Body(..., description="URL request body"),
):
    """
    Get reputation report from VirusTotal for a URL

    Args:
        intcid: Customer ID
        request: Request body containing URL

    Returns:
        Reputation report for the provided URL
    """
    url = request.url
    aid = request.aid
    tid = request.tid
    question_id = request.question_id
    triage_question = request.triage_question
    Logger.info(
        f"api: /intelligence/virustotal/get_url_reputation_report/{intcid}: Retrieving reputation for URL {url}"
    )

    result = {
        "url": url,
    }

    try:
        # Assuming a function get_url_reputation_report exists to fetch the report
        result = get_url_reputation_report(intcid, url, aid, tid, question_id, triage_question)
        return result
    except Exception as e:
        Logger.error(f"Error retrieving URL reputation: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed to retrieve URL reputation: {str(e)}"},
        )
        
@router.post("/get_domain_reputation_report/{intcid}")
async def domain_reputation_route(
    intcid: str = Path(..., description="Customer ID"),
    request: DomainRequest = Body(..., description="Domain request body"),
):
    """
    Get reputation report from VirusTotal for a domain

    Args:
        intcid: Customer ID
        request: Request body containing domain

    Returns:
        Reputation report for the provided domain
    """
    domain = request.domain
    aid = request.aid
    tid = request.tid
    question_id = request.question_id
    triage_question = request.triage_question
    Logger.info(
        f"api: /intelligence/virustotal/get_domain_reputation_report/{intcid}: Retrieving reputation for domain {domain}"
    )

    result = {
        "domain": domain,
    }

    try:
        # Assuming a function get_domain_reputation_report exists to fetch the report
        result = get_domain_reputation_report(intcid, domain, aid, tid, question_id, triage_question)
        return result
    except Exception as e:
        Logger.error(f"Error retrieving domain reputation: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed to retrieve domain reputation: {str(e)}"},
        )