# app/api/routes/intelligence/shodan/__init__.py

from fastapi import APIRouter, Path, Body
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Dict, Any

from pltfrm import Logger2 as Logger 

# Import requests and json for the hardcoded test route (if still needed for any specific logic in this file)
# If no hardcoded tests remain, these imports can be removed.
import requests
import json

# Import the high-level intelligence function from tools.py
from app.services.intelligence.shodan.tools import fetch_shodan_host_intelligence

# --- Dummy Logger (remove if using actual pltfrm) ---
class Logger:
    @staticmethod
    def info(message):
        print(f"[INFO] {message}")
    @staticmethod
    def error(message):
        print(f"[ERROR] {message}")
    @staticmethod
    def warning(message): 
        print(f"[WARNING] {message}")


# --- Pydantic Model for Request Body for the remaining route ---
class ShodanHostRequest(BaseModel):
    ip_address: str = Field(..., description="The IP address to query Shodan for.")


# --- FastAPI Router ---
router = APIRouter(tags=["shodan_intelligence"])

# --- Only the specified API Route Definition Remains ---

@router.post("/ip_reputation_report/{intcid}", response_model=Dict[str, Any])
async def get_shodan_ip_reputation_report_route(
    intcid: str = Path(..., description="Customer ID for configuration lookup"),
    request: ShodanHostRequest = Body(..., description="Shodan host lookup request body"),
):
    """
    Retrieve detailed IP reputation report from Shodan.
    Pass the IP address in the request body. intcid is used for config lookup.
    """
    ip_address = request.ip_address
    Logger.info(f"api: /intelligence/shodan/ip_reputation_report/{intcid}: Request for Shodan IP reputation for IP {ip_address}.")
    
    result = await fetch_shodan_host_intelligence(intcid=intcid, ip_address=ip_address)
    
    if result.get("status"):
        Logger.info(f"api: /intelligence/shodan/ip_reputation_report/{intcid}: Shodan IP reputation retrieved successfully for IP {ip_address}.")
        return JSONResponse(status_code=200, content=result)
    else:
        Logger.error(f"api: /intelligence/shodan/ip_reputation_report/{intcid}: Failed to retrieve Shodan IP reputation for IP {ip_address}. Reason: {result.get('description')}")
        return JSONResponse(status_code=500, content={"status": "error", "description": result.get('description', 'Unknown error.')})