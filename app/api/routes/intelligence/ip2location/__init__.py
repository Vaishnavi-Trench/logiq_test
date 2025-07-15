# app/api/routes/intelligence/ip2location/__init__.py

# Standard library imports
import json
from typing import Dict, Any

# FastAPI imports
from fastapi import APIRouter, Path, Body
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import requests

# --- pltfrm imports (replace with your actual imports) ---
# from pltfrm import Logger2 as Logger 

# --- Dummy Logger for testing (REMOVE IN PRODUCTION) ---
class Logger:
    @staticmethod
    def info(message):
        print(f"[INFO] {message}")
    @staticmethod
    def error(message):
        print(f"[ERROR] {message}")
    @staticmethod
    def warning(message): # Added warning method for consistency
        print(f"[WARNING] {message}")


# Local imports from your project's services layer
from app.services.intelligence.ip2location.tools import fetch_ip2location_intelligence


# --- Pydantic Model for Request Body ---
class IP2LocationRequest(BaseModel):
    ip_address: str = Field(..., description="The IP address to query IP2Location for.")

# --- Pydantic Model for Hardcoded Test Route ---
class IP2LocationHardcodedTestRequest(BaseModel):
    ip_address: str = Field(..., description="The hardcoded IP address to test.")


# --- FastAPI Router ---
router = APIRouter(tags=["ip2location_intelligence"])

# --- API Route Definition (Standard: expects IP in body) ---

@router.post("/ip_geolocation_report", response_model=Dict[str, Any])
async def get_ip2location_geolocation_report_route(
    request: IP2LocationRequest = Body(..., description="IP2Location geolocation request body"),
):
    """
    Retrieve IP geolocation report from IP2Location.
    Pass the IP address in the request body.
    """
    ip_address = request.ip_address
    Logger.info(f"api: /intelligence/ip2location/ip_geolocation_report: Request for IP2Location report for IP {ip_address}.")
    
    result = await fetch_ip2location_intelligence(ip_address=ip_address)
    
    if result.get("status"):
        Logger.info(f"api: /intelligence/ip2location/ip_geolocation_report: IP2Location report retrieved successfully for IP {ip_address}.")
        return JSONResponse(status_code=200, content=result)
    else:
        Logger.error(f"api: /intelligence/ip2location/ip_geolocation_report: Failed to retrieve IP2Location report for IP {ip_address}. Reason: {result.get('description')}")
        return JSONResponse(status_code=500, content={"status": "error", "description": result.get('description', 'Unknown error.')})

# --- NEW TEST ROUTE WITH HARDCODED IP AND API KEY ---
@router.post("/test_hardcoded", response_model=Dict[str, Any], tags=["test"])
async def test_ip2location_hardcoded_route(
    request: IP2LocationHardcodedTestRequest = Body(..., description="Hardcoded IP2Location test request body"),
):
    """
    TEST ONLY: Perform an IP2Location lookup using a hardcoded API key and input IP.
    This route uses a hardcoded API key and IP address for quick testing.
    DO NOT USE IN PRODUCTION.
    """
    TEST_IP_ADDRESS = request.ip_address 
    
    # --- HARDCODED VALUES FOR TESTING (accessed from utils directly) ---
    # We will instantiate IP2LocationUtils to access its hardcoded API key and base URL
    # This ensures consistency with the primary methods.
    from app.services.intelligence.ip2location.ip2location_utils import IP2LocationUtils as TestIP2LocationUtils
    
    try:
        test_ip2location_utils_instance = TestIP2LocationUtils() 
        API_KEY_TO_USE = test_ip2location_utils_instance.API_KEY
        BASE_URL_TO_USE = test_ip2location_utils_instance.BASE_URL
    except ValueError as e:
        Logger.error(f"api: /intelligence/ip2location/test_hardcoded: IP2LocationUtils initialization failed: {e}")
        return JSONResponse(
            status_code=500,
            content={"status": "error", "description": f"IP2Location test config error: {str(e)}"},
        )

    Logger.info(f"api: /intelligence/ip2location/test_hardcoded: Performing hardcoded IP2Location test for IP {TEST_IP_ADDRESS}.")

    params = {
        "ip": TEST_IP_ADDRESS,
        "key": API_KEY_TO_USE,
        "package": "WS1", # You can try "WS1" if WS25 requires a higher tier.
        "addon": "", # Addons might be limited by package
        "format": "json"
    }

    try:
        response = requests.get(BASE_URL_TO_USE, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()

        if "response" in data and data["response"].startswith("ERROR"):
            Logger.error(f"api: Test: IP2Location API Error for {TEST_IP_ADDRESS}: {data['response']}")
            return JSONResponse(
                status_code=500,
                content={"status": "error", "description": f"IP2Location API Error: {data['response']}"},
            )

        # --- Flattening the test report directly in the route (for this specific test route only) ---
        # Mirrors the logic in ip2location_utils.py for consistency
        report = {
            "status": True,
            "description": f"IP2Location report fetched for {TEST_IP_ADDRESS}",
            "ip_address": TEST_IP_ADDRESS,
            "country_code": data.get("country_code", "N/A"),
            "country_name": data.get("country_name", "N/A"),
            "region_name": data.get("region_name", "N/A"),
            "city_name": data.get("city_name", "N/A"),
            "latitude": data.get("latitude", "N/A"),
            "longitude": data.get("longitude", "N/A"),
            "zip_code": data.get("zip_code", "N/A"),
            "time_zone": data.get("time_zone", "N/A"),
            "isp": data.get("isp", "N/A"),
            "organization": data.get("organization", "N/A"),
            "domain": data.get("domain", "N/A"),
            "asn": data.get("asn", "N/A"),
            "as_name": data.get("as_name", "N/A"),
            "usage_type": data.get("usage_type", "N/A"),
            "is_proxy": data.get("is_proxy", "N/A"),
            "proxy_type": data.get("proxy_type", "N/A"),
        }
        
        Logger.info(f"api: /intelligence/ip2location/test_hardcoded: Test completed successfully.")
        return JSONResponse(status_code=200, content=report)

    except requests.exceptions.HTTPError as http_err:
        Logger.error(f"api: /intelligence/ip2location/test_hardcoded: HTTP error: {http_err}")
        try: error_details = response.json()
        except json.JSONDecodeError: error_details = {"message": response.text}
        return JSONResponse(
            status_code=500,
            content={"status": "error", "description": f"HTTP error: {http_err}"},
        )
    except requests.exceptions.RequestException as req_err:
        Logger.error(f"api: /intelligence/ip2location/test_hardcoded: Network error: {req_err}")
        return JSONResponse(
            status_code=500,
            content={"status": "error", "description": f"Network or unexpected error: {str(req_err)}"},
        )
    except Exception as e:
        Logger.error(f"api: /intelligence/ip2location/test_hardcoded: Unexpected error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"status": "error", "description": f"An unexpected error occurred: {str(e)}"},
        )