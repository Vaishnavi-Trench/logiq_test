# app/services/intelligence/ip2location/tools.py

# Standard library imports
from typing import Any, Dict

# Local imports from your project
from app.services.intelligence.ip2location.ip2location_utils import IP2LocationUtils
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


async def fetch_ip2location_intelligence(ip_address: str) -> Dict[str, Any]:
    """
    Fetches IP geolocation intelligence from IP2Location using IP2LocationUtils.
    API key is hardcoded within IP2LocationUtils.
    """
    try:
        ip2location_utils = IP2LocationUtils() # Instantiate without arguments
        result = await ip2location_utils.fetch_ip_info(ip_address)
        return result
    except ValueError as e: # Catch ValueErrors from IP2LocationUtils if config is missing
        Logger.error(f"tools: IP2Location configuration error: {e}")
        return {"status": False, "description": f"IP2Location configuration error: {str(e)}"}
    except Exception as e:
        Logger.error(f"tools: Error fetching IP2Location intelligence: {e}")
        return {"status": False, "description": f"An unexpected error occurred: {str(e)}"}