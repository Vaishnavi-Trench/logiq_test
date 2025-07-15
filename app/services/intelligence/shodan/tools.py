# app/services/intelligence/shodan/tools.py

from app.services.intelligence.shodan.shodan_utils import ShodanUtils
from typing import Any, Dict # Removed Optional, List as not needed for this single function
from pltfrm import Logger2 as Logger 

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


async def fetch_shodan_host_intelligence(intcid: str, ip_address: str) -> Dict[str, Any]:
    """
    Fetches detailed host information from Shodan using ShodanUtils.
    intcid is used to retrieve credentials from MongoDB.
    """
    try:
        shodan_utils = ShodanUtils(intcid=intcid) # Pass intcid to ShodanUtils
        result = await shodan_utils.fetch_host_info(ip_address)
        return result
    except ValueError as e: 
        Logger.error(f"tools: Shodan configuration error: {e}")
        return {"status": False, "description": f"Shodan configuration error: {str(e)}"}
    except Exception as e:
        Logger.error(f"tools: Error fetching Shodan host intelligence: {e}")
        return {"status": False, "description": f"An unexpected error occurred: {str(e)}"}

# --- The search_shodan_intelligence function has been REMOVED ---
# as it is no longer used.