# app/services/intelligence/ip2location/ip2location_utils.py

# Standard library imports
import requests
import json
from typing import Dict, Any, Optional

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


class IP2LocationUtils:
    """Utility class for IP2Location operations."""

    # --- HARDCODED IP2LOCATION API CONFIGURATION ---
    # IMPORTANT: THIS IS FOR TESTING ONLY. DO NOT USE IN PRODUCTION.
    # Get your API key from https://www.ip2location.com/ (after signing up/logging in)
    API_KEY = "B2F87EB2CB48F8C6544FE84321D564DC" # <<< IMPORTANT: REPLACE WITH YOUR ACTUAL IP2LOCATION API KEY
    BASE_URL = "https://api.ip2location.com/v2/" # IP2Location Web Service API URL
    # --- END HARDCODED CONFIGURATION ---

    def __init__(self):
        """
        Initializes the IP2LocationUtils class with hardcoded credentials.
        """
        Logger.info(f"IP2LocationUtils: Initializing with hardcoded credentials.")
        
        # Check if the API_KEY is still the placeholder or empty
        if not self.API_KEY or self.API_KEY == "YOUR_IP2LOCATION_API_KEY_HERE":
            Logger.error("IP2LocationUtils: Hardcoded IP2Location API key is missing or not replaced. Please set it.")
            raise ValueError("IP2Location API key is not configured.")

    async def fetch_ip_info(self, ip_address: str) -> Dict[str, Any]:
        """
        Fetches IP geolocation information from IP2Location Web Service and flattens it.
        """
        Logger.info(f"IP2LocationUtils: Fetching IP info for: {ip_address}")

        params = {
            "ip": ip_address,
            "key": self.API_KEY,
            "package": "WS1", # You can try "WS1" if WS25 requires a higher tier.
            "addon": "", # Addons might be limited by package
            "format": "json"
        }

        try:
            response = requests.get(self.BASE_URL, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            # Check for API-specific errors from IP2Location
            if "response" in data and data["response"].startswith("ERROR"):
                Logger.error(f"IP2LocationUtils: API Error for {ip_address}: {data['response']}")
                return {
                    "status": False,
                    "description": f"IP2Location API Error: {data['response']}",
                    "ip_address": ip_address
                }

            Logger.info(f"IP2LocationUtils: IP info fetched successfully for: {ip_address}.")
            
            # --- Flattening the IP2Location Report (consistent with Shodan flat output) ---
            report = {
                "status": True,
                "description": f"IP2Location report fetched for {ip_address}",
                "ip_address": ip_address,
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
            
            return report

        except requests.exceptions.HTTPError as http_err:
            Logger.error(f"IP2LocationUtils: HTTP error fetching IP info for {ip_address}: {http_err}. Response: {response.text}")
            return {
                "status": False,
                "description": f"HTTP error: {http_err}",
                "ip_address": ip_address
            }
        except requests.exceptions.RequestException as err:
            Logger.error(f"IP2LocationUtils: Network or unexpected error fetching IP info: {err}")
            return {
                "status": False,
                "description": f"An unexpected network error occurred: {str(err)}",
                "ip_address": ip_address
            }