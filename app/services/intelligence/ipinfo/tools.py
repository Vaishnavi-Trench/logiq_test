"""ip info tool"""

from app.services.intelligence.ipinfo.utils import get_ip_info
from pltfrm import Logger2 as Logger


def get_ip_geolocation(intcid: str, ip_address: str) -> dict:
    """
    Threat intel tool
    Performs a geolocation lookup for an IP address.
    """

    Logger.debug(
        f"\ntool:check_geolocation:\nChecking geolocation for IP: {ip_address}\n"
    )
    result = get_ip_info(intcid, ip_address)

    continent_name = result.get("continent", {}).get("name", "Unknown")
    continent_code = result.get("continent", {}).get("code", "XX")

    geo_loc = {
        "ip_address": ip_address,
        "status": "Valid public IP address, retrieved geolocation",
        "continent": f"{continent_name}, {continent_code}",
        "country": result.get("country", "Unknown"),
        "cordinates": result.get("loc", "Unknown"),
        "timezone": result.get("timezone", "Unknown"),
    }

    Logger.debug(f"Geolocation: {geo_loc}")
    return geo_loc
