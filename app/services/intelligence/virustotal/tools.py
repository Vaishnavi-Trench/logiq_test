"""Implements Virustotal Intelligence Tools."""

from app.services.intelligence.virustotal.utils import fetch_ip_report
from pltfrm import Logger2 as Logger


def get_ip_reputation_report(intcid: str, ip_address: str) -> str:
    """
    Threat Intelligence tool
    Retrieves malicious percentage of a specific IP
    """
    Logger.debug(
        f"\ntool:get_ip_report:\nChecking IP Threat Intel for IP: {ip_address} for {intcid}\n"
    )
    response = fetch_ip_report(intcid, ip_address)
    Logger.debug(f"IP Threat Intel: {response}")
    return response
