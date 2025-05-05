"""ip utils tool"""

import ipaddress
from pltfrm import Logger2 as Logger


def get_ip_type(ip_address: str) -> dict:
    """
    Determines the type and characteristics of an IP address.

    Args:
        intcid: Interaction ID for tracking
        ip_address: The IP address to analyze

    Returns:
        dict: Details about the IP address including type, category, and description
    """
    Logger.debug(f"\ntool:get_ip_type:\nAnalyzing IP: {ip_address}\n")

    summary = {
        "ip_address": ip_address,
        "valid": False,  # Start with assumption that it's invalid
        "version": None,
        "type": None,
        "description": "",
    }

    # Pre-validation checks
    if not ip_address:
        summary["description"] = "Invalid IP address: Empty string provided"
        Logger.error("Error analyzing IP: Empty string provided")
        return summary

    if not isinstance(ip_address, str):
        summary["description"] = (
            f"Invalid IP address: Not a string ({type(ip_address)})"
        )
        Logger.error(f"Error analyzing IP: Not a string ({type(ip_address)})")
        return summary

    try:
        # Try parsing as IPv4 first
        try:
            ip_obj = ipaddress.IPv4Address(ip_address)
            summary["version"] = 4
            summary["valid"] = True
        except ipaddress.AddressValueError:
            # If not IPv4, try IPv6
            try:
                ip_obj = ipaddress.IPv6Address(ip_address)
                summary["version"] = 6
                summary["valid"] = True
            except ipaddress.AddressValueError as e:
                # Neither IPv4 nor IPv6
                summary["description"] = f"Invalid IP address format: {str(e)}"
                Logger.error(f"Error analyzing IP {ip_address}: {str(e)}")
                return summary

        # Determine IP type (only proceed if valid)
        if ip_obj.is_loopback:
            summary["type"] = "loopback"
            summary["description"] = "Loopback address for local machine communication"
        elif ip_obj.is_private:
            summary["type"] = "private"
            summary["description"] = "Private address for internal network use"
        elif ip_obj.is_reserved:
            summary["type"] = "reserved"
            summary["description"] = "Reserved address for special use"
        elif ip_obj.is_multicast:
            summary["type"] = "multicast"
            summary["description"] = "Multicast address for one-to-many communication"
        elif ip_obj.is_link_local:
            summary["type"] = "link_local"
            summary["description"] = (
                "Link-local address for communication on local network segment"
            )
        elif hasattr(ip_obj, "is_global") and ip_obj.is_global:
            summary["type"] = "public"
            summary["description"] = "Public address routable on the global internet"
        else:
            summary["type"] = "public"
            summary["description"] = "Public address routable on the global internet"

        # Add specific network information
        if summary["version"] == 4:
            if ip_obj.is_private:
                if ip_address.startswith("10."):
                    summary["description"] += " (Class A private range 10.0.0.0/8)"
                elif ip_address.startswith("172."):
                    summary["description"] += " (Class B private range 172.16.0.0/12)"
                elif ip_address.startswith("192.168."):
                    summary["description"] += " (Class C private range 192.168.0.0/16)"

    except Exception as e:
        summary["valid"] = False
        summary["description"] = f"Invalid IP address: {str(e)}"
        Logger.error(f"Error analyzing IP {ip_address}: {str(e)}")

    Logger.debug(f"IP analysis result: {summary}")
    return summary


def is_whitelist_ip(ip_address: str) -> dict:
    # Pre-validation checks
    whitelist_report = {}
    summary = get_ip_type(ip_address)
    if not summary["valid"]:
        whitelist_report["description"] = summary["description"]

    if summary["type"] == "private":
        whitelist_report["result"] = (
            "error: invalid ip address not applicable for whitelist check"
        )
        whitelist_report["description"] = (
            "IP address belongs to Private ip address range. Need not check for whitelist. It is usually a trusted internal access."
        )
    elif summary["type"] == "loopback":
        whitelist_report["result"] = (
            "error: loopback ip address not applicable for whitelist check"
        )
        whitelist_report["description"] = (
            "IP address belongs to Loopback ip address range. Need not check against whitelist."
        )
    elif summary["type"] == "link_local":
        whitelist_report["result"] = (
            "error: link_local ip address not applicable for whitelist check"
        )
        whitelist_report["description"] = (
            "IP address belongs to Link local range. Need not check against whitelist."
        )

    # check against whitelist here
    whitelist_report["result"] = "false"
    whitelist_report["description"] = "Not a whitelist IP"
    return whitelist_report


def is_blocklist_ip(ip_address: str) -> dict:
    # Pre-validation checks
    blocklist_report = {}
    summary = get_ip_type(ip_address)
    if not summary["valid"]:
        blocklist_report["description"] = summary["description"]

    if summary["type"] == "private":
        blocklist_report["result"] = (
            "error: private ip address not applicable for blocklist check"
        )
        blocklist_report["description"] = (
            "IP address belongs to Private ip address range. Need not check against blocklist. It is usually a trusted internal access."
        )
    elif summary["type"] == "loopback":
        blocklist_report["result"] = (
            "error: loopback ip address not applicable for blocklist check"
        )
        blocklist_report["description"] = (
            "IP address belongs to Loopback ip address range. Need not check against blocklist."
        )
    elif summary["type"] == "link_local":
        blocklist_report["result"] = (
            "error: link local ip address not applicable for blocklist check"
        )
        blocklist_report["description"] = (
            "IP address belongs to Link local range. Need not check against blocklist."
        )

    # check against blocklist here
    blocklist_report["result"] = "false"
    blocklist_report["description"] = "Not a blocklist IP"
    return blocklist_report
