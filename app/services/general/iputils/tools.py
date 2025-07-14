"""ip utils tool"""

import ipaddress
from pltfrm import PropX, MongoDBManager
from pltfrm import Logger2 as Logger
import datetime
from bson import ObjectId
import json

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


def is_whitelist_ip(ip_address: str, intcid: str = None) -> dict:
    """
    Checks if the IP address is present in the whitelist collection for the given intcid.
    Supports configTypes: ipaddress, ipnetwork, iprange.
    Returns a dictionary with result, description, and matching entry if found.
    """
    main_db = PropX.get_property("module.integration.config.db")
    collection_name = PropX.get_property("module.configurations.collection")
    query = {"listType": "whitelist", "intcid": intcid} if intcid else {"listType": "whitelist"}
    whitelist_entries = MongoDBManager.get_record_by_multiple_fields(main_db, collection_name, query)
    whitelist_entries = flatten_dicts_only(whitelist_entries)
    # Defensive: ensure all entries are dicts
    non_dicts = [type(e) for e in whitelist_entries if not isinstance(e, dict)]
    if non_dicts:
        raise Exception(f"Sanitization failed: whitelist_entries contains non-dict types: {non_dicts}")

    try:
        ip_obj = ipaddress.ip_address(ip_address)
    except ValueError as e:
        return {"result": False, "description": f"Invalid IP address: {str(e)}"}

    for entry in whitelist_entries:
        if not isinstance(entry, dict):
            continue
        if entry.get("configType") == "ipaddress" and entry.get("value") == ip_address:
            return {"result": True, "description": entry.get("description", "Whitelisted")}
        elif entry.get("configType") == "iprange":
            try:
                start_ip, end_ip = entry.get("value", "").split("-")
                if ipaddress.ip_address(ip_address) >= ipaddress.ip_address(start_ip.strip()) and ipaddress.ip_address(ip_address) <= ipaddress.ip_address(end_ip.strip()):
                    return {"result": True, "description": entry.get("description", "Whitelisted range")}
            except Exception:
                continue
        elif entry.get("configType") == "ipnetwork":
            try:
                if ipaddress.ip_address(ip_address) in ipaddress.ip_network(entry.get("value")):
                    return {"result": True, "description": entry.get("description", "Whitelisted network")}
            except Exception:
                continue
    return {"result": False, "description": "IP address is not whitelisted"}


def is_blocklist_ip(ip_address: str, intcid: str = None) -> dict:
    """
    Checks if the IP address is present in the blocklist collection for the given intcid.
    Supports configTypes: ipaddress, ipnetwork, iprange.
    Returns a dictionary with result, description, and matching entry if found.
    """
    main_db = PropX.get_property("module.integration.config.db")
    collection_name = PropX.get_property("module.configurations.collection")
    query = {"listType": "blacklist", "intcid": intcid} if intcid else {"listType": "blacklist"}
    blocklist_entries = MongoDBManager.get_record_by_multiple_fields(main_db, collection_name, query)
    blocklist_entries = flatten_dicts_only(blocklist_entries)
    # Defensive: ensure all entries are dicts
    non_dicts = [type(e) for e in blocklist_entries if not isinstance(e, dict)]
    if non_dicts:
        raise Exception(f"Sanitization failed: blocklist_entries contains non-dict types: {non_dicts}")

    try:
        ip_obj = ipaddress.ip_address(ip_address)
    except ValueError as e:
        return {"result": False, "description": f"Invalid IP address: {str(e)}"}

    for entry in blocklist_entries:
        if not isinstance(entry, dict):
            continue
        if entry.get("configType") == "ipaddress" and entry.get("value") == ip_address:
            return {"result": True, "description": entry.get("description", "Blocklisted")}
        elif entry.get("configType") == "iprange":
            try:
                start_ip, end_ip = entry.get("value", "").split("-")
                if ipaddress.ip_address(ip_address) >= ipaddress.ip_address(start_ip.strip()) and ipaddress.ip_address(ip_address) <= ipaddress.ip_address(end_ip.strip()):
                    return {"result": True, "description": entry.get("description", "Blocklisted range")}
            except Exception:
                continue
        elif entry.get("configType") == "ipnetwork":
            try:
                if ipaddress.ip_address(ip_address) in ipaddress.ip_network(entry.get("value")):
                    return {"result": True, "description": entry.get("description", "Blocklisted network")}
            except Exception:
                continue
    return {"result": False, "description": "IP address is not blocklisted"}


def flatten_dicts_only(obj):
    """
    Recursively flattens a nested structure, returning a flat list of only dicts.
    Skips any non-dict, non-list entries.
    """
    result = []
    if isinstance(obj, dict):
        result.append(obj)
    elif isinstance(obj, list):
        for item in obj:
            result.extend(flatten_dicts_only(item))
    # else: skip non-dict, non-list
    return result
