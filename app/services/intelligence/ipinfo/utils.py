"""This module contains utility functions for VirusTotal intelligence agent."""

import ipinfo

from pltfrm import Logger2 as Logger
from pltfrm import MongoDBManager, PropX


def get_ip_info(intcid, ip):
    """Fetches IP info from ipinfo."""
    Logger.info(f"Fetching IP info for: {ip}, intcid: {intcid}")
    ipinfo_data_query = {"intcid": intcid, "vendor": "ipinfo", "type": "intelligence"}
    integration_db = PropX.get_property("module.integration.config.db")
    integration_collection = PropX.get_property("module.integration.config.collection")
    document = MongoDBManager.get_record_by_multiple_fields(
                    integration_db, integration_collection, ipinfo_data_query)
    ipinfo_key = document.get("api_key")
    access_token = ipinfo_key
    handler = ipinfo.getHandler(access_token)
    details = handler.getDetails(ip)

    if not isinstance(details.all, dict):
        raise TypeError(f"Unexpected response format: {details.all}")

    details_dict = details.all

    if details_dict.get("bogon", False):
        details_dict["continent"] = {"name": "Unknown", "code": "XX"}

    Logger.info(f"IP info fetched for: {ip}")
    return details_dict
