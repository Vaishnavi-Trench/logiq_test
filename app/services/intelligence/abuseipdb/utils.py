"""This module contains utility functions for Abuseipdb intelligence agent."""


import requests
import json


from pltfrm import Logger2 as Logger
from pltfrm import MongoDBManager, PropX


def fetch_ip_report(intcid, ip):
    """Fetches IP report from AbuseIPDB."""
    Logger.info(f"Fetching IP report for: {ip}, intcid: {intcid}")

    abuseipdb_data_query = {
        "intcid": intcid,
        "vendor": "abuse",
        "type": "intelligence",
    }

    integration_db = PropX.get_property("module.integration.config.db")
    integration_collection = PropX.get_property("module.integration.config.collection")
    document = MongoDBManager.get_record_by_multiple_fields(
        integration_db, integration_collection, abuseipdb_data_query
    )

    # Get either api_key or secret_key
    abuse_api_key = document.get("api_key") or document.get("secret_key")
    if not abuse_api_key:
        Logger.error("API key or Secret key not found in the document")
        return {"error": "API key or Secret key not found"}

    url = 'https://api.abuseipdb.com/api/v2/check'
    
    querystring = {
        'ipAddress': ip,
        'maxAgeInDays': '90'
    }

    headers = {
        'Accept': 'application/json',
        'Key': abuse_api_key
    }

    response = requests.request(method='GET', url=url, headers=headers, params=querystring, timeout=10)
    
    response_data = response.json()
    
    if response_data.get("data"):
        report = {
            "ip": response_data.get("data").get("ipAddress"),
            "isPublic": response_data.get("data").get("isPublic"),
            "ipVersion": response_data.get("data").get("ipVersion"),
            "isWhitelisted": response_data.get("data").get("isWhitelisted"),
            "abuseConfidenceScore": response_data.get("data").get("abuseConfidenceScore"),
            "countryCode": response_data.get("data").get("countryCode"),
            "usageType": response_data.get("data").get("usageType"),
            "isp": response_data.get("data").get("isp"),
            "domain": response_data.get("data").get("domain"),
            "hostnames": response_data.get("data").get("hostnames"),
            "isTor": response_data.get("data").get("isTor"),
            "totalReports": response_data.get("data").get("totalReports"),
            "numDistinctUsers": response_data.get("data").get("numDistinctUsers"),
            "lastReportedAt": response_data.get("data").get("lastReportedAt"),
        }
        Logger.info(f"IP report fetched successfully: {report}")
        return {"report": report}
    else:
        Logger.info("No data found in the response")
        return {"report": "No data found in the response."}
