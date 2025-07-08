"""This module contains utility functions for VirusTotal intelligence agent."""

import re
import datetime

import requests

from pltfrm import Logger2 as Logger
from pltfrm import MongoDBManager, PropX


def fetch_ip_report(intcid, ip):
    """Fetches IP report from VirusTotal."""
    Logger.info(f"Fetching IP report for: {ip}, intcid: {intcid}")

    virustotal_data_query = {
        "intcid": intcid,
        "vendor": "virustotal",
        "type": "intelligence",
    }

    integration_db = PropX.get_property("module.integration.config.db")
    integration_collection = PropX.get_property("module.integration.config.collection")
    document = MongoDBManager.get_record_by_multiple_fields(
        integration_db, integration_collection, virustotal_data_query
    )

    vt_api_key = document.get("api_key")

    domain_pattern = re.compile(r"^(?!-)[A-Za-z0-9.-]+\.[A-Za-z]{2,6}$")

    url = (
        f"https://www.virustotal.com/api/v3/domains/{ip}"
        if domain_pattern.match(ip)
        else f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    )

    headers = {"accept": "application/json", "x-apikey": vt_api_key}

    response = requests.get(url, headers=headers, timeout=60)
    response_data = response.json()
    attributes = response_data.get("data", {}).get("attributes", {})
    last_analysis_results = attributes.get("last_analysis_results", {})
    malicious_count = sum(
        1
        for result in last_analysis_results.values()
        if result["category"] == "malicious"
    )
    total_engines = len(last_analysis_results)
    reputation_score = (
        f"{malicious_count}/{total_engines}" if total_engines > 0 else "N/A"
    )
    report = {
        "ip_address": ip,
        "status": "Valid public ip address, report fetched",
        "continent": attributes.get("continent"),
        "country": attributes.get("country"),
        "malicious_count": malicious_count,
        "total_engines": total_engines,
        "reputation_score": reputation_score,
    }
    
    
    Logger.info(f"IP report fetched for: {ip}, report: {report}")
    return report

def fetch_hash_report(intcid, hash):
    """Fetches file hash report from VirusTotal."""
    Logger.info(f"Fetching file hash report for: {hash}, intcid: {intcid}")

    virustotal_data_query = {
        "intcid": intcid,
        "vendor": "virustotal",
        "type": "intelligence",
    }

    integration_db = PropX.get_property("module.integration.config.db")
    integration_collection = PropX.get_property("module.integration.config.collection")
    document = MongoDBManager.get_record_by_multiple_fields(
        integration_db, integration_collection, virustotal_data_query
    )

    vt_api_key = document.get("api_key")

    url = f"https://www.virustotal.com/api/v3/files/{hash}"
    headers = {"accept": "application/json", "x-apikey": vt_api_key}

    response = requests.get(url, headers=headers, timeout=60)
    response_data = response.json()
    attributes = response_data.get("data", {}).get("attributes", {})
    last_analysis_results = attributes.get("last_analysis_results", {})
    malicious_count = sum(
        1 for result in last_analysis_results.values() if result["category"] == "malicious"
    )
    total_engines = len(last_analysis_results)
    reputation_score = (
        f"{malicious_count}/{total_engines}" if total_engines > 0 else "N/A"
    )
    
    report = {
        "hash": hash,
        "status": "Valid file hash, report fetched",
        "malicious_count": malicious_count,
        "total_engines": total_engines,
        "reputation_score": reputation_score,
    }
    
    Logger.info(f"File hash report fetched for: {hash}, report: {report}")
    return report

def fetch_url_report(intcid, url):
    """Fetches URL report from VirusTotal."""
    Logger.info(f"Fetching URL report for: {url}, intcid: {intcid}")

    virustotal_data_query = {
        "intcid": intcid,
        "vendor": "virustotal",
        "type": "intelligence",
    }

    integration_db = PropX.get_property("module.integration.config.db")
    integration_collection = PropX.get_property("module.integration.config.collection")
    document = MongoDBManager.get_record_by_multiple_fields(
        integration_db, integration_collection, virustotal_data_query
    )

    vt_api_key = document.get("api_key")
    
    data = {
        "url": url
        }
    headers = {
        "x-apikey": vt_api_key
    }
    url = "https://www.virustotal.com/api/v3/urls/"
    response = requests.post(url, headers=headers, json=data, timeout=60)

    # url = f"https://www.virustotal.com/api/v3/urls/{url}"
    # headers = {"accept": "application/json", "x-apikey": vt_api_key}

    # response = requests.get(url, headers=headers, timeout=60)
    response_data = response.json()
    attributes = response_data.get("data", {}).get("attributes", {})
    last_analysis_results = attributes.get("last_analysis_results", {})
    malicious_count = sum(
        1 for result in last_analysis_results.values() if result["category"] == "malicious"
    )
    total_engines = len(last_analysis_results)
    reputation_score = (
        f"{malicious_count}/{total_engines}" if total_engines > 0 else "N/A"
    )
    
    report = {
        "url": url,
        "status": "Valid URL, report fetched",
        "malicious_count": malicious_count,
        "total_engines": total_engines,
        "reputation_score": reputation_score,
    }
    
    Logger.info(f"URL report fetched for: {url}, report: {report}")
    return report

def fetch_domain_report(intcid, domain):
    """Fetches domain report from VirusTotal."""
    Logger.info(f"Fetching domain report for: {domain}, intcid: {intcid}")

    virustotal_data_query = {
        "intcid": intcid,
        "vendor": "virustotal",
        "type": "intelligence",
    }

    integration_db = PropX.get_property("module.integration.config.db")
    integration_collection = PropX.get_property("module.integration.config.collection")
    document = MongoDBManager.get_record_by_multiple_fields(
        integration_db, integration_collection, virustotal_data_query
    )

    vt_api_key = document.get("api_key")

    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"accept": "application/json", "x-apikey": vt_api_key}

    response = requests.get(url, headers=headers, timeout=60)
    response_data = response.json()
    attributes = response_data.get("data", {}).get("attributes", {})
    last_analysis_results = attributes.get("last_analysis_results", {})
    malicious_count = sum(
        1 for result in last_analysis_results.values() if result["category"] == "malicious"
    )
    total_engines = len(last_analysis_results)
    reputation_score = (
        f"{malicious_count}/{total_engines}" if total_engines > 0 else "N/A"
    )
    
    report = {
        "domain": domain,
        "status": "Valid domain, report fetched",
        "malicious_count": malicious_count,
        "total_engines": total_engines,
        "reputation_score": reputation_score,
    }
    
    Logger.info(f"Domain report fetched for: {domain}, report: {report}")
    return report


def push_report_to_mongo(intcid, tid, aid, question_id, triage_question, response):
    """Pushes the report to MongoDB."""
    Logger.info(f"Pushing report to MongoDB: intcid: {intcid}")

    db_name = PropX.get_property("module.integration.config.db")
    collection_name = PropX.get_property("module.intelligence.records.collection")

    filter_query = {"tid": tid, "aid": aid, "question_id": question_id}

    update_data = {
        "$set": {
            "intcid": intcid,
            "triage_question": triage_question,
            "report": response,
            "updated_at": datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
        }
    }

    result = MongoDBManager.upsert_record(
        db_name, collection_name, filter_query, update_data
    )

    if result is not None:
        Logger.info(f"Report upserted to MongoDB for filter: {filter_query}")
        return True
    
    Logger.error(f"Failed to upsert report to MongoDB for filter: {filter_query}")
    return False


