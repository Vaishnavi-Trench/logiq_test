"""Implements Virustotal Intelligence Tools."""

from app.services.intelligence.virustotal.utils import fetch_ip_report, fetch_hash_report, fetch_url_report, fetch_domain_report 
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

def get_hash_reputation_report(intcid: str, file_hash: str) -> str:
    """
    Threat Intelligence tool
    Retrieves malicious percentage of a specific file hash
    """
    Logger.debug(
        f"\ntool:get_hash_report:\nChecking File Hash Threat Intel for Hash: {file_hash} for {intcid}\n"
    )
    response = fetch_hash_report(intcid, file_hash)
    Logger.debug(f"File Hash Threat Intel: {response}")
    return response

def get_url_reputation_report(intcid: str, url: str) -> str:
    """
    Threat Intelligence tool
    Retrieves malicious percentage of a specific URL
    """
    Logger.debug(
        f"\ntool:get_url_report:\nChecking URL Threat Intel for URL: {url} for {intcid}\n"
    )
    response = fetch_url_report(intcid, url)
    Logger.debug(f"URL Threat Intel: {response}")
    return response

def get_domain_reputation_report(intcid: str, domain: str) -> str:
    """
    Threat Intelligence tool
    Retrieves malicious percentage of a specific domain
    """
    Logger.debug(
        f"\ntool:get_domain_report:\nChecking Domain Threat Intel for Domain: {domain} for {intcid}\n"
    )
    response = fetch_domain_report(intcid, domain)
    Logger.debug(f"Domain Threat Intel: {response}")
    return response