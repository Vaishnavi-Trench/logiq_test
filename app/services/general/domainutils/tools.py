"""domain utils tool"""

import re
from pltfrm import PropX, MongoDBManager
from pltfrm import Logger2 as Logger
import datetime
from bson import ObjectId
import json


def is_whitelist_domain(domain: str, intcid: str = None) -> dict:
    """
    Checks if the domain is present in the whitelist collection for the given intcid.
    Supports configTypes: domain (exact match), subdomain (wildcard match), regex.
    Returns a dictionary with result, description, and matching entry if found.
    """
    main_db = PropX.get_property("module.integration.config.db")
    collection_name = PropX.get_property("module.configurations.collection")
    query = {"listType": "whitelist", "intcid": intcid} if intcid else {"listType": "whitelist"}
    whitelist_entries = MongoDBManager.get_all_records(main_db, collection_name, query)
    whitelist_entries = flatten_dicts_only(list(whitelist_entries) if whitelist_entries else [])
    
    # Defensive: ensure all entries are dicts
    non_dicts = [type(e) for e in whitelist_entries if not isinstance(e, dict)]
    if non_dicts:
        raise Exception(f"Sanitization failed: whitelist_entries contains non-dict types: {non_dicts}")

    # Validate domain format
    if not is_valid_domain(domain):
        return {"result": False, "description": f"Invalid domain format: {domain}"}

    # Normalize domain to lowercase for comparison
    normalized_domain = domain.lower().strip()

    for entry in whitelist_entries:
        if not isinstance(entry, dict):
            continue
        
        entry_config_type = entry.get("configType", "")
        entry_value = entry.get("value", "").lower().strip()
        
        if entry_config_type == "domain" and entry_value == normalized_domain:
            return {"result": True, "description": entry.get("description", "Whitelisted domain")}
        elif entry_config_type == "subdomain":
            try:
                # Support wildcard matching for subdomains (e.g., *.example.com)
                if entry_value.startswith("*."):
                    base_domain = entry_value[2:]  # Remove "*."
                    if normalized_domain == base_domain or normalized_domain.endswith("." + base_domain):
                        return {"result": True, "description": entry.get("description", "Whitelisted subdomain")}
                elif normalized_domain.endswith("." + entry_value) or normalized_domain == entry_value:
                    return {"result": True, "description": entry.get("description", "Whitelisted subdomain")}
            except Exception:
                continue

                
    return {"result": False, "description": "Domain is not whitelisted"}


def is_blocklist_domain(domain: str, intcid: str = None) -> dict:
    """
    Checks if the domain is present in the blocklist collection for the given intcid.
    Supports configTypes: domain (exact match), subdomain (wildcard match), regex.
    Returns a dictionary with result, description, and matching entry if found.
    """
    main_db = PropX.get_property("module.integration.config.db")
    collection_name = PropX.get_property("module.configurations.collection")
    query = {"listType": "blacklist", "intcid": intcid} if intcid else {"listType": "blacklist"}
    blocklist_entries = MongoDBManager.get_all_records(main_db, collection_name, query)
    blocklist_entries = flatten_dicts_only(list(blocklist_entries) if blocklist_entries else [])
    
    # Defensive: ensure all entries are dicts
    non_dicts = [type(e) for e in blocklist_entries if not isinstance(e, dict)]
    if non_dicts:
        raise Exception(f"Sanitization failed: blocklist_entries contains non-dict types: {non_dicts}")

    # Validate domain format
    if not is_valid_domain(domain):
        return {"result": False, "description": f"Invalid domain format: {domain}"}

    # Normalize domain to lowercase for comparison
    normalized_domain = domain.lower().strip()

    for entry in blocklist_entries:
        if not isinstance(entry, dict):
            continue
            
        entry_config_type = entry.get("configType", "")
        entry_value = entry.get("value", "").lower().strip()
        
        if entry_config_type == "domain" and entry_value == normalized_domain:
            return {"result": True, "description": entry.get("description", "Blocklisted domain")}
        elif entry_config_type == "subdomain":
            try:
                # Support wildcard matching for subdomains (e.g., *.example.com)
                if entry_value.startswith("*."):
                    base_domain = entry_value[2:]  # Remove "*."
                    if normalized_domain == base_domain or normalized_domain.endswith("." + base_domain):
                        return {"result": True, "description": entry.get("description", "Blocklisted subdomain")}
                elif normalized_domain.endswith("." + entry_value) or normalized_domain == entry_value:
                    return {"result": True, "description": entry.get("description", "Blocklisted subdomain")}
            except Exception:
                continue

    return {"result": False, "description": "Domain is not blocklisted"}


def is_valid_domain(domain: str) -> bool:
    """
    Validates if the given string is a valid domain name format.
    """
    if not domain or len(domain) > 253:
        return False
    
    # Basic domain regex pattern
    domain_pattern = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
    )
    
    return bool(domain_pattern.match(domain))


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
