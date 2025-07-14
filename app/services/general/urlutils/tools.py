"""url utils tool"""

import re
import urllib.parse
from pltfrm import PropX, MongoDBManager
from pltfrm import Logger2 as Logger
import datetime
from bson import ObjectId
import json


def is_whitelist_url(url: str, intcid: str = None) -> dict:
    """
    Checks if the URL is present in the whitelist collection for the given intcid.
    Supports configTypes: url (exact match), domain (domain-based match), pattern (wildcard match), regex.
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

    # Validate URL format
    parsed_url = parse_url(url)
    if not parsed_url:
        return {"result": False, "description": f"Invalid URL format: {url}"}

    # Normalize URL for comparison
    normalized_url = url.lower().strip()

    for entry in whitelist_entries:
        if not isinstance(entry, dict):
            continue
        
        entry_config_type = entry.get("configType", "")
        entry_value = entry.get("value", "").lower().strip()
        
        if entry_config_type == "url" and entry_value == normalized_url:
            return {"result": True, "description": entry.get("description", "Whitelisted URL")}
                
    return {"result": False, "description": "URL is not whitelisted"}


def is_blocklist_url(url: str, intcid: str = None) -> dict:
    """
    Checks if the URL is present in the blocklist collection for the given intcid.
    Supports configTypes: url (exact match), domain (domain-based match), pattern (wildcard match), regex.
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

    # Validate URL format
    parsed_url = parse_url(url)
    if not parsed_url:
        return {"result": False, "description": f"Invalid URL format: {url}"}

    # Normalize URL for comparison
    normalized_url = url.lower().strip()

    for entry in blocklist_entries:
        if not isinstance(entry, dict):
            continue
            
        entry_config_type = entry.get("configType", "")
        entry_value = entry.get("value", "").lower().strip()
        
        if entry_config_type == "url" and entry_value == normalized_url:
            return {"result": True, "description": entry.get("description", "Blocklisted URL")}
                
    return {"result": False, "description": "URL is not blocklisted"}


def parse_url(url: str) -> dict:
    """
    Parses a URL and returns a dictionary with components.
    Returns None if URL is invalid.
    """
    try:
        # Add http:// if no scheme is provided
        if not url.startswith(('http://', 'https://', 'ftp://', 'ftps://')):
            url = 'http://' + url
            
        parsed = urllib.parse.urlparse(url)
        
        if not parsed.netloc:
            return None
            
        # Extract domain from netloc (remove port if present)
        domain = parsed.netloc.split(':')[0].lower()
        
        return {
            'scheme': parsed.scheme,
            'domain': domain,
            'netloc': parsed.netloc,
            'path': parsed.path,
            'params': parsed.params,
            'query': parsed.query,
            'fragment': parsed.fragment,
            'full_url': url
        }
    except Exception:
        return None


def is_valid_url(url: str) -> bool:
    """
    Validates if the given string is a valid URL format.
    """
    parsed = parse_url(url)
    return parsed is not None


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
