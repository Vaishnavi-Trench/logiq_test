"""user utils tool"""

import re
from pltfrm import PropX, MongoDBManager
from pltfrm import Logger2 as Logger
import datetime
from bson import ObjectId
import json


def is_whitelist_user(user_identifier: str, intcid: str = None) -> dict:
    """
    Checks if the user is present in the whitelist collection for the given intcid.
    Supports configTypes: username (exact match), email (exact match), userid (exact match), domain (email domain match), regex.
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

    # Validate user identifier
    if not user_identifier or not isinstance(user_identifier, str):
        return {"result": False, "description": "Invalid user identifier"}

    # Normalize user identifier for comparison
    normalized_user = user_identifier.lower().strip()

    for entry in whitelist_entries:
        if not isinstance(entry, dict):
            continue
        
        entry_config_type = entry.get("configType", "")
        entry_value = entry.get("value", "").lower().strip()
        
        if entry_config_type == "user" and entry_value == normalized_user:
            return {"result": True, "description": entry.get("description", "Whitelisted username")}
                
    return {"result": False, "description": "User is not whitelisted"}


def is_blocklist_user(user_identifier: str, intcid: str = None) -> dict:
    """
    Checks if the user is present in the blocklist collection for the given intcid.
    Supports configTypes: username (exact match), email (exact match), userid (exact match), domain (email domain match), regex.
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

    # Validate user identifier
    if not user_identifier or not isinstance(user_identifier, str):
        return {"result": False, "description": "Invalid user identifier"}

    # Normalize user identifier for comparison
    normalized_user = user_identifier.lower().strip()

    for entry in blocklist_entries:
        if not isinstance(entry, dict):
            continue
            
        entry_config_type = entry.get("configType", "")
        entry_value = entry.get("value", "").lower().strip()
        
        if entry_config_type == "user" and entry_value == normalized_user:
            return {"result": True, "description": entry.get("description", "Blocklisted username")}

                
    return {"result": False, "description": "User is not blocklisted"}



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