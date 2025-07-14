"""file hash utils tool"""

import re
import hashlib
from pltfrm import PropX, MongoDBManager
from pltfrm import Logger2 as Logger
import datetime
from bson import ObjectId
import json


def is_whitelist_filehash(file_hash: str, intcid: str = None) -> dict:
    """
    Checks if the file hash is present in the whitelist collection for the given intcid.
    Supports configTypes: md5, sha1, sha256, hash (generic), regex.
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

    # Validate hash format
    hash_info = validate_hash(file_hash)
    if not hash_info:
        return {"result": False, "description": f"Invalid hash format: {file_hash}"}

    # Normalize hash for comparison (lowercase)
    normalized_hash = file_hash.lower().strip()

    for entry in whitelist_entries:
        if not isinstance(entry, dict):
            continue
        
        entry_config_type = entry.get("configType", "")
        entry_value = entry.get("value", "").lower().strip()
        
        # Exact hash match for specific hash types
        if entry_config_type == "filehash" and entry_value == normalized_hash:
            return {"result": True, "description": entry.get("description", f"Whitelisted {entry_config_type} hash")}

    return {"result": False, "description": "File hash is not whitelisted"}


def is_blocklist_filehash(file_hash: str, intcid: str = None) -> dict:
    """
    Checks if the file hash is present in the blocklist collection for the given intcid.
    Supports configTypes: md5, sha1, sha256, hash (generic), regex.
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

    # Validate hash format
    hash_info = validate_hash(file_hash)
    if not hash_info:
        return {"result": False, "description": f"Invalid hash format: {file_hash}"}

    # Normalize hash for comparison (lowercase)
    normalized_hash = file_hash.lower().strip()

    for entry in blocklist_entries:
        if not isinstance(entry, dict):
            continue
            
        entry_config_type = entry.get("configType", "")
        entry_value = entry.get("value", "").lower().strip()
        
        # Exact hash match for specific hash types
        if entry_config_type =="filehash" and entry_value == normalized_hash:
            return {"result": True, "description": entry.get("description", f"Blocklisted {entry_config_type} hash")}
    
        
                
    return {"result": False, "description": "File hash is not blocklisted"}


def validate_hash(hash_value: str) -> dict:
    """
    Validates the hash format and returns information about the hash type.
    Returns None if the hash format is invalid.
    """
    if not hash_value or not isinstance(hash_value, str):
        return None
    
    # Remove whitespace and convert to lowercase
    hash_value = hash_value.strip().lower()
    
    # Check for hexadecimal characters only
    if not re.match(r'^[a-f0-9]+$', hash_value):
        return None
    
    hash_length = len(hash_value)
    
    # Determine hash type based on length
    if hash_length == 32:
        return {"type": "md5", "length": 32, "valid": True}
    elif hash_length == 40:
        return {"type": "sha1", "length": 40, "valid": True}
    elif hash_length == 64:
        return {"type": "sha256", "length": 64, "valid": True}
    elif hash_length == 128:
        return {"type": "sha512", "length": 128, "valid": True}
    else:
        # Allow other hash lengths but mark as generic
        return {"type": "unknown", "length": hash_length, "valid": True}




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