import os
import json
from typing import List, Dict, Any
from app.models.schemas import Tool, ToolParameter
from pltfrm import Logger2 as Logger
from pltfrm.mongo.manager import MongoDBManager
from app.core.config import settings

# Path to the tools JSON file
# TOOLS_JSON_PATH = os.path.join("tools.json")


# Cache class to avoid using global variables
class ToolCache:
    """
    Cache class to avoid using global variables
    """

    tool_cache = None
    tools_json_cache = None


CACHE = ToolCache()


def load_tools_from_db() -> List[Dict]:
    """
    Load tools from the database
    """
    try:
        tools = MongoDBManager.get_all_records(
            "main_db",
            "tools",
            {"recordType": "tool_definitions", "category": "investigation"},
        )
        if not tools:
            Logger.error("No tools found in the database")
            return []
        
        # The result from get_all_records is a cursor
        tools_list = list(tools)
        for tool in tools_list:
            if "_id" in tool and hasattr(tool["_id"], "binary"):
                tool["_id"] = str(tool["_id"])
        return tools_list

    except Exception as e:
        Logger.error(f"Error loading tools from DB: {str(e)}")
        return []


def load_response_tools_from_db() -> List[Dict]:
    """
    Load response tools from the database
    """
    try:
        tools = MongoDBManager.get_all_records(
            "main_db",
            "tools",
            {"recordType": "tool_definitions", "category": "response"},
        )
        if not tools:
            Logger.error("No response tools found in the database")
            return []
        
        # The result from get_all_records is a cursor
        tools_list = list(tools)
        for tool in tools_list:
            if "_id" in tool and hasattr(tool["_id"], "binary"):
                tool["_id"] = str(tool["_id"])
        return tools_list

    except Exception as e:
        Logger.error(f"Error loading response tools from DB: {str(e)}")
        return []


def get_tools(intcid: str) -> List[Dict]:
    """
    Get the list of available tools for a specific customer ID

    Args:
        intcid: The customer ID to get tools for

    Returns:
        List of Tool objects available for the customer
    """

    # Fetch tool availability from MongoDB using settings
    tools_status = MongoDBManager.get_record_by_multiple_fields(
        settings.MAIN_DB,
        settings.MAIN_COLLECTION,
        {"intcid": intcid, "type": "tools_status"},
    )

    # If no status record found, return all tools
    if not tools_status:
        Logger.info(
            f"No tool status found for customer {intcid}, returning empty tool list"
        )
        return []

    # Filter tools based on availability
    available_tools = []
    available_tool_names = []
    tool_status_dict = tools_status.get("tools", {})

    if CACHE.tool_cache is None:
        CACHE.tool_cache = load_tools_from_db()

    Logger.info(
        f"Tool cache loaded with {len(tool_status_dict)} tools for customer {intcid}, {tool_status_dict}"
    )
    Logger.info(
        f"Tool cache loaded with {len(CACHE.tool_cache)} tools for customer {intcid}: {CACHE.tool_cache}"
    )
    for tool in CACHE.tool_cache:
        # Get the tool namespace (first two parts)
        tool_parts = tool.get("name").split("/")
        if len(tool_parts) >= 2:
            tool_namespace = "/".join(tool_parts[:2])
        else:
            # Handle cases where the name might not have two parts, although unlikely based on format
            tool_namespace = tool.get("name")  # Or potentially skip/log error

        tool_type = tool_parts[0]
        vendor = tool_parts[1]
        # Check if the tool namespace is available
        if tool_status_dict.get(tool_namespace) == "available":
            # Create a copy of the tool to avoid mutating the cached object
            tool_copy = tool.copy()
            desc = None
            if type != "general":
                # Fetch fetch integration record
                tool_config = MongoDBManager.get_record_by_multiple_fields(
                    settings.MAIN_DB,
                    settings.MAIN_COLLECTION,
                    {"intcid": intcid, "type": tool_type, "vendor": vendor},
                )
                if tool_config:
                    desc = tool_config["desc"]  # Assign string directly, not a set
            if desc:
                tool_copy["description"] = f"{desc} {tool_copy.get('description')}"
            available_tools.append(tool_copy)
            available_tool_names.append(tool_copy.get("name"))

    Logger.info(
        f"Returning {len(available_tools)} available tools for customer {intcid}, names: {available_tool_names}"
    )
    return available_tools


def get_response_tools(intcid: str) -> List[Dict]:
    """
    Get the list of available response tools for a specific customer ID

    Args:
        intcid: The customer ID to get tools for

    Returns:
        List of Tool objects available for the customer
    """

    # Fetch tool availability from MongoDB using settings
    tools_status = MongoDBManager.get_record_by_multiple_fields(
        settings.MAIN_DB,
        settings.MAIN_COLLECTION,
        {"intcid": intcid, "type": "tools_status"},
    )

    # If no status record found, return all tools
    if not tools_status:
        Logger.info(
            f"No tool status found for customer {intcid}, returning empty tool list"
        )
        return []

    # Filter tools based on availability
    available_tools = []
    available_tool_names = []
    tool_status_dict = tools_status.get("tools", {})

    response_tools = load_response_tools_from_db()

    Logger.info(
        f"Tool cache loaded with {len(tool_status_dict)} tools for customer {intcid}, {tool_status_dict}"
    )
    Logger.info(
        f"Tool cache loaded with {len(response_tools)} tools for customer {intcid}: {response_tools}"
    )
    for tool in response_tools:
        # Get the tool namespace (first two parts)
        tool_parts = tool.get("name").split("/")
        if len(tool_parts) >= 2:
            tool_namespace = "/".join(tool_parts[:2])
        else:
            # Handle cases where the name might not have two parts, although unlikely based on format
            tool_namespace = tool.get("name")  # Or potentially skip/log error

        tool_type = tool_parts[0]
        vendor = tool_parts[1]
        # Check if the tool namespace is available
        if tool_status_dict.get(tool_namespace) == "available":
            # Create a copy of the tool to avoid mutating the cached object
            tool_copy = tool.copy()
            desc = None
            if type != "general":
                # Fetch fetch integration record
                tool_config = MongoDBManager.get_record_by_multiple_fields(
                    settings.MAIN_DB,
                    settings.MAIN_COLLECTION,
                    {"intcid": intcid, "type": tool_type, "vendor": vendor},
                )
                if tool_config:
                    desc = tool_config["desc"]  # Assign string directly, not a set
            if desc:
                tool_copy["description"] = f"{desc} {tool_copy.get('description')}"
            available_tools.append(tool_copy)
            available_tool_names.append(tool_copy.get("name"))

    Logger.info(
        f"Returning {len(available_tools)} available tools for customer {intcid}, names: {available_tool_names}"
    )
    return available_tools
