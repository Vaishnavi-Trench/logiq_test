from fastapi import APIRouter, Path
from typing import List, Dict
from app.services.tools_service import get_tools, get_response_tools
from pltfrm import Logger2 as Logger

router = APIRouter(tags=["tools"])


@router.get("/get_tools/{intcid}", response_model=List[Dict])
async def get_tools_route(intcid: str = Path(..., description="Customer ID")):
    """
    Get available tools for a specific customer ID as Tool objects
    """
    Logger.info(
        f"api: /get_tools/{intcid}: Retrieving available tools for customer {intcid}"
    )
    # Get tools for this specific customer ID
    tools = get_tools(intcid)

    return tools


@router.get("/get_response_tools/{intcid}", response_model=List[Dict])
async def get_response_tools_route(intcid: str = Path(..., description="Customer ID")):
    """
    Get available response tools for a specific customer ID as Tool objects
    """
    Logger.info(
        f"api: /get_response_tools/{intcid}: Retrieving available response tools for customer {intcid}"
    )
    # Get response tools for this specific customer ID
    tools = get_response_tools(intcid)

    return tools
