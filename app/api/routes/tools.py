from fastapi import APIRouter, Path
from typing import List, Dict
from app.services.tools_service import get_tools
from pltfrm import Logger2 as Logger

router = APIRouter(prefix="/tools", tags=["tools"])


@router.get("/{intcid}", response_model=List[Dict])
async def get_tools_route(intcid: str = Path(..., description="Customer ID")):
    """
    Get available tools for a specific customer ID as Tool objects
    """
    Logger.info(
        f"api: /tools/{intcid}: Retrieving available tools for customer {intcid}"
    )
    # Get tools for this specific customer ID
    tools = get_tools(intcid)

    return tools
