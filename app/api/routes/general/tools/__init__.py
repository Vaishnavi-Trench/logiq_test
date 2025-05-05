"""IPInfo routes package."""

from fastapi.responses import JSONResponse
from fastapi import APIRouter, Path, Body
from pydantic import BaseModel
from typing import Optional
from pltfrm import Logger2 as Logger
from app.services.tools_service import get_tools


class ToolsInformationRequest(BaseModel):
    task: Optional[str] = None


# Create router without prefix (prefix is added by parent router)
router = APIRouter(tags=["tools"])


@router.post("/get_all_available_tools_information/{intcid}")
async def get_all_available_tools_information_route(
    intcid: str = Path(..., description="Customer ID"),
    request: ToolsInformationRequest = Body(
        ..., description="Tools Information request body"
    ),
):
    Logger.info(f"api: /get_all_available_tools_information_route/{intcid}")
    try:
        result = get_tools(intcid)
        return result
    except Exception as e:
        Logger.error(f"Error get_tools: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed to retrieve tools: {str(e)}"},
        )
