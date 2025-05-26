from fastapi import APIRouter, Path, Body
from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field

from app.services.prompt_service import execute_prompt
from pltfrm import Logger2 as Logger

router = APIRouter(tags=["execute"])


class ExecutePromptRequest(BaseModel):
    task: Optional[str] = None
    model_name: str = Field(..., description="model name to use for executing prompt.")
    system_prompt: str = Field(..., description="system prompt to use.")
    user_prompt: str = Field(..., description="user prompt to use.")
    model_class: Optional[str] = Field(
        None, description="model class to use for executing prompt."
    )


@router.post("/execute/{intcid}", response_model=Any)
async def execute_route(
    intcid: str = Path(..., description="Customer ID"),
    request: ExecutePromptRequest = Body(..., description="Request to execute prompt"),
):
    """
    Execute a prompt for a specific customer ID and get results
    When model_class is specified, returns structured output based on the provided class
    Otherwise returns string response from the model
    """
    Logger.info(f"api: /execute/{intcid}: executing prompt for customer {intcid}")

    response = execute_prompt(
        intcid,
        request.model_name,
        request.system_prompt,
        request.user_prompt,
        model_class=request.model_class,
    )

    return response
