"""Splunk routes package."""

from fastapi import APIRouter, Path, Body
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from pltfrm import Logger2 as Logger
from typing import Optional
import traceback

# Assuming these are implemented in the services layer
from app.services.siem.splunk.tools import (
    splunk_choose_index,
    generate_splunk_query,
    run_splunk_query,
)


# Request models
class SplunkChooseIndexRequest(BaseModel):
    task: str
    requirement: str
    alert: str


class GenerateSplunkQueryRequest(BaseModel):
    task: str
    requirement: str
    index_name: str
    sourcetype: str
    alert: str


class RunSplunkQueryRequest(BaseModel):
    task: str
    splunk_query: str


# Create router without prefix (prefix is added by parent router)
router = APIRouter(tags=["splunk"])


@router.post("/splunk_choose_index/{intcid}")
async def splunk_choose_index_route(
    intcid: str = Path(..., description="Customer ID"),
    request: SplunkChooseIndexRequest = Body(
        ..., description="Index selection request"
    ),
):
    """
    Choose the appropriate Splunk index for the requirement

    Args:
        intcid: Customer ID
        request: Request body containing requirement and alert

    Returns:
        JSON object with Splunk index name
    """
    Logger.info(
        f"api: /siem/splunk/splunk_choose_index/{intcid}: Selecting index for requirement"
    )
    try:
        result = await splunk_choose_index(intcid, request.requirement, request.alert)
        return result
    except Exception as e:
        Logger.error(f"Error selecting Splunk index: {str(e)}")
        Logger.error(
            f"Error selecting Splunk index: {str(e)}\n{traceback.format_exc()}"
        )
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed to select Splunk index: {str(e)}"},
        )


@router.post("/generate_splunk_query/{intcid}")
async def generate_splunk_query_route(
    intcid: str = Path(..., description="Customer ID"),
    request: GenerateSplunkQueryRequest = Body(
        ..., description="Query generation request"
    ),
):
    """
    Generate a Splunk query based on the requirement

    Args:
        intcid: Customer ID
        request: Request body containing requirement, index name, and alert

    Returns:
        JSON object with generated Splunk query
    """
    Logger.info(
        f"api: /siem/splunk/generate_splunk_query/{intcid}: Generating Splunk query"
    )
    try:
        result = await generate_splunk_query(
            intcid,
            request.index_name,
            request.sourcetype,
            request.requirement,
            request.alert,
        )
        return result
    except Exception as e:
        Logger.error(f"Error generating Splunk query: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed to generate Splunk query: {str(e)}"},
        )


@router.post("/run_splunk_query/{intcid}")
async def run_splunk_query_route(
    intcid: str = Path(..., description="Customer ID"),
    request: RunSplunkQueryRequest = Body(..., description="Query execution request"),
):
    """
    Execute a Splunk query and return the results

    Args:
        intcid: Customer ID
        request: Request body containing Splunk query to execute

    Returns:
        JSON object with query results from Splunk
    """
    Logger.info(f"api: /siem/splunk/run_splunk_query/{intcid}: Executing Splunk query")
    try:
        result = await run_splunk_query(intcid, request.splunk_query)
        return result
    except Exception as e:
        Logger.error(f"Error executing Splunk query: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed to execute Splunk query: {str(e)}"},
        )
