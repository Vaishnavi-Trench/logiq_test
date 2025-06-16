from fastapi import APIRouter, Path, Body, Request, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, ValidationError
from typing import Dict, List, Optional, Any  # Added Any for alert dict
from pltfrm import Logger2 as Logger
import traceback
import json


from app.services.siem.sumologic.tools import get_available_indices, run_sumo_query, get_system_alerts
class SumoLogicIndicesRequest(BaseModel):
    task: str = Field(..., description="Task identifier for logging")

class SumoLogicQueryRequest(BaseModel):
    task: str = Field(..., description="Task identifier for logging")
    query: str = Field(..., description="Query to run against SumoLogic")

class SumoLogicSystemAlertsRequest(BaseModel):
    task: str = Field(..., description="Task identifier for logging")
    start_time: Optional[str] = Field(None, description="Start time for the query")
    end_time: Optional[str] = Field(None, description="End time for the query")

class SumoLogicSystemMonitorsRequest(BaseModel):
    task: str = Field(..., description="Task identifier for logging")
    start_time: Optional[str] = Field(None, description="Start time for the query")
    end_time: Optional[str] = Field(None, description="End time for the query")

router = APIRouter(tags=["sumologic"])

@router.post("/get_indices/{intcid}")
async def get_indices(
    intcid: str = Path(..., description="Customer ID"),
    request: SumoLogicIndicesRequest = Body(..., description="Request body containing task identifier")
):
    """
    Get all available indices in SumoLogic using the Partitions API.
    """
    try:
        task = request.task
        Logger.info(f"Task: {task} - Integration ID: {intcid}")
        indices = await get_available_indices(intcid=intcid, task=task)
        return indices
    except (ValueError, TypeError) as e:
        Logger.error(f"Error getting index {str(e)}")
        Logger.error(
            f"Error in get_indices: {str(e)}\n{traceback.format_exc()}"
        )
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed to get indices from sumologic: {str(e)}"},
        )
        
        
@router.post("/run_query/{intcid}")
async def run_query(
    intcid: str = Path(..., description="Customer ID"),
    request: SumoLogicQueryRequest = Body(..., description="Request body containing task and query to run against SumoLogic")
):
    """
    Run a query against SumoLogic.
    """
    try:
        task = request.task
        Logger.info(f"Task: {task} - Integration ID: {intcid}")
        query = request.query
        Logger.info(f"Running query for intcid {intcid}")
        result = await run_sumo_query(intcid=intcid, task=task, query=query)
        return result
    except (ValueError, TypeError) as e:
        Logger.error(f"Error running query {str(e)}")
        Logger.error(
            f"Error in run_query: {str(e)}\n{traceback.format_exc()}"
        )
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed to run query on sumologic: {str(e)}"},
        )
        
@router.post("/get_system_alerts/{intcid}")
async def get_system_alerts_route(
    intcid: str = Path(..., description="Customer ID"),
    request: SumoLogicSystemAlertsRequest = Body(..., description="Request body containing task and optional start and end time for the query")
):
    """
    Get system alerts from SumoLogic.
    """
    try:
        task = request.task
        Logger.info(f"Task: {task} - Integration ID: {intcid}")
        result = await get_system_alerts(
           intcid=intcid,
           task=task,
           start_time=request.start_time,
           end_time=request.end_time
           )
        return result
    except (ValueError, TypeError) as e:
        Logger.error(f"Error getting system alerts {str(e)}")
        Logger.error(
            f"Error in get_system_alerts: {str(e)}\n{traceback.format_exc()}"
        )
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed to get system alerts from sumologic: {str(e)}"},
        )

