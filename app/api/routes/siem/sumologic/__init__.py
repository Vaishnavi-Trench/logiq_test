from fastapi import APIRouter, Path, Body, Request, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, ValidationError
from typing import Dict, List, Optional, Any  # Added Any for alert dict
from pltfrm import Logger2 as Logger
import traceback
import json


from app.services.siem.sumologic.tools import (
    get_available_indices,
    sumologic_run_sql_query,
    fetch_security_alerts,
    fetch_security_alerts_with_query,
    get_available_fields,
    sumologic_get_alert_context,
    sumologic_choose_table,
    sumologic_generate_query,
)


class SumoLogicIndicesRequest(BaseModel):
    task: str = Field(..., description="Task identifier for logging")


class SumoLogicQueryRequest(BaseModel):
    task: str = Field(..., description="Task identifier for logging")
    query: str = Field(..., description="Query to run against SumoLogic")
    from_time: Optional[str] = Field(None, description="Start time for the query")
    to_time: Optional[str] = Field(None, description="End time for the query")


class SumoLogicSystemAlertsRequest(BaseModel):
    task: str = Field(..., description="Task identifier for logging")
    start_time: Optional[str] = Field(None, description="Start time for the query")
    end_time: Optional[str] = Field(None, description="End time for the query")


class SumoLogicGetSecurityAlertsExecutingQueryRequest(BaseModel):
    task: Optional[str] = None
    query: str = Field(
        ..., description="The Sumlogic query string to execute for fetching alerts."
    )
    time_field: str = Field(..., description="The time field to filter alerts by.")
    start_time: str = Field(..., description="Start time for the alert query.")
    end_time: str = Field(..., description="End time for the alert query.")


class SumoLogicSystemMonitorsRequest(BaseModel):
    task: str = Field(..., description="Task identifier for logging")
    start_time: Optional[str] = Field(None, description="Start time for the query")
    end_time: Optional[str] = Field(None, description="End time for the query")


class SumoLogicFieldsRequest(BaseModel):
    task: str = Field(..., description="Task identifier for logging")
    index_name: str = Field(..., description="Index to fetch fields from")


class SumoLogicAlertContextRequest(BaseModel):
    task: str = Field(..., description="Task identifier for logging")
    alert: Any = Field(..., description="Alert data to extract context from")
    aid: str = Field(..., description="Alert ID for logging purposes")


class SumologicChooseTableRequest(BaseModel):
    task: str = Field(..., description="Task identifier for logging")
    aid: str = Field(..., description="Alert ID for logging purposes")
    tid: str = Field(..., description="Triage ID for logging purposes")
    question_id: str = Field(..., description="Question ID for logging purposes")
    step_id: str = Field(..., description="Step ID for logging purposes")
    triage_question: str = Field(..., description="Triage question to answer")
    alert_context: dict = Field(
        ..., description="Alert context to use for choosing table"
    )


class SumoLogicGenerateQueryRequest(BaseModel):
    task: str
    aid: str
    step_id: str
    tid: str
    question_id: str
    triage_question: str
    table_name: str
    alert_context: Dict  # Assuming alert is passed as string for this specific tool


router = APIRouter(tags=["sumologic"])


@router.post("/get_indices/{intcid}")
async def get_indices(
    intcid: str = Path(..., description="Customer ID"),
    request: SumoLogicIndicesRequest = Body(
        ..., description="Request body containing task identifier"
    ),
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
        Logger.error(f"Error in get_indices: {str(e)}\n{traceback.format_exc()}")
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed to get indices from sumologic: {str(e)}"},
        )


@router.post("/get_fields/{intcid}")
async def get_fields(
    intcid: str = Path(..., description="Customer ID"),
    request: SumoLogicFieldsRequest = Body(
        ..., description="Request body containing task and indices to fetch fields from"
    ),
):
    """
    Get all available fields in SumoLogic using the Partitions API.
    """
    try:
        task = request.task
        index_name = request.index_name
        Logger.info(f"Task: {task} - Integration ID: {intcid}")
        Logger.info(f"Fetching fields for indices {index_name} with task {task}")
        fields = await get_available_fields(
            intcid=intcid, task=task, index_name=index_name
        )
        return fields
    except (ValueError, TypeError) as e:
        Logger.error(f"Error getting fields {str(e)}")
        Logger.error(f"Error in get_fields: {str(e)}\n{traceback.format_exc()}")
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed to get fields from sumologic: {str(e)}"},
        )


@router.post("/run_query/{intcid}")
async def run_query_route(
    intcid: str = Path(..., description="Customer ID"),
    request: SumoLogicQueryRequest = Body(
        ...,
        description="Request body containing task and query to run against SumoLogic",
    ),
):
    """
    Run a query against SumoLogic.
    """
    try:
        task = request.task
        Logger.info(f"Task: {task} - Integration ID: {intcid}")
        query = request.query
        Logger.info(f"Running query for intcid {intcid}")
        result = await sumologic_run_sql_query(intcid=intcid, task=task, query=query, from_time=request.from_time, to_time=request.to_time)
        return result
    except (ValueError, TypeError) as e:
        Logger.error(f"Error running query {str(e)}")
        Logger.error(f"Error in run_query: {str(e)}\n{traceback.format_exc()}")
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed to run query on sumologic: {str(e)}"},
        )


@router.post("/fetch_security_alerts/{intcid}")
async def fetch_security_alerts_route(
    intcid: str = Path(..., description="Customer ID"),
    request: SumoLogicSystemAlertsRequest = Body(
        ...,
        description="Request body containing task and optional start and end time for the query",
    ),
):
    """
    Get system alerts from SumoLogic.
    """
    try:
        task = request.task
        Logger.info(f"Task: {task} - Integration ID: {intcid}")
        result = await fetch_security_alerts(
            intcid=intcid,
            task=task,
            start_time=request.start_time,
            end_time=request.end_time,
        )
        return result
    except (ValueError, TypeError) as e:
        Logger.error(f"Error getting system alerts {str(e)}")
        Logger.error(f"Error in get_system_alerts: {str(e)}\n{traceback.format_exc()}")
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed to get system alerts from sumologic: {str(e)}"},
        )


@router.post("/fetch_alerts_executing_query/{intcid}")
async def fetch_alerts_executing_query_route(
    intcid: str = Path(..., description="Customer ID"),
    request: SumoLogicGetSecurityAlertsExecutingQueryRequest = Body(
        ..., description="Request to fetch security alerts"
    ),
):
    """Fetches security alerts from sumlogic.

    Retrieves security alerts based on the specified customer ID and time range.

    Args:
        intcid: The customer ID for which to fetch alerts.
        request: A request body containing the task description, start time,
                 and end time for the alert query.

    Returns:
        A JSON response containing the fetched security alerts or an error
        message if the operation fails.
    """
    Logger.info(
        f"api: /siem/sumologic/fetch_alerts_executing_query/{intcid}: Task: {request.task}"
    )
    try:
        result = await fetch_security_alerts_with_query(
            intcid,
            request.task,
            request.query,
            request.time_field,
            request.start_time,
            request.end_time,
        )
        return result
    except Exception as e:
        Logger.error(f"Error fetching security alerts: {str(e)}")
        Logger.error(
            f"Error in fetch_security_alerts: {str(e)}\n{traceback.format_exc()}"
        )
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed to fetch security alerts: {str(e)}"},
        )


@router.post("/get_alert_context/{intcid}")
async def get_alert_context_route(
    intcid: str = Path(..., description="Customer ID"),
    request: SumoLogicAlertContextRequest = Body(
        ...,
        description="Request body containing task and alert data to extract context from",
    ),
):
    """
    Get alert context from SumoLogic.
    """
    try:
        task = request.task
        Logger.info(f"Task: {task} - Integration ID: {intcid}")
        alert = request.alert
        aid = request.aid
        Logger.info(f"Extracting alert context for intcid {intcid}")
        result = await sumologic_get_alert_context(
            intcid=intcid, task=task, aid=aid, alert=alert
        )
        return result
    except (ValueError, TypeError) as e:
        Logger.error(f"Error getting alert context {str(e)}")
        Logger.error(f"Error in get_alert_context: {str(e)}\n{traceback.format_exc()}")
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed to get alert context from sumologic: {str(e)}"},
        )


@router.post("/choose_table/{intcid}")
async def choose_table_route(
    intcid: str = Path(..., description="Customer ID"),
    request: SumologicChooseTableRequest = Body(
        ...,
        description="Request body containing task, aid, tid, question_id, step_id, triage_question and alert_context",
    ),
):
    """
    Choose the best table for the alert context.
    """
    try:
        task = request.task
        Logger.info(f"Task: {task} - Integration ID: {intcid}")
        aid = request.aid
        tid = request.tid
        question_id = request.question_id
        step_id = request.step_id
        triage_question = request.triage_question
        alert_context = request.alert_context

        Logger.info(f"Choosing table for intcid {intcid} with aid {aid}")
        result = await sumologic_choose_table(
            intcid=intcid,
            task=task,
            aid=aid,
            tid=tid,
            question_id=question_id,
            step_id=step_id,
            triage_question=triage_question,
            alert_context=alert_context,
        )
        return result
    except (ValueError, TypeError) as e:
        Logger.error(f"Error choosing table {str(e)}")
        Logger.error(f"Error in choose_table: {str(e)}\n{traceback.format_exc()}")
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed to choose table from sumologic: {str(e)}"},
        )


@router.post("/generate_query/{intcid}")
async def generate_query_route(
    intcid: str = Path(..., description="Customer ID"),
    request: SumoLogicGenerateQueryRequest = Body(
        ...,
        description="Request body containing task, aid, step_id, tid, question_id, triage_question, table_name and alert_context",
    ),
):
    """
    Generate a query for the alert context.
    """
    try:
        Logger.info(f"Task: {request.task} - Integration ID: {intcid}")
        Logger.info(f"Generating query for intcid {intcid} with aid {request.aid}")
        result = await sumologic_generate_query(
            intcid=intcid,
            task=request.task,
            aid=request.aid,
            table_name=request.table_name,
            tid=request.tid,
            question_id=request.question_id,
            step_id=request.step_id,
            triage_question=request.triage_question,
            alert_context=request.alert_context,
        )
        return result
    except (ValueError, TypeError) as e:
        Logger.error(f"Error generating query {str(e)}")
        Logger.error(
            f"Error in generate_query_route: {str(e)}\n{traceback.format_exc()}"
        )
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed to generate query from sumologic: {str(e)}"},
        )
