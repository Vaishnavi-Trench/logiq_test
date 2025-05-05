"""sentinel routes package."""

from fastapi import APIRouter, Path, Body, Request, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, ValidationError
from typing import Dict, List, Optional, Any  # Added Any for alert dict
from pltfrm import Logger2 as Logger
import traceback
import json

# Assuming these are implemented in the services layer
from app.services.siem.sentinel.tools import (
    get_sentinel_tables_with_schema,
    fetch_security_alerts,
    fetch_security_incidents,
    sentinel_generate_kql_query,
    sentinel_run_kql_query,
    sentinel_choose_table,  # Added import
    sentinel_get_single_matching_record,  # Added import
    sentinel_get_alert_context,  # Added import
)


# Request models
class sentinelTableRequest(BaseModel):
    task: str


class SentinelGetSecurityAlertsRequest(BaseModel):
    task: str = Field(..., description="Task description for fetching security alerts.")
    start_time: str = Field(..., description="Start time for the alert query.")
    end_time: str = Field(..., description="End time for the alert query.")


class SentinelGetSecurityIncidentsRequest(BaseModel):
    task: str = Field(
        ..., description="Task description for fetching security incidents."
    )  # Corrected description
    start_time: str = Field(
        ..., description="Start time for the incident query."
    )  # Corrected description
    end_time: str = Field(
        ..., description="End time for the incident query."
    )  # Corrected description


class GenerateSentinelQueryRequest(BaseModel):
    task: str
    tid: str
    question_id: str
    step_id: str
    triage_question: str
    table_name: str
    alert_context: Dict  # Assuming alert is passed as string for this specific tool
    additional_info: str
    env: str


# --- New Request Models ---


class SentinelRunKQLQueryRequest(BaseModel):
    task: str = Field(..., description="Description of the task executing the query.")
    kql_query: str = Field(..., description="The KQL query string to execute.")


class SentinelChooseTableRequest(BaseModel):
    tid: str = Field(..., description="The triage ID.")
    question_id: str = Field(
        ..., description="The specific question ID within the triage process."
    )
    step_id: str = Field(..., description="The specific step id of triage plan.")
    triage_question: str = Field(
        ..., description="The text of the triage question being addressed."
    )
    alert_context: Any = Field(
        ..., description="The relevant alert context content (dict or string)."
    )
    additional_info: str = Field(
        ...,
        description="Additional information extracted during the triage process which might be needed by this tool to generate the KQL query..",
    )


class SentinelGetSingleRecordRequest(BaseModel):
    task: str = Field(
        ..., description="A description of the task requesting the record."
    )
    table_name: str = Field(
        ..., description="The name of the Sentinel table targeted by the query."
    )
    kql_query: str = Field(
        ..., description="The KQL query string expected to return a single record."
    )


class SentinelGetAlertContextRequest(BaseModel):
    task: str = Field(
        ...,
        description="The specific task or information needed from the alert context.",
    )
    alert: Any = Field(..., description="The Sentinel alert/event content.")


# Create router without prefix (prefix is added by parent router)
router = APIRouter(tags=["sentinel"])


@router.post("/get_tables/{intcid}")
async def get_tables_route(
    intcid: str = Path(..., description="Customer ID"),
    request: sentinelTableRequest = Body(
        ..., description="request for Log Management Tables"
    ),
):
    """
    Retrieves all Log Management tables from Sentinel that contain data,
    along with their schemas. # Corrected docstring

    Args:
        intcid: Customer ID
        request: Request body containing task information

    Returns:
        JSON object with table names and their schemas
    """
    Logger.info(
        f"api: /siem/sentinel/sentinel_get_tables/{intcid}: {request.task}"  # Corrected path in log
    )
    try:
        result = await get_sentinel_tables_with_schema(intcid, request.task)
        return result
    except Exception as e:
        Logger.error(f"Error getting tables {str(e)}")
        Logger.error(
            f"Error in get_sentinel_tables_with_schema: {str(e)}\n{traceback.format_exc()}"
        )
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed to get tables from sentinel: {str(e)}"},
        )


@router.post("/fetch_security_alerts/{intcid}")
async def fetch_security_alerts_route(
    intcid: str = Path(..., description="Customer ID"),
    request: SentinelGetSecurityAlertsRequest = Body(
        ..., description="Request to fetch security alerts"
    ),
):
    """Fetches security alerts from Microsoft Sentinel.

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
        f"api: /siem/sentinel/fetch_security_alerts/{intcid}: Task: {request.task}"
    )
    try:
        result = await fetch_security_alerts(
            intcid, request.task, request.start_time, request.end_time
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


@router.post("/fetch_security_incidents/{intcid}")
async def fetch_security_incidents_route(
    intcid: str = Path(..., description="Customer ID"),
    request: SentinelGetSecurityIncidentsRequest = Body(
        ..., description="Request to fetch security incidents"
    ),
):
    """Fetches security incidents from Microsoft Sentinel.

    Retrieves security incidents based on the specified customer ID and time range.

    Args:
        intcid: The customer ID for which to fetch incidents.
        request: A request body containing the task description, start time,
                 and end time for the incident query.

    Returns:
        A JSON response containing the fetched security incidents or an error
        message if the operation fails.
    """
    Logger.info(
        f"api: /siem/sentinel/fetch_security_incidents/{intcid}: Task: {request.task}"
    )
    try:
        # Call the correct service function
        result = await fetch_security_incidents(
            intcid, request.task, request.start_time, request.end_time
        )
        return result
    except Exception as e:
        Logger.error(f"Error fetching security incidents: {str(e)}")
        Logger.error(
            f"Error in fetch_security_incidents: {str(e)}\n{traceback.format_exc()}"
        )
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed to fetch security incidents: {str(e)}"},
        )


@router.post("/generate_query/{intcid}")
async def generate_query_route(
    request: Request,
    intcid: str = Path(..., description="Customer ID"),
    request_body: GenerateSentinelQueryRequest = Body(
        ...,
        description="Request to generate Sentinel KQL query",
    ),
):
    """
    Generate a Sentinel KQL query based on the requirement, alert, and context.

    Args:
        intcid: Customer ID
        request_body: Request body containing task, table name, alert, and triage context.

    Returns:
        JSON object with generated Sentinel KQL query.
    """
    Logger.info(
        f"api: /siem/sentinel/sentinel_generate_kql_query/{intcid}: {request_body.task}, {request_body.tid}, {request_body.question_id}, {request_body.triage_question}, {request_body.table_name}, {request_body.env}"
    )
    try:
        raw_body = await request.body()
        Logger.info(
            f"REQUEST PAYLOAD for sentinel_run_kql_query/{intcid}: {raw_body.decode()}"
        )
    except Exception as e:
        Logger.error(f"Failed to log request payload: {str(e)}")

    # Also log the validated request object
    try:
        Logger.info(
            f"VALIDATED REQUEST for sentinel_generate_kql_query/{intcid}: {request_body.json()}"
        )
    except Exception as e:
        Logger.error(f"Failed to log validated request: {str(e)}")

    try:
        result = await sentinel_generate_kql_query(
            intcid,
            request_body.task,
            request_body.table_name,
            request_body.tid,
            request_body.question_id,
            request_body.step_id,
            request_body.triage_question,
            request_body.alert_context,
            request_body.additional_info,
            request_body.env,
        )
        return result

    except Exception as e:
        Logger.error(f"Error generating Sentinel KQL query: {str(e)}")
        Logger.error(
            f"Error generating Sentinel KQL query: {str(e)}\n{traceback.format_exc()}"
        )
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed to generate Sentinel KQL query: {str(e)}"},
        )


# --- New Routes ---


@router.post("/run_query/{intcid}")
async def run_query_route(
    request: Request,
    intcid: str = Path(..., description="Customer ID"),
    request_body: SentinelRunKQLQueryRequest = Body(
        ..., description="Request to run a Sentinel KQL query"
    ),
):
    """
    Executes a given KQL query against the Sentinel Log Analytics workspace.

    Args:
        intcid: Customer ID
        request_body: Request body containing the task description and KQL query.

    Returns:
        JSON object with the query results or an error.
    """
    # Log the raw request body for debugging
    try:
        raw_body = await request.body()
        Logger.info(
            f"REQUEST PAYLOAD for sentinel_run_kql_query/{intcid}: {raw_body.decode()}"
        )
    except Exception as e:
        Logger.error(f"Failed to log request payload: {str(e)}")

    Logger.info(
        f"api: /siem/sentinel/sentinel_run_kql_query/{intcid}: Task: {request_body.task}"
    )
    try:
        result = await sentinel_run_kql_query(
            intcid,
            request_body.task,
            request_body.kql_query,
        )
        return result
    except Exception as e:
        Logger.error(f"Error running Sentinel KQL query: {str(e)}")
        Logger.error(
            f"Error running Sentinel KQL query: {str(e)}\n{traceback.format_exc()}"
        )
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed to run Sentinel KQL query: {str(e)}"},
        )


@router.post("/choose_table/{intcid}")
async def choose_table_route(
    intcid: str = Path(..., description="Customer ID"),
    request: SentinelChooseTableRequest = Body(
        ..., description="Request to choose a Sentinel table"
    ),
):
    """
    Selects the appropriate Sentinel table for a given triage requirement and alert.

    Args:
        intcid: Customer ID
        request: Request body containing triage context and alert details.

    Returns:
        JSON object with the chosen table name and environment, or an error.
    """
    Logger.info(
        f"api: /siem/sentinel/sentinel_choose_table/{intcid}: TID: {request.tid}, QID: {request.question_id}"
    )
    try:
        result = await sentinel_choose_table(
            intcid,
            request.task,
            request.tid,
            request.question_id,
            request.step_id,
            request.triage_question,
            request.alert_context,
            request.additional_info,
        )
        return result
    except Exception as e:
        Logger.error(f"Error choosing Sentinel table: {str(e)}")
        Logger.error(
            f"Error choosing Sentinel table: {str(e)}\n{traceback.format_exc()}"
        )
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed to choose Sentinel table: {str(e)}"},
        )


@router.post("/get_single_matching_record/{intcid}")
async def get_single_matching_record_route(
    intcid: str = Path(..., description="Customer ID"),
    request: SentinelGetSingleRecordRequest = Body(
        ..., description="Request to get a single matching record using KQL"
    ),
):
    """
    Fetches a single record matching a specific KQL query from a Sentinel table.

    Args:
        intcid: Customer ID
        request: Request body containing task, table name, and the specific KQL query.

    Returns:
        JSON object with the table name, query, and the single result, or an error.
    """
    Logger.info(
        f"api: /siem/sentinel/sentinel_get_single_matching_record/{intcid}: Task: {request.task}, Table: {request.table_name}"
    )
    try:
        result = await sentinel_get_single_matching_record(
            intcid,
            request.task,
            request.table_name,
            request.kql_query,
        )
        return result
    except Exception as e:
        Logger.error(f"Error getting single Sentinel record: {str(e)}")
        Logger.error(
            f"Error getting single Sentinel record: {str(e)}\n{traceback.format_exc()}"
        )
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed to get single Sentinel record: {str(e)}"},
        )


@router.post("/get_alert_context/{intcid}")
async def get_alert_context_route(
    intcid: str = Path(..., description="Customer ID"),
    request: SentinelGetAlertContextRequest = Body(
        ..., description="Request to get context for a Sentinel alert"
    ),
):
    """
    Retrieves context for a given Sentinel alert/event using AI.

    Args:
        intcid: Customer ID
        request: Request body containing the task description and the alert dictionary.

    Returns:
        JSON object with the extracted alert context or an error.
    """
    Logger.info(f"api: /siem/sentinel/get_alert_context/{intcid}: Task: {request.task}")
    try:
        result = await sentinel_get_alert_context(
            intcid,
            request.task,
            request.alert,
        )
        return result
    except Exception as e:
        Logger.error(f"Error getting Sentinel alert context: {str(e)}")
        Logger.error(
            f"Error getting Sentinel alert context: {str(e)}\n{traceback.format_exc()}"
        )
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed to get Sentinel alert context: {str(e)}"},
        )
