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
    get_detection_rules,
    get_sentinel_tables_with_schema,
    get_sentinel_table_row_count,
    get_sentinel_table_schema,
    fetch_security_alerts_with_query,
    fetch_security_alerts,
    fetch_security_incidents,
    sentinel_generate_kql_query,
    sentinel_run_kql_query,
    sentinel_choose_table,  # Added import
    sentinel_get_single_matching_record,  # Added import
    sentinel_get_alert_context,  # Added import
    fetch_sample_records,  # Added import
    sentinel_generate_kql_query_template,  # Added new import
    # test_sentinel_generate_kql_query,  # Added new import
    test_sentinel_choose_table,  # Added new import
)


# Request models
class sentinelTableRequest(BaseModel):
    task: Optional[str] = None


class sentinelDetectionRulesRequest(BaseModel):
    task: Optional[str] = None


class sentinelTableRowCountRequest(BaseModel):
    task: Optional[str] = None
    table_name: str = Field(..., description="The name of the Sentinel table to query.")


class sentinelTableSchemaRequest(BaseModel):
    task: Optional[str] = None
    table_name: str = Field(..., description="The name of the Sentinel table to query.")


class SentinelGetSecurityAlertsExecutingQueryRequest(BaseModel):
    task: Optional[str] = None
    query: str = Field(
        ..., description="The KQL query string to execute for fetching alerts."
    )
    time_field: str = Field(..., description="The time field to filter alerts by.")
    start_time: str = Field(..., description="Start time for the alert query.")
    end_time: str = Field(..., description="End time for the alert query.")


class SentinelGetSecurityAlertsRequest(BaseModel):
    task: Optional[str] = None
    start_time: str = Field(..., description="Start time for the alert query.")
    end_time: str = Field(..., description="End time for the alert query.")


class SentinelGetSecurityIncidentsRequest(BaseModel):
    task: Optional[str] = None
    start_time: str = Field(
        ..., description="Start time for the incident query."
    )  # Corrected description
    end_time: str = Field(
        ..., description="End time for the incident query."
    )  # Corrected description


class GenerateSentinelQueryRequest(BaseModel):
    task: str
    step_id: str
    tid: str
    question_id: str
    triage_question: str
    table_name: str
    alert_context: Dict  # Assuming alert is passed as string for this specific tool


# --- New Request Models ---


class SentinelRunKQLQueryRequest(BaseModel):
    task: Optional[str] = None
    query: str = Field(..., description="The KQL query string to execute.")


class SentinelChooseTableRequest(BaseModel):
    task: str
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


class SentinelGetSingleRecordRequest(BaseModel):
    task: Optional[str] = None
    table_name: str = Field(
        ..., description="The name of the Sentinel table targeted by the query."
    )
    query: str = Field(
        ..., description="The KQL query string expected to return a single record."
    )


class SentinelGetAlertContextRequest(BaseModel):
    task: Optional[str] = None
    alert: Any = Field(..., description="The Sentinel alert/event content.")


class GenerateSentinelQueryTemplateRequest(BaseModel):
    task: str
    tid: str = Field(..., description="The triage ID.")
    question_id: str = Field(
        ..., description="The specific question ID within the triage process."
    )
    step_id: str = Field(..., description="The specific step id of triage plan.")
    tables: List[str] = Field(
        ..., description="List of table names to generate templates for"
    )
    alert_context: Dict = Field(..., description="The alert context dictionary")
    triage_question: str = Field(..., description="The triage question text")


class TestSentinelPrepareQueryRequest(BaseModel):
    task: str = Field(..., description="The task description")
    alert_context: Dict = Field(..., description="The alert context dictionary")
    query_templates: List[str] = Field(
        ..., description="List of query templates to test"
    )


class TestSentinelChooseTableRequest(BaseModel):
    task: str = Field(..., description="The task description")
    alert: str = Field(..., description="The alert string")
    triage_question: str = Field(..., description="The triage question text")
    alert_context: Dict = Field(..., description="The alert context dictionary")


# Create router without prefix (prefix is added by parent router)
router = APIRouter(tags=["sentinel"])


@router.post("/get_detection_rules/{intcid}")
async def get_detection_rules_route(
    intcid: str = Path(..., description="Customer ID"),
    request: sentinelDetectionRulesRequest = Body(
        ..., description="request for detection rules"
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
        f"api: /siem/sentinel/get_detection_rules/{intcid}: {request.task}"  # Corrected path in log
    )
    try:
        result = await get_detection_rules(intcid, request.task)
        return result
    except Exception as e:
        Logger.error(f"Error getting rules {str(e)}")
        Logger.error(
            f"Error in get_detection_rules: {str(e)}\n{traceback.format_exc()}"
        )
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed to get rules from sentinel: {str(e)}"},
        )


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


@router.post("/get_table_schema/{intcid}")
async def get_table_schema_croute(
    intcid: str = Path(..., description="Customer ID"),
    request: sentinelTableSchemaRequest = Body(
        ..., description="request for Log Management Tables"
    ),
):
    """
    Retrieves given table row count from Sentinel
    along with their schemas. # Corrected docstring

    Args:
        intcid: Customer ID
        request: Request body containing task information

    Returns:
        JSON object with table names and their schemas
    """
    Logger.info(
        f"api: /siem/sentinel/get_table_row_count/{intcid}: {request.task}"  # Corrected path in log
    )
    try:
        result = await get_sentinel_table_schema(
            intcid, request.task, request.table_name
        )
        return result
    except Exception as e:
        Logger.error(f"Error getting table row count {str(e)}")
        Logger.error(
            f"Error in get_table_row_count: {str(e)}\n{traceback.format_exc()}"
        )
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed to get table row count from sentinel: {str(e)}"},
        )


@router.post("/get_table_row_count/{intcid}")
async def get_table_row_count_route(
    intcid: str = Path(..., description="Customer ID"),
    request: sentinelTableRowCountRequest = Body(
        ..., description="request for Log Management Tables"
    ),
):
    """
    Retrieves given table row count from Sentinel
    along with their schemas. # Corrected docstring

    Args:
        intcid: Customer ID
        request: Request body containing task information

    Returns:
        JSON object with table names and their schemas
    """
    Logger.info(
        f"api: /siem/sentinel/get_table_row_count/{intcid}: {request.task}"  # Corrected path in log
    )
    try:
        result = await get_sentinel_table_row_count(
            intcid, request.task, request.table_name
        )
        return result
    except Exception as e:
        Logger.error(f"Error getting table row count {str(e)}")
        Logger.error(
            f"Error in get_table_row_count: {str(e)}\n{traceback.format_exc()}"
        )
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed to get table row count from sentinel: {str(e)}"},
        )


@router.post("/fetch_alerts_executing_query/{intcid}")
async def fetch_alerts_executing_query_route(
    intcid: str = Path(..., description="Customer ID"),
    request: SentinelGetSecurityAlertsExecutingQueryRequest = Body(
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
        f"api: /siem/sentinel/fetch_alerts_executing_query/{intcid}: Task: {request.task}"
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
        f"api: /siem/sentinel/generate_query{intcid}: {request_body.task}, {request_body.tid}, {request_body.question_id}, {request_body.triage_question}, {request_body.table_name}"
    )
    try:
        raw_body = await request.body()
        Logger.info(f"REQUEST PAYLOAD for generate_query/{intcid}: {raw_body.decode()}")
    except Exception as e:
        Logger.error(f"Failed to log request payload: {str(e)}")

    # Also log the validated request object
    try:
        Logger.info(
            f"VALIDATED REQUEST for generate_query/{intcid}: {request_body.json()}"
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
            request_body.query,
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
        f"api: /siem/sentinel/choose_table/{intcid}: TID: {request.tid}, QID: {request.question_id}"
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
            request.query,
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


@router.post("/get_sample_records/{intcid}")
async def fetch_sample_records_route(
    intcid: str = Path(..., description="Customer ID"),
    request: sentinelTableSchemaRequest = Body(
        ..., description="Request to fetch sample records from a Sentinel table"
    ),
):
    """
    Fetches sample records from a specified Sentinel table.

    Args:
        intcid: Customer ID
        request: Request body containing the table name and task information.

    Returns:
        JSON object with sample records or an error message.
    """
    Logger.info(
        f"api: /siem/sentinel/get_sample_records/{intcid}: Task: {request.task}, Table: {request.table_name}"
    )
    try:
        result = await fetch_sample_records(intcid, request.table_name)
        return result
    except Exception as e:
        Logger.error(f"Error fetching sample records: {str(e)}")
        Logger.error(
            f"Error in fetch_sample_records: {str(e)}\n{traceback.format_exc()}"
        )
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed to fetch sample records: {str(e)}"},
        )


@router.post("/generate_query_template/{intcid}")
async def generate_query_template_route(
    request: Request,
    intcid: str = Path(..., description="Customer ID"),
    request_body: GenerateSentinelQueryTemplateRequest = Body(
        ...,
        description="Request to generate Sentinel KQL query templates",
    ),
):
    """
    Generate Sentinel KQL query templates based on the requirement, tables, and alert context.

    Args:
        intcid: Customer ID
        request_body: Request body containing task, tables, alert context, and triage question.

    Returns:
        JSON object with generated Sentinel KQL query templates.
    """
    Logger.info(
        f"api: /siem/sentinel/generate_query_template/{intcid}: Task: {request_body.task}, Tables: {request_body.tables}"
    )
    try:
        raw_body = await request.body()
        Logger.info(
            f"REQUEST PAYLOAD for generate_query_template/{intcid}: {raw_body.decode()}"
        )
    except Exception as e:
        Logger.error(f"Failed to log request payload: {str(e)}")

    try:
        Logger.info(
            f"VALIDATED REQUEST for generate_query_template/{intcid}: {request_body.json()}"
        )
    except Exception as e:
        Logger.error(f"Failed to log validated request: {str(e)}")

    try:
        result = await sentinel_generate_kql_query_template(
            intcid,
            request_body.tid,
            request_body.question_id,
            request_body.step_id,
            request_body.task,
            request_body.tables,
            request_body.alert_context,
            request_body.triage_question,
        )
        return result

    except Exception as e:
        Logger.error(f"Error generating Sentinel KQL query templates: {str(e)}")
        Logger.error(
            f"Error generating Sentinel KQL query templates: {str(e)}\n{traceback.format_exc()}"
        )
        return JSONResponse(
            status_code=500,
            content={
                "error": f"Failed to generate Sentinel KQL query templates: {str(e)}"
            },
        )


@router.post("/test_generate_query/{intcid}")
async def test_generate_query_route(
    request: Request,
    intcid: str = Path(..., description="Customer ID"),
    task: str = Path(..., description="Task"),
    tid: str = Path(..., description="Triage ID"),
    question_id: str = Path(..., description="Question ID"),
    step_id: str = Path(..., description="Step ID"),
    triage_question: str = Path(..., description="Triage Question"),
    alert_context: Dict = Path(..., description="Alert Context"),
    query_templates: List[str] = Path(..., description="Query Templates"),
    request_body: TestSentinelPrepareQueryRequest = Body(
        ...,
        description="Request to test generate Sentinel KQL queries",
    ),
):
    """
    Test generate Sentinel KQL queries based on query templates and alert context.

    Args:
        intcid: Customer ID
        request_body: Request body containing task, alert context, and query templates.

    Returns:
        JSON object with generated test Sentinel KQL queries.
    """
    Logger.info(
        f"api: /siem/sentinel/test_generate_query/{intcid}: Task: {request_body.task}"
    )
    try:
        raw_body = await request.body()
        Logger.info(
            f"REQUEST PAYLOAD for test_generate_query/{intcid}: {raw_body.decode()}"
        )
    except Exception as e:
        Logger.error(f"Failed to log request payload: {str(e)}")

    try:
        Logger.info(
            f"VALIDATED REQUEST for test_generate_query/{intcid}: {request_body.json()}"
        )
    except Exception as e:
        Logger.error(f"Failed to log validated request: {str(e)}")

    try:
        result = await sentinel_prepare_kql_query(
            intcid,
            request_body.task,
            request_body.alert_context,
            request_body.query_templates,
        )
        return result

    except Exception as e:
        Logger.error(f"Error testing Sentinel KQL query generation: {str(e)}")
        Logger.error(
            f"Error testing Sentinel KQL query generation: {str(e)}\n{traceback.format_exc()}"
        )
        return JSONResponse(
            status_code=500,
            content={
                "error": f"Failed to test Sentinel KQL query generation: {str(e)}"
            },
        )


@router.post("/test_choose_table/{intcid}")
async def test_choose_table_route(
    request: Request,
    intcid: str = Path(..., description="Customer ID"),
    request_body: TestSentinelChooseTableRequest = Body(
        ...,
        description="Request to test choose Sentinel tables",
    ),
):
    """
    Test choose appropriate Sentinel tables based on the alert and context.

    Args:
        intcid: Customer ID
        request_body: Request body containing task, alert, triage question, and alert context.

    Returns:
        JSON object with chosen Sentinel tables.
    """
    Logger.info(
        f"api: /siem/sentinel/test_choose_table/{intcid}: Task: {request_body.task}"
    )
    try:
        raw_body = await request.body()
        Logger.info(
            f"REQUEST PAYLOAD for test_choose_table/{intcid}: {raw_body.decode()}"
        )
    except Exception as e:
        Logger.error(f"Failed to log request payload: {str(e)}")

    try:
        Logger.info(
            f"VALIDATED REQUEST for test_choose_table/{intcid}: {request_body.json()}"
        )
    except Exception as e:
        Logger.error(f"Failed to log validated request: {str(e)}")

    try:
        result = await test_sentinel_choose_table(
            intcid,
            request_body.alert,
            request_body.task,
            request_body.triage_question,
            request_body.alert_context,
        )
        return result

    except Exception as e:
        Logger.error(f"Error testing Sentinel table selection: {str(e)}")
        Logger.error(
            f"Error testing Sentinel table selection: {str(e)}\n{traceback.format_exc()}"
        )
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed to test Sentinel table selection: {str(e)}"},
        )
