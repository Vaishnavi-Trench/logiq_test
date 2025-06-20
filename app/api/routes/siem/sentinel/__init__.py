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
    standalone_sentinel_prepare_kql_query,
    sentinel_functions,
    get_top_matching_tables,
    get_user_auth_details,
    get_successful_login_details,
    get_failed_login_details,
    get_user_ip_details
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
    aid: str
    step_id: str
    tid: str
    question_id: str
    triage_question: str
    table_name: str
    alert_context: Dict  # Assuming alert is passed as string for this specific tool


class PrepareSentinelQueryRequest(BaseModel):
    task: str
    aid: str
    question_id: str
    step_id: str
    tid: str
    alert_context: dict
    query_template: str


class SentinelFunctionsRequest(BaseModel):
    task: str = Field(..., description="The task description for the request.")


# --- New Request Models ---


class SentinelRunKQLQueryRequest(BaseModel):
    task: Optional[str] = None
    query: str = Field(..., description="The KQL query string to execute.")


class SentinelChooseTableRequest(BaseModel):
    task: str
    aid: str = Field(..., description="The alert ID.")
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
    aid: str = Field(..., description="The alert ID.")
    alert: Any = Field(..., description="The Sentinel alert/event content.")


class GenerateSentinelQueryTemplateRequest(BaseModel):
    task: str
    aid: str = Field(..., description="The alert ID.")
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


class GetTopMatchingTablesRequest(BaseModel):
    tags: Dict
    task: Optional[str] = None

class GetUserAuthDetailsRequest(BaseModel):
    task: Optional[str] = None
    alert_context: Dict = Field(
        ..., description="The alert context dictionary containing user details"
    )

class GetUserIPDetailsRequest(BaseModel):
    task: Optional[str] = None
    alert_context: Dict = Field(
        ..., description="The alert context dictionary containing user IP details"
    )

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
        request_body: Request body containing task, alert_context, and query_template.

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
            request_body.aid,
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


@router.post("/standalone_prepare_query/{intcid}")
async def prepare_query_route(
    request: Request,
    intcid: str = Path(..., description="Customer ID"),
    request_body: PrepareSentinelQueryRequest = Body(
        ...,
        description="Request to prepare Sentinel KQL query",
    ),
):
    """
    Prepare a Sentinel KQL query based on the requirement, alert, and context.

    Args:
        intcid: Customer ID
        request_body: Request body containing task, table name, alert, and triage context.

    Returns:
        JSON object with prepared Sentinel KQL query.
    """
    Logger.info(
        f"api: /siem/sentinel/standalone_prepare_query/{intcid}: {request_body.task}"
    )
    try:
        raw_body = await request.body()
        sanitized_payload = raw_body.decode()[:100]  # Log only the first 100 characters
        Logger.info(f"REQUEST PAYLOAD for prepare_query/{intcid}: {sanitized_payload}")
    except Exception as e:
        Logger.error(f"Failed to log request payload: {str(e)}")

    # Also log the validated request object
    try:
        Logger.info(
            f"VALIDATED REQUEST for prepare_query/{intcid}: {request_body.json()}"
        )
    except Exception as e:
        Logger.error(f"Failed to log validated request: {str(e)}")

    try:
        result = await standalone_sentinel_prepare_kql_query(
            intcid,
            request_body.task,
            request_body.alert_context,
            request_body.query_template,
            request_body.question_id,
            request_body.step_id,
            request_body.tid,
            request_body.aid,
        )
        return result

    except Exception as e:
        Logger.error(f"Error preparing Sentinel KQL query: {str(e)}")
        Logger.error(
            f"Error preparing Sentinel KQL query: {str(e)}\n{traceback.format_exc()}"
        )
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed to prepare Sentinel KQL query: {str(e)}"},
        )


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
            request.aid,
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
            request.aid,
            request.alert
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
            request_body.aid,
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


@router.post("/sentinel_functions/{intcid}")
async def sentinel_functions_route(
    intcid: str = Path(..., description="Customer ID"),
    request_body: SentinelFunctionsRequest = Body(
        ..., description="Request to get Sentinel functions"
    ),
):
    """
    Retrieves KQL functions available in Microsoft Sentinel.

    Args:
        intcid: Customer ID
        request_body: Request body containing task description.

    Returns:
        JSON object with the list of KQL functions or an error.
    """
    Logger.info(
        f"api: /siem/sentinel/sentinel_functions/{intcid}: Task: {request_body.task}"
    )
    try:
        result = await sentinel_functions(intcid, request_body.task)
        return result
    except Exception as e:
        Logger.error(f"Error retrieving Sentinel functions: {str(e)}")
        Logger.error(
            f"Error retrieving Sentinel functions: {str(e)}\n{traceback.format_exc()}"
        )
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed to retrieve Sentinel functions: {str(e)}"},
        )


@router.post("/get_top_matching_tables/{intcid}")
async def get_top_matching_tables_route(
    intcid: str = Path(..., description="Customer ID"),
    request_body: GetTopMatchingTablesRequest = Body(
        ..., description="Request to get top matching tables by tags"
    ),
):
    """
    Returns the top matching Sentinel tables for the given tags.
    Args:
        intcid: Customer ID
        request_body: Request body containing tags and task (optional)
    Returns:
        JSON object with the prioritized list of matching table names.
    """
    Logger.info(
        f"api: /siem/sentinel/get_top_matching_tables/{intcid}: Task: {request_body.task}"
    )
    try:
        tags = request_body.tags
        task = request_body.task
        if not tags:
            return JSONResponse(
                status_code=400, content={"error": "Missing 'tags' in request body."}
            )
        result = await get_top_matching_tables(intcid, tags, task)
        return result
    except ValidationError as ve:
        Logger.error(
            f"Validation error in get_top_matching_tables: {str(ve)}\n{traceback.format_exc()}"
        )
        return JSONResponse(
            status_code=422,
            content={"error": f"Validation error: {str(ve)}"},
        )
    except RuntimeError as e:
        Logger.error(
            f"Runtime error in get_top_matching_tables: {str(e)}\n{traceback.format_exc()}"
        )
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed to get top matching tables: {str(e)}"},
        )
    except Exception as e:
        Logger.error(
            f"Unexpected error in get_top_matching_tables: {str(e)}\n{traceback.format_exc()}"
        )
        return JSONResponse(
            status_code=500,
            content={
                "error": "An unexpected error occurred while getting top matching tables."
            },
        )

@router.post("/get_user_auth_details/{intcid}")
async def get_user_auth_details_route(
    intcid: str = Path(..., description="Customer ID"),
    request_body: GetUserAuthDetailsRequest = Body(
        ..., description="Request to get user authentication details from alert context"
    ),
):
    """
    Retrieves user authentication details from the alert context.

    Args:
        intcid: Customer ID
        request_body: Request body containing task and alert context.

    Returns:
        JSON object with user authentication details or an error.
    """
    Logger.info(
        f"api: /siem/sentinel/get_user_auth_details/{intcid}: Task: {request_body.task}"
    )
    try:
        result = await get_user_auth_details(intcid, request_body.task, request_body.alert_context)
        return result
    except Exception as e:
        Logger.error(f"Error getting user auth details: {str(e)}")
        Logger.error(
            f"Error getting user auth details: {str(e)}\n{traceback.format_exc()}"
        )
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed to get user auth details: {str(e)}"},
        )   
        

@router.post("/get_successful_login_details/{intcid}")
async def get_successful_login_details_route(
    intcid: str = Path(..., description="Customer ID"),
    request_body: GetUserAuthDetailsRequest = Body(
        ..., description="Request to get successful login details from alert context"
    ),
):
    """
    Retrieves successful login details from the alert context.

    Args:
        intcid: Customer ID
        request_body: Request body containing task and alert context.

    Returns:
        JSON object with successful login details or an error.
    """
    Logger.info(
        f"api: /siem/sentinel/get_successful_login_details/{intcid}: Task: {request_body.task}"
    )
    try:
        result = await get_successful_login_details(intcid, request_body.task, request_body.alert_context)
        return result
    except Exception as e:
        Logger.error(f"Error getting successful login details: {str(e)}")
        Logger.error(
            f"Error getting successful login details: {str(e)}\n{traceback.format_exc()}"
        )
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed to get successful login details: {str(e)}"},
        )

@router.post("/get_failed_login_details/{intcid}")
async def get_failed_login_details_route(
    intcid: str = Path(..., description="Customer ID"),
    request_body: GetUserAuthDetailsRequest = Body(
        ..., description="Request to get failed login details from alert context"
    ),
):
    """
    Retrieves failed login details from the alert context.

    Args:
        intcid: Customer ID
        request_body: Request body containing task and alert context.

    Returns:
        JSON object with failed login details or an error.
    """
    Logger.info(
        f"api: /siem/sentinel/get_failed_login_details/{intcid}: Task: {request_body.task}"
    )
    try:
        result = await get_failed_login_details(intcid, request_body.task, request_body.alert_context)
        return result
    except Exception as e:
        Logger.error(f"Error getting failed login details: {str(e)}")
        Logger.error(
            f"Error getting failed login details: {str(e)}\n{traceback.format_exc()}"
        )
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed to get failed login details: {str(e)}"},
        )

@router.post("/get_user_ip_details/{intcid}")
async def get_user_ip_details_route(
    intcid: str = Path(..., description="Customer ID"),
    request_body: GetUserIPDetailsRequest = Body(
        ..., description="Request to get user IP details from alert context"
    ),
):
    """
    Retrieves user IP details from the alert context.

    Args:
        intcid: Customer ID
        request_body: Request body containing task and alert context.

    Returns:
        JSON object with user IP details or an error.
    """
    Logger.info(
        f"api: /siem/sentinel/get_user_ip_details/{intcid}: Task: {request_body.task}"
    )
    try:
        result = await get_user_ip_details(intcid, request_body.task, request_body.alert_context)
        return result
    except Exception as e:
        Logger.error(f"Error getting user IP details: {str(e)}")
        Logger.error(
            f"Error getting user IP details: {str(e)}\n{traceback.format_exc()}"
        )
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed to get user IP details: {str(e)}"},
        )   
        
