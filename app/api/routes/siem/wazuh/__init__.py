"""Wazuh routes package."""

from fastapi import APIRouter, Path, Body
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from pltfrm import Logger2 as Logger
import traceback

# Assuming these are implemented in the services layer
from app.services.siem.wazuh.tools import (
    wazuh_get_alert_context,
    wazuh_get_all_index_names,
    wazuh_get_available_fields_of_index,
    wazuh_get_single_matching_record,
    wazuh_choose_index,
    wazuh_generate_query,
    wazuh_run_query,
)


# Request models
class WazuhGetAllIndexNamesRequest(BaseModel):
    task: str


class WazuhGetAvailableFieldsRequest(BaseModel):
    task: str
    index_name: str


class WazuhGetAlertContextRequest(BaseModel):
    task: str
    aid: str
    alert: str


class WazuhGetSingleMatchingRecordRequest(BaseModel):
    task: str
    index_name: str
    query: str


class WazuhChooseIndexRequest(BaseModel):
    task: str
    aid: str
    tid: str
    question_id: str
    triage_question: str
    alert: str


class GenerateWazuhQueryRequest(BaseModel):
    task: str
    aid: str
    tid: str
    question_id: str
    triage_question: str
    index_name: str
    alert: str
    env: str


class RunWazuhQueryRequest(BaseModel):
    task: str
    index_name: str
    wazuh_query: str


# Create router without prefix (prefix is added by parent router)
router = APIRouter(tags=["wazuh"])


@router.post("/get_alert_context/{intcid}")
async def get_alert_context_route(
    intcid: str = Path(..., description="Customer ID"),
    request: WazuhGetAlertContextRequest = Body(
        ..., description="Index selection request"
    ),
):
    """
    Choose the appropriate Wazuh Opensearch index for the requirement

    Args:
        intcid: Customer ID
        request: Request body containing requirement and alert

    Returns:
        JSON object with Wazuh Opensearch index names
    """
    Logger.info(
        f"api: /siem/wazuh/get_alert_context/{intcid}: {request.task}, {request.alert}"
    )
    try:
        result = await wazuh_get_alert_context(
            intcid, request.aid, request.task, request.alert
        )
        return result
    except Exception as e:
        Logger.error(f"Error in wazuh_get_alert_context: {str(e)}")
        Logger.error(
            f"Error in wazuh_get_alert_context: {str(e)}\n{traceback.format_exc()}"
        )
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed to get Wazuh index names: {str(e)}"},
        )


@router.post("/wazuh_get_all_index_names/{intcid}")
async def wazuh_get_all_index_names_route(
    intcid: str = Path(..., description="Customer ID"),
    request: WazuhGetAllIndexNamesRequest = Body(
        ..., description="Index selection request"
    ),
):
    """
    Choose the appropriate Wazuh Opensearch index for the requirement

    Args:
        intcid: Customer ID
        request: Request body containing requirement and alert

    Returns:
        JSON object with Wazuh Opensearch index names
    """
    Logger.info(f"api: /siem/wazuh/wazuh_get_all_index_names/{intcid}: {request.task}")
    try:
        result = await wazuh_get_all_index_names(intcid, request.task)
        return result
    except Exception as e:
        Logger.error(f"Error getting Wazuh index names: {str(e)}")
        Logger.error(
            f"Error getting Wazuh index names: {str(e)}\n{traceback.format_exc()}"
        )
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed to get Wazuh index names: {str(e)}"},
        )


@router.post("/wazuh_get_available_fields_for_index/{intcid}")
async def wazuh_get_available_fields_for_index_route(
    intcid: str = Path(..., description="Customer ID"),
    request: WazuhGetAvailableFieldsRequest = Body(
        ..., description="Index selection request"
    ),
):
    """
    Choose the appropriate Wazuh Opensearch index for the requirement

    Args:
        intcid: Customer ID
        request: Request body containing requirement and alert

    Returns:
        JSON object with Wazuh Opensearch index name
    """
    Logger.info(
        f"api: /siem/wazuh/wazuh_get_available_fields_for_index/{intcid}: {request.task}"
    )
    try:
        result = await wazuh_get_available_fields_of_index(
            intcid, request.task, request.index_name
        )
        return result
    except Exception as e:
        Logger.error(f"Error getting Wazuh field names: {str(e)}")
        Logger.error(
            f"Error getting Wazuh field names: {str(e)}\n{traceback.format_exc()}"
        )
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed to get Wazuh field names: {str(e)}"},
        )


@router.post("/wazuh_get_single_matching_record/{intcid}")
async def wazuh_get_single_matching_record_route(
    intcid: str = Path(..., description="Customer ID"),
    request: WazuhGetSingleMatchingRecordRequest = Body(
        ..., description="Index selection request"
    ),
):
    """
    Choose the appropriate Wazuh Opensearch index for the requirement

    Args:
        intcid: Customer ID
        request: Request body containing requirement and alert

    Returns:
        JSON object with Wazuh Opensearch index name
    """
    Logger.info(
        f"api: /siem/wazuh/wazuh_get_single_matching_record/{intcid}: {request.task}, request.index_name, {request.query}"
    )
    try:
        result = await wazuh_get_single_matching_record(
            intcid, request.task, request.index_name, request.query
        )
        return result
    except Exception as e:
        Logger.error(f"Error in wazuh_get_single_matching_record: {str(e)}")
        Logger.error(
            f"Error in wazuh_get_single_matching_record: {str(e)}\n{traceback.format_exc()}"
        )
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed to get Wazuh field names: {str(e)}"},
        )


@router.post("/wazuh_choose_index_and_environment/{intcid}")
async def wazuh_choose_index_route(
    intcid: str = Path(..., description="Customer ID"),
    request: WazuhChooseIndexRequest = Body(..., description="Index selection request"),
):
    """
    Choose the appropriate Wazuh Opensearch index for the requirement

    Args:
        intcid: Customer ID
        request: Request body containing requirement and alert

    Returns:
        JSON object with Wazuh Opensearch index name
    """
    Logger.info(
        f"api: /siem/wazuh/wazuh_choose_index/{intcid}: {request.task}, {request.aid}, {request.tid}, {request.question_id}, {request.triage_question}, {request.alert}"
    )
    try:
        result = await wazuh_choose_index(
            intcid,
            request.aid,
            request.tid,
            request.question_id,
            request.triage_question,
            request.alert,
        )
        return result
    except Exception as e:
        Logger.error(f"Error selecting Wazuh index: {str(e)}")
        Logger.error(f"Error selecting Wazuh index: {str(e)}\n{traceback.format_exc()}")
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed to select Wazuh index: {str(e)}"},
        )


@router.post("/wazuh_generate_query/{intcid}")
async def wazuh_generate_query_route(
    intcid: str = Path(..., description="Customer ID"),
    request: GenerateWazuhQueryRequest = Body(
        ..., description="Query generation request"
    ),
):
    """
    Generate a Wazuh query based on the requirement

    Args:
        intcid: Customer ID
        request: Request body containing requirement, index name, and alert

    Returns:
        JSON object with generated Wazuh query
    """
    Logger.info(
        f"api: /siem/wazuh/wazuh_generate_query/{intcid}: {request.task}, {request.tid}, {request.question_id}, {request.triage_question}, {request.index_name}, {request.alert}, {request.env}"
    )
    try:
        result = await wazuh_generate_query(
            intcid,
            request.task,
            request.aid,
            request.index_name,
            request.tid,
            request.question_id,
            request.triage_question,
            request.alert,
            request.env,
        )
        return result
    except Exception as e:
        Logger.error(f"Error generating Wazuh query: {str(e)}")
        Logger.error(
            f"Error generating Wazuh query: {str(e)}\n{traceback.format_exc()}"
        )
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed to generate Wazuh query: {str(e)}"},
        )


@router.post("/wazuh_run_query/{intcid}")
async def wazuh_run_query_route(
    intcid: str = Path(..., description="Customer ID"),
    request: RunWazuhQueryRequest = Body(..., description="Query execution request"),
):
    """
    Execute a Wazuh query and return the results

    Args:
        intcid: Customer ID
        request: Request body containing Wazuh query to execute

    Returns:
        JSON object with query results from Wazuh
    """
    Logger.info(
        f"api: /siem/wazuh/wazuh_run_query/{intcid}: {request.task}, {request.index_name}, {request.wazuh_query}"
    )
    try:
        result = await wazuh_run_query(intcid, request.index_name, request.wazuh_query)
        return result
    except Exception as e:
        Logger.error(f"Error executing Wazuh query: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed to execute Wazuh query: {str(e)}"},
        )
