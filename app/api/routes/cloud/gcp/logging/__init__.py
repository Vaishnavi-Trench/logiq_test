"""GCP Logging routes package."""

from fastapi import APIRouter, Path, Body
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from pltfrm import Logger2 as Logger

# Assuming this is implemented in the services layer
from app.services.cloud.gcp.logging.tools import generate_gcp_logging_query


# Request models
class LoggingQueryRequest(BaseModel):
    task: str
    query: str
    project_id: str


# Create router without prefix (prefix is added by parent router)
router = APIRouter(tags=["gcp_logging"])


@router.post("/generate_gcp_logging_query/{intcid}")
async def generate_gcp_logging_query_route(
    intcid: str = Path(..., description="Customer ID"),
    request: LoggingQueryRequest = Body(..., description="Logging query request"),
):
    """
    Generate and execute a GCP logging query

    Args:
        intcid: Customer ID
        request: Request body containing query and project ID

    Returns:
        JSON object with log events from GCP logging
    """
    Logger.info(
        f"api: /cloud/gcp/logging/generate_gcp_logging_query/{intcid}: Generating and executing logging query"
    )
    try:
        result = generate_gcp_logging_query(intcid, request.query, request.project_id)
        return result
    except Exception as e:
        Logger.error(f"Error generating/executing logging query: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed to generate/execute logging query: {str(e)}"},
        )
