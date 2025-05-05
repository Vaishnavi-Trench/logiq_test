"""GCP Audit Logs routes package."""

from fastapi import APIRouter, Path, Body
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from pltfrm import Logger2 as Logger

# Assuming this is implemented in the services layer
from app.services.cloud.gcp.audit_logs.tools import fetch_audit_logs


# Request models
class AuditLogsRequest(BaseModel):
    task: str
    query: str
    project_id: str


# Create router without prefix (prefix is added by parent router)
router = APIRouter(tags=["gcp_audit_logs"])


@router.post("/fetch_audit_logs/{intcid}")
async def fetch_audit_logs_route(
    intcid: str = Path(..., description="Customer ID"),
    request: AuditLogsRequest = Body(..., description="Audit logs request"),
):
    """
    Fetch logs from GCP Audit Logs

    Args:
        intcid: Customer ID
        request: Request body containing query and project ID

    Returns:
        JSON object with audit log events
    """
    Logger.info(
        f"api: /cloud/gcp/audit_logs/fetch_audit_logs/{intcid}: Fetching audit logs from project {request.project_id}"
    )
    try:
        result = fetch_audit_logs(intcid, request.query, request.project_id)
        return result
    except Exception as e:
        Logger.error(f"Error fetching audit logs: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed to fetch audit logs: {str(e)}"},
        )
