"""GCP IAM routes package."""

from fastapi import APIRouter, Path, Body
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from pltfrm import Logger2 as Logger

# Assuming this is implemented in the services layer
from app.services.cloud.gcp.iam.tools import gcp_iam_role_lookup


# Request models
class IAMRoleRequest(BaseModel):
    task: str
    project_id: str
    target_user: str


# Create router without prefix (prefix is added by parent router)
router = APIRouter(tags=["gcp_iam"])


@router.post("/gcp_iam_role_lookup/{intcid}")
async def gcp_iam_role_lookup_route(
    intcid: str = Path(..., description="Customer ID"),
    request: IAMRoleRequest = Body(..., description="IAM role lookup request"),
):
    """
    Check IAM roles for a user in GCP

    Args:
        intcid: Customer ID
        request: Request body containing project ID and target user

    Returns:
        JSON object with IAM roles assigned to the user
    """
    Logger.info(
        f"api: /cloud/gcp/iam/gcp_iam_role_lookup/{intcid}: Looking up IAM roles for {request.target_user}"
    )
    try:
        result = gcp_iam_role_lookup(intcid, request.project_id, request.target_user)
        return result
    except Exception as e:
        Logger.error(f"Error looking up IAM roles: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed to lookup IAM roles: {str(e)}"},
        )
