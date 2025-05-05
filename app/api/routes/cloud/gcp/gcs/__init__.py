"""GCP GCS routes package."""

from fastapi import APIRouter, Path, Body
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from pltfrm import Logger2 as Logger

# Assuming this is implemented in the services layer
from app.services.cloud.gcp.gcs.tools import gcs_list_files


# Request models
class GCSBucketRequest(BaseModel):
    task: str
    bucket_name: str


# Create router without prefix (prefix is added by parent router)
router = APIRouter(tags=["gcp_gcs"])


@router.post("/gcs_list_files/{intcid}")
async def gcs_list_files_route(
    intcid: str = Path(..., description="Customer ID"),
    request: GCSBucketRequest = Body(..., description="GCS bucket request"),
):
    """
    List files in a Google Cloud Storage bucket

    Args:
        intcid: Customer ID
        request: Request body containing bucket name

    Returns:
        JSON object with list of files in the bucket
    """
    Logger.info(
        f"api: /cloud/gcp/gcs/gcs_list_files/{intcid}: Listing files in bucket {request.bucket_name}"
    )
    try:
        result = gcs_list_files(intcid, request.bucket_name)
        return result
    except Exception as e:
        Logger.error(f"Error listing GCS files: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed to list GCS files: {str(e)}"},
        )
